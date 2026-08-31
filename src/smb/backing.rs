// Storage seam between the SMB protocol and an immutable ZIP archive.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use zip::ZipArchive;

use super::path::SmbPath;
use super::proto::status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeKind {
    File,
    Dir,
}

impl NodeKind {
    pub(crate) fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct NodeInfo {
    pub(crate) name: String,
    pub(crate) kind: NodeKind,
    pub(crate) size: u64,
    pub(crate) mtime: SystemTime,
    pub(crate) atime: SystemTime,
    pub(crate) ctime: SystemTime,
}

impl NodeInfo {
    pub(crate) fn synthetic_dir(name: &str, now: SystemTime) -> Self {
        Self {
            name: name.to_string(),
            kind: NodeKind::Dir,
            size: 0,
            mtime: now,
            atime: now,
            ctime: now,
        }
    }
}

pub(crate) trait FileReader: Send + Sync {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32>;
}

pub(crate) trait Backing: Send + Sync {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32>;
    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32>;
    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32>;
    fn label(&self) -> &str;
    fn total_size(&self) -> u64;
}

#[derive(Clone)]
struct Entry {
    info: NodeInfo,
    zip_index: Option<usize>,
    // The first open expands this entry into an anonymous temporary file.
    // Later SMB handles reuse it, giving true positional reads without keeping
    // a potentially enormous decompressed entry in RAM.
    cache: Option<Arc<Mutex<Option<Arc<CachedFile>>>>>,
}

impl Entry {
    fn dir(name: &str, timestamp: SystemTime) -> Self {
        Self {
            info: NodeInfo::synthetic_dir(name, timestamp),
            zip_index: None,
            cache: None,
        }
    }

    fn file(name: &str, size: u64, timestamp: SystemTime, zip_index: usize) -> Self {
        Self {
            info: NodeInfo {
                name: name.to_string(),
                kind: NodeKind::File,
                size,
                mtime: timestamp,
                atime: timestamp,
                ctime: timestamp,
            },
            zip_index: Some(zip_index),
            cache: Some(Arc::new(Mutex::new(None))),
        }
    }
}

/// A ZIP archive indexed once when the service starts.
///
/// The source file is opened read-only and kept open for the server lifetime,
/// so replacing its pathname cannot silently switch the mounted contents to a
/// different archive. Callers must not modify the file in place while serving.
pub(crate) struct ZipBacking {
    archive: Mutex<ZipArchive<File>>,
    // Keys are Unicode-lowercased components. SMB paths are case-insensitive;
    // rejecting collisions during indexing gives every client spelling one
    // unambiguous entry.
    entries: BTreeMap<Vec<String>, Entry>,
    label: String,
    total_size: u64,
    file_count: usize,
}

impl ZipBacking {
    pub(crate) fn open(path: &Path, label: impl Into<String>) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening ZIP archive {}", path.display()))?;
        let timestamp = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or_else(|_| SystemTime::now());
        let mut archive = ZipArchive::new(file)
            .with_context(|| format!("reading ZIP directory from {}", path.display()))?;

        let mut entries = BTreeMap::new();
        entries.insert(Vec::new(), Entry::dir("", timestamp));
        let mut total_size = 0u64;
        let mut file_count = 0usize;

        for zip_index in 0..archive.len() {
            // Raw access exposes metadata even for encrypted entries. The
            // normal reader refuses those before `encrypted()` can be checked.
            let (raw_name, encrypted, is_dir, compression, size) = {
                let zip_entry = archive
                    .by_index_raw(zip_index)
                    .with_context(|| format!("reading ZIP entry {zip_index}"))?;
                (
                    zip_entry.name().to_string(),
                    zip_entry.encrypted(),
                    zip_entry.is_dir(),
                    zip_entry.compression(),
                    zip_entry.size(),
                )
            };
            if encrypted {
                bail!(
                    "ZIP entry {raw_name:?} is encrypted; only unencrypted ZIP archives are supported"
                );
            }

            if !is_dir {
                // Constructing the normal reader verifies that this build can
                // decode the entry's compression method. It does not expand
                // any data yet.
                drop(archive.by_index(zip_index).with_context(|| {
                    format!(
                        "ZIP entry {raw_name:?} uses unsupported or invalid compression method {compression}"
                    )
                })?);
            }

            let components = parse_zip_path(&raw_name, is_dir)?;
            if components.is_empty() {
                // A conventional root entry (`/`) carries no content and adds
                // nothing to the synthetic share root.
                continue;
            }

            // ZIP archives do not require explicit directory records. Build
            // every missing parent so those archives still form a real tree.
            for depth in 1..components.len() {
                insert_directory(&mut entries, &components[..depth], timestamp)?;
            }

            if is_dir {
                insert_directory(&mut entries, &components, timestamp)?;
                continue;
            }

            let key = normalized_key(&components);
            if let Some(existing) = entries.get(&key) {
                bail!(
                    "ZIP path {raw_name:?} conflicts with existing {} {:?}",
                    if existing.info.kind.is_dir() {
                        "directory"
                    } else {
                        "file"
                    },
                    display_components(&components)
                );
            }
            let name = components.last().expect("non-empty path");
            entries.insert(key, Entry::file(name, size, timestamp, zip_index));
            total_size = total_size.saturating_add(size);
            file_count += 1;
        }

        if archive
            .has_overlapping_files()
            .context("checking ZIP entries for overlapping compressed data")?
        {
            bail!("ZIP entries contain overlapping compressed data");
        }

        Ok(Self {
            archive: Mutex::new(archive),
            entries,
            label: label.into(),
            total_size,
            file_count,
        })
    }

    pub(crate) fn file_count(&self) -> usize {
        self.file_count
    }

    fn entry(&self, path: &SmbPath) -> Option<&Entry> {
        self.entries.get(&key_for_smb_path(path))
    }

    fn expand(&self, entry: &Entry, path: &SmbPath) -> Result<Arc<CachedFile>, u32> {
        let zip_index = entry.zip_index.ok_or(status::FILE_IS_A_DIRECTORY)?;
        let cache = entry.cache.as_ref().ok_or(status::UNEXPECTED_IO_ERROR)?;
        let mut cached = cache.lock().map_err(|_| status::UNEXPECTED_IO_ERROR)?;
        if let Some(file) = &*cached {
            return Ok(file.clone());
        }

        let result = (|| -> Result<Arc<CachedFile>> {
            let mut archive = self
                .archive
                .lock()
                .map_err(|_| anyhow!("ZIP archive lock was poisoned"))?;
            let mut source = archive
                .by_index(zip_index)
                .with_context(|| format!("opening ZIP entry {}", path.to_smb_absolute()))?;
            if source.encrypted() {
                bail!("ZIP entry became encrypted after indexing");
            }

            let mut file = tempfile::tempfile().context("creating ZIP entry cache")?;
            let copied = std::io::copy(&mut source, &mut file)
                .with_context(|| format!("decompressing {}", path.to_smb_absolute()))?;
            if copied != entry.info.size {
                bail!(
                    "decompressed {} bytes for {}, expected {}",
                    copied,
                    path.to_smb_absolute(),
                    entry.info.size
                );
            }
            file.flush().context("flushing ZIP entry cache")?;
            Ok(Arc::new(CachedFile {
                file: Mutex::new(file),
                size: copied,
            }))
        })();

        match result {
            Ok(file) => {
                *cached = Some(file.clone());
                Ok(file)
            }
            Err(error) => {
                smb_log!("open {:?} failed: {error:#}", path.to_smb_absolute());
                Err(status::UNEXPECTED_IO_ERROR)
            }
        }
    }
}

impl Backing for ZipBacking {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        self.entry(path)
            .map(|entry| entry.info.clone())
            .ok_or(status::OBJECT_NAME_NOT_FOUND)
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        let parent_key = key_for_smb_path(path);
        let parent = self
            .entries
            .get(&parent_key)
            .ok_or(status::OBJECT_PATH_NOT_FOUND)?;
        if !parent.info.kind.is_dir() {
            return Err(status::NOT_A_DIRECTORY);
        }

        Ok(self
            .entries
            .iter()
            .filter(|(key, _)| key.len() == parent_key.len() + 1 && key.starts_with(&parent_key))
            .map(|(_, entry)| entry.info.clone())
            .collect())
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        let entry = self.entry(path).ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        if entry.info.kind.is_dir() {
            return Err(status::FILE_IS_A_DIRECTORY);
        }
        let file: Arc<dyn FileReader> = self.expand(entry, path)?;
        Ok(file)
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn total_size(&self) -> u64 {
        self.total_size
    }
}

fn insert_directory(
    entries: &mut BTreeMap<Vec<String>, Entry>,
    components: &[String],
    timestamp: SystemTime,
) -> Result<()> {
    let key = normalized_key(components);
    if let Some(existing) = entries.get(&key) {
        let expected_name = components.last().expect("non-root directory");
        if !existing.info.kind.is_dir() || existing.info.name != *expected_name {
            bail!(
                "ZIP directory {:?} conflicts with an existing path",
                display_components(components)
            );
        }
        return Ok(());
    }
    let name = components.last().expect("non-root directory");
    entries.insert(key, Entry::dir(name, timestamp));
    Ok(())
}

fn parse_zip_path(raw: &str, is_dir: bool) -> Result<Vec<String>> {
    let path = if is_dir {
        raw.strip_suffix('/').unwrap_or(raw)
    } else {
        raw
    };
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if path.starts_with('/') {
        bail!("ZIP entry {raw:?} has an absolute path");
    }

    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            bail!("ZIP entry {raw:?} has an unsafe or ambiguous path component");
        }
        if component.chars().any(|ch| {
            ch == '\\'
                || ch == '\0'
                || ch < ' '
                || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|')
        }) {
            bail!("ZIP entry {raw:?} contains a name SMB cannot represent safely");
        }
        components.push(component.to_string());
    }
    Ok(components)
}

fn normalized_key(components: &[String]) -> Vec<String> {
    components.iter().map(|part| part.to_lowercase()).collect()
}

fn key_for_smb_path(path: &SmbPath) -> Vec<String> {
    path.components().map(str::to_lowercase).collect()
}

fn display_components(components: &[String]) -> String {
    components.join("/")
}

struct CachedFile {
    file: Mutex<File>,
    size: u64,
}

impl FileReader for CachedFile {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
        if offset >= self.size {
            return Ok(Bytes::new());
        }
        let wanted = u64::from(len).min(self.size - offset);
        let wanted = usize::try_from(wanted).map_err(|_| status::INVALID_PARAMETER)?;
        let mut buffer = vec![0u8; wanted];
        let mut file = self.file.lock().map_err(|_| status::UNEXPECTED_IO_ERROR)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| status::UNEXPECTED_IO_ERROR)?;

        let mut filled = 0usize;
        while filled < buffer.len() {
            let read = file
                .read(&mut buffer[filled..])
                .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        buffer.truncate(filled);
        Ok(Bytes::from(buffer))
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[derive(Default)]
    pub(crate) struct MemBacking {
        entries: BTreeMap<String, (NodeInfo, Vec<u8>)>,
    }

    impl MemBacking {
        pub(crate) fn new() -> Self {
            let mut backing = Self::default();
            backing.entries.insert(
                String::new(),
                (NodeInfo::synthetic_dir("", UNIX_EPOCH), Vec::new()),
            );
            backing
        }

        pub(crate) fn with_dir(mut self, path: &str) -> Self {
            let name = path.rsplit('\\').next().unwrap_or(path).to_string();
            self.entries.insert(
                path.to_string(),
                (
                    NodeInfo {
                        name,
                        kind: NodeKind::Dir,
                        size: 0,
                        mtime: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                        atime: UNIX_EPOCH + Duration::from_secs(1_600_000_001),
                        ctime: UNIX_EPOCH + Duration::from_secs(1_600_000_002),
                    },
                    Vec::new(),
                ),
            );
            self
        }

        pub(crate) fn with_file(mut self, path: &str, content: &[u8]) -> Self {
            let name = path.rsplit('\\').next().unwrap_or(path).to_string();
            self.entries.insert(
                path.to_string(),
                (
                    NodeInfo {
                        name,
                        kind: NodeKind::File,
                        size: content.len() as u64,
                        mtime: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                        atime: UNIX_EPOCH + Duration::from_secs(1_600_000_001),
                        ctime: UNIX_EPOCH + Duration::from_secs(1_600_000_002),
                    },
                    content.to_vec(),
                ),
            );
            self
        }
    }

    impl Backing for MemBacking {
        fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
            self.entries
                .get(&path.to_smb_string())
                .map(|(info, _)| info.clone())
                .ok_or(status::OBJECT_NAME_NOT_FOUND)
        }

        fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
            let prefix = path.to_smb_string();
            let (info, _) = self
                .entries
                .get(&prefix)
                .ok_or(status::OBJECT_PATH_NOT_FOUND)?;
            if !info.kind.is_dir() {
                return Err(status::NOT_A_DIRECTORY);
            }
            let scope = if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}\\")
            };
            Ok(self
                .entries
                .iter()
                .filter(|(key, _)| {
                    !key.is_empty() && key.starts_with(&scope) && !key[scope.len()..].contains('\\')
                })
                .map(|(_, (info, _))| info.clone())
                .collect())
        }

        fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
            let (info, content) = self
                .entries
                .get(&path.to_smb_string())
                .ok_or(status::OBJECT_NAME_NOT_FOUND)?;
            if info.kind.is_dir() {
                return Err(status::FILE_IS_A_DIRECTORY);
            }
            Ok(Arc::new(MemFile {
                content: content.clone(),
            }))
        }

        fn label(&self) -> &str {
            "test"
        }

        fn total_size(&self) -> u64 {
            self.entries.values().map(|(info, _)| info.size).sum()
        }
    }

    struct MemFile {
        content: Vec<u8>,
    }

    impl FileReader for MemFile {
        fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
            let Ok(offset) = usize::try_from(offset) else {
                return Ok(Bytes::new());
            };
            if offset >= self.content.len() {
                return Ok(Bytes::new());
            }
            let end = offset.saturating_add(len as usize).min(self.content.len());
            Ok(Bytes::copy_from_slice(&self.content[offset..end]))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    fn smb_path(path: &str) -> SmbPath {
        SmbPath::parse(path).expect("valid test SMB path")
    }

    fn archive(entries: &[(&str, &[u8])]) -> (NamedTempFile, ZipBacking) {
        let temp = NamedTempFile::new().expect("temporary ZIP");
        let mut writer = ZipWriter::new(temp.reopen().expect("reopen temporary ZIP"));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, contents) in entries {
            writer.start_file(*name, options).expect("start ZIP entry");
            writer.write_all(contents).expect("write ZIP entry");
        }
        writer.finish().expect("finish ZIP");
        let backing = ZipBacking::open(temp.path(), "fixture").expect("open ZIP backing");
        (temp, backing)
    }

    #[test]
    fn implicit_directories_are_indexed_and_listed() {
        let (_temp, backing) = archive(&[
            ("docs/readme.txt", b"hello"),
            ("docs/deep/data.bin", b"123"),
            ("root.txt", b"r"),
        ]);

        let root = backing.list(&smb_path("")).unwrap();
        assert_eq!(
            root.iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["docs", "root.txt"]
        );
        let docs = backing.list(&smb_path("DOCS")).unwrap();
        assert_eq!(
            docs.iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["deep", "readme.txt"]
        );
        assert!(backing.stat(&smb_path("docs\\deep")).unwrap().kind.is_dir());
        assert_eq!(backing.total_size(), 9);
        assert_eq!(backing.file_count(), 3);
    }

    #[test]
    fn files_support_repeated_positional_reads() {
        let (_temp, backing) = archive(&[("numbers.txt", b"0123456789")]);
        let file = backing.open(&smb_path("NUMBERS.TXT")).unwrap();
        assert_eq!(&file.read_at(3, 4).unwrap()[..], b"3456");
        assert_eq!(&file.read_at(0, 3).unwrap()[..], b"012");
        assert_eq!(&file.read_at(8, 20).unwrap()[..], b"89");
        assert!(file.read_at(10, 1).unwrap().is_empty());
    }

    #[test]
    fn unsafe_and_ambiguous_paths_are_rejected() {
        for name in ["../secret", "/absolute", "a//b", "a\\b", "bad:name"] {
            let temp = NamedTempFile::new().unwrap();
            let mut writer = ZipWriter::new(temp.reopen().unwrap());
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"x").unwrap();
            writer.finish().unwrap();
            let error = ZipBacking::open(temp.path(), "fixture")
                .err()
                .expect("unsafe ZIP must fail");
            assert!(
                error.to_string().contains("ZIP entry"),
                "{name:?}: {error:#}"
            );
        }
    }

    #[test]
    fn case_collisions_are_rejected() {
        let temp = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(temp.reopen().unwrap());
        for name in ["Docs/a.txt", "docs/b.txt"] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let error = ZipBacking::open(temp.path(), "fixture")
            .err()
            .expect("case collision must fail");
        assert!(error.to_string().contains("conflicts"), "{error:#}");
    }

    #[test]
    fn encrypted_entries_are_rejected_before_serving() {
        let temp = NamedTempFile::new().unwrap();
        let mut writer = ZipWriter::new(temp.reopen().unwrap());
        writer
            .start_file("secret.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"secret").unwrap();
        writer.finish().unwrap();

        // Mark both the local and central headers as encrypted. The payload
        // need not be encrypted: indexing must reject the flag before a reader
        // or password is ever requested.
        let mut bytes = std::fs::read(temp.path()).unwrap();
        let mut marked = 0;
        for (signature, flags_offset) in [(&b"PK\x03\x04"[..], 6usize), (&b"PK\x01\x02"[..], 8usize)] {
            let start = bytes
                .windows(signature.len())
                .position(|window| window == signature)
                .expect("ZIP header signature");
            bytes[start + flags_offset] |= 1;
            marked += 1;
        }
        assert_eq!(marked, 2);
        std::fs::write(temp.path(), bytes).unwrap();

        let error = ZipBacking::open(temp.path(), "fixture")
            .err()
            .expect("encrypted ZIP must fail");
        assert!(error.to_string().contains("encrypted"), "{error:#}");
        assert!(error.to_string().contains("only unencrypted"), "{error:#}");
    }
}
