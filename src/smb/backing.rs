// Storage seam between the SMB protocol and an immutable ZIP archive.

use std::collections::{BTreeMap, HashMap};
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

/// Where an entry's expanded copy lives, if it currently has one. Shared with
/// `ExpandedCache` so eviction can release it without going through the map of
/// entries.
type CacheSlot = Arc<Mutex<Option<Arc<CachedFile>>>>;

#[derive(Clone)]
struct Entry {
    info: NodeInfo,
    zip_index: Option<usize>,
    // The first open expands this entry into an anonymous temporary file.
    // Later SMB handles reuse it, giving true positional reads without keeping
    // a potentially enormous decompressed entry in RAM.
    cache: Option<CacheSlot>,
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

/// Total expanded bytes kept on disk before the least recently used copies are
/// dropped. Reading every file in an archive otherwise leaves the whole thing
/// decompressed in the temporary directory at once, which for a large archive
/// fills the disk.
const MAX_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

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
    // Bounds the expanded copies `expand` leaves behind. Separate from
    // `entries` because eviction is ordered by use, not by path.
    expanded: Mutex<ExpandedCache>,
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
            expanded: Mutex::new(ExpandedCache::new(MAX_EXPANDED_BYTES)),
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
        let slot = entry.cache.as_ref().ok_or(status::UNEXPECTED_IO_ERROR)?;
        let key = key_for_smb_path(path);

        // The slot lock is held across the decompression below, so a hit is
        // taken and released first: a second reader of a file already expanded
        // must not queue behind a first reader still expanding another.
        let hit = {
            let cached = slot.lock().map_err(|_| status::UNEXPECTED_IO_ERROR)?;
            (*cached).clone()
        };
        if let Some(file) = hit {
            self.touch_expanded(&key);
            return Ok(file);
        }

        let mut cached = slot.lock().map_err(|_| status::UNEXPECTED_IO_ERROR)?;
        // Another thread may have expanded it while this one waited.
        if let Some(file) = (*cached).clone() {
            drop(cached);
            self.touch_expanded(&key);
            return Ok(file);
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
                // Registered only after the slot guard is released: eviction
                // takes slot locks while holding the cache lock, so a thread
                // holding a slot must never wait for that lock.
                let size = file.size;
                drop(cached);
                self.remember_expanded(key, slot.clone(), size);
                Ok(file)
            }
            Err(error) => {
                smb_log!("open {:?} failed: {error:#}", path.to_smb_absolute());
                Err(status::UNEXPECTED_IO_ERROR)
            }
        }
    }

    fn touch_expanded(&self, key: &[String]) {
        if let Ok(mut expanded) = self.expanded.lock() {
            expanded.touch(key);
        }
    }

    fn remember_expanded(&self, key: Vec<String>, slot: CacheSlot, size: u64) {
        if let Ok(mut expanded) = self.expanded.lock() {
            expanded.insert(key, slot, size);
        }
    }

    #[cfg(test)]
    fn set_expanded_limit(&self, limit: u64) {
        let mut expanded = self.expanded.lock().expect("cache lock");
        expanded.limit = limit;
        expanded.evict_down_to_limit(&[]);
    }

    #[cfg(test)]
    fn expanded_bytes(&self) -> u64 {
        self.expanded.lock().expect("cache lock").total
    }
}

/// Least-recently-used accounting over the expanded copies.
///
/// Holds no file itself: each resident entry keeps the slot the copy lives in,
/// and evicting one clears that slot. A handle already reading the file holds
/// its own `Arc`, so the temporary file survives eviction until the last reader
/// drops it — the cache stops *reusing* it, it does not pull it away.
struct ExpandedCache {
    limit: u64,
    total: u64,
    /// Monotonic use counter; the lowest value is the least recently used.
    tick: u64,
    order: BTreeMap<u64, Vec<String>>,
    resident: HashMap<Vec<String>, Resident>,
}

struct Resident {
    tick: u64,
    size: u64,
    slot: CacheSlot,
}

impl ExpandedCache {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            total: 0,
            tick: 0,
            order: BTreeMap::new(),
            resident: HashMap::new(),
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    fn touch(&mut self, key: &[String]) {
        let tick = self.next_tick();
        if let Some(resident) = self.resident.get_mut(key) {
            self.order.remove(&resident.tick);
            resident.tick = tick;
            self.order.insert(tick, key.to_vec());
        }
    }

    fn insert(&mut self, key: Vec<String>, slot: CacheSlot, size: u64) {
        if let Some(previous) = self.resident.remove(&key) {
            self.order.remove(&previous.tick);
            self.total = self.total.saturating_sub(previous.size);
        }
        let tick = self.next_tick();
        self.order.insert(tick, key.clone());
        self.total = self.total.saturating_add(size);
        self.resident
            .insert(key.clone(), Resident { tick, size, slot });
        self.evict_down_to_limit(&key);
    }

    /// Drop least-recently-used copies until the total is back inside the
    /// limit. `keep` is the entry just inserted: a single file larger than the
    /// whole limit would otherwise be expanded and immediately discarded on
    /// every open.
    fn evict_down_to_limit(&mut self, keep: &[String]) {
        if self.total <= self.limit {
            return;
        }
        let candidates: Vec<(u64, Vec<String>)> = self
            .order
            .iter()
            .map(|(tick, key)| (*tick, key.clone()))
            .collect();
        for (tick, key) in candidates {
            if self.total <= self.limit {
                break;
            }
            if key == keep {
                continue;
            }
            let Some((size, slot)) = self
                .resident
                .get(&key)
                .map(|resident| (resident.size, resident.slot.clone()))
            else {
                continue;
            };
            // An entry being expanded right now holds its slot lock. Waiting
            // for it would block every other open behind the cache lock, so it
            // is left for a later insert to reconsider.
            let Ok(mut guard) = slot.try_lock() else {
                continue;
            };
            *guard = None;
            drop(guard);
            self.resident.remove(&key);
            self.order.remove(&tick);
            self.total = self.total.saturating_sub(size);
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

    /// Expanded copies are temporary files on disk, so reading through a large
    /// archive must not leave every entry decompressed at once.
    #[test]
    fn the_expanded_cache_evicts_least_recently_used_copies() {
        let (_temp, backing) = archive(&[
            ("a.txt", b"aaaaaaaaaa"),
            ("b.txt", b"bbbbbbbbbb"),
            ("c.txt", b"cccccccccc"),
        ]);
        // Room for two of the three ten-byte entries.
        backing.set_expanded_limit(25);

        let a = backing.open(&smb_path("a.txt")).unwrap();
        backing.open(&smb_path("b.txt")).unwrap();
        // Re-reading `a` makes `b` the least recently used one.
        backing.open(&smb_path("a.txt")).unwrap();
        backing.open(&smb_path("c.txt")).unwrap();

        assert!(
            backing.expanded_bytes() <= 25,
            "cache grew past its limit: {}",
            backing.expanded_bytes()
        );
        {
            let expanded = backing.expanded.lock().unwrap();
            assert!(expanded.resident.contains_key(&vec!["a.txt".to_string()]));
            assert!(expanded.resident.contains_key(&vec!["c.txt".to_string()]));
            assert!(
                !expanded.resident.contains_key(&vec!["b.txt".to_string()]),
                "the least recently used copy must be the one dropped"
            );
        }

        // A handle taken before eviction keeps reading its own copy, and an
        // evicted entry simply expands again.
        assert_eq!(&a.read_at(0, 4).unwrap()[..], b"aaaa");
        assert_eq!(
            &backing
                .open(&smb_path("b.txt"))
                .unwrap()
                .read_at(0, 4)
                .unwrap()[..],
            b"bbbb"
        );
    }

    /// A file larger than the whole limit is still served: it is kept for the
    /// open that expanded it rather than discarded on the spot and re-expanded
    /// on every read.
    #[test]
    fn an_entry_larger_than_the_limit_is_still_cached() {
        let (_temp, backing) = archive(&[("big.bin", &[7u8; 64])]);
        backing.set_expanded_limit(8);
        let file = backing.open(&smb_path("big.bin")).unwrap();
        assert_eq!(file.read_at(0, 2).unwrap().len(), 2);
        let expanded = backing.expanded.lock().unwrap();
        assert!(expanded.resident.contains_key(&vec!["big.bin".to_string()]));
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
        for (signature, flags_offset) in
            [(&b"PK\x03\x04"[..], 6usize), (&b"PK\x01\x02"[..], 8usize)]
        {
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
