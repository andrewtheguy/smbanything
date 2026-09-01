// Format-independent archive dispatch, indexing, and SMB folder placement.

mod tar;
#[cfg(test)]
pub(crate) mod test_support;
mod zip;

use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Result, bail};
use smbanything_core::smb::{
    Backing, FileReader, NodeInfo, NodeKind, SmbPath, status,
};

use self::tar::TarBacking;
use self::zip::ZipBacking;

pub(crate) struct ArchiveBacking(ArchiveKind);

enum ArchiveKind {
    Zip(ZipBacking),
    Tar(TarBacking),
}

/// The archive formats served, told apart by file name alone so that a
/// directory listing can pick out archives without opening them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    Zip,
    Tar,
    TarGz,
}

impl Format {
    /// The format an archive path names, or `None` for anything else.
    pub(crate) fn of(path: &Path) -> Option<Self> {
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        let tar_gz = extension.as_deref() == Some("gz")
            && path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.to_ascii_lowercase().ends_with(".tar"));
        match extension.as_deref() {
            Some("zip") => Some(Self::Zip),
            Some("tar") => Some(Self::Tar),
            Some("tgz") => Some(Self::TarGz),
            Some("gz") if tar_gz => Some(Self::TarGz),
            _ => None,
        }
    }
}

impl ArchiveBacking {
    pub(crate) fn open(path: &Path, label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        match Format::of(path) {
            Some(Format::Zip) => Ok(Self(ArchiveKind::Zip(ZipBacking::open(path, label)?))),
            Some(Format::Tar) => Ok(Self(ArchiveKind::Tar(TarBacking::open(path, label)?))),
            Some(Format::TarGz) => {
                Ok(Self(ArchiveKind::Tar(TarBacking::open_gzip(path, label)?)))
            }
            None => match path.extension().and_then(|extension| extension.to_str()) {
                Some(extension) => bail!(
                    "unsupported archive extension .{extension}; expected .zip, .tar, .tar.gz, or .tgz"
                ),
                None => bail!("archive path must end in .zip, .tar, .tar.gz, or .tgz"),
            },
        }
    }

    pub(crate) fn file_count(&self) -> usize {
        match &self.0 {
            ArchiveKind::Zip(backing) => backing.file_count(),
            ArchiveKind::Tar(backing) => backing.file_count(),
        }
    }
}

impl Backing for ArchiveBacking {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        match &self.0 {
            ArchiveKind::Zip(backing) => backing.stat(path),
            ArchiveKind::Tar(backing) => backing.stat(path),
        }
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        match &self.0 {
            ArchiveKind::Zip(backing) => backing.list(path),
            ArchiveKind::Tar(backing) => backing.list(path),
        }
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        match &self.0 {
            ArchiveKind::Zip(backing) => backing.open(path),
            ArchiveKind::Tar(backing) => backing.open(path),
        }
    }

    fn label(&self) -> &str {
        match &self.0 {
            ArchiveKind::Zip(backing) => backing.label(),
            ArchiveKind::Tar(backing) => backing.label(),
        }
    }

    fn total_size(&self) -> u64 {
        match &self.0 {
            ArchiveKind::Zip(backing) => backing.total_size(),
            ArchiveKind::Tar(backing) => backing.total_size(),
        }
    }
}

pub(super) struct IndexedEntry<T> {
    pub(super) info: NodeInfo,
    pub(super) content: Option<T>,
}

pub(super) struct ArchiveIndex<T> {
    entries: BTreeMap<Vec<String>, IndexedEntry<T>>,
    total_size: u64,
    file_count: usize,
}

impl<T> ArchiveIndex<T> {
    pub(super) fn new(timestamp: SystemTime) -> Self {
        let mut entries = BTreeMap::new();
        entries.insert(
            Vec::new(),
            IndexedEntry {
                info: NodeInfo::synthetic_dir("", timestamp),
                content: None,
            },
        );
        Self {
            entries,
            total_size: 0,
            file_count: 0,
        }
    }

    pub(super) fn insert(
        &mut self,
        raw_name: &str,
        is_dir: bool,
        size: u64,
        timestamp: SystemTime,
        format: &str,
        content: Option<T>,
    ) -> Result<()> {
        let components = parse_archive_path(raw_name, is_dir, format)?;
        if components.is_empty() {
            return Ok(());
        }

        for depth in 1..components.len() {
            self.insert_directory(&components[..depth], timestamp, format)?;
        }

        if is_dir {
            debug_assert!(content.is_none());
            return self.insert_directory(&components, timestamp, format);
        }

        let key = normalized_key(&components);
        if let Some(existing) = self.entries.get(&key) {
            bail!(
                "{format} path {raw_name:?} conflicts with existing {} {:?}",
                if existing.info.kind.is_dir() {
                    "directory"
                } else {
                    "file"
                },
                display_components(&components)
            );
        }
        let content = content.expect("file archive entry must have content");
        let name = components.last().expect("non-empty path");
        self.entries.insert(
            key,
            IndexedEntry {
                info: NodeInfo {
                    name: name.to_string(),
                    kind: NodeKind::File,
                    size,
                    mtime: timestamp,
                    atime: timestamp,
                    ctime: timestamp,
                },
                content: Some(content),
            },
        );
        self.total_size = self.total_size.saturating_add(size);
        self.file_count += 1;
        Ok(())
    }

    fn insert_directory(
        &mut self,
        components: &[String],
        timestamp: SystemTime,
        format: &str,
    ) -> Result<()> {
        let key = normalized_key(components);
        if let Some(existing) = self.entries.get(&key) {
            let expected_name = components.last().expect("non-root directory");
            if !existing.info.kind.is_dir() || existing.info.name != *expected_name {
                bail!(
                    "{format} directory {:?} conflicts with an existing path",
                    display_components(components)
                );
            }
            return Ok(());
        }
        let name = components.last().expect("non-root directory");
        self.entries.insert(
            key,
            IndexedEntry {
                info: NodeInfo::synthetic_dir(name, timestamp),
                content: None,
            },
        );
        Ok(())
    }

    pub(super) fn entry(&self, path: &SmbPath) -> Option<&IndexedEntry<T>> {
        self.entries.get(&key_for_smb_path(path))
    }

    pub(super) fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        self.entry(path)
            .map(|entry| entry.info.clone())
            .ok_or(status::OBJECT_NAME_NOT_FOUND)
    }

    pub(super) fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        let parent_key = key_for_smb_path(path);
        let parent = self
            .entries
            .get(&parent_key)
            .ok_or(status::OBJECT_PATH_NOT_FOUND)?;
        if !parent.info.kind.is_dir() {
            return Err(status::NOT_A_DIRECTORY);
        }

        // Keys sort so that every descendant of `parent_key` follows it
        // contiguously, so the range walks only this subtree instead of the
        // whole archive; the length test then keeps just the direct children.
        Ok(self
            .entries
            .range::<Vec<String>, _>((Bound::Excluded(&parent_key), Bound::Unbounded))
            .take_while(|(key, _)| key.starts_with(&parent_key))
            .filter(|(key, _)| key.len() == parent_key.len() + 1)
            .map(|(_, entry)| entry.info.clone())
            .collect())
    }

    pub(super) fn total_size(&self) -> u64 {
        self.total_size
    }

    pub(super) fn file_count(&self) -> usize {
        self.file_count
    }
}

pub(super) fn key_for_smb_path(path: &SmbPath) -> Vec<String> {
    path.components().map(str::to_lowercase).collect()
}

fn parse_archive_path(raw: &str, is_dir: bool, format: &str) -> Result<Vec<String>> {
    let path = if is_dir {
        raw.strip_suffix('/').unwrap_or(raw)
    } else {
        raw
    };
    if path.is_empty() {
        return Ok(Vec::new());
    }
    if path.starts_with('/') {
        bail!("{format} entry {raw:?} has an absolute path");
    }

    let mut components = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            bail!("{format} entry {raw:?} has an unsafe or ambiguous path component");
        }
        if component.chars().any(|ch| {
            ch == '\\'
                || ch == '\0'
                || ch < ' '
                || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|')
        }) {
            bail!("{format} entry {raw:?} contains a name SMB cannot represent safely");
        }
        components.push(component.to_string());
    }
    Ok(components)
}

fn normalized_key(components: &[String]) -> Vec<String> {
    components.iter().map(|part| part.to_lowercase()).collect()
}

fn display_components(components: &[String]) -> String {
    components.join("/")
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use super::test_support::{gzip_member, smb_path};

    #[test]
    fn unknown_extensions_are_rejected() {
        for suffix in [".rar", ".gz", ".tarball.gz"] {
            let temp = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
            let error = ArchiveBacking::open(temp.path(), "fixture")
                .err()
                .expect("unsupported extension must fail");
            assert!(
                error
                    .to_string()
                    .contains("expected .zip, .tar, .tar.gz, or .tgz"),
                "{suffix}: {error:#}"
            );
        }
    }

    #[test]
    fn gzip_tar_extensions_dispatch_to_the_tar_backing() {
        for suffix in [".tar.gz", ".TAR.GZ", ".tgz"] {
            let mut tar_bytes = Vec::new();
            let mut writer = ::tar::Builder::new(&mut tar_bytes);
            let mut header = ::tar::Header::new_gnu();
            header.set_size(5);
            header.set_mode(0o644);
            header.set_cksum();
            writer.append_data(&mut header, "hello.txt", &b"hello"[..]).unwrap();
            writer.finish().unwrap();
            drop(writer);

            let mut temp = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
            temp.write_all(&gzip_member(&tar_bytes)).unwrap();
            temp.flush().unwrap();

            let backing = ArchiveBacking::open(temp.path(), "fixture").unwrap();
            assert_eq!(backing.file_count(), 1, "{suffix}");
            let file = backing.open(&smb_path("hello.txt")).unwrap();
            assert_eq!(&file.read_at(0, 5).unwrap()[..], b"hello", "{suffix}");
        }
    }
}
