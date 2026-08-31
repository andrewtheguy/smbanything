// Archive-specific implementations of the core SMB backing interface.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use smbanything_core::smb::{
    Backing, FileReader, NodeInfo, NodeKind, SmbPath, status,
};
use zip::ZipArchive;

/// Places one backing beneath a single directory at the share root.
///
/// The directory name identifies the archive while keeping `anything` as the one
/// SMB share clients connect to. There is deliberately no route to the inner
/// backing at the share root: every archive path begins with this directory.
pub(crate) struct FolderBacking {
    folder: NodeInfo,
    inner: Arc<dyn Backing>,
}

impl FolderBacking {
    pub(crate) fn new(name: impl Into<String>, inner: Arc<dyn Backing>) -> Self {
        Self {
            folder: NodeInfo::synthetic_dir(&name.into(), SystemTime::now()),
            inner,
        }
    }

    fn inner_path(&self, path: &SmbPath) -> Option<SmbPath> {
        let (first, rest) = path.split_first()?;
        first
            .eq_ignore_ascii_case(&self.folder.name)
            .then_some(rest)
    }
}

impl Backing for FolderBacking {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        if path.components().next().is_none() {
            return Ok(NodeInfo::synthetic_dir("", self.folder.mtime));
        }
        let inner_path = self
            .inner_path(path)
            .ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        if inner_path.components().next().is_none() {
            return Ok(self.folder.clone());
        }
        self.inner.stat(&inner_path)
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        if path.components().next().is_none() {
            return Ok(vec![self.folder.clone()]);
        }
        let inner_path = self
            .inner_path(path)
            .ok_or(status::OBJECT_PATH_NOT_FOUND)?;
        self.inner.list(&inner_path)
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        let inner_path = self
            .inner_path(path)
            .ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        self.inner.open(&inner_path)
    }

    fn label(&self) -> &str {
        self.inner.label()
    }

    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }
}

/// Where an entry's expanded copy lives, if it currently has one. Shared with
/// `ExpandedCache` so eviction can release it without going through the map of
/// entries.
type CacheSlot = Arc<Mutex<Option<Arc<CachedFile>>>>;

#[derive(Clone)]
struct Entry {
    info: NodeInfo,
    content: Option<EntryContent>,
}

#[derive(Clone)]
enum EntryContent {
    Zip {
        index: usize,
        // The first open expands this entry into an anonymous temporary file.
        // Later SMB handles reuse it, giving true positional reads without
        // keeping a potentially enormous decompressed entry in RAM.
        cache: CacheSlot,
    },
    Tar {
        offset: u64,
    },
}

impl Entry {
    fn dir(name: &str, timestamp: SystemTime) -> Self {
        Self {
            info: NodeInfo::synthetic_dir(name, timestamp),
            content: None,
        }
    }

    fn file(name: &str, size: u64, timestamp: SystemTime, content: EntryContent) -> Self {
        Self {
            info: NodeInfo {
                name: name.to_string(),
                kind: NodeKind::File,
                size,
                mtime: timestamp,
                atime: timestamp,
                ctime: timestamp,
            },
            content: Some(content),
        }
    }

    fn zip_file(name: &str, size: u64, timestamp: SystemTime, index: usize) -> Self {
        Self::file(
            name,
            size,
            timestamp,
            EntryContent::Zip {
                index,
                cache: Arc::new(Mutex::new(None)),
            },
        )
    }

    fn tar_file(name: &str, size: u64, timestamp: SystemTime, offset: u64) -> Self {
        Self::file(name, size, timestamp, EntryContent::Tar { offset })
    }
}

/// Total expanded bytes kept on disk before the least recently used copies are
/// dropped. Reading every file in an archive otherwise leaves the whole thing
/// decompressed in the temporary directory at once, which for a large archive
/// fills the disk.
const MAX_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

enum ArchiveSource {
    Zip(Mutex<ZipArchive<File>>),
    Tar(Arc<Mutex<File>>),
}

/// A ZIP or uncompressed TAR archive indexed once when the service starts.
///
/// The source file is opened read-only and kept open for the server lifetime,
/// so replacing its pathname cannot silently switch the mounted contents to a
/// different archive. Callers must not modify the file in place while serving.
pub(crate) struct ArchiveBacking {
    source: ArchiveSource,
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

impl ArchiveBacking {
    pub(crate) fn open(path: &Path, label: impl Into<String>) -> Result<Self> {
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        match extension.as_deref() {
            Some("zip") => Self::open_zip(path, label.into()),
            Some("tar") => Self::open_tar(path, label.into()),
            Some(extension) => bail!(
                "unsupported archive extension .{extension}; expected .zip or .tar"
            ),
            None => bail!("archive path must end in .zip or .tar"),
        }
    }

    fn open_zip(path: &Path, label: String) -> Result<Self> {
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

            let components = parse_archive_path(&raw_name, is_dir, "ZIP")?;
            if components.is_empty() {
                // A conventional root entry (`/`) carries no content and adds
                // nothing to the synthetic share root.
                continue;
            }

            // ZIP archives do not require explicit directory records. Build
            // every missing parent so those archives still form a real tree.
            for depth in 1..components.len() {
                insert_directory(&mut entries, &components[..depth], timestamp, "ZIP")?;
            }

            if is_dir {
                insert_directory(&mut entries, &components, timestamp, "ZIP")?;
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
            entries.insert(key, Entry::zip_file(name, size, timestamp, zip_index));
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
            source: ArchiveSource::Zip(Mutex::new(archive)),
            entries,
            label,
            total_size,
            file_count,
            expanded: Mutex::new(ExpandedCache::new(MAX_EXPANDED_BYTES)),
        })
    }

    fn open_tar(path: &Path, label: String) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening TAR archive {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("reading TAR archive metadata from {}", path.display()))?;
        let archive_size = metadata.len();
        let archive_timestamp = metadata.modified().unwrap_or_else(|_| SystemTime::now());
        let scanner = file
            .try_clone()
            .with_context(|| format!("cloning TAR archive handle for {}", path.display()))?;
        let source = Arc::new(Mutex::new(file));
        let mut archive = tar::Archive::new(scanner);

        let mut entries = BTreeMap::new();
        entries.insert(Vec::new(), Entry::dir("", archive_timestamp));
        let mut total_size = 0u64;
        let mut file_count = 0usize;

        for (tar_index, tar_entry) in archive
            .entries_with_seek()
            .with_context(|| format!("reading TAR entries from {}", path.display()))?
            .enumerate()
        {
            let mut tar_entry =
                tar_entry.with_context(|| format!("reading TAR entry {tar_index}"))?;
            let path_bytes = tar_entry.path_bytes();
            let raw_name = std::str::from_utf8(&path_bytes)
                .with_context(|| format!("TAR entry {tar_index} path is not valid UTF-8"))?
                .to_string();
            let entry_type = tar_entry.header().entry_type();
            if entry_type.is_pax_global_extensions() {
                let extensions = tar_entry
                    .pax_extensions()
                    .with_context(|| format!("reading global PAX header {raw_name:?}"))?
                    .ok_or_else(|| anyhow!("global PAX header {raw_name:?} has no records"))?;
                for extension in extensions {
                    extension.with_context(|| {
                        format!("reading record in global PAX header {raw_name:?}")
                    })?;
                }
                continue;
            }
            let is_dir = entry_type.is_dir();
            if !is_dir && !entry_type.is_file() {
                bail!("TAR entry {raw_name:?} has unsupported type {entry_type:?}");
            }
            let size = if is_dir { 0 } else { tar_entry.size() };
            let offset = tar_entry.raw_file_position();
            let end = offset
                .checked_add(size)
                .ok_or_else(|| anyhow!("TAR entry {raw_name:?} data range overflows u64"))?;
            if end > archive_size {
                bail!(
                    "TAR entry {raw_name:?} extends past the end of the archive"
                );
            }
            let timestamp = tar_entry
                .header()
                .mtime()
                .ok()
                .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
                .unwrap_or(archive_timestamp);
            let components = parse_archive_path(&raw_name, is_dir, "TAR")?;
            if components.is_empty() {
                continue;
            }

            for depth in 1..components.len() {
                insert_directory(&mut entries, &components[..depth], timestamp, "TAR")?;
            }

            if is_dir {
                insert_directory(&mut entries, &components, timestamp, "TAR")?;
                continue;
            }

            let key = normalized_key(&components);
            if let Some(existing) = entries.get(&key) {
                bail!(
                    "TAR path {raw_name:?} conflicts with existing {} {:?}",
                    if existing.info.kind.is_dir() {
                        "directory"
                    } else {
                        "file"
                    },
                    display_components(&components)
                );
            }
            let name = components.last().expect("non-empty path");
            entries.insert(key, Entry::tar_file(name, size, timestamp, offset));
            total_size = total_size.saturating_add(size);
            file_count += 1;
        }

        Ok(Self {
            source: ArchiveSource::Tar(source),
            entries,
            label,
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

    fn expand_zip(
        &self,
        entry: &Entry,
        path: &SmbPath,
        zip_index: usize,
        slot: &CacheSlot,
    ) -> Result<Arc<CachedFile>, u32> {
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
            let ArchiveSource::Zip(archive) = &self.source else {
                return Err(anyhow!("ZIP entry is not backed by a ZIP archive"));
            };
            let mut archive = archive
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
                if std::env::var_os("SMBANYTHING_LOG").is_some() {
                    eprintln!(
                        "[archive] open {:?} failed: {error:#}",
                        path.to_smb_absolute()
                    );
                }
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

impl Backing for ArchiveBacking {
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
        match entry.content.as_ref() {
            None => Err(status::FILE_IS_A_DIRECTORY),
            Some(EntryContent::Zip { index, cache }) => {
                let file: Arc<dyn FileReader> = self.expand_zip(entry, path, *index, cache)?;
                Ok(file)
            }
            Some(EntryContent::Tar { offset }) => {
                let ArchiveSource::Tar(file) = &self.source else {
                    return Err(status::UNEXPECTED_IO_ERROR);
                };
                Ok(Arc::new(TarFile {
                    file: file.clone(),
                    offset: *offset,
                    size: entry.info.size,
                }))
            }
        }
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
    format: &str,
) -> Result<()> {
    let key = normalized_key(components);
    if let Some(existing) = entries.get(&key) {
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
    entries.insert(key, Entry::dir(name, timestamp));
    Ok(())
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

struct TarFile {
    file: Arc<Mutex<File>>,
    offset: u64,
    size: u64,
}

impl FileReader for TarFile {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
        if offset >= self.size {
            return Ok(Bytes::new());
        }
        let wanted = u64::from(len).min(self.size - offset);
        let wanted = usize::try_from(wanted).map_err(|_| status::INVALID_PARAMETER)?;
        let absolute_offset = self
            .offset
            .checked_add(offset)
            .ok_or(status::INVALID_PARAMETER)?;
        let mut buffer = vec![0u8; wanted];
        let mut file = self
            .file
            .lock()
            .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
        file.seek(SeekFrom::Start(absolute_offset))
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
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    fn smb_path(path: &str) -> SmbPath {
        SmbPath::parse(path).expect("valid test SMB path")
    }

    fn zip_archive(entries: &[(&str, &[u8])]) -> (NamedTempFile, ArchiveBacking) {
        let temp = tempfile::Builder::new()
            .suffix(".zip")
            .tempfile()
            .expect("temporary ZIP");
        let mut writer = ZipWriter::new(temp.reopen().expect("reopen temporary ZIP"));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, contents) in entries {
            writer.start_file(*name, options).expect("start ZIP entry");
            writer.write_all(contents).expect("write ZIP entry");
        }
        writer.finish().expect("finish ZIP");
        let backing = ArchiveBacking::open(temp.path(), "fixture").expect("open ZIP backing");
        (temp, backing)
    }

    fn tar_archive(entries: &[(&str, &[u8])]) -> (NamedTempFile, ArchiveBacking) {
        let temp = tempfile::Builder::new()
            .suffix(".tar")
            .tempfile()
            .expect("temporary TAR");
        let mut writer = tar::Builder::new(temp.reopen().expect("reopen temporary TAR"));
        for (name, contents) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(1_600_000_000);
            header.set_cksum();
            writer
                .append_data(&mut header, *name, *contents)
                .expect("write TAR entry");
        }
        writer.finish().expect("finish TAR");
        let backing = ArchiveBacking::open(temp.path(), "fixture").expect("open TAR backing");
        (temp, backing)
    }

    fn tar_with_raw_path(path: &[u8]) -> NamedTempFile {
        assert!(path.len() <= 100);
        let temp = tempfile::Builder::new()
            .suffix(".tar")
            .tempfile()
            .expect("temporary TAR");
        let mut writer = tar::Builder::new(temp.reopen().unwrap());
        let mut header = tar::Header::new_gnu();
        header.as_mut_bytes()[..path.len()].copy_from_slice(path);
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        writer.append(&header, &b"x"[..]).unwrap();
        writer.finish().unwrap();
        temp
    }

    #[test]
    fn folder_backing_exposes_the_archive_only_beneath_its_folder() {
        let (_temp, inner) = zip_archive(&[("docs/readme.txt", b"hello")]);
        let inner: Arc<dyn Backing> = Arc::new(inner);
        let backing = FolderBacking::new("a1b2c3d4", inner);

        let root = backing.list(&smb_path("")).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].name, "a1b2c3d4");
        assert!(root[0].kind.is_dir());

        let archive_root = backing.list(&smb_path("A1B2C3D4")).unwrap();
        assert_eq!(archive_root.len(), 1);
        assert_eq!(archive_root[0].name, "docs");
        assert!(backing.list(&smb_path("docs")).is_err());

        let file = backing
            .open(&smb_path(r"a1b2c3d4\docs\readme.txt"))
            .unwrap();
        assert_eq!(&file.read_at(0, 5).unwrap()[..], b"hello");
        assert_eq!(backing.total_size(), 5);
        assert_eq!(backing.label(), "fixture");
    }

    #[test]
    fn implicit_directories_are_indexed_and_listed() {
        let (_temp, backing) = zip_archive(&[
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
        let (_temp, backing) = zip_archive(&[("numbers.txt", b"0123456789")]);
        let file = backing.open(&smb_path("NUMBERS.TXT")).unwrap();
        assert_eq!(&file.read_at(3, 4).unwrap()[..], b"3456");
        assert_eq!(&file.read_at(0, 3).unwrap()[..], b"012");
        assert_eq!(&file.read_at(8, 20).unwrap()[..], b"89");
        assert!(file.read_at(10, 1).unwrap().is_empty());
    }

    #[test]
    fn tar_archives_are_indexed_and_read_by_offset() {
        let (_temp, backing) = tar_archive(&[
            ("docs/readme.txt", b"hello"),
            ("docs/deep/numbers.txt", b"0123456789"),
            ("root.txt", b"root"),
        ]);

        let root = backing.list(&smb_path("")).unwrap();
        assert_eq!(
            root.iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["docs", "root.txt"]
        );
        let file = backing
            .open(&smb_path(r"DOCS\DEEP\NUMBERS.TXT"))
            .unwrap();
        assert_eq!(&file.read_at(3, 4).unwrap()[..], b"3456");
        assert_eq!(&file.read_at(0, 3).unwrap()[..], b"012");
        assert_eq!(&file.read_at(8, 20).unwrap()[..], b"89");
        assert!(file.read_at(10, 1).unwrap().is_empty());
        assert_eq!(backing.total_size(), 19);
        assert_eq!(backing.file_count(), 3);
    }

    #[test]
    fn tar_case_collisions_are_rejected() {
        let temp = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
        let mut writer = tar::Builder::new(temp.reopen().unwrap());
        for name in ["Docs/a.txt", "docs/b.txt"] {
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(0o644);
            header.set_cksum();
            writer
                .append_data(&mut header, name, &b"x"[..])
                .unwrap();
        }
        writer.finish().unwrap();

        let error = ArchiveBacking::open(temp.path(), "fixture")
            .err()
            .expect("case collision must fail");
        assert!(error.to_string().contains("conflicts"), "{error:#}");
    }

    #[test]
    fn tar_unsafe_and_non_utf8_paths_are_rejected() {
        for path in [
            &b"../secret"[..],
            &b"/absolute"[..],
            &b"a//b"[..],
            &b"bad:name"[..],
            &b"\xff"[..],
        ] {
            let temp = tar_with_raw_path(path);
            let error = ArchiveBacking::open(temp.path(), "fixture")
                .err()
                .expect("unsafe TAR must fail");
            assert!(
                error.to_string().contains("TAR entry"),
                "{path:?}: {error:#}"
            );
        }
    }

    #[test]
    fn tar_non_file_entries_are_rejected() {
        let temp = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
        let mut writer = tar::Builder::new(temp.reopen().unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("target.txt").unwrap();
        header.set_cksum();
        writer
            .append_data(&mut header, "link.txt", std::io::empty())
            .unwrap();
        writer.finish().unwrap();

        let error = ArchiveBacking::open(temp.path(), "fixture")
            .err()
            .expect("symlink must fail");
        assert!(error.to_string().contains("unsupported type"), "{error:#}");
    }

    #[test]
    fn tar_global_pax_metadata_is_accepted() {
        let temp = tempfile::Builder::new().suffix(".tar").tempfile().unwrap();
        let mut writer = tar::Builder::new(temp.reopen().unwrap());
        let pax = b"16 comment=test\n";
        let mut pax_header = tar::Header::new_gnu();
        pax_header.set_entry_type(tar::EntryType::XGlobalHeader);
        pax_header.set_size(pax.len() as u64);
        pax_header.set_mode(0o644);
        pax_header.set_cksum();
        writer
            .append_data(&mut pax_header, "pax_global_header", &pax[..])
            .unwrap();
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(5);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        writer
            .append_data(&mut file_header, "hello.txt", &b"hello"[..])
            .unwrap();
        writer.finish().unwrap();

        let backing = ArchiveBacking::open(temp.path(), "fixture").unwrap();
        assert_eq!(backing.file_count(), 1);
        let file = backing.open(&smb_path("hello.txt")).unwrap();
        assert_eq!(&file.read_at(0, 5).unwrap()[..], b"hello");
    }

    #[test]
    fn gzip_and_unknown_extensions_are_rejected() {
        for suffix in [".tar.gz", ".tgz", ".rar"] {
            let temp = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
            let error = ArchiveBacking::open(temp.path(), "fixture")
                .err()
                .expect("unsupported extension must fail");
            assert!(
                error.to_string().contains("expected .zip or .tar"),
                "{suffix}: {error:#}"
            );
        }
    }

    /// Expanded copies are temporary files on disk, so reading through a large
    /// archive must not leave every entry decompressed at once.
    #[test]
    fn the_expanded_cache_evicts_least_recently_used_copies() {
        let (_temp, backing) = zip_archive(&[
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
        let (_temp, backing) = zip_archive(&[("big.bin", &[7u8; 64])]);
        backing.set_expanded_limit(8);
        let file = backing.open(&smb_path("big.bin")).unwrap();
        assert_eq!(file.read_at(0, 2).unwrap().len(), 2);
        let expanded = backing.expanded.lock().unwrap();
        assert!(expanded.resident.contains_key(&vec!["big.bin".to_string()]));
    }

    #[test]
    fn unsafe_and_ambiguous_paths_are_rejected() {
        for name in ["../secret", "/absolute", "a//b", "a\\b", "bad:name"] {
            let temp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
            let mut writer = ZipWriter::new(temp.reopen().unwrap());
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"x").unwrap();
            writer.finish().unwrap();
            let error = ArchiveBacking::open(temp.path(), "fixture")
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
        let temp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
        let mut writer = ZipWriter::new(temp.reopen().unwrap());
        for name in ["Docs/a.txt", "docs/b.txt"] {
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"x").unwrap();
        }
        writer.finish().unwrap();
        let error = ArchiveBacking::open(temp.path(), "fixture")
            .err()
            .expect("case collision must fail");
        assert!(error.to_string().contains("conflicts"), "{error:#}");
    }

    #[test]
    fn encrypted_entries_are_rejected_before_serving() {
        let temp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
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

        let error = ArchiveBacking::open(temp.path(), "fixture")
            .err()
            .expect("encrypted ZIP must fail");
        assert!(error.to_string().contains("encrypted"), "{error:#}");
        assert!(error.to_string().contains("only unencrypted"), "{error:#}");
    }
}
