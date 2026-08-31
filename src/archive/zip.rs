use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use smbanything_core::smb::{Backing, FileReader, NodeInfo, SmbPath, status};
use zip::ZipArchive;

use super::{ArchiveIndex, IndexedEntry, key_for_smb_path};

type CacheSlot = Arc<Mutex<Option<Arc<CachedFile>>>>;

#[derive(Clone)]
struct ZipContent {
    index: usize,
    // The first open expands this entry into an anonymous temporary file.
    // Later SMB handles reuse it, giving true positional reads without keeping
    // a potentially enormous decompressed entry in RAM.
    cache: CacheSlot,
}

/// Total expanded bytes kept on disk before the least recently used copies are
/// dropped. Reading every file in a ZIP otherwise leaves the whole thing
/// decompressed in the temporary directory at once.
const MAX_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub(super) struct ZipBacking {
    archive: Mutex<ZipArchive<File>>,
    index: ArchiveIndex<ZipContent>,
    label: String,
    expanded: Mutex<ExpandedCache>,
}

impl ZipBacking {
    pub(super) fn open(path: &Path, label: String) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening ZIP archive {}", path.display()))?;
        let timestamp = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or_else(|_| SystemTime::now());
        let mut archive = ZipArchive::new(file)
            .with_context(|| format!("reading ZIP directory from {}", path.display()))?;
        let mut index = ArchiveIndex::new(timestamp);

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

            let content = (!is_dir).then(|| ZipContent {
                index: zip_index,
                cache: Arc::new(Mutex::new(None)),
            });
            index.insert(&raw_name, is_dir, size, timestamp, "ZIP", content)?;
        }

        if archive
            .has_overlapping_files()
            .context("checking ZIP entries for overlapping compressed data")?
        {
            bail!("ZIP entries contain overlapping compressed data");
        }

        Ok(Self {
            archive: Mutex::new(archive),
            index,
            label,
            expanded: Mutex::new(ExpandedCache::new(MAX_EXPANDED_BYTES)),
        })
    }

    pub(super) fn file_count(&self) -> usize {
        self.index.file_count()
    }

    fn expand(
        &self,
        entry: &IndexedEntry<ZipContent>,
        path: &SmbPath,
        content: &ZipContent,
    ) -> Result<Arc<CachedFile>, u32> {
        let key = key_for_smb_path(path);

        let hit = {
            let cached = content
                .cache
                .lock()
                .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
            (*cached).clone()
        };
        if let Some(file) = hit {
            self.touch_expanded(&key);
            return Ok(file);
        }

        let mut cached = content
            .cache
            .lock()
            .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
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
                .by_index(content.index)
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
                let size = file.size;
                drop(cached);
                self.remember_expanded(key, content.cache.clone(), size);
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

impl Backing for ZipBacking {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        self.index.stat(path)
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        self.index.list(path)
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        let entry = self
            .index
            .entry(path)
            .ok_or(status::OBJECT_NAME_NOT_FOUND)?;
        let content = entry
            .content
            .as_ref()
            .ok_or(status::FILE_IS_A_DIRECTORY)?;
        let file: Arc<dyn FileReader> = self.expand(entry, path, content)?;
        Ok(file)
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn total_size(&self) -> u64 {
        self.index.total_size()
    }
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

/// Least-recently-used accounting over expanded ZIP entries.
struct ExpandedCache {
    limit: u64,
    total: u64,
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
        let backing = ZipBacking::open(temp.path(), "fixture".to_string()).expect("open ZIP");
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
    fn the_expanded_cache_evicts_least_recently_used_copies() {
        let (_temp, backing) = archive(&[
            ("a.txt", b"aaaaaaaaaa"),
            ("b.txt", b"bbbbbbbbbb"),
            ("c.txt", b"cccccccccc"),
        ]);
        backing.set_expanded_limit(25);

        let a = backing.open(&smb_path("a.txt")).unwrap();
        backing.open(&smb_path("b.txt")).unwrap();
        backing.open(&smb_path("a.txt")).unwrap();
        backing.open(&smb_path("c.txt")).unwrap();

        assert!(backing.expanded_bytes() <= 25);
        {
            let expanded = backing.expanded.lock().unwrap();
            assert!(expanded.resident.contains_key(&vec!["a.txt".to_string()]));
            assert!(expanded.resident.contains_key(&vec!["c.txt".to_string()]));
            assert!(!expanded.resident.contains_key(&vec!["b.txt".to_string()]));
        }
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
            let temp = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
            let mut writer = ZipWriter::new(temp.reopen().unwrap());
            writer
                .start_file(name, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(b"x").unwrap();
            writer.finish().unwrap();
            let error = ZipBacking::open(temp.path(), "fixture".to_string())
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
        let error = ZipBacking::open(temp.path(), "fixture".to_string())
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

        let error = ZipBacking::open(temp.path(), "fixture".to_string())
            .err()
            .expect("encrypted ZIP must fail");
        assert!(error.to_string().contains("encrypted"), "{error:#}");
        assert!(error.to_string().contains("only unencrypted"), "{error:#}");
    }
}
