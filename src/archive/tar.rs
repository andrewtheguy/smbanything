use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use smbanything_core::smb::{Backing, FileReader, NodeInfo, SmbPath, status};

use super::ArchiveIndex;

pub(super) struct TarBacking {
    file: Arc<Mutex<File>>,
    index: ArchiveIndex<u64>,
    label: String,
}

impl TarBacking {
    pub(super) fn open(path: &Path, label: String) -> Result<Self> {
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
        let file = Arc::new(Mutex::new(file));
        let mut archive = tar::Archive::new(scanner);
        let mut index = ArchiveIndex::new(archive_timestamp);

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
                bail!("TAR entry {raw_name:?} extends past the end of the archive");
            }
            let timestamp = tar_entry
                .header()
                .mtime()
                .ok()
                .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
                .unwrap_or(archive_timestamp);
            let content = (!is_dir).then_some(offset);
            index.insert(&raw_name, is_dir, size, timestamp, "TAR", content)?;
        }

        Ok(Self { file, index, label })
    }

    pub(super) fn file_count(&self) -> usize {
        self.index.file_count()
    }
}

impl Backing for TarBacking {
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
        let offset = entry
            .content
            .as_ref()
            .ok_or(status::FILE_IS_A_DIRECTORY)?;
        Ok(Arc::new(TarFile {
            file: self.file.clone(),
            offset: *offset,
            size: entry.info.size,
        }))
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn total_size(&self) -> u64 {
        self.index.total_size()
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
    use tempfile::NamedTempFile;

    use super::*;

    fn smb_path(path: &str) -> SmbPath {
        SmbPath::parse(path).expect("valid test SMB path")
    }

    fn archive(entries: &[(&str, &[u8])]) -> (NamedTempFile, TarBacking) {
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
        let backing = TarBacking::open(temp.path(), "fixture".to_string()).expect("open TAR");
        (temp, backing)
    }

    fn archive_with_raw_path(path: &[u8]) -> NamedTempFile {
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
    fn archives_are_indexed_and_read_by_offset() {
        let (_temp, backing) = archive(&[
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
    fn case_collisions_are_rejected() {
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

        let error = TarBacking::open(temp.path(), "fixture".to_string())
            .err()
            .expect("case collision must fail");
        assert!(error.to_string().contains("conflicts"), "{error:#}");
    }

    #[test]
    fn unsafe_and_non_utf8_paths_are_rejected() {
        for path in [
            &b"../secret"[..],
            &b"/absolute"[..],
            &b"a//b"[..],
            &b"bad:name"[..],
            &b"\xff"[..],
        ] {
            let temp = archive_with_raw_path(path);
            let error = TarBacking::open(temp.path(), "fixture".to_string())
                .err()
                .expect("unsafe TAR must fail");
            assert!(
                error.to_string().contains("TAR entry"),
                "{path:?}: {error:#}"
            );
        }
    }

    #[test]
    fn non_file_entries_are_rejected() {
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

        let error = TarBacking::open(temp.path(), "fixture".to_string())
            .err()
            .expect("symlink must fail");
        assert!(error.to_string().contains("unsupported type"), "{error:#}");
    }

    #[test]
    fn global_pax_metadata_is_accepted() {
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

        let backing = TarBacking::open(temp.path(), "fixture".to_string()).unwrap();
        assert_eq!(backing.file_count(), 1);
        let file = backing.open(&smb_path("hello.txt")).unwrap();
        assert_eq!(&file.read_at(0, 5).unwrap()[..], b"hello");
    }
}
