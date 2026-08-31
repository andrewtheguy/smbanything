use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use rapidgzip_core::{Decoder, DeflateIndex, IndexOptions, IndexedReader};
use smbanything_core::smb::{Backing, FileReader, NodeInfo, SmbPath, status};

use super::ArchiveIndex;

/// Maximum decompressed gzip size. Checkpoint indexing does not materialize
/// these bytes, but the cap still bounds gzip-bomb CPU time, index size, and
/// the logical size exposed through SMB.
const MAX_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub(super) struct TarBacking {
    source: TarSource,
    index: ArchiveIndex<u64>,
    label: String,
}

#[derive(Clone)]
enum TarSource {
    Plain(Arc<Mutex<File>>),
    Gzip(Arc<GzipSource>),
}

impl TarBacking {
    pub(super) fn open(path: &Path, label: String) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("opening TAR archive {}", path.display()))?;
        let archive_timestamp = file
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or_else(|_| SystemTime::now());
        let archive_size = file
            .metadata()
            .context("reading TAR archive metadata")?
            .len();
        let scanner = file
            .try_clone()
            .context("cloning TAR archive handle")?;
        let mut archive = tar::Archive::new(scanner);
        let entries = archive
            .entries_with_seek()
            .context("reading TAR entries")?;
        let (index, _) = Self::index_entries(entries, archive_timestamp, Some(archive_size))?;
        Ok(Self {
            source: TarSource::Plain(Arc::new(Mutex::new(file))),
            index,
            label,
        })
    }

    /// Builds a compact DEFLATE checkpoint index while the TAR headers are
    /// scanned. The decompressed TAR is never materialized; positional SMB
    /// reads resume inflation at the nearest preceding checkpoint.
    pub(super) fn open_gzip(path: &Path, label: String) -> Result<Self> {
        Self::open_gzip_with_limit(path, label, MAX_EXPANDED_BYTES)
    }

    fn open_gzip_with_limit(path: &Path, label: String, expanded_limit: u64) -> Result<Self> {
        let compressed = File::open(path)
            .with_context(|| format!("opening gzip TAR archive {}", path.display()))?;
        let archive_timestamp = compressed
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or_else(|_| SystemTime::now());
        let decoder = Decoder::builder()
            .decoder_threads(1)
            .output_limit(Some(expanded_limit))
            .build()
            .context("configuring the indexed gzip decoder")?;
        let mut scanner = decoder
            .reader_with_index(compressed, IndexOptions::default())
            .with_context(|| format!("decompressing gzip TAR archive {}", path.display()))?;
        let (index, maximum_entry_end) = {
            let mut archive = tar::Archive::new(&mut scanner);
            let entries = archive.entries().context("reading gzip TAR entries")?;
            Self::index_entries(entries, archive_timestamp, None)
                .with_context(|| format!("decompressing gzip TAR archive {}", path.display()))?
        };
        let report = scanner
            .finish()
            .with_context(|| format!("decompressing gzip TAR archive {}", path.display()))?;
        if maximum_entry_end > report.decode.decompressed_bytes {
            bail!("gzip TAR entry extends past the end of the archive");
        }

        let compressed = File::open(path)
            .with_context(|| format!("reopening gzip TAR archive {}", path.display()))?;
        let source = GzipSource::start(compressed, report.index)?;
        Ok(Self {
            source: TarSource::Gzip(Arc::new(source)),
            index,
            label,
        })
    }

    fn index_entries<'a, R: Read + 'a>(
        entries: impl Iterator<Item = std::io::Result<tar::Entry<'a, R>>>,
        archive_timestamp: SystemTime,
        archive_size: Option<u64>,
    ) -> Result<(ArchiveIndex<u64>, u64)> {
        let mut index = ArchiveIndex::new(archive_timestamp);
        let mut maximum_entry_end = 0;

        for (tar_index, tar_entry) in entries.enumerate() {
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
            if archive_size.is_some_and(|archive_size| end > archive_size) {
                bail!("TAR entry {raw_name:?} extends past the end of the archive");
            }
            maximum_entry_end = maximum_entry_end.max(end);
            let timestamp = tar_entry
                .header()
                .mtime()
                .ok()
                .and_then(|seconds| UNIX_EPOCH.checked_add(Duration::from_secs(seconds)))
                .unwrap_or(archive_timestamp);
            let content = (!is_dir).then_some(offset);
            index.insert(&raw_name, is_dir, size, timestamp, "TAR", content)?;
        }

        Ok((index, maximum_entry_end))
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
            source: self.source.clone(),
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
    source: TarSource,
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
        match &self.source {
            TarSource::Plain(source) => {
                let mut buffer = vec![0u8; wanted];
                let mut source = source
                    .lock()
                    .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
                let filled = read_at(&mut *source, absolute_offset, &mut buffer)
                    .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
                buffer.truncate(filled);
                Ok(Bytes::from(buffer))
            }
            TarSource::Gzip(source) => source.read_at(absolute_offset, wanted),
        }
    }
}

fn read_at<R: Read + Seek>(
    source: &mut R,
    absolute_offset: u64,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    source.seek(SeekFrom::Start(absolute_offset))?;

    let mut filled = 0;
    while filled < buffer.len() {
        let read = source.read(&mut buffer[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

/// Upper bound on pooled gzip readers. Each reader owns its own clone of the
/// checkpoint index and its own inflate state, so the pool stays small.
const MAX_GZIP_READERS: usize = 4;

/// A bounded pool of checkpoint-indexed gzip readers.
///
/// `IndexedReader` is not `Send`, so each reader lives on its own worker
/// thread. Requests route stickily: a read continuing where a worker left off
/// stays on that worker, so concurrent sequential streams keep hot readers
/// instead of paying a checkpoint resume on every read.
struct GzipSource {
    workers: Vec<GzipWorker>,
    router: Mutex<Router>,
}

struct GzipWorker {
    requests: mpsc::Sender<GzipRequest>,
    worker: Option<JoinHandle<()>>,
}

enum GzipRequest {
    Read {
        offset: u64,
        len: usize,
        response: mpsc::SyncSender<std::result::Result<Vec<u8>, ()>>,
    },
    Stop,
}

struct Router {
    routes: Vec<Route>,
    clock: u64,
}

#[derive(Clone, Copy)]
struct Route {
    next_offset: u64,
    last_used: u64,
}

impl Router {
    fn new(workers: usize) -> Self {
        Self {
            routes: vec![
                Route {
                    next_offset: 0,
                    last_used: 0,
                };
                workers
            ],
            clock: 0,
        }
    }

    /// Picks the worker whose reader already sits at `offset`, falling back to
    /// the least recently used worker for non-sequential reads.
    fn pick(&mut self, offset: u64, len: usize) -> usize {
        let chosen = self
            .routes
            .iter()
            .position(|route| route.next_offset == offset)
            .unwrap_or_else(|| {
                self.routes
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, route)| route.last_used)
                    .map(|(index, _)| index)
                    .unwrap_or(0)
            });
        self.clock += 1;
        self.routes[chosen] = Route {
            next_offset: offset.saturating_add(len as u64),
            last_used: self.clock,
        };
        chosen
    }
}

impl GzipSource {
    fn start(compressed: File, index: DeflateIndex) -> Result<Self> {
        let pool = thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .min(MAX_GZIP_READERS);
        let mut workers = Vec::with_capacity(pool);
        for worker_index in 0..pool {
            let compressed = compressed
                .try_clone()
                .context("cloning the gzip archive handle")?;
            workers.push(GzipWorker::start(worker_index, compressed, index.clone())?);
        }
        Ok(Self {
            router: Mutex::new(Router::new(workers.len())),
            workers,
        })
    }

    fn read_at(&self, offset: u64, len: usize) -> Result<Bytes, u32> {
        let worker = {
            let mut router = self
                .router
                .lock()
                .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
            router.pick(offset, len)
        };
        let (response_sender, response_receiver) = mpsc::sync_channel(0);
        self.workers[worker]
            .requests
            .send(GzipRequest::Read {
                offset,
                len,
                response: response_sender,
            })
            .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
        let buffer = response_receiver
            .recv()
            .map_err(|_| status::UNEXPECTED_IO_ERROR)?
            .map_err(|_| status::UNEXPECTED_IO_ERROR)?;
        Ok(Bytes::from(buffer))
    }
}

impl GzipWorker {
    fn start(worker_index: usize, compressed: File, index: DeflateIndex) -> Result<Self> {
        let (request_sender, request_receiver) = mpsc::channel();
        let (initialization_sender, initialization_receiver) = mpsc::sync_channel(0);
        let worker = thread::Builder::new()
            .name(format!("smbanything-gzip-reader-{worker_index}"))
            .spawn(move || {
                let mut reader = match IndexedReader::new(compressed, index) {
                    Ok(reader) => {
                        if initialization_sender.send(Ok(())).is_err() {
                            return;
                        }
                        reader
                    }
                    Err(error) => {
                        let _ = initialization_sender.send(Err(error.to_string()));
                        return;
                    }
                };

                while let Ok(request) = request_receiver.recv() {
                    match request {
                        GzipRequest::Read {
                            offset,
                            len,
                            response,
                        } => {
                            let mut buffer = vec![0; len];
                            let result = read_at(&mut reader, offset, &mut buffer)
                                .map(|filled| {
                                    buffer.truncate(filled);
                                    buffer
                                })
                                .map_err(|_| ());
                            let _ = response.send(result);
                        }
                        GzipRequest::Stop => break,
                    }
                }
            })
            .context("starting a checkpoint-indexed gzip reader")?;

        match initialization_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                requests: request_sender,
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                bail!("opening the checkpoint-indexed gzip stream: {error}")
            }
            Err(_) => {
                let _ = worker.join();
                bail!("checkpoint-indexed gzip reader stopped during initialization")
            }
        }
    }
}

impl Drop for GzipWorker {
    fn drop(&mut self) {
        let _ = self.requests.send(GzipRequest::Stop);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use rapidgzip_core::DecodeError;
    use tempfile::NamedTempFile;

    use super::*;

    /// Extracts the decoder's typed failure, which reaches callers either
    /// directly through `finish` or boxed inside the `io::Error` that the
    /// decoding reader returns mid-stream.
    fn decode_error(error: &anyhow::Error) -> &DecodeError {
        error
            .chain()
            .find_map(|cause| {
                cause.downcast_ref::<DecodeError>().or_else(|| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::get_ref)
                        .and_then(|source| source.downcast_ref::<DecodeError>())
                })
            })
            .unwrap_or_else(|| panic!("expected a decoder failure: {error:#}"))
    }

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
    fn gzip_archives_are_checkpoint_indexed_and_read_by_offset() {
        use std::io::Write as _;

        let temp = tempfile::Builder::new()
            .suffix(".tar.gz")
            .tempfile()
            .expect("temporary TAR.GZ");
        let mut writer = tar::Builder::new(flate2::write::GzEncoder::new(
            temp.reopen().expect("reopen temporary TAR.GZ"),
            flate2::Compression::default(),
        ));
        for (name, contents) in [
            ("docs/readme.txt", &b"hello"[..]),
            ("docs/deep/numbers.txt", &b"0123456789"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(1_600_000_000);
            header.set_cksum();
            writer
                .append_data(&mut header, name, contents)
                .expect("write TAR entry");
        }
        writer
            .into_inner()
            .expect("finish TAR")
            .finish()
            .expect("finish gzip")
            .flush()
            .expect("flush gzip");

        let backing =
            TarBacking::open_gzip(temp.path(), "fixture".to_string()).expect("open TAR.GZ");
        let root = backing.list(&smb_path("")).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].name, "docs");
        let file = backing.open(&smb_path(r"DOCS\DEEP\NUMBERS.TXT")).unwrap();
        let concurrent = file.clone();
        let concurrent_read = std::thread::spawn(move || concurrent.read_at(0, 5));
        assert_eq!(&file.read_at(3, 4).unwrap()[..], b"3456");
        assert_eq!(&file.read_at(8, 20).unwrap()[..], b"89");
        assert_eq!(&concurrent_read.join().unwrap().unwrap()[..], b"01234");
        assert_eq!(backing.total_size(), 15);
        assert_eq!(backing.file_count(), 2);
    }

    #[test]
    fn multi_member_gzip_archives_are_checkpoint_indexed() {
        use std::io::Write as _;

        let mut tar_bytes = Vec::new();
        {
            let mut writer = tar::Builder::new(&mut tar_bytes);
            let contents = b"a gzip member boundary can split the TAR byte stream";
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            writer
                .append_data(&mut header, "split.txt", &contents[..])
                .expect("write TAR entry");
            writer.finish().expect("finish TAR");
        }

        let split = 530;
        let mut gzip_bytes = Vec::new();
        for part in [&tar_bytes[..split], &tar_bytes[split..]] {
            let mut encoder = flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::default(),
            );
            encoder.write_all(part).expect("write gzip member");
            gzip_bytes.extend(encoder.finish().expect("finish gzip member"));
        }
        let mut temp = tempfile::Builder::new()
            .suffix(".tar.gz")
            .tempfile()
            .expect("temporary TAR.GZ");
        temp.write_all(&gzip_bytes).expect("write multi-member gzip");
        temp.flush().expect("flush multi-member gzip");

        let backing =
            TarBacking::open_gzip(temp.path(), "fixture".to_string()).expect("open TAR.GZ");
        let file = backing.open(&smb_path("split.txt")).unwrap();
        assert_eq!(&file.read_at(2, 12).unwrap()[..], b"gzip member ");
        assert_eq!(&file.read_at(0, 5).unwrap()[..], b"a gzi");
    }

    #[test]
    fn gzip_reads_seek_across_interior_checkpoints() {
        use std::io::Write as _;

        let contents: Vec<u8> = (0..5 * 1024 * 1024 + 257)
            .map(|index| (index as u8).wrapping_mul(31))
            .collect();
        let temp = tempfile::Builder::new()
            .suffix(".tar.gz")
            .tempfile()
            .expect("temporary TAR.GZ");
        let mut writer = tar::Builder::new(flate2::write::GzEncoder::new(
            temp.reopen().expect("reopen temporary TAR.GZ"),
            flate2::Compression::fast(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        writer
            .append_data(&mut header, "large.bin", &contents[..])
            .expect("write TAR entry");
        writer
            .into_inner()
            .expect("finish TAR")
            .finish()
            .expect("finish gzip")
            .flush()
            .expect("flush gzip");

        let backing =
            TarBacking::open_gzip(temp.path(), "fixture".to_string()).expect("open TAR.GZ");
        let file = backing.open(&smb_path("large.bin")).unwrap();
        let late_offset = 4 * 1024 * 1024 + 113;
        assert_eq!(
            &file.read_at(late_offset as u64, 4096).unwrap()[..],
            &contents[late_offset..late_offset + 4096]
        );
        assert_eq!(&file.read_at(17, 1024).unwrap()[..], &contents[17..1041]);

        let contents = Arc::new(contents);
        let streams: Vec<_> = (0..3)
            .map(|stream| {
                let file = file.clone();
                let contents = contents.clone();
                std::thread::spawn(move || {
                    let start = stream * (1024 * 1024 + 61);
                    for chunk in 0..24 {
                        let offset = start + chunk * 4096;
                        assert_eq!(
                            &file.read_at(offset as u64, 4096).unwrap()[..],
                            &contents[offset..offset + 4096],
                            "stream {stream} chunk {chunk}"
                        );
                    }
                })
            })
            .collect();
        for stream in streams {
            stream.join().expect("concurrent sequential stream");
        }
    }

    #[test]
    fn gzip_archives_past_the_expansion_limit_are_rejected() {
        use std::io::Write as _;

        let temp = tempfile::Builder::new()
            .suffix(".tar.gz")
            .tempfile()
            .expect("temporary TAR.GZ");
        let mut writer = tar::Builder::new(flate2::write::GzEncoder::new(
            temp.reopen().expect("reopen temporary TAR.GZ"),
            flate2::Compression::default(),
        ));
        let contents = [0u8; 4096];
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        writer
            .append_data(&mut header, "zeros.bin", &contents[..])
            .expect("write TAR entry");
        writer
            .into_inner()
            .expect("finish TAR")
            .finish()
            .expect("finish gzip")
            .flush()
            .expect("flush gzip");

        let error = TarBacking::open_gzip_with_limit(temp.path(), "fixture".to_string(), 1024)
            .err()
            .expect("oversized gzip must fail");
        assert!(
            matches!(
                decode_error(&error),
                DecodeError::OutputLimitExceeded { limit: 1024 }
            ),
            "{error:#}"
        );
    }

    #[test]
    fn corrupt_gzip_archives_are_rejected() {
        use std::io::Write as _;

        let mut temp = tempfile::Builder::new()
            .suffix(".tar.gz")
            .tempfile()
            .unwrap();
        temp.write_all(b"this is not a gzip stream").unwrap();
        temp.flush().unwrap();

        let error = TarBacking::open_gzip(temp.path(), "fixture".to_string())
            .err()
            .expect("corrupt gzip must fail");
        assert!(error.to_string().contains("decompressing"), "{error:#}");
    }

    #[test]
    fn gzip_checksum_mismatches_are_rejected() {
        use std::io::Write as _;

        let mut temp = tempfile::Builder::new()
            .suffix(".tar.gz")
            .tempfile()
            .expect("temporary TAR.GZ");
        let mut encoder = flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        );
        {
            let mut writer = tar::Builder::new(&mut encoder);
            let mut header = tar::Header::new_gnu();
            header.set_size(5);
            header.set_mode(0o644);
            header.set_cksum();
            writer
                .append_data(&mut header, "file.txt", &b"hello"[..])
                .expect("write TAR entry");
            writer.finish().expect("finish TAR");
        }
        let mut gzip = encoder.finish().expect("finish gzip");
        let checksum_byte = gzip.len() - 8;
        gzip[checksum_byte] ^= 0xff;
        temp.write_all(&gzip).expect("write corrupt gzip");
        temp.flush().expect("flush corrupt gzip");

        let error = TarBacking::open_gzip(temp.path(), "fixture".to_string())
            .err()
            .expect("checksum mismatch must fail");
        assert!(
            matches!(
                decode_error(&error),
                DecodeError::ChecksumMismatch { member: 0, .. }
            ),
            "{error:#}"
        );
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
