use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use bytes::Bytes;
use smbanything_core::smb::{Backing, FileReader, NodeInfo, SmbPath, status};

use super::ArchiveIndex;

pub(crate) fn smb_path(path: &str) -> SmbPath {
    SmbPath::parse(path).expect("valid test SMB path")
}

/// One file, `docs/readme.txt`, holding `hello`.
pub(crate) struct TestBacking {
    index: ArchiveIndex<Vec<u8>>,
}

impl TestBacking {
    pub(crate) fn new() -> Self {
        let mut index = ArchiveIndex::new(UNIX_EPOCH);
        index
            .insert(
                "docs/readme.txt",
                false,
                5,
                UNIX_EPOCH,
                "test",
                Some(b"hello".to_vec()),
            )
            .unwrap();
        Self { index }
    }
}

impl Backing for TestBacking {
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
        Ok(Arc::new(TestFile(Mutex::new(content.clone()))))
    }

    fn label(&self) -> &str {
        "fixture"
    }

    fn total_size(&self) -> u64 {
        self.index.total_size()
    }
}

struct TestFile(Mutex<Vec<u8>>);

impl FileReader for TestFile {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
        let content = self.0.lock().map_err(|_| status::UNEXPECTED_IO_ERROR)?;
        let offset = usize::try_from(offset).map_err(|_| status::INVALID_PARAMETER)?;
        if offset >= content.len() {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(len as usize).min(content.len());
        Ok(Bytes::copy_from_slice(&content[offset..end]))
    }
}

const DEFLATE_BLOCK_SIZE: usize = 64 * 1024;
const LENGTH_BASES: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99,
    115, 131, 163, 195, 227, 258,
];
const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
    0,
];

/// Wraps bytes in a gzip member using fixed-Huffman DEFLATE blocks.
pub(super) fn gzip_member(contents: &[u8]) -> Vec<u8> {
    let mut gzip = Vec::with_capacity(10 + contents.len() + 8);
    gzip.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]);
    gzip.extend(deflate(contents));
    gzip.extend_from_slice(&crc32(contents).to_le_bytes());
    gzip.extend_from_slice(&(contents.len() as u32).to_le_bytes());
    gzip
}

fn deflate(contents: &[u8]) -> Vec<u8> {
    let mut writer = BitWriter::default();
    let block_count = contents.len().div_ceil(DEFLATE_BLOCK_SIZE).max(1);

    for block_index in 0..block_count {
        let start = block_index * DEFLATE_BLOCK_SIZE;
        let end = start.saturating_add(DEFLATE_BLOCK_SIZE).min(contents.len());
        writer.write_bits(u16::from(block_index + 1 == block_count), 1);
        writer.write_bits(1, 2);

        let mut position = start;
        while position < end {
            let repeated = position > 0 && contents[position] == contents[position - 1];
            let run_length = if repeated {
                contents[position..end]
                    .iter()
                    .take(258)
                    .take_while(|&&byte| byte == contents[position - 1])
                    .count()
            } else {
                0
            };
            if run_length >= 3 {
                writer.write_length(run_length);
                writer.write_bits(0, 5);
                position += run_length;
            } else {
                writer.write_fixed_symbol(u16::from(contents[position]));
                position += 1;
            }
        }
        writer.write_fixed_symbol(256);
    }

    writer.finish()
}

#[derive(Default)]
struct BitWriter {
    bytes: Vec<u8>,
    pending: u8,
    pending_bits: u8,
}

impl BitWriter {
    fn write_bits(&mut self, mut value: u16, count: u8) {
        for _ in 0..count {
            self.pending |= ((value & 1) as u8) << self.pending_bits;
            self.pending_bits += 1;
            value >>= 1;
            if self.pending_bits == 8 {
                self.bytes.push(self.pending);
                self.pending = 0;
                self.pending_bits = 0;
            }
        }
    }

    fn write_fixed_symbol(&mut self, symbol: u16) {
        let (code, bit_count) = match symbol {
            0..=143 => (0b0011_0000 + symbol, 8),
            144..=255 => (0b1_1001_0000 + symbol - 144, 9),
            256..=279 => (symbol - 256, 7),
            280..=287 => (0b1100_0000 + symbol - 280, 8),
            _ => panic!("invalid fixed-Huffman symbol {symbol}"),
        };
        self.write_bits(code.reverse_bits() >> (u16::BITS - bit_count), bit_count as u8);
    }

    fn write_length(&mut self, length: usize) {
        let index = LENGTH_BASES
            .iter()
            .rposition(|&base| base <= length)
            .expect("DEFLATE match length is at least three");
        self.write_fixed_symbol(257 + index as u16);
        self.write_bits(
            (length - LENGTH_BASES[index]) as u16,
            LENGTH_EXTRA_BITS[index],
        );
    }

    fn finish(mut self) -> Vec<u8> {
        if self.pending_bits != 0 {
            self.bytes.push(self.pending);
        }
        self.bytes
    }
}

fn crc32(contents: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in contents {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
