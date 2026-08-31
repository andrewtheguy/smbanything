// Info-class encoders for QUERY_INFO and QUERY_DIRECTORY.
//
// These are fixed-layout structures from MS-FSCC. Every field is written with
// its spec offset in a comment, and each encoder has a test asserting the total
// size, because a structure one byte short does not produce an error from
// cifs.ko — it produces a directory listing full of garbage names, or a mount
// that fails several operations later with no indication of the cause.
//
// The directory-information classes are all prefixes of one another, which is
// why one encoder emits all of them from a single field list rather than five
// near-identical functions drifting apart.

use std::time::SystemTime;

use super::backing::{NodeInfo, NodeKind};
use super::proto::{status, to_filetime};
use super::wire::{Writer, utf16le};

/// `InfoType` in a QUERY_INFO request (MS-SMB2 2.2.37).
pub(crate) mod info_type {
    pub(crate) const FILE: u8 = 0x01;
    pub(crate) const FILESYSTEM: u8 = 0x02;
    pub(crate) const SECURITY: u8 = 0x03;
    pub(crate) const QUOTA: u8 = 0x04;
}

/// File information classes (MS-FSCC 2.4).
pub(crate) mod file_class {
    pub(crate) const BASIC: u8 = 4;
    pub(crate) const STANDARD: u8 = 5;
    pub(crate) const INTERNAL: u8 = 6;
    pub(crate) const EA: u8 = 7;
    /// Queried by `ls -l` via listxattr. Answered with "no EAs" rather than
    /// left to the catch-all, because it is asked on every single file.
    pub(crate) const FULL_EA: u8 = 15;
    pub(crate) const ACCESS: u8 = 8;
    pub(crate) const NAME: u8 = 9;
    pub(crate) const POSITION: u8 = 14;
    pub(crate) const MODE: u8 = 16;
    pub(crate) const ALIGNMENT: u8 = 17;
    pub(crate) const ALL: u8 = 18;
    pub(crate) const STREAM: u8 = 22;
    pub(crate) const NETWORK_OPEN: u8 = 34;
    pub(crate) const ATTRIBUTE_TAG: u8 = 35;
}

/// Filesystem information classes (MS-FSCC 2.5).
pub(crate) mod fs_class {
    pub(crate) const VOLUME: u8 = 1;
    pub(crate) const SIZE: u8 = 3;
    pub(crate) const DEVICE: u8 = 4;
    pub(crate) const ATTRIBUTE: u8 = 5;
    pub(crate) const FULL_SIZE: u8 = 7;
    pub(crate) const SECTOR_SIZE: u8 = 11;
}

/// Directory information classes used by QUERY_DIRECTORY (MS-FSCC 2.4).
pub(crate) mod dir_class {
    pub(crate) const DIRECTORY: u8 = 1;
    pub(crate) const FULL_DIRECTORY: u8 = 2;
    pub(crate) const BOTH_DIRECTORY: u8 = 3;
    pub(crate) const NAMES: u8 = 12;
    pub(crate) const ID_BOTH_DIRECTORY: u8 = 37;
    pub(crate) const ID_FULL_DIRECTORY: u8 = 38;
}

/// File attribute bits (MS-FSCC 2.6). NORMAL is unused because it is defined as
/// "no other attribute set" and everything here carries READONLY, but leaving it
/// out invites someone to reach for 0 instead.
#[allow(dead_code)]
pub(crate) mod attr {
    pub(crate) const READONLY: u32 = 0x0000_0001;
    pub(crate) const DIRECTORY: u32 = 0x0000_0010;
    pub(crate) const NORMAL: u32 = 0x0000_0080;
}

/// Attributes for a node. Everything on this share is read-only, and that bit
/// is what makes a client's file manager grey out rename and delete instead of
/// offering them and failing.
pub(crate) fn file_attributes(kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Dir => attr::DIRECTORY | attr::READONLY,
        // NORMAL is defined as "no other attributes set", so it must never be
        // combined with READONLY.
        NodeKind::File => attr::READONLY,
    }
}

/// Allocation size: the on-disk footprint, which clients expect to be a
/// multiple of the cluster size. Reporting it equal to the file size makes
/// `du`-style tools disagree with `ls`; rounding up to 4 KiB matches what every
/// real filesystem reports.
pub(crate) const CLUSTER_SIZE: u64 = 4096;

pub(crate) fn allocation_size(size: u64) -> u64 {
    // Saturating: rounding up overflows for a size within one cluster of
    // `u64::MAX`, which a debug build turns into a panic on the connection
    // thread — a corrupt or hostile size field would drop the mount rather than
    // report a silly number.
    size.div_ceil(CLUSTER_SIZE).saturating_mul(CLUSTER_SIZE)
}

fn write_times(w: &mut Writer, info: &NodeInfo) {
    // SMB has a creation time and restic does not record one. ctime is the
    // closest available: it is the inode-change time, which for a file written
    // once and never modified equals its creation.
    w.u64(to_filetime(info.ctime)); // CreationTime
    w.u64(to_filetime(info.atime)); // LastAccessTime
    w.u64(to_filetime(info.mtime)); // LastWriteTime
    w.u64(to_filetime(info.ctime)); // ChangeTime
}

/// FileBasicInformation — MS-FSCC 2.4.7. 40 bytes.
pub(crate) fn file_basic(info: &NodeInfo) -> Vec<u8> {
    let mut w = Writer::with_capacity(40);
    write_times(&mut w, info);
    w.u32(file_attributes(info.kind)); // 32 FileAttributes
    w.u32(0); // 36 Reserved
    w.into_vec()
}

/// FileStandardInformation — MS-FSCC 2.4.41. 24 bytes.
pub(crate) fn file_standard(info: &NodeInfo) -> Vec<u8> {
    let mut w = Writer::with_capacity(24);
    w.u64(allocation_size(info.size)); // 0 AllocationSize
    w.u64(info.size); // 8 EndOfFile
    w.u32(1); // 16 NumberOfLinks
    w.u8(0); // 20 DeletePending — never, the share is read-only
    w.u8(u8::from(info.kind.is_dir())); // 21 Directory
    w.u16(0); // 22 Reserved
    w.into_vec()
}

/// FileInternalInformation — MS-FSCC 2.4.20. 8 bytes.
pub(crate) fn file_internal(file_id: u64) -> Vec<u8> {
    let mut w = Writer::with_capacity(8);
    w.u64(file_id); // IndexNumber
    w.into_vec()
}

/// FileEaInformation — MS-FSCC 2.4.12. 4 bytes. No extended attributes are
/// exposed, so this is always zero.
pub(crate) fn file_ea() -> Vec<u8> {
    let mut w = Writer::with_capacity(4);
    w.u32(0); // EaSize
    w.into_vec()
}

/// FileAccessInformation — MS-FSCC 2.4.1. 4 bytes.
pub(crate) fn file_access(granted: u32) -> Vec<u8> {
    let mut w = Writer::with_capacity(4);
    w.u32(granted); // AccessFlags
    w.into_vec()
}

/// FilePositionInformation — MS-FSCC 2.4.35. 8 bytes. This server holds no file
/// position: every READ carries its own offset.
pub(crate) fn file_position() -> Vec<u8> {
    let mut w = Writer::with_capacity(8);
    w.u64(0); // CurrentByteOffset
    w.into_vec()
}

/// FileModeInformation — MS-FSCC 2.4.26. 4 bytes.
pub(crate) fn file_mode() -> Vec<u8> {
    let mut w = Writer::with_capacity(4);
    w.u32(0); // Mode — no write-through, no sequential-only, no delete-on-close
    w.into_vec()
}

/// FileAlignmentInformation — MS-FSCC 2.4.3. 4 bytes.
pub(crate) fn file_alignment() -> Vec<u8> {
    let mut w = Writer::with_capacity(4);
    w.u32(0); // FILE_BYTE_ALIGNMENT — reads may start anywhere
    w.into_vec()
}

/// FileNameInformation — MS-FSCC 2.4.27. Variable.
pub(crate) fn file_name(path: &str) -> Vec<u8> {
    let encoded = utf16le(path);
    let mut w = Writer::with_capacity(4 + encoded.len());
    w.u32(encoded.len() as u32); // FileNameLength
    w.bytes(&encoded);
    w.into_vec()
}

/// FileAllInformation — MS-FSCC 2.4.2. The concatenation of Basic, Standard,
/// Internal, EA, Access, Position, Mode, Alignment and Name, in that order.
pub(crate) fn file_all(info: &NodeInfo, file_id: u64, granted: u32, path: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&file_basic(info));
    out.extend_from_slice(&file_standard(info));
    out.extend_from_slice(&file_internal(file_id));
    out.extend_from_slice(&file_ea());
    out.extend_from_slice(&file_access(granted));
    out.extend_from_slice(&file_position());
    out.extend_from_slice(&file_mode());
    out.extend_from_slice(&file_alignment());
    out.extend_from_slice(&file_name(path));
    out
}

/// FileNetworkOpenInformation — MS-FSCC 2.4.29. 56 bytes.
pub(crate) fn file_network_open(info: &NodeInfo) -> Vec<u8> {
    let mut w = Writer::with_capacity(56);
    write_times(&mut w, info);
    w.u64(allocation_size(info.size)); // 32 AllocationSize
    w.u64(info.size); // 40 EndOfFile
    w.u32(file_attributes(info.kind)); // 48 FileAttributes
    w.u32(0); // 52 Reserved
    w.into_vec()
}

/// FileAttributeTagInformation — MS-FSCC 2.4.6. 8 bytes.
pub(crate) fn file_attribute_tag(info: &NodeInfo) -> Vec<u8> {
    let mut w = Writer::with_capacity(8);
    w.u32(file_attributes(info.kind)); // FileAttributes
    w.u32(0); // ReparseTag — nothing here is a reparse point
    w.into_vec()
}

/// FileStreamInformation — MS-FSCC 2.4.44. One unnamed data stream per file;
/// a directory has none, which is an empty buffer rather than an error.
pub(crate) fn file_stream(info: &NodeInfo) -> Vec<u8> {
    if info.kind.is_dir() {
        return Vec::new();
    }
    let name = utf16le("::$DATA");
    let mut w = Writer::with_capacity(24 + name.len());
    w.u32(0); // NextEntryOffset — the only entry
    w.u32(name.len() as u32); // StreamNameLength
    w.u64(info.size); // StreamSize
    w.u64(allocation_size(info.size)); // StreamAllocationSize
    w.bytes(&name);
    w.into_vec()
}

/// FileFsVolumeInformation — MS-FSCC 2.5.9.
pub(crate) fn fs_volume(label: &str, created: SystemTime, serial: u32) -> Vec<u8> {
    let encoded = utf16le(label);
    let mut w = Writer::with_capacity(18 + encoded.len());
    w.u64(to_filetime(created)); // 0 VolumeCreationTime
    w.u32(serial); // 8 VolumeSerialNumber
    w.u32(encoded.len() as u32); // 12 VolumeLabelLength
    w.u8(0); // 16 SupportsObjects
    w.u8(0); // 17 Reserved
    w.bytes(&encoded);
    w.into_vec()
}

/// FileFsSizeInformation — MS-FSCC 2.5.8. 24 bytes.
///
/// Available units are zero throughout: an immutable archive is full by definition. That
/// is not a cosmetic choice — a client that believes there is free space will
/// offer to copy files into the share.
pub(crate) fn fs_size(total_bytes: u64) -> Vec<u8> {
    let units = total_bytes.div_ceil(CLUSTER_SIZE).max(1);
    let mut w = Writer::with_capacity(24);
    w.u64(units); // 0 TotalAllocationUnits
    w.u64(0); // 8 AvailableAllocationUnits
    w.u32((CLUSTER_SIZE / 512) as u32); // 16 SectorsPerAllocationUnit
    w.u32(512); // 20 BytesPerSector
    w.into_vec()
}

/// FileFsFullSizeInformation — MS-FSCC 2.5.4. 32 bytes.
pub(crate) fn fs_full_size(total_bytes: u64) -> Vec<u8> {
    let units = total_bytes.div_ceil(CLUSTER_SIZE).max(1);
    let mut w = Writer::with_capacity(32);
    w.u64(units); // 0 TotalAllocationUnits
    w.u64(0); // 8 CallerAvailableAllocationUnits
    w.u64(0); // 16 ActualAvailableAllocationUnits
    w.u32((CLUSTER_SIZE / 512) as u32); // 24 SectorsPerAllocationUnit
    w.u32(512); // 28 BytesPerSector
    w.into_vec()
}

/// FileFsDeviceInformation — MS-FSCC 2.5.10. 8 bytes.
pub(crate) fn fs_device() -> Vec<u8> {
    const FILE_DEVICE_DISK: u32 = 0x0000_0007;
    const FILE_READ_ONLY_DEVICE: u32 = 0x0000_0002;
    const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;
    let mut w = Writer::with_capacity(8);
    w.u32(FILE_DEVICE_DISK); // DeviceType
    w.u32(FILE_READ_ONLY_DEVICE | FILE_DEVICE_IS_MOUNTED); // Characteristics
    w.into_vec()
}

/// FileFsAttributeInformation — MS-FSCC 2.5.1.
pub(crate) fn fs_attribute() -> Vec<u8> {
    const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
    const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;
    const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;

    let name = utf16le("smbzip");
    let mut w = Writer::with_capacity(12 + name.len());
    w.u32(
        FILE_CASE_PRESERVED_NAMES
            | FILE_UNICODE_ON_DISK
            | FILE_READ_ONLY_VOLUME,
    ); // 0 FileSystemAttributes
    w.u32(255); // 4 MaximumComponentNameLength
    w.u32(name.len() as u32); // 8 FileSystemNameLength
    w.bytes(&name);
    w.into_vec()
}

/// FileFsSectorSizeInformation — MS-FSCC 2.5.7. 28 bytes.
pub(crate) fn fs_sector_size() -> Vec<u8> {
    const ALIGNED_DEVICE: u32 = 0x0000_0001;
    const PARTITION_ALIGNED: u32 = 0x0000_0002;
    let mut w = Writer::with_capacity(28);
    w.u32(512); // 0 LogicalBytesPerSector
    w.u32(512); // 4 PhysicalBytesPerSectorForAtomicity
    w.u32(512); // 8 PhysicalBytesPerSectorForPerformance
    w.u32(512); // 12 FileSystemEffectivePhysicalBytesPerSectorForAtomicity
    w.u32(ALIGNED_DEVICE | PARTITION_ALIGNED); // 16 Flags
    w.u32(0); // 20 ByteOffsetForSectorAlignment
    w.u32(0); // 24 ByteOffsetForPartitionAlignment
    w.into_vec()
}

/// Size of the fixed part of a directory-information entry, before the name.
///
/// Public because it is also the smallest an entry of this class can be, which
/// is what `query_directory` sizes a page from: it caps how many matches it
/// clones at how many could possibly fit, rather than cloning every remaining
/// one for the encoder to discard.
pub(crate) fn dir_entry_fixed_len(class: u8) -> Option<usize> {
    Some(match class {
        dir_class::DIRECTORY => 64,
        dir_class::FULL_DIRECTORY => 68,
        dir_class::BOTH_DIRECTORY => 94,
        dir_class::NAMES => 12,
        dir_class::ID_BOTH_DIRECTORY => 104,
        dir_class::ID_FULL_DIRECTORY => 80,
        _ => return None,
    })
}

/// Encode one directory entry, leaving `NextEntryOffset` at zero.
///
/// The caller links an entry to its predecessor when it writes the *next* one,
/// so the final entry is terminated by construction rather than by a fix-up
/// pass — there is no path on which a buffer ends with a dangling forward
/// pointer into whatever follows it in memory.
///
/// The classes share a prefix, so this writes the common fields once and then
/// appends only what each class adds.
fn write_dir_entry(
    out: &mut Writer,
    class: u8,
    index: u32,
    info: &NodeInfo,
    file_id: u64,
) -> Result<(), u32> {
    let fixed = dir_entry_fixed_len(class).ok_or(status::INVALID_INFO_CLASS)?;
    let name = utf16le(&info.name);
    let start = out.len();

    out.u32(0); // 0 NextEntryOffset, patched below
    out.u32(index); // 4 FileIndex

    if class == dir_class::NAMES {
        out.u32(name.len() as u32); // 8 FileNameLength
    } else {
        write_times(out, info); // 8..40
        out.u64(info.size); // 40 EndOfFile
        out.u64(allocation_size(info.size)); // 48 AllocationSize
        out.u32(file_attributes(info.kind)); // 56 FileAttributes
        out.u32(name.len() as u32); // 60 FileNameLength

        match class {
            dir_class::DIRECTORY => {}
            dir_class::FULL_DIRECTORY => {
                out.u32(0); // 64 EaSize
            }
            dir_class::BOTH_DIRECTORY => {
                out.u32(0); // 64 EaSize
                out.u8(0); // 68 ShortNameLength — no 8.3 names are generated
                out.u8(0); // 69 Reserved
                out.zeros(24); // 70 ShortName[12] as UTF-16
            }
            dir_class::ID_BOTH_DIRECTORY => {
                out.u32(0); // 64 EaSize
                out.u8(0); // 68 ShortNameLength
                out.u8(0); // 69 Reserved
                out.zeros(24); // 70 ShortName[12]
                out.u16(0); // 94 Reserved2
                out.u64(file_id); // 96 FileId
            }
            dir_class::ID_FULL_DIRECTORY => {
                out.u32(0); // 64 EaSize
                out.u32(0); // 68 Reserved
                out.u64(file_id); // 72 FileId
            }
            _ => return Err(status::INVALID_INFO_CLASS),
        }
    }

    // Checked, not debug-asserted. `encode_dir_entries` reserved exactly `fixed`
    // bytes for this entry and links the next one relative to it, so a mismatch
    // between the table and what the arms above write does not fail loudly — it
    // ships a listing whose chain offsets land mid-structure, which a client
    // renders as garbage names. Better to refuse the class than to emit that,
    // and in a release build the assertion would not have caught it at all.
    if out.len() - start != fixed {
        return Err(status::INVALID_INFO_CLASS);
    }
    out.bytes(&name);
    Ok(())
}

/// Encode as many entries as fit in `max_len`, starting at `entries[0]`.
///
/// Returns the buffer and how many entries were consumed. A caller that gets
/// back fewer than it supplied must resume from that point on the next
/// QUERY_DIRECTORY; returning zero for a non-empty input means the very first
/// entry does not fit, which is an error rather than an empty page.
pub(crate) fn encode_dir_entries(
    class: u8,
    entries: &[(NodeInfo, u64)],
    start_index: u32,
    max_len: usize,
    single: bool,
) -> Result<(Vec<u8>, usize), u32> {
    let fixed = dir_entry_fixed_len(class).ok_or(status::INVALID_INFO_CLASS)?;
    let mut out = Writer::with_capacity(max_len.min(64 * 1024));
    let mut count = 0usize;
    let mut last_start = 0usize;

    for (i, (info, file_id)) in entries.iter().enumerate() {
        let name_len = utf16le(&info.name).len();
        // Where this entry would begin: after padding the previous one out to
        // an 8-byte boundary. Checked before anything is written, so a buffer
        // that cannot hold the entry is never partially filled.
        let start = if count == 0 {
            out.len()
        } else {
            out.len().next_multiple_of(8)
        };
        if start + fixed + name_len > max_len {
            if count == 0 {
                // Not "the page is full" — this entry cannot ever be returned
                // at this buffer size, so reporting an empty page would make
                // the client spin.
                return Err(status::INFO_LENGTH_MISMATCH);
            }
            break;
        }

        if count > 0 {
            // Link the previous entry to this one, now that its distance is
            // known. This padding is the same 8-byte boundary `start` was
            // computed against above, and nothing may be written between the
            // two — `start` is then reused as the entry's offset rather than
            // re-derived, so the fit check and the write cannot disagree.
            out.align_to(8);
            let prev_len = (out.len() - last_start) as u32;
            out.patch_u32(last_start, prev_len);
        }
        debug_assert_eq!(
            out.len(),
            start,
            "padding must land where the check assumed"
        );
        last_start = start;
        write_dir_entry(&mut out, class, start_index + i as u32, info, *file_id)?;
        count += 1;
        if single {
            break;
        }
    }

    Ok((out.into_vec(), count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn file(name: &str, size: u64) -> NodeInfo {
        NodeInfo {
            name: name.to_string(),
            kind: NodeKind::File,
            size,
            mtime: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
            atime: UNIX_EPOCH + Duration::from_secs(1_600_000_001),
            ctime: UNIX_EPOCH + Duration::from_secs(1_600_000_002),
        }
    }

    fn dir(name: &str) -> NodeInfo {
        NodeInfo {
            kind: NodeKind::Dir,
            ..file(name, 0)
        }
    }

    #[test]
    fn fixed_size_classes_have_their_documented_length() {
        assert_eq!(file_basic(&file("a", 1)).len(), 40);
        assert_eq!(file_standard(&file("a", 1)).len(), 24);
        assert_eq!(file_internal(7).len(), 8);
        assert_eq!(file_ea().len(), 4);
        assert_eq!(file_access(0).len(), 4);
        assert_eq!(file_position().len(), 8);
        assert_eq!(file_mode().len(), 4);
        assert_eq!(file_alignment().len(), 4);
        assert_eq!(file_network_open(&file("a", 1)).len(), 56);
        assert_eq!(file_attribute_tag(&file("a", 1)).len(), 8);
        assert_eq!(fs_size(0).len(), 24);
        assert_eq!(fs_full_size(0).len(), 32);
        assert_eq!(fs_device().len(), 8);
        assert_eq!(fs_sector_size().len(), 28);
    }

    #[test]
    fn file_all_is_the_concatenation_of_its_parts() {
        let info = file("x.txt", 10);
        let all = file_all(&info, 42, 0x89, "dir\\x.txt");
        // 40 + 24 + 8 + 4 + 4 + 8 + 4 + 4 = 96 fixed, then the name info.
        assert_eq!(all.len(), 96 + file_name("dir\\x.txt").len());
        assert_eq!(&all[..40], file_basic(&info).as_slice());
        assert_eq!(&all[40..64], file_standard(&info).as_slice());
        assert_eq!(&all[64..72], file_internal(42).as_slice());
        assert_eq!(&all[96..], file_name("dir\\x.txt").as_slice());
    }

    #[test]
    fn directories_and_files_get_distinct_attributes() {
        assert_eq!(
            file_attributes(NodeKind::Dir),
            attr::DIRECTORY | attr::READONLY
        );
        assert_eq!(file_attributes(NodeKind::File), attr::READONLY);
        // NORMAL means "nothing else set" and must never appear with READONLY.
        assert_eq!(file_attributes(NodeKind::File) & attr::NORMAL, 0);
    }

    #[test]
    fn standard_information_marks_directories() {
        let d = file_standard(&dir("d"));
        assert_eq!(d[21], 1, "Directory flag at offset 21");
        assert_eq!(d[20], 0, "DeletePending is never set on a read-only share");
        let f = file_standard(&file("f", 1));
        assert_eq!(f[21], 0);
    }

    #[test]
    fn allocation_size_rounds_up_to_a_cluster() {
        assert_eq!(allocation_size(0), 0);
        assert_eq!(allocation_size(1), 4096);
        assert_eq!(allocation_size(4096), 4096);
        assert_eq!(allocation_size(4097), 8192);
        // Rounding up has nowhere to go: it saturates rather than panicking in
        // a debug build, which would take the connection down mid-listing.
        assert_eq!(allocation_size(u64::MAX), u64::MAX);
    }

    #[test]
    fn an_archive_reports_no_free_space() {
        // Offsets 8..16 of FileFsSizeInformation are AvailableAllocationUnits.
        let s = fs_size(1_000_000);
        assert_eq!(u64::from_le_bytes(s[8..16].try_into().unwrap()), 0);
        let f = fs_full_size(1_000_000);
        assert_eq!(u64::from_le_bytes(f[8..16].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(f[16..24].try_into().unwrap()), 0);
        // Total must be non-zero even for an empty archive, or clients report
        // a broken volume.
        assert!(u64::from_le_bytes(fs_size(0)[0..8].try_into().unwrap()) >= 1);
    }

    #[test]
    fn the_volume_advertises_itself_as_read_only() {
        const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;
        let a = fs_attribute();
        let flags = u32::from_le_bytes(a[0..4].try_into().unwrap());
        assert_eq!(flags & FILE_READ_ONLY_VOLUME, FILE_READ_ONLY_VOLUME);

        const FILE_READ_ONLY_DEVICE: u32 = 0x0000_0002;
        let d = fs_device();
        let chars = u32::from_le_bytes(d[4..8].try_into().unwrap());
        assert_eq!(chars & FILE_READ_ONLY_DEVICE, FILE_READ_ONLY_DEVICE);
    }

    #[test]
    fn volume_information_length_matches_its_label() {
        let v = fs_volume("snap", UNIX_EPOCH, 0x1234);
        let label_len = u32::from_le_bytes(v[12..16].try_into().unwrap()) as usize;
        assert_eq!(label_len, utf16le("snap").len());
        assert_eq!(v.len(), 18 + label_len);
        assert_eq!(&v[18..], utf16le("snap").as_slice());
    }

    #[test]
    fn a_directory_has_no_data_stream() {
        assert!(file_stream(&dir("d")).is_empty());
        let s = file_stream(&file("f", 99));
        assert_eq!(u64::from_le_bytes(s[8..16].try_into().unwrap()), 99);
    }

    #[test]
    fn every_directory_class_has_its_documented_fixed_size() {
        for (class, want) in [
            (dir_class::DIRECTORY, 64),
            (dir_class::FULL_DIRECTORY, 68),
            (dir_class::BOTH_DIRECTORY, 94),
            (dir_class::NAMES, 12),
            (dir_class::ID_BOTH_DIRECTORY, 104),
            (dir_class::ID_FULL_DIRECTORY, 80),
        ] {
            let entries = vec![(file("a", 1), 7u64)];
            let (buf, n) = encode_dir_entries(class, &entries, 0, 4096, false).unwrap();
            assert_eq!(n, 1);
            let name_len = utf16le("a").len();
            assert_eq!(
                buf.len(),
                want + name_len,
                "class {class} fixed part should be {want}"
            );
        }
    }

    #[test]
    fn an_unknown_directory_class_is_refused() {
        let entries = vec![(file("a", 1), 7u64)];
        assert_eq!(
            encode_dir_entries(99, &entries, 0, 4096, false).unwrap_err(),
            status::INVALID_INFO_CLASS
        );
    }

    #[test]
    fn id_both_directory_places_the_file_id_at_offset_96() {
        let entries = vec![(file("name.txt", 123), 0xDEAD_BEEF_u64)];
        let (buf, _) =
            encode_dir_entries(dir_class::ID_BOTH_DIRECTORY, &entries, 0, 4096, false).unwrap();
        assert_eq!(
            u64::from_le_bytes(buf[96..104].try_into().unwrap()),
            0xDEAD_BEEF
        );
        let name_len = u32::from_le_bytes(buf[60..64].try_into().unwrap()) as usize;
        assert_eq!(name_len, utf16le("name.txt").len());
        assert_eq!(&buf[104..104 + name_len], utf16le("name.txt").as_slice());
        assert_eq!(u64::from_le_bytes(buf[40..48].try_into().unwrap()), 123);
    }

    #[test]
    fn entries_chain_on_eight_byte_boundaries_and_the_last_terminates() {
        let entries = vec![
            (file("a", 1), 1u64),
            (file("bb", 2), 2u64),
            (file("ccc", 3), 3u64),
        ];
        let (buf, n) =
            encode_dir_entries(dir_class::ID_BOTH_DIRECTORY, &entries, 0, 8192, false).unwrap();
        assert_eq!(n, 3);

        let mut offset = 0usize;
        let mut seen = Vec::new();
        loop {
            let next = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            let name_len =
                u32::from_le_bytes(buf[offset + 60..offset + 64].try_into().unwrap()) as usize;
            let name_start = offset + 104;
            let name = String::from_utf16_lossy(
                &buf[name_start..name_start + name_len]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect::<Vec<_>>(),
            );
            seen.push(name);
            if next == 0 {
                break;
            }
            assert!(next.is_multiple_of(8), "entries must be 8-byte aligned");
            offset += next;
        }
        assert_eq!(seen, vec!["a", "bb", "ccc"]);
    }

    #[test]
    fn file_index_counts_from_the_supplied_start() {
        let entries = vec![(file("a", 1), 1u64), (file("b", 2), 2u64)];
        let (buf, _) =
            encode_dir_entries(dir_class::ID_BOTH_DIRECTORY, &entries, 10, 8192, false).unwrap();
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 10);
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(
            u32::from_le_bytes(buf[next + 4..next + 8].try_into().unwrap()),
            11
        );
    }

    #[test]
    fn a_truncated_buffer_stops_early_and_terminates_the_chain() {
        let entries: Vec<_> = (0..50)
            .map(|i| (file(&format!("file{i:03}"), 1), i as u64))
            .collect();
        // Room for only a couple of 104-byte-plus-name entries.
        let (buf, n) =
            encode_dir_entries(dir_class::ID_BOTH_DIRECTORY, &entries, 0, 400, false).unwrap();
        assert!(n > 0 && n < 50, "expected a partial page, got {n}");

        // Walk to the end: the chain must terminate inside the buffer.
        let mut offset = 0usize;
        let mut walked = 1;
        loop {
            let next = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            if next == 0 {
                break;
            }
            offset += next;
            walked += 1;
            assert!(offset < buf.len(), "chain must not run past the buffer");
        }
        assert_eq!(walked, n, "chain length must match the reported count");
        assert!(buf.len() <= 400);
    }

    #[test]
    fn a_single_entry_request_returns_exactly_one() {
        let entries = vec![(file("a", 1), 1u64), (file("b", 2), 2u64)];
        let (buf, n) =
            encode_dir_entries(dir_class::ID_BOTH_DIRECTORY, &entries, 0, 8192, true).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            0,
            "a single entry terminates the chain"
        );
    }

    #[test]
    fn an_entry_too_large_for_the_buffer_is_an_error_not_an_empty_page() {
        let entries = vec![(file("a-very-long-file-name-indeed", 1), 1u64)];
        assert_eq!(
            encode_dir_entries(dir_class::ID_BOTH_DIRECTORY, &entries, 0, 32, false).unwrap_err(),
            status::INFO_LENGTH_MISMATCH
        );
    }
}
