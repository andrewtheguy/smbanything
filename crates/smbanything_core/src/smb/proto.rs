// SMB2 header codec and the protocol constants this server uses.
//
// Field offsets follow MS-SMB2 section 2.2.1.2 (the sync header). We only ever
// emit sync headers: async responses exist to let a server return
// STATUS_PENDING on a long operation, and every operation here is either
// instant or served from a blocking task that the client waits on normally.

use anyhow::{Result, bail};

use super::wire::{Reader, Writer};

pub(crate) const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];
pub(crate) const HEADER_LEN: usize = 64;

/// Command codes (MS-SMB2 2.2.1.2, `Command`).
pub(crate) mod cmd {
    pub(crate) const NEGOTIATE: u16 = 0x0000;
    pub(crate) const SESSION_SETUP: u16 = 0x0001;
    pub(crate) const LOGOFF: u16 = 0x0002;
    pub(crate) const TREE_CONNECT: u16 = 0x0003;
    pub(crate) const TREE_DISCONNECT: u16 = 0x0004;
    pub(crate) const CREATE: u16 = 0x0005;
    pub(crate) const CLOSE: u16 = 0x0006;
    pub(crate) const FLUSH: u16 = 0x0007;
    pub(crate) const READ: u16 = 0x0008;
    pub(crate) const WRITE: u16 = 0x0009;
    pub(crate) const LOCK: u16 = 0x000A;
    pub(crate) const IOCTL: u16 = 0x000B;
    pub(crate) const CANCEL: u16 = 0x000C;
    pub(crate) const ECHO: u16 = 0x000D;
    pub(crate) const QUERY_DIRECTORY: u16 = 0x000E;
    pub(crate) const CHANGE_NOTIFY: u16 = 0x000F;
    pub(crate) const QUERY_INFO: u16 = 0x0010;
    pub(crate) const SET_INFO: u16 = 0x0011;
    pub(crate) const OPLOCK_BREAK: u16 = 0x0012;

    pub(crate) fn name(c: u16) -> &'static str {
        match c {
            NEGOTIATE => "NEGOTIATE",
            SESSION_SETUP => "SESSION_SETUP",
            LOGOFF => "LOGOFF",
            TREE_CONNECT => "TREE_CONNECT",
            TREE_DISCONNECT => "TREE_DISCONNECT",
            CREATE => "CREATE",
            CLOSE => "CLOSE",
            FLUSH => "FLUSH",
            READ => "READ",
            WRITE => "WRITE",
            LOCK => "LOCK",
            IOCTL => "IOCTL",
            CANCEL => "CANCEL",
            ECHO => "ECHO",
            QUERY_DIRECTORY => "QUERY_DIRECTORY",
            CHANGE_NOTIFY => "CHANGE_NOTIFY",
            QUERY_INFO => "QUERY_INFO",
            SET_INFO => "SET_INFO",
            OPLOCK_BREAK => "OPLOCK_BREAK",
            _ => "UNKNOWN",
        }
    }
}

/// NTSTATUS values (MS-ERREF 2.3.1).
///
/// Deliberately complete for the errors a file server can return, not trimmed
/// to the ones currently constructed: a half-populated status list is how you
/// end up inventing a wrong code under pressure, and a client that gets the
/// wrong NTSTATUS fails in ways that look like a bug in the file, not the
/// server. Hence the allow — unused entries here are the point.
#[allow(dead_code)]
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const BUFFER_OVERFLOW: u32 = 0x8000_0005;
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
    pub const INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const NO_SUCH_FILE: u32 = 0xC000_000F;
    pub const END_OF_FILE: u32 = 0xC000_0011;
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const LOGON_FAILURE: u32 = 0xC000_006D;
    pub const EAS_NOT_SUPPORTED: u32 = 0xC000_004F;
    pub const NO_EAS_ON_FILE: u32 = 0xC000_0052;
    pub const OBJECT_NAME_INVALID: u32 = 0xC000_0033;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    pub const UNEXPECTED_IO_ERROR: u32 = 0xC000_00E9;
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub const OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
    pub const MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub const NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
    pub const BAD_NETWORK_NAME: u32 = 0xC000_00CC;
    pub const NOT_A_DIRECTORY: u32 = 0xC000_0103;
    pub const FILE_CLOSED: u32 = 0xC000_0128;
    pub const USER_SESSION_DELETED: u32 = 0xC000_0203;
    pub const FS_DRIVER_REQUIRED: u32 = 0xC000_019C;
    pub const INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
    pub const FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
    pub const INVALID_INFO_CLASS: u32 = 0xC000_0003;
    pub const REQUEST_NOT_ACCEPTED: u32 = 0xC000_00D0;
}

/// Header `Flags` bits (MS-SMB2 2.2.1.2). Complete rather than trimmed, so that
/// masking against them reads correctly; ASYNC_COMMAND and DFS_OPERATIONS are
/// bits this server never sets but must not be confused about.
#[allow(dead_code)]
pub(crate) mod flags {
    pub(crate) const SERVER_TO_REDIR: u32 = 0x0000_0001;
    pub(crate) const ASYNC_COMMAND: u32 = 0x0000_0002;
    pub(crate) const RELATED_OPERATIONS: u32 = 0x0000_0004;
    pub(crate) const SIGNED: u32 = 0x0000_0008;
    pub(crate) const DFS_OPERATIONS: u32 = 0x1000_0000;
}

/// The single dialect this server speaks. 2.1 is deliberate: it predates the
/// 3.x pre-auth integrity hashes, negotiate contexts, AES-CMAC signing and
/// AES-GCM encryption, none of which a loopback read-only share needs.
pub(crate) const DIALECT_SMB_2_1: u16 = 0x0210;

/// SMB2_WILDCARD_REVISION_NUMBER. Not a dialect a session ever runs at — it is
/// the reply to an SMB1 multi-protocol negotiate, meaning "I speak SMB2, send a
/// real SMB2 NEGOTIATE".
pub(crate) const DIALECT_WILDCARD: u16 = 0x02FF;

/// Negotiate `SecurityMode` bits.
///
/// Both are set. ENABLED alone makes a client sign opportunistically — Samba's
/// signs the session setup and tree connect and then stops, so the first CREATE
/// arrives unsigned. REQUIRED is what tells a client every message must be
/// signed, which is the only correct advertisement now that every session
/// authenticates.
pub(crate) const SIGNING_ENABLED: u16 = 0x0001;
pub(crate) const SIGNING_REQUIRED: u16 = 0x0002;

/// Negotiate `Capabilities`. LARGE_MTU is what lets the client use multi-credit
/// reads; without it cifs.ko is stuck at 64 KiB per READ.
pub(crate) const CAP_LARGE_MTU: u32 = 0x0000_0004;

/// Share types for TREE_CONNECT responses (MS-SMB2 2.2.10).
pub(crate) const SHARE_TYPE_DISK: u8 = 0x01;
pub(crate) const SHARE_TYPE_PIPE: u8 = 0x02;

/// Access mask bits (MS-SMB2 2.2.13.1.1).
pub(crate) mod access {
    pub(crate) const FILE_READ_DATA: u32 = 0x0000_0001;
    pub(crate) const FILE_WRITE_DATA: u32 = 0x0000_0002;
    pub(crate) const FILE_APPEND_DATA: u32 = 0x0000_0004;
    pub(crate) const FILE_READ_EA: u32 = 0x0000_0008;
    pub(crate) const FILE_WRITE_EA: u32 = 0x0000_0010;
    /// The same bit means "run this file as an image" on a file and "traverse"
    /// on a directory. Directories need it — without it a Windows client cannot
    /// walk into a subdirectory — and files must not have it: this share is for
    /// browsing a backup, not for launching one out of it.
    pub(crate) const FILE_EXECUTE: u32 = 0x0000_0020;
    pub(crate) const FILE_TRAVERSE: u32 = FILE_EXECUTE;
    pub(crate) const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    pub(crate) const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    pub(crate) const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    pub(crate) const DELETE: u32 = 0x0001_0000;
    pub(crate) const READ_CONTROL: u32 = 0x0002_0000;
    pub(crate) const WRITE_DAC: u32 = 0x0004_0000;
    pub(crate) const WRITE_OWNER: u32 = 0x0008_0000;
    pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;

    /// Everything a caller may hold on a file here: read, and nothing else.
    /// FILE_EXECUTE is deliberately absent — see `read_only`.
    pub(crate) const READ_ONLY_FILE: u32 =
        FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

    /// The same for a directory, plus FILE_TRAVERSE, which is what a client
    /// needs to descend into it. Also what TREE_CONNECT reports as
    /// MaximalAccess, the share root being a directory.
    pub(crate) const READ_ONLY_DIR: u32 = READ_ONLY_FILE | FILE_TRAVERSE;

    /// Access granted on an open, and reported by FileAccessInformation.
    ///
    /// Files get no execute bit. On Windows that is the whole mechanism: image
    /// activation opens with FILE_EXECUTE, so refusing it means an executable
    /// on the share cannot be launched from it, only copied off and run
    /// locally. Linux clients decide that from the mode instead, which comes
    /// from the mount's `file_mode=`/`dir_mode=` (0444/0555 in the mount
    /// commands smbanything prints), because SMB 2.1 carries no POSIX mode.
    pub(crate) const fn read_only(is_dir: bool) -> u32 {
        if is_dir {
            READ_ONLY_DIR
        } else {
            READ_ONLY_FILE
        }
    }

    /// Generic access bits (MS-DTYP 2.4.3). Mapping these to the object-specific
    /// rights they stand for is the *server's* job, so every check below has to
    /// name them: a mask of specific bits alone would let `GENERIC_WRITE` — the
    /// same request, differently spelled — walk past a check that `FILE_WRITE_DATA`
    /// fails.
    ///
    /// `GENERIC_READ` (0x8000_0000) is deliberately absent: it maps to
    /// FILE_GENERIC_READ, which is exactly what this share grants, and it is how
    /// cifs.ko opens every file.
    pub(crate) const GENERIC_ALL: u32 = 0x1000_0000;
    pub(crate) const GENERIC_EXECUTE: u32 = 0x2000_0000;
    pub(crate) const GENERIC_WRITE: u32 = 0x4000_0000;

    /// Every spelling of "I intend to run this". Refused on a file; on a
    /// directory the specific bit is FILE_TRAVERSE and is granted instead.
    /// GENERIC_ALL subsumes execute as well as write, so it appears here too
    /// rather than being treated as a write-only request.
    pub(crate) const EXECUTE_BITS: u32 = FILE_EXECUTE | GENERIC_EXECUTE | GENERIC_ALL;

    /// Any of these in a CREATE request means the caller intends to modify
    /// something, and the open is refused outright rather than silently
    /// downgraded — a client that asked for write access and got a read-only
    /// handle fails later, in a much more confusing place.
    pub(crate) const WRITE_BITS: u32 = FILE_WRITE_DATA
        | FILE_APPEND_DATA
        | FILE_WRITE_EA
        | FILE_DELETE_CHILD
        | FILE_WRITE_ATTRIBUTES
        | DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | GENERIC_WRITE
        | GENERIC_ALL;
}

/// Parsed SMB2 sync header.
#[derive(Debug, Clone)]
pub(crate) struct Header {
    pub(crate) credit_charge: u16,
    /// Requests carry Status = 0 (the field is `ChannelSequence`/Reserved on the
    /// way in), so nothing reads this. Parsed anyway so the struct mirrors the
    /// wire layout field-for-field — a header codec with holes in it is one you
    /// cannot check against the spec by eye.
    #[allow(dead_code)]
    pub(crate) status: u32,
    pub(crate) command: u16,
    pub(crate) credits: u16,
    pub(crate) flags: u32,
    pub(crate) next_command: u32,
    pub(crate) message_id: u64,
    pub(crate) tree_id: u32,
    pub(crate) session_id: u64,
}

impl Header {
    pub(crate) fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let magic = r.bytes(4)?;
        if magic != SMB2_MAGIC {
            // An SMB1 negotiate (0xFF 'S' 'M' 'B') is the one other thing a
            // client may open with. We do not speak SMB1 at all; the caller
            // drops the connection, and clients then retry as SMB2.
            bail!("not an SMB2 message: magic {magic:02X?}");
        }
        let structure_size = r.u16()?;
        if structure_size != HEADER_LEN as u16 {
            bail!("header StructureSize is {structure_size}, expected {HEADER_LEN}");
        }
        let credit_charge = r.u16()?;
        let status = r.u32()?;
        let command = r.u16()?;
        let credits = r.u16()?;
        let flags = r.u32()?;
        let next_command = r.u32()?;
        let message_id = r.u64()?;
        r.skip(4)?; // Reserved (AsyncId low half in async headers)
        let tree_id = r.u32()?;
        let session_id = r.u64()?;
        // Signature. Skipped here on purpose: verification needs the whole PDU,
        // not a parsed header, so `sign::verify` runs over the raw message
        // before this ever sees it (see `serve_connection`). Copying the field
        // into the struct would only invite a second, weaker check.
        r.skip(16)?;
        Ok(Self {
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
        })
    }

    /// Write the response header for this request. `NextCommand` is left zero;
    /// the compound assembler patches it once the body length is known.
    ///
    /// `session_id` and `tree_id` are passed explicitly rather than echoed from
    /// the request: SESSION_SETUP has to return the id the server just
    /// allocated, and TREE_CONNECT the tree it just opened. Those are the only
    /// two ways a client ever learns them.
    pub(crate) fn write_response(
        &self,
        w: &mut Writer,
        status: u32,
        credits: u16,
        session_id: u64,
        tree_id: u32,
    ) {
        w.bytes(&SMB2_MAGIC);
        w.u16(HEADER_LEN as u16);
        w.u16(self.credit_charge);
        w.u32(status);
        w.u16(self.command);
        w.u16(credits);
        // RELATED_OPERATIONS is echoed back so the client can match a compounded
        // response chain. SIGNED is not: `sign::sign` sets it as it signs, and
        // it has to go on immediately before the hash because the flag is
        // itself part of the signed bytes.
        w.u32(flags::SERVER_TO_REDIR | (self.flags & flags::RELATED_OPERATIONS));
        w.u32(0); // NextCommand, patched later
        w.u64(self.message_id);
        w.u32(0); // Reserved
        w.u32(tree_id);
        w.u64(session_id);
        w.zeros(16); // Signature
    }
}

/// Offset of `NextCommand` within a header, for compound-chain patching.
pub(crate) const NEXT_COMMAND_OFFSET: usize = 20;

/// The generic SMB2 error response body (MS-SMB2 2.2.2). `StructureSize` is 9,
/// which per spec means 8 fixed bytes plus one byte of variable data that must
/// be present even when `ByteCount` is zero.
pub(crate) fn write_error_body(w: &mut Writer) {
    w.u16(9); // StructureSize
    w.u8(0); // ErrorContextCount
    w.u8(0); // Reserved
    w.u32(0); // ByteCount
    w.u8(0); // one byte of (absent) ErrorData
}

/// Convert a `SystemTime` to a Windows FILETIME: 100-nanosecond ticks since
/// 1601-01-01 UTC. Times before the FILETIME epoch, and times that overflow,
/// clamp rather than wrap — a nonsense timestamp in a directory listing is far
/// better than a panic in the middle of a response.
pub(crate) fn to_filetime(t: std::time::SystemTime) -> u64 {
    const UNIX_TO_FILETIME_SECS: u64 = 11_644_473_600;
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs().saturating_add(UNIX_TO_FILETIME_SECS);
            secs.saturating_mul(10_000_000)
                .saturating_add(u64::from(d.subsec_nanos()) / 100)
        }
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request_header() -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&SMB2_MAGIC);
        w.u16(64); // StructureSize
        w.u16(1); // CreditCharge
        w.u32(0); // Status
        w.u16(cmd::TREE_CONNECT);
        w.u16(31); // CreditRequest
        w.u32(0); // Flags
        w.u32(0); // NextCommand
        w.u64(0x1122_3344_5566_7788); // MessageId
        w.u32(0); // Reserved
        w.u32(0xAABB_CCDD); // TreeId
        w.u64(0x0102_0304_0506_0708); // SessionId
        w.zeros(16); // Signature
        w.into_vec()
    }

    #[test]
    fn header_parses_every_field_at_its_spec_offset() {
        let buf = sample_request_header();
        assert_eq!(buf.len(), HEADER_LEN);
        let mut r = Reader::new(&buf);
        let h = Header::parse(&mut r).unwrap();
        assert_eq!(h.credit_charge, 1);
        assert_eq!(h.command, cmd::TREE_CONNECT);
        assert_eq!(h.credits, 31);
        assert_eq!(h.message_id, 0x1122_3344_5566_7788);
        assert_eq!(h.tree_id, 0xAABB_CCDD);
        assert_eq!(h.session_id, 0x0102_0304_0506_0708);
        assert_eq!(r.pos(), HEADER_LEN, "parse must consume exactly 64 bytes");
    }

    #[test]
    fn header_rejects_smb1_and_bad_structure_size() {
        let mut smb1 = sample_request_header();
        smb1[0] = 0xFF;
        assert!(Header::parse(&mut Reader::new(&smb1)).is_err());

        let mut bad = sample_request_header();
        bad[4] = 0x41; // StructureSize = 65
        assert!(Header::parse(&mut Reader::new(&bad)).is_err());
    }

    #[test]
    fn header_rejects_a_truncated_message() {
        let buf = sample_request_header();
        assert!(Header::parse(&mut Reader::new(&buf[..63])).is_err());
    }

    #[test]
    fn response_header_echoes_identity_and_sets_server_flag() {
        let buf = sample_request_header();
        let h = Header::parse(&mut Reader::new(&buf)).unwrap();
        let mut w = Writer::new();
        h.write_response(&mut w, status::ACCESS_DENIED, 8, h.session_id, h.tree_id);
        let out = w.into_vec();
        assert_eq!(out.len(), HEADER_LEN);

        let parsed = Header::parse(&mut Reader::new(&out)).unwrap();
        assert_eq!(parsed.status, status::ACCESS_DENIED);
        assert_eq!(parsed.credits, 8);
        assert_eq!(parsed.command, h.command);
        assert_eq!(parsed.message_id, h.message_id);
        assert_eq!(parsed.tree_id, h.tree_id);
        assert_eq!(parsed.session_id, h.session_id);
        assert_eq!(
            parsed.flags & flags::SERVER_TO_REDIR,
            flags::SERVER_TO_REDIR
        );
        assert_eq!(
            parsed.flags & flags::SIGNED,
            0,
            "the header codec leaves SIGNED clear; sign::sign sets it"
        );
    }

    #[test]
    fn response_header_echoes_related_operations_only() {
        let mut buf = sample_request_header();
        // Flags at offset 16: set RELATED_OPERATIONS and SIGNED.
        buf[16..20].copy_from_slice(&(flags::RELATED_OPERATIONS | flags::SIGNED).to_le_bytes());
        let h = Header::parse(&mut Reader::new(&buf)).unwrap();
        let mut w = Writer::new();
        h.write_response(&mut w, status::SUCCESS, 1, h.session_id, h.tree_id);
        let out = w.into_vec();
        let parsed = Header::parse(&mut Reader::new(&out)).unwrap();
        assert_eq!(
            parsed.flags & flags::RELATED_OPERATIONS,
            flags::RELATED_OPERATIONS
        );
        assert_eq!(parsed.flags & flags::SIGNED, 0);
    }

    #[test]
    fn response_header_carries_server_assigned_ids() {
        // SESSION_SETUP and TREE_CONNECT answer with ids the request did not
        // contain; this is the only channel by which the client learns them.
        let buf = sample_request_header();
        let h = Header::parse(&mut Reader::new(&buf)).unwrap();
        let mut w = Writer::new();
        h.write_response(&mut w, status::SUCCESS, 1, 0xFEED_FACE, 0x0000_0007);
        let parsed = Header::parse(&mut Reader::new(&w.into_vec())).unwrap();
        assert_eq!(parsed.session_id, 0xFEED_FACE);
        assert_eq!(parsed.tree_id, 7);
    }

    #[test]
    fn next_command_offset_points_at_the_next_command_field() {
        let buf = sample_request_header();
        let mut w = Writer::new();
        w.bytes(&buf);
        w.patch_u32(NEXT_COMMAND_OFFSET, 0x1234_5678);
        let out = w.into_vec();
        let parsed = Header::parse(&mut Reader::new(&out)).unwrap();
        assert_eq!(parsed.next_command, 0x1234_5678);
    }

    #[test]
    fn error_body_is_nine_bytes() {
        let mut w = Writer::new();
        write_error_body(&mut w);
        assert_eq!(
            w.len(),
            9,
            "StructureSize 9 means 8 fixed + 1 variable byte"
        );
    }

    #[test]
    fn read_only_access_mask_excludes_every_write_bit() {
        assert_eq!(access::READ_ONLY_FILE & access::WRITE_BITS, 0);
        assert_eq!(access::READ_ONLY_DIR & access::WRITE_BITS, 0);
    }

    #[test]
    fn generic_rights_are_covered_by_the_masks_they_map_to() {
        // A generic bit stands for the specific rights the server maps it to,
        // so each must be caught by the check its specific form would fail.
        assert_ne!(access::GENERIC_WRITE & access::WRITE_BITS, 0);
        assert_ne!(access::GENERIC_ALL & access::WRITE_BITS, 0);
        assert_ne!(access::GENERIC_EXECUTE & access::EXECUTE_BITS, 0);
        // GENERIC_ALL means write *and* execute, not write alone.
        assert_ne!(access::GENERIC_ALL & access::EXECUTE_BITS, 0);
        // GENERIC_READ maps to FILE_GENERIC_READ, which this share grants:
        // catching it would break every cifs.ko open.
        const GENERIC_READ: u32 = 0x8000_0000;
        assert_eq!(
            GENERIC_READ & (access::WRITE_BITS | access::EXECUTE_BITS),
            0
        );
    }

    #[test]
    fn only_directories_get_the_execute_traverse_bit() {
        assert_eq!(access::read_only(false) & access::FILE_EXECUTE, 0);
        assert_eq!(
            access::read_only(true) & access::FILE_TRAVERSE,
            access::FILE_TRAVERSE
        );
        // Traverse is the only difference between the two.
        assert_eq!(
            access::read_only(true) & !access::FILE_TRAVERSE,
            access::read_only(false)
        );
    }

    #[test]
    fn filetime_matches_known_epoch_values() {
        use std::time::{Duration, UNIX_EPOCH};
        // The Unix epoch is 11644473600 seconds after the FILETIME epoch.
        assert_eq!(to_filetime(UNIX_EPOCH), 11_644_473_600 * 10_000_000);
        assert_eq!(
            to_filetime(UNIX_EPOCH + Duration::from_secs(1)),
            11_644_473_601 * 10_000_000
        );
        // Sub-second precision lands in 100ns ticks.
        assert_eq!(
            to_filetime(UNIX_EPOCH + Duration::from_nanos(500)),
            11_644_473_600 * 10_000_000 + 5
        );
    }

    #[test]
    fn filetime_clamps_below_the_unix_epoch_instead_of_wrapping() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(to_filetime(UNIX_EPOCH - Duration::from_secs(1)), 0);
    }
}
