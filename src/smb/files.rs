// CREATE, CLOSE, READ, QUERY_DIRECTORY, QUERY_INFO and IOCTL.
//
// Read-only is enforced here rather than relied upon from the absence of a
// write path: a CREATE asking for write access, a create disposition that would
// modify anything, or FILE_DELETE_ON_CLOSE is refused outright. Downgrading
// such a request to a read handle would "work" right up until the client tried
// the write it announced, and fail somewhere far less obvious.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use super::backing::{Backing, FileReader, NodeInfo};
use super::info::{self, file_class, fs_class, info_type};
use super::path::SmbPath;
use super::proto::{HEADER_LEN, access, status, to_filetime};
use super::session::MAX_READ_SIZE;
use super::wire::{Reader, Writer, from_utf16le};

/// Create dispositions (MS-SMB2 2.2.13).
mod disposition {
    pub(super) const SUPERSEDE: u32 = 0;
    pub(super) const OPEN: u32 = 1;
    pub(super) const CREATE: u32 = 2;
    pub(super) const OPEN_IF: u32 = 3;
    pub(super) const OVERWRITE: u32 = 4;
    pub(super) const OVERWRITE_IF: u32 = 5;
}

/// Create options (MS-SMB2 2.2.13).
mod options {
    pub(super) const DIRECTORY_FILE: u32 = 0x0000_0001;
    pub(super) const NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    pub(super) const DELETE_ON_CLOSE: u32 = 0x0000_1000;
}

/// QUERY_DIRECTORY flags (MS-SMB2 2.2.33).
mod query_dir_flags {
    pub(super) const RESTART_SCANS: u8 = 0x01;
    pub(super) const RETURN_SINGLE_ENTRY: u8 = 0x02;
    // SMB2_INDEX_SPECIFIED (0x04) is deliberately absent: see the FileIndex
    // comment in `query_directory`.
    pub(super) const REOPEN: u8 = 0x10;
}

/// CreateAction in a CREATE response. Nothing here ever creates or overwrites,
/// so an open is the only outcome.
const FILE_OPENED: u32 = 1;

/// The FileId a compounded request uses to mean "whatever the previous CREATE
/// in this chain opened" (MS-SMB2 3.2.4.1.4).
const RELATED_FILE_ID: u64 = u64::MAX;

/// One open handle.
pub(crate) struct OpenHandle {
    /// The tree it was opened through. Kept so a TREE_DISCONNECT can release
    /// everything that tree owns; a handle outliving its tree is unreachable
    /// but would still hold its reader.
    tree_id: u32,
    pub(crate) path: SmbPath,
    pub(crate) info: NodeInfo,
    /// Lazily opened: a client frequently opens a file only to stat it, and
    /// the first read may need to decompress the entry into its cache.
    reader: Option<Arc<dyn FileReader>>,
    /// Directory listing, captured on the first QUERY_DIRECTORY.
    ///
    /// The archive cannot change under us, so this is a cache rather than a
    /// consistency device — but SMB directory enumeration is explicitly
    /// stateful (each call resumes where the last stopped), so the position has
    /// to live with the handle regardless.
    dir_entries: Option<Vec<(NodeInfo, u64)>>,
    dir_pos: usize,
    /// Whether a QUERY_DIRECTORY on this handle has already returned entries.
    /// Distinguishes "this search matched nothing" from "the enumeration is
    /// finished", which are different statuses to a client. Reset by
    /// RESTART_SCANS/REOPEN along with the cursor.
    scanned: bool,
}

/// Per-connection open handles.
pub(crate) struct Handles {
    open: BTreeMap<u64, OpenHandle>,
    next_id: u64,
    /// The handle opened by the most recent CREATE, for related compounds.
    last_created: Option<u64>,
}

impl Default for Handles {
    fn default() -> Self {
        Self {
            open: BTreeMap::new(),
            // Start above zero; 0 and u64::MAX are both reserved.
            next_id: 1,
            last_created: None,
        }
    }
}

impl Handles {
    fn insert(&mut self, handle: OpenHandle) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.open.insert(id, handle);
        self.last_created = Some(id);
        id
    }

    /// Forget the related-compound placeholder.
    ///
    /// Called by the dispatcher before every request that is *not* related, so
    /// the placeholder never outlives the chain that set it. Without this, a
    /// stray 0xFF..FF — or a related request whose own CREATE failed — resolves
    /// onto whatever handle the previous chain happened to open, and a CLOSE
    /// carrying it shuts a file the client still believes is open.
    pub(crate) fn clear_chain(&mut self) {
        self.last_created = None;
    }

    fn get_mut(&mut self, id: u64, related: bool) -> Option<&mut OpenHandle> {
        let id = self.resolve(id, related)?;
        self.open.get_mut(&id)
    }

    fn get(&self, id: u64, related: bool) -> Option<&OpenHandle> {
        self.open.get(&self.resolve(id, related)?)
    }

    fn remove(&mut self, id: u64, related: bool) -> Option<OpenHandle> {
        let id = self.resolve(id, related)?;
        if self.last_created == Some(id) {
            self.last_created = None;
        }
        self.open.remove(&id)
    }

    /// Release every handle opened through `tree_id`, for TREE_DISCONNECT.
    pub(crate) fn close_tree(&mut self, tree_id: u32) {
        self.open.retain(|_, h| h.tree_id != tree_id);
        self.forget_stale_last_created();
    }

    /// Release everything, for LOGOFF: the session is gone, so no file id in it
    /// can ever be named again.
    pub(crate) fn close_all(&mut self) {
        self.open.clear();
        self.last_created = None;
    }

    /// Drop the compound placeholder if the handle it points at is gone.
    /// Leaving it dangling would let a later related compound resolve onto a
    /// handle id that was reused.
    fn forget_stale_last_created(&mut self) {
        if let Some(id) = self.last_created
            && !self.open.contains_key(&id)
        {
            self.last_created = None;
        }
    }

    /// How many handles are open. Tests assert on this to catch a leak — a
    /// CREATE that never gets its matching CLOSE would otherwise be invisible
    /// until a long-lived mount ran the table up.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.open.len()
    }

    /// Map the compound placeholder onto the handle the chain just opened.
    ///
    /// Only inside a related chain: outside one the placeholder names nothing,
    /// and falling through to the ordinary lookup gives it the FILE_CLOSED it
    /// deserves rather than someone else's handle.
    fn resolve(&self, id: u64, related: bool) -> Option<u64> {
        if id == RELATED_FILE_ID && related {
            self.last_created
        } else {
            Some(id)
        }
    }
}

/// Read a 16-byte SMB2 FileId, returning the volatile half — the only part this
/// server distinguishes, since handles do not survive a reconnect.
fn read_file_id(r: &mut Reader<'_>) -> Result<u64, u32> {
    let persistent = r.u64().map_err(|_| status::INVALID_PARAMETER)?;
    let volatile = r.u64().map_err(|_| status::INVALID_PARAMETER)?;
    // Both halves are set to the placeholder in a related compound.
    if persistent == RELATED_FILE_ID && volatile == RELATED_FILE_ID {
        return Ok(RELATED_FILE_ID);
    }
    Ok(volatile)
}

fn write_file_id(w: &mut Writer, id: u64) {
    w.u64(id); // Persistent
    w.u64(id); // Volatile
}

/// Read a CREATE's filename and DesiredAccess back out of the request, for the
/// trace log. Same idea as `session::peek_dialects`: a client reports a refused
/// open as a generic system error, so "CREATE -> ACCESS_DENIED" on its own does
/// not say *which* path was refused or what it asked for — the two things
/// needed to tell a real bug from a client probing for write access.
///
/// Returns None rather than an error: this only ever feeds a log line, and a
/// request too malformed to peek at is about to be rejected by `create` anyway.
pub(crate) fn peek_create(body: &[u8], message: &[u8]) -> Option<(String, u32)> {
    let mut r = Reader::new(body);
    if r.u16().ok()? != 57 {
        return None;
    }
    r.skip(1).ok()?; // SecurityFlags
    r.skip(1).ok()?; // RequestedOplockLevel
    r.skip(4).ok()?; // ImpersonationLevel
    r.skip(8).ok()?; // SmbCreateFlags
    r.skip(8).ok()?; // Reserved
    let desired_access = r.u32().ok()?;
    r.skip(4).ok()?; // FileAttributes
    r.skip(4).ok()?; // ShareAccess
    r.skip(4).ok()?; // CreateDisposition
    r.skip(4).ok()?; // CreateOptions
    let name_off = r.u16().ok()? as usize;
    let name_len = r.u16().ok()? as usize;
    let raw = Reader::new(message).slice_at(name_off, name_len).ok()?;
    Some((from_utf16le(raw).ok()?, desired_access))
}

/// CREATE (MS-SMB2 2.2.13 request, 2.2.14 response).
pub(crate) fn create(
    body: &[u8],
    message: &[u8],
    backing: &dyn Backing,
    handles: &mut Handles,
    tree_id: u32,
) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 57 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // SecurityFlags
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // RequestedOplockLevel
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // ImpersonationLevel
    r.skip(8).map_err(|_| status::INVALID_PARAMETER)?; // SmbCreateFlags
    r.skip(8).map_err(|_| status::INVALID_PARAMETER)?; // Reserved
    let desired_access = r.u32().map_err(|_| status::INVALID_PARAMETER)?;
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // FileAttributes
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // ShareAccess
    let create_disposition = r.u32().map_err(|_| status::INVALID_PARAMETER)?;
    let create_options = r.u32().map_err(|_| status::INVALID_PARAMETER)?;
    let name_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let name_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let contexts_off = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let contexts_len = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    // Only one create context is answered, and only because its absence is
    // actively misleading: MxAc asks "what could I do with this file?", and a
    // client that gets no answer assumes the maximum. Windows Explorer then
    // offers rename and delete on every file in the share and fails them one by
    // one. Every other context — macOS's AAPL, durable handles, leases — is
    // still ignored, which is valid: returning no context for one is exactly
    // how a server says it does not support it.

    // Refuse anything that intends to modify. Checked before the path is even
    // resolved so that a write attempt fails identically whether or not the
    // target exists, which avoids leaking existence.
    if desired_access & access::WRITE_BITS != 0 {
        return Err(status::ACCESS_DENIED);
    }
    match create_disposition {
        disposition::OPEN | disposition::OPEN_IF => {}
        disposition::SUPERSEDE
        | disposition::CREATE
        | disposition::OVERWRITE
        | disposition::OVERWRITE_IF => return Err(status::MEDIA_WRITE_PROTECTED),
        _ => return Err(status::INVALID_PARAMETER),
    }
    if create_options & options::DELETE_ON_CLOSE != 0 {
        return Err(status::MEDIA_WRITE_PROTECTED);
    }

    let msg_reader = Reader::new(message);
    let raw_name = msg_reader
        .slice_at(name_off, name_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let name = from_utf16le(raw_name).map_err(|_| status::OBJECT_PATH_SYNTAX_BAD)?;
    let path = SmbPath::parse(&name)?;

    let info = backing.stat(&path)?;

    // Nothing here is executable. On a file the bit means "run this as an
    // image", and refusing it is what stops a Windows client launching a
    // binary straight off the share — this is a way to browse a backup, not a
    // way to restore or run one. On a directory the identical bit means
    // traverse, which every client needs to descend, so it is granted there.
    if !info.kind.is_dir() && desired_access & access::EXECUTE_BITS != 0 {
        return Err(status::ACCESS_DENIED);
    }

    // Honour the caller's stated expectation about what it is opening.
    if create_options & options::DIRECTORY_FILE != 0 && !info.kind.is_dir() {
        return Err(status::NOT_A_DIRECTORY);
    }
    if create_options & options::NON_DIRECTORY_FILE != 0 && info.kind.is_dir() {
        return Err(status::FILE_IS_A_DIRECTORY);
    }

    let granted = access::read_only(info.kind.is_dir());
    let wants_max_access = msg_reader
        .slice_at(contexts_off, contexts_len)
        .map(|c| has_create_context(c, MAX_ACCESS_TAG))
        .unwrap_or(false);

    let file_id = handles.insert(OpenHandle {
        tree_id,
        path,
        info: info.clone(),
        reader: None,
        dir_entries: None,
        dir_pos: 0,
        scanned: false,
    });

    let mut w = Writer::with_capacity(88);
    w.u16(89); // StructureSize
    w.u8(0); // OplockLevel — SMB2_OPLOCK_LEVEL_NONE. No leases: the data is
    // immutable, so there is nothing for a lease to protect against.
    w.u8(0); // Flags
    w.u32(FILE_OPENED); // CreateAction
    w.u64(to_filetime(info.ctime)); // CreationTime
    w.u64(to_filetime(info.atime)); // LastAccessTime
    w.u64(to_filetime(info.mtime)); // LastWriteTime
    w.u64(to_filetime(info.ctime)); // ChangeTime
    w.u64(info::allocation_size(info.size)); // AllocationSize
    w.u64(info.size); // EndOfFile
    w.u32(info::file_attributes(info.kind)); // FileAttributes
    w.u32(0); // Reserved2
    write_file_id(&mut w, file_id);
    if wants_max_access {
        // Offsets count from the SMB2 header, and the fixed part of a CREATE
        // response is 88 bytes.
        let context = max_access_context(granted);
        w.u32((HEADER_LEN + 88) as u32); // CreateContextsOffset
        w.u32(context.len() as u32); // CreateContextsLength
        w.bytes(&context);
    } else {
        w.u32(0); // CreateContextsOffset — none returned
        w.u32(0); // CreateContextsLength
    }
    Ok(w.into_vec())
}

/// `MxAc` — the maximal-access create context tag (MS-SMB2 2.2.13.2.5).
const MAX_ACCESS_TAG: &[u8; 4] = b"MxAc";

/// Whether a create-context chain carries the context named by `tag`.
///
/// The chain is a list of (Next, NameOffset, NameLength, ...) records, each
/// linked by a byte distance from its own start and terminated by a zero. Only
/// the names are read; no context's payload is interpreted.
fn has_create_context(buf: &[u8], tag: &[u8; 4]) -> bool {
    let mut at = 0usize;
    loop {
        let Some(rec) = buf.get(at..) else {
            return false;
        };
        if rec.len() < 16 {
            return false;
        }
        let next = u32::from_le_bytes(rec[0..4].try_into().expect("4 bytes")) as usize;
        let name_off = u16::from_le_bytes(rec[4..6].try_into().expect("2 bytes")) as usize;
        let name_len = u16::from_le_bytes(rec[6..8].try_into().expect("2 bytes")) as usize;
        if rec.get(name_off..name_off.saturating_add(name_len)) == Some(tag.as_slice()) {
            return true;
        }
        // A zero Next terminates; anything that does not advance would spin.
        if next < 16 {
            return false;
        }
        at += next;
    }
}

/// The `MxAc` response context: the access this open would actually be granted.
fn max_access_context(granted: u32) -> Vec<u8> {
    let mut w = Writer::with_capacity(32);
    w.u32(0); // Next — the only context returned
    w.u16(16); // NameOffset, from the start of this record
    w.u16(4); // NameLength
    w.u16(0); // Reserved
    w.u16(24); // DataOffset
    w.u32(8); // DataLength
    w.bytes(MAX_ACCESS_TAG); // 16 Name
    w.zeros(4); // padding to the 8-byte-aligned data
    w.u32(status::SUCCESS); // 24 QueryStatus
    w.u32(granted); // 28 MaximalAccess
    w.into_vec()
}

/// CLOSE (MS-SMB2 2.2.15 request, 2.2.16 response).
pub(crate) fn close(body: &[u8], handles: &mut Handles, related: bool) -> Result<Vec<u8>, u32> {
    const POSTQUERY_ATTRIB: u16 = 0x0001;

    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 24 {
        return Err(status::INVALID_PARAMETER);
    }
    let flags = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Reserved
    let file_id = read_file_id(&mut r)?;

    let handle = handles
        .remove(file_id, related)
        .ok_or(status::FILE_CLOSED)?;

    let mut w = Writer::with_capacity(60);
    w.u16(60); // StructureSize
    if flags & POSTQUERY_ATTRIB != 0 {
        // The client asked for the final attributes rather than issuing a
        // separate QUERY_INFO. Cheap to answer and saves it a round trip.
        w.u16(POSTQUERY_ATTRIB);
        w.u32(0); // Reserved
        w.u64(to_filetime(handle.info.ctime));
        w.u64(to_filetime(handle.info.atime));
        w.u64(to_filetime(handle.info.mtime));
        w.u64(to_filetime(handle.info.ctime));
        w.u64(info::allocation_size(handle.info.size));
        w.u64(handle.info.size);
        w.u32(info::file_attributes(handle.info.kind));
    } else {
        w.u16(0); // Flags
        w.u32(0); // Reserved
        // Four FILETIMEs, AllocationSize, EndOfFile and FileAttributes: 52
        // bytes, all left unset because the client did not ask for them.
        w.zeros(52);
    }
    Ok(w.into_vec())
}

/// READ (MS-SMB2 2.2.19 request, 2.2.20 response).
pub(crate) fn read(
    body: &[u8],
    backing: &dyn Backing,
    handles: &mut Handles,
    related: bool,
) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 49 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // Padding
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // Flags
    let length = r.u32().map_err(|_| status::INVALID_PARAMETER)?;
    let offset = r.u64().map_err(|_| status::INVALID_PARAMETER)?;
    let file_id = read_file_id(&mut r)?;
    let minimum_count = r.u32().map_err(|_| status::INVALID_PARAMETER)?;

    // Cap before allocating: Length is client-supplied and we advertised a
    // maximum in NEGOTIATE, but nothing forces a client to honour it.
    let length = length.min(MAX_READ_SIZE);

    let handle = handles
        .get_mut(file_id, related)
        .ok_or(status::FILE_CLOSED)?;
    if handle.info.kind.is_dir() {
        return Err(status::INVALID_DEVICE_REQUEST);
    }

    // Open on first read rather than at CREATE: many opens never read.
    if handle.reader.is_none() {
        handle.reader = Some(backing.open(&handle.path)?);
    }
    let reader = handle.reader.as_ref().expect("just opened");
    let data = reader.read_at(offset, length)?;

    // No data where some was asked for means end of file; a client that got
    // SUCCESS with an empty buffer would loop forever. A read that asked for
    // nothing is not that — it succeeds, empty. Samba draws the same line
    // (`nread == 0 && in_length != 0`, smb2_read.c:404-408).
    if data.is_empty() && length > 0 {
        return Err(status::END_OF_FILE);
    }
    if (data.len() as u32) < minimum_count {
        return Err(status::END_OF_FILE);
    }

    let mut w = Writer::with_capacity(16 + data.len());
    w.u16(17); // StructureSize
    w.u8((HEADER_LEN + 16) as u8); // DataOffset, from the SMB2 header
    w.u8(0); // Reserved
    w.u32(data.len() as u32); // DataLength
    w.u32(0); // DataRemaining — unused for a non-channelled read
    w.u32(0); // Reserved2
    w.bytes(&data);
    Ok(w.into_vec())
}

/// The three DOS wildcards, which are ordinary characters on the wire and
/// wildcards only to a filename matcher (MS-FSA 2.1.4.4).
///
/// Windows does *not* send `*.txt`. Its runtime rewrites a Win32 mask into
/// these before it ever reaches a server: `*` before a dot becomes DOS_STAR,
/// `?` becomes DOS_QM, and a dot before `*`, `?` or the end becomes DOS_DOT. So
/// `dir *.txt` arrives as `<.txt` and `dir *.*` as `<"*`. Treating them as
/// literals — which is what not implementing them means, since no filename can
/// contain one — matches nothing, and every wildcard listing from cmd.exe comes
/// back "File Not Found". Samba implements exactly these three, for the same
/// reason (`lib/util/ms_fnmatch.c:39-153`).
mod dos_wildcard {
    /// `<` — like `*`, but never matches the final dot of a name.
    pub(super) const STAR: u8 = b'<';
    /// `>` — like `?`, but also matches "nothing" at the end of a name or
    /// before a dot.
    pub(super) const QM: u8 = b'>';
    /// `"` — matches a literal dot, or nothing at the end of a name.
    pub(super) const DOT: u8 = b'"';
}

/// Longest pattern the matcher will walk.
///
/// Recursion depth follows the pattern length — every branch below consumes a
/// pattern byte, but only some of them consume a name byte — and the pattern
/// arrives off the wire in a 16-bit length field, so a client can ask for tens
/// of thousands of frames. That overflows the stack, which aborts the process
/// rather than failing the request, and no step budget can catch it because the
/// frames are spent before the steps are. A search pattern is a file name with
/// wildcards in it and a name is at most 255 characters, so nothing a client
/// legitimately sends comes near this.
const MAX_PATTERN: usize = 1024;

/// Match a QUERY_DIRECTORY search pattern. Clients almost always send `*`, but
/// a lookup of a single name by pattern is legal and macOS does it.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern.is_empty() || pattern == "*" {
        return true;
    }
    let (pattern, name) = (pattern.as_bytes(), name.as_bytes());
    if pattern.len() > MAX_PATTERN {
        return false;
    }
    let mut budget = match_budget(pattern, name);
    glob_match(pattern, name, &mut budget)
}

/// How many calls `glob_match` may make for one name before giving up and
/// reporting no match.
///
/// The matcher backtracks, so its cost is exponential in the number of `*`-like
/// wildcards rather than linear in the pattern: `**********x` against a name
/// with no `x` explores every way of dividing the name between the ten stars,
/// and does not finish in any useful time. The pattern comes straight from the
/// client, and this runs once per directory entry, so the bound has to be here
/// rather than in what the caller is willing to accept.
///
/// A matcher that memoised would visit each (pattern position, name position)
/// pair once, which makes the pair count the natural unit; the multiplier is
/// how much re-visiting this one is allowed before it concedes. Both sit far
/// above what the patterns clients actually send need — `*`, a literal name,
/// `<.txt`, `<"*`, none with more than two wildcards — so a budget is only ever
/// exhausted by a pattern built to exhaust it, for which "no match" is the
/// honest answer anyway.
fn match_budget(pattern: &[u8], name: &[u8]) -> u32 {
    const REVISITS: u32 = 64;
    const CEILING: u32 = 100_000;
    let pairs = (pattern.len() as u32)
        .saturating_add(1)
        .saturating_mul(name.len() as u32 + 1);
    pairs.saturating_mul(REVISITS).min(CEILING)
}

/// Wildcard matcher for `*` and `?` plus the three DOS wildcards.
///
/// Recursive at the wildcards only. The iterative form does not survive the DOS
/// wildcards: `>` and `"` can match the empty string in the middle of a name,
/// so a single backtrack point is no longer enough. `budget` is what keeps the
/// backtracking from running away — see `match_budget`.
///
/// Case-insensitivity is **ASCII-only**: the comparison is over raw UTF-8 bytes,
/// so `A` matches `a` but `É` does not match `é`. Real Unicode case folding
/// would mean decoding both sides and carrying a folding table, and the clients
/// that send a pattern at all send `*` or a literal name they read back from us
/// moments earlier.
fn glob_match(pattern: &[u8], name: &[u8], budget: &mut u32) -> bool {
    // Charged per call, including the ones that return immediately: it is the
    // number of calls, not the depth, that runs away.
    if *budget == 0 {
        return false;
    }
    *budget -= 1;

    let Some((&p, rest)) = pattern.split_first() else {
        // Pattern exhausted: a match only if the name is too.
        return name.is_empty();
    };

    match p {
        // `*` matches any run of characters, so try the rest of the pattern at
        // every position including the end of the name.
        b'*' => {
            for skip in 0..=name.len() {
                if glob_match(rest, &name[skip..], budget) {
                    return true;
                }
                // Nothing further can succeed once the budget is gone, and the
                // loops already on the stack would otherwise each spin out
                // their full range over calls that return false on entry.
                if *budget == 0 {
                    return false;
                }
            }
            false
        }

        // DOS_STAR is `*` that stops at the name's *last* dot: it may end
        // before that dot or step over it, but never runs past it. That is what
        // makes `<.txt` (which is how `dir *.txt` reaches the wire) match
        // `a.txt` and `notes.txt` but not `a.txt.bak`.
        dos_wildcard::STAR => {
            let last_dot = name.iter().rposition(|&c| c == b'.');
            for skip in 0..name.len() {
                if glob_match(rest, &name[skip..], budget) {
                    return true;
                }
                if last_dot == Some(skip) {
                    // The one position past the last dot, and then no further.
                    return glob_match(rest, &name[skip + 1..], budget);
                }
                if *budget == 0 {
                    return false;
                }
            }
            // Ran out of name without meeting a dot.
            glob_match(rest, &[], budget)
        }

        // DOS_QM matches one character — except at the end of the name, or
        // where a dot begins, in which case it matches nothing and does *not*
        // consume the dot.
        dos_wildcard::QM => {
            if name.is_empty() || name[0] == b'.' {
                glob_match(rest, name, budget)
            } else {
                glob_match(rest, &name[1..], budget)
            }
        }

        // DOS_DOT is a soft dot: a literal dot, or nothing at the end of a name.
        dos_wildcard::DOT => {
            if name.is_empty() {
                glob_match(rest, name, budget)
            } else {
                name[0] == b'.' && glob_match(rest, &name[1..], budget)
            }
        }

        b'?' => !name.is_empty() && glob_match(rest, &name[1..], budget),
        literal => {
            !name.is_empty()
                && literal.eq_ignore_ascii_case(&name[0])
                && glob_match(rest, &name[1..], budget)
        }
    }
}

/// QUERY_DIRECTORY (MS-SMB2 2.2.33 request, 2.2.34 response).
pub(crate) fn query_directory(
    body: &[u8],
    message: &[u8],
    backing: &dyn Backing,
    handles: &mut Handles,
    now: SystemTime,
    related: bool,
) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 33 {
        return Err(status::INVALID_PARAMETER);
    }
    let class = r.u8().map_err(|_| status::INVALID_PARAMETER)?;
    let flags = r.u8().map_err(|_| status::INVALID_PARAMETER)?;
    // FileIndex is only meaningful with SMB2_INDEX_SPECIFIED, which no client
    // sends — NTFS itself cannot restart an enumeration by index, and Samba
    // ignores the field outright. Skipped rather than honoured: implementing it
    // would mean defining what an index *means* under a filtering pattern, and
    // nothing would ever exercise the answer.
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // FileIndex
    let file_id = read_file_id(&mut r)?;
    let pattern_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let pattern_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let output_len = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;

    let msg_reader = Reader::new(message);
    let raw_pattern = msg_reader
        .slice_at(pattern_off, pattern_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let pattern = from_utf16le(raw_pattern).map_err(|_| status::OBJECT_NAME_INVALID)?;

    // Everything the listing needs, read under one immutable borrow, which then
    // ends: `backing.list` can be a storage call, and the mutable borrow for the
    // cursor cannot be taken until after it.
    let (path, needs_listing) = {
        let handle = handles.get(file_id, related).ok_or(status::FILE_CLOSED)?;
        if !handle.info.kind.is_dir() {
            return Err(status::NOT_A_DIRECTORY);
        }
        (handle.path.clone(), handle.dir_entries.is_none())
    };

    let listing = if needs_listing {
        let mut entries = Vec::new();
        // `.` and `..` are expected by enough clients that omitting them causes
        // odd behaviour in file managers, and they cost nothing to synthesise.
        entries.push((NodeInfo::synthetic_dir(".", now), path.file_id()));
        entries.push((NodeInfo::synthetic_dir("..", now), path.file_id()));
        for info in backing.list(&path)? {
            let id = path.join(&info.name).file_id();
            entries.push((info, id));
        }
        Some(entries)
    } else {
        None
    };

    let handle = handles
        .get_mut(file_id, related)
        .ok_or(status::FILE_CLOSED)?;
    if let Some(listing) = listing {
        handle.dir_entries = Some(listing);
    }
    if flags & (query_dir_flags::RESTART_SCANS | query_dir_flags::REOPEN) != 0 {
        handle.dir_pos = 0;
        handle.scanned = false;
    }

    let all = handle.dir_entries.as_ref().expect("populated above");
    // Each match carries its position in the *unfiltered* listing, because that
    // is what `dir_pos` indexes. Advancing the cursor by the number of encoded
    // matches instead would skip over the entries the pattern rejected: with
    // `[., .., a.txt, b.log]` and `*.log`, one match would move the cursor to 1
    // rather than past `b.log`, and the next call would hand out `b.log` again,
    // for ever.
    //
    // Positions first, then a clone of only the entries that can fit in this
    // page. Cloning every remaining match — twice, as this once did — is O(n)
    // heap allocations per call and quadratic over a large directory's
    // enumeration, for entries the encoder was going to discard anyway.
    let matched: Vec<usize> = all
        .iter()
        .enumerate()
        .skip(handle.dir_pos)
        .filter(|(_, (info, _))| pattern_matches(&pattern, &info.name))
        .map(|(i, _)| i)
        .collect();
    let max_len = output_len.min(MAX_READ_SIZE as usize);
    let single = flags & query_dir_flags::RETURN_SINGLE_ENTRY != 0;
    // An entry is at least its class's fixed part, so this many can fit at
    // most; a shorter buffer just means the encoder stops earlier. An unknown
    // class caps at one and is refused by the encoder a few lines below, which
    // is where that error belongs.
    let page_cap = if single {
        1
    } else {
        info::dir_entry_fixed_len(class)
            .map_or(1, |fixed| max_len / fixed)
            .max(1)
            .min(matched.len())
    };
    let page: Vec<(NodeInfo, u64)> = matched
        .iter()
        .take(page_cap)
        .map(|&i| all[i].clone())
        .collect();

    if matched.is_empty() {
        // Exhaustion and "nothing ever matched" are different answers. A first
        // scan that matches nothing is STATUS_NO_SUCH_FILE, which Windows maps
        // to ERROR_FILE_NOT_FOUND — what FindFirstFile callers test for;
        // NO_MORE_FILES is for a continuation that has run out. Samba draws the
        // same distinction on whether the cursor was just created
        // (smb2_query_directory.c:408-424).
        return Err(if handle.scanned {
            status::NO_MORE_FILES
        } else {
            status::NO_SUCH_FILE
        });
    }

    let start_index = handle.dir_pos as u32;
    handle.scanned = true;
    let (buf, consumed) = info::encode_dir_entries(class, &page, start_index, max_len, single)?;
    // Resume immediately after the last entry actually encoded. `consumed` is
    // never zero here — `encode_dir_entries` errors rather than report an empty
    // page — but the cursor is left alone rather than trusting that.
    if let Some(&last) = consumed.checked_sub(1).and_then(|i| matched.get(i)) {
        handle.dir_pos = last + 1;
    }

    let mut w = Writer::with_capacity(8 + buf.len());
    w.u16(9); // StructureSize
    w.u16((HEADER_LEN + 8) as u16); // OutputBufferOffset
    w.u32(buf.len() as u32); // OutputBufferLength
    w.bytes(&buf);
    Ok(w.into_vec())
}

/// Read a QUERY_INFO's type, class and buffer size back out of the request,
/// for the trace log. Same contract as `peek_create`: None on a malformed
/// body, which `query_info` is about to reject anyway.
pub(crate) fn peek_query_info(body: &[u8]) -> Option<(u8, u8, u32)> {
    let mut r = Reader::new(body);
    if r.u16().ok()? != 41 {
        return None;
    }
    let ty = r.u8().ok()?;
    let class = r.u8().ok()?;
    let output_len = r.u32().ok()?;
    Some((ty, class, output_len))
}

/// QUERY_INFO (MS-SMB2 2.2.37 request, 2.2.38 response).
///
/// Success is a body plus a status, not just a body, because a truncated
/// answer is delivered as STATUS_BUFFER_OVERFLOW — a warning that carries a
/// valid response body — rather than as an error.
pub(crate) fn query_info(
    body: &[u8],
    backing: &dyn Backing,
    handles: &Handles,
    volume_created: SystemTime,
    volume_serial: u32,
    related: bool,
) -> Result<(Vec<u8>, u32), u32> {
    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 41 {
        return Err(status::INVALID_PARAMETER);
    }
    let ty = r.u8().map_err(|_| status::INVALID_PARAMETER)?;
    let class = r.u8().map_err(|_| status::INVALID_PARAMETER)?;
    let output_len = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // InputBufferOffset
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // Reserved
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // InputBufferLength
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // AdditionalInformation
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Flags
    let file_id = read_file_id(&mut r)?;

    let handle = handles.get(file_id, related).ok_or(status::FILE_CLOSED)?;

    let buf = match ty {
        info_type::FILE => {
            // Absolute form: FileNameInformation is share-relative but starts
            // with a backslash, and the root's name must not be empty.
            let path = handle.path.to_smb_absolute();
            let id = handle.path.file_id();
            let granted = access::read_only(handle.info.kind.is_dir());
            match class {
                file_class::BASIC => info::file_basic(&handle.info),
                file_class::STANDARD => info::file_standard(&handle.info),
                file_class::INTERNAL => info::file_internal(id),
                file_class::EA => info::file_ea(),
                file_class::ACCESS => info::file_access(granted),
                file_class::NAME => info::file_name(&path),
                file_class::POSITION => info::file_position(),
                file_class::MODE => info::file_mode(),
                file_class::ALIGNMENT => info::file_alignment(),
                file_class::ALL => info::file_all(&handle.info, id, granted, &path),
                file_class::STREAM => info::file_stream(&handle.info),
                file_class::NETWORK_OPEN => info::file_network_open(&handle.info),
                file_class::ATTRIBUTE_TAG => info::file_attribute_tag(&handle.info),
                // `ls -l` calls listxattr on every entry, which lands here.
                // The accurate answer is "this file has none"; it maps to
                // ENODATA, which callers ignore silently.
                file_class::FULL_EA => return Err(status::NO_EAS_ON_FILE),
                // NOT_SUPPORTED, not INVALID_INFO_CLASS. cifs.ko maps the
                // latter to EIO, so an unimplemented class would surface to the
                // user as a broken filesystem rather than as a missing optional
                // feature; NOT_SUPPORTED maps to EOPNOTSUPP, which callers
                // degrade past.
                _ => return Err(status::NOT_SUPPORTED),
            }
        }
        info_type::FILESYSTEM => match class {
            fs_class::VOLUME => info::fs_volume(backing.label(), volume_created, volume_serial),
            fs_class::SIZE => info::fs_size(backing.total_size()),
            fs_class::FULL_SIZE => info::fs_full_size(backing.total_size()),
            fs_class::DEVICE => info::fs_device(),
            fs_class::ATTRIBUTE => info::fs_attribute(),
            fs_class::SECTOR_SIZE => info::fs_sector_size(),
            _ => return Err(status::NOT_SUPPORTED),
        },
        // No security descriptors and no quotas. Clients treat both as
        // optional; refusing is cleaner than inventing an ACL that does not
        // describe anything real.
        info_type::SECURITY | info_type::QUOTA => return Err(status::NOT_SUPPORTED),
        _ => return Err(status::INVALID_PARAMETER),
    };

    // Each class's C-struct size, and where its trailing string starts, for the
    // classes that have one. The NT I/O manager probes the struct size before
    // it looks at anything else, so this is checked whether or not the answer
    // would have fit: a buffer below it is a mismatch even when the payload is
    // short enough to fit in it. Samba applies the same check in the same order
    // (smb2_getinfo.c:432-437 for FILE, :493-498 for FILESYSTEM).
    let (min_len, string_off) = match (ty, class) {
        (info_type::FILE, file_class::NAME) => (8, Some(4)),
        (info_type::FILE, file_class::ALL) => (104, Some(100)),
        (info_type::FILESYSTEM, fs_class::VOLUME) => (24, Some(18)),
        (info_type::FILESYSTEM, fs_class::ATTRIBUTE) => (16, Some(12)),
        // Everything else is fixed-size, so its struct size is what it encoded
        // and it has nothing sensible to truncate.
        _ => (buf.len(), None),
    };
    if output_len < min_len {
        return Err(status::INFO_LENGTH_MISMATCH);
    }

    let mut buf = buf;
    let mut reply_status = status::SUCCESS;
    if buf.len() > output_len {
        // The client's buffer is too small for this class, and this is not a
        // corner case: the Windows CRT queries FileFsVolumeInformation with a
        // 24-byte buffer on every fstat(), which cannot hold any volume label
        // (measured; failing it hard is what made VLC report "read error:
        // Permission denied" on the share, via STATUS_INFO_LENGTH_MISMATCH →
        // ERROR_BAD_LENGTH → the CRT's blanket EACCES mapping).
        //
        // NT's rule, MS-FSCC 2.4/2.5: classes that end in a variable-length
        // string get the portion that fits plus STATUS_BUFFER_OVERFLOW — a
        // warning, delivered with a normal data-bearing response — and the
        // embedded length field still reports the full string so the caller
        // can size a retry. The string is cut on a UTF-16 code-unit boundary;
        // half a unit would decode as a garbage final character. Everything
        // else has nothing sensible to truncate; a buffer too small for one of
        // those was already refused by the struct-size check above.
        let string_off = string_off.ok_or(status::INFO_LENGTH_MISMATCH)?;
        buf.truncate(string_off + (output_len - string_off) / 2 * 2);
        reply_status = status::BUFFER_OVERFLOW;
    }

    let mut w = Writer::with_capacity(8 + buf.len());
    w.u16(9); // StructureSize
    w.u16((HEADER_LEN + 8) as u16); // OutputBufferOffset
    w.u32(buf.len() as u32); // OutputBufferLength
    w.bytes(&buf);
    Ok((w.into_vec(), reply_status))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests name directory classes explicitly; the handler passes the
    // client's class straight through to the encoder.
    use crate::smb::backing::test_support::MemBacking;
    use crate::smb::info::dir_class;
    use crate::smb::wire::utf16le;
    use std::time::UNIX_EPOCH;

    fn message(body: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; HEADER_LEN];
        m.extend_from_slice(body);
        m
    }

    // The handlers take the related-compound flag, which is only ever true for
    // a request chained behind a CREATE. These shadow the real functions so
    // that the ordinary tests — every one that is not about compounds — read as
    // the standalone requests they are; the compound tests call through to
    // `super::` with the flag set.
    fn close(body: &[u8], handles: &mut Handles) -> Result<Vec<u8>, u32> {
        super::close(body, handles, false)
    }

    fn read(body: &[u8], b: &dyn Backing, h: &mut Handles) -> Result<Vec<u8>, u32> {
        super::read(body, b, h, false)
    }

    fn query_directory(
        body: &[u8],
        message: &[u8],
        b: &dyn Backing,
        h: &mut Handles,
        now: SystemTime,
    ) -> Result<Vec<u8>, u32> {
        super::query_directory(body, message, b, h, now, false)
    }

    fn query_info(
        body: &[u8],
        b: &dyn Backing,
        h: &Handles,
        created: SystemTime,
        serial: u32,
    ) -> Result<(Vec<u8>, u32), u32> {
        super::query_info(body, b, h, created, serial, false)
    }

    fn create_body(name: &str, desired: u32, disp: u32, opts: u32) -> Vec<u8> {
        let encoded = utf16le(name);
        let mut w = Writer::new();
        w.u16(57);
        w.u8(0); // SecurityFlags
        w.u8(0); // RequestedOplockLevel
        w.u32(2); // ImpersonationLevel
        w.u64(0); // SmbCreateFlags
        w.u64(0); // Reserved
        w.u32(desired);
        w.u32(0); // FileAttributes
        w.u32(7); // ShareAccess
        w.u32(disp);
        w.u32(opts);
        w.u16((HEADER_LEN + 56) as u16); // NameOffset
        w.u16(encoded.len() as u16);
        w.u32(0); // CreateContextsOffset
        w.u32(0); // CreateContextsLength
        w.bytes(&encoded);
        w.into_vec()
    }

    /// The tree id the tests open through. Any non-zero value works; handles
    /// only ever compare it against the tree a TREE_DISCONNECT names.
    const TREE: u32 = 1;

    fn open_path(b: &dyn Backing, h: &mut Handles, name: &str) -> Result<u64, u32> {
        open_path_on(b, h, name, TREE)
    }

    fn open_path_on(
        b: &dyn Backing,
        h: &mut Handles,
        name: &str,
        tree_id: u32,
    ) -> Result<u64, u32> {
        let body = create_body(name, access::READ_ONLY_FILE, disposition::OPEN, 0);
        let msg = message(&body);
        let resp = create(&body, &msg, b, h, tree_id)?;
        Ok(u64::from_le_bytes(resp[72..80].try_into().unwrap()))
    }

    fn backing() -> MemBacking {
        MemBacking::new()
            .with_dir("dir")
            .with_file("dir\\a.txt", b"hello world")
            .with_file("dir\\b.log", b"xy")
            .with_file("top.bin", &[0u8; 5000])
    }

    #[test]
    fn create_opens_a_file_and_reports_its_size() {
        let b = backing();
        let mut h = Handles::default();
        let body = create_body("top.bin", access::READ_ONLY_FILE, disposition::OPEN, 0);
        let resp = create(&body, &message(&body), &b, &mut h, TREE).unwrap();

        assert_eq!(u16::from_le_bytes(resp[0..2].try_into().unwrap()), 89);
        assert_eq!(resp[2], 0, "no oplock is granted");
        assert_eq!(
            u32::from_le_bytes(resp[4..8].try_into().unwrap()),
            FILE_OPENED
        );
        assert_eq!(u64::from_le_bytes(resp[48..56].try_into().unwrap()), 5000);
        assert_eq!(
            u64::from_le_bytes(resp[40..48].try_into().unwrap()),
            info::allocation_size(5000)
        );
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn create_refuses_every_write_intent() {
        let b = backing();
        let mut h = Handles::default();

        // Any write bit in the access mask, in either its specific or its
        // generic spelling — mapping a generic right onto the specific ones it
        // stands for is the server's job, so both have to be refused here.
        for bit in [
            access::FILE_WRITE_DATA,
            access::FILE_APPEND_DATA,
            access::DELETE,
            access::FILE_WRITE_ATTRIBUTES,
            access::GENERIC_WRITE,
            access::GENERIC_ALL,
        ] {
            let body = create_body(
                "top.bin",
                access::FILE_READ_DATA | bit,
                disposition::OPEN,
                0,
            );
            assert_eq!(
                create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
                status::ACCESS_DENIED,
                "access bit {bit:#x} must be refused"
            );
        }

        // Any disposition that would create or truncate.
        for disp in [
            disposition::SUPERSEDE,
            disposition::CREATE,
            disposition::OVERWRITE,
            disposition::OVERWRITE_IF,
        ] {
            let body = create_body("top.bin", access::READ_ONLY_FILE, disp, 0);
            assert_eq!(
                create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
                status::MEDIA_WRITE_PROTECTED,
                "disposition {disp} must be refused"
            );
        }

        // Delete-on-close.
        let body = create_body(
            "top.bin",
            access::READ_ONLY_FILE,
            disposition::OPEN,
            options::DELETE_ON_CLOSE,
        );
        assert_eq!(
            create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
            status::MEDIA_WRITE_PROTECTED
        );

        assert_eq!(h.len(), 0, "no handle may leak from a refused create");
    }

    #[test]
    fn create_refuses_execute_on_a_file_but_allows_traverse_on_a_directory() {
        let b = backing();
        let mut h = Handles::default();

        // Image activation on Windows asks for FILE_EXECUTE, in either its
        // specific or its generic spelling. Nothing on this share may be
        // launched out of it.
        for name in ["top.bin", "dir\\a.txt"] {
            for bit in [access::FILE_EXECUTE, access::GENERIC_EXECUTE] {
                let body = create_body(name, access::READ_ONLY_FILE | bit, disposition::OPEN, 0);
                assert_eq!(
                    create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
                    status::ACCESS_DENIED,
                    "{name} must not open for execute ({bit:#x})"
                );
            }
        }
        assert_eq!(h.len(), 0, "no handle may leak from a refused create");

        // The same bit on a directory is FILE_TRAVERSE, which a client needs to
        // descend into it.
        let body = create_body(
            "dir",
            access::READ_ONLY_DIR,
            disposition::OPEN,
            options::DIRECTORY_FILE,
        );
        assert!(create(&body, &message(&body), &b, &mut h, TREE).is_ok());
    }

    #[test]
    fn peek_create_recovers_the_name_and_access_for_the_log() {
        let body = create_body(r"Users\andrew\Documents", 0x0012_00A9, disposition::OPEN, 0);
        let (name, access) = peek_create(&body, &message(&body)).unwrap();
        assert_eq!(name, r"Users\andrew\Documents");
        assert_eq!(access, 0x0012_00A9);

        // A body too short to parse must not panic — it only feeds a log line.
        assert!(peek_create(&body[..8], &message(&body)).is_none());
    }

    #[test]
    fn create_accepts_generic_read() {
        // How cifs.ko opens every file. FILE_GENERIC_READ is exactly what the
        // share grants, so it must not be caught by the write or execute masks.
        const GENERIC_READ: u32 = 0x8000_0000;
        let b = backing();
        let mut h = Handles::default();
        let body = create_body("top.bin", GENERIC_READ, disposition::OPEN, 0);
        assert!(create(&body, &message(&body), &b, &mut h, TREE).is_ok());
    }

    #[test]
    fn query_info_grants_traverse_only_to_directories() {
        let b = backing();
        let mut h = Handles::default();

        for (name, want) in [
            ("dir\\a.txt", access::READ_ONLY_FILE),
            ("dir", access::READ_ONLY_DIR),
        ] {
            let id = open_path(&b, &mut h, name).unwrap();
            let body = query_info_body(info_type::FILE, file_class::ACCESS, id, 4096);
            let resp = query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap().0;
            assert_eq!(
                u32::from_le_bytes(resp[8..12].try_into().unwrap()),
                want,
                "{name} granted access"
            );

            // FileAllInformation carries the same mask, at offset 76 of the
            // structure (Basic 40 + Standard 24 + Internal 8 + EA 4).
            let body = query_info_body(info_type::FILE, file_class::ALL, id, 4096);
            let resp = query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap().0;
            assert_eq!(
                u32::from_le_bytes(resp[8 + 76..8 + 80].try_into().unwrap()),
                want,
                "{name} granted access in FileAllInformation"
            );
        }
    }

    #[test]
    fn create_refuses_a_path_that_escapes_the_share() {
        let b = backing();
        let mut h = Handles::default();
        let body = create_body(
            r"..\..\etc\shadow",
            access::READ_ONLY_FILE,
            disposition::OPEN,
            0,
        );
        assert_eq!(
            create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
            status::OBJECT_PATH_SYNTAX_BAD
        );
    }

    #[test]
    fn create_honours_the_directory_expectation() {
        let b = backing();
        let mut h = Handles::default();

        let body = create_body(
            "top.bin",
            access::READ_ONLY_FILE,
            disposition::OPEN,
            options::DIRECTORY_FILE,
        );
        assert_eq!(
            create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
            status::NOT_A_DIRECTORY
        );

        let body = create_body(
            "dir",
            access::READ_ONLY_FILE,
            disposition::OPEN,
            options::NON_DIRECTORY_FILE,
        );
        assert_eq!(
            create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
            status::FILE_IS_A_DIRECTORY
        );
    }

    #[test]
    fn create_reports_a_missing_file() {
        let b = backing();
        let mut h = Handles::default();
        let body = create_body("nope.txt", access::READ_ONLY_FILE, disposition::OPEN, 0);
        assert_eq!(
            create(&body, &message(&body), &b, &mut h, TREE).unwrap_err(),
            status::OBJECT_NAME_NOT_FOUND
        );
    }

    fn read_body(file_id: u64, offset: u64, length: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(49);
        w.u8(0); // Padding
        w.u8(0); // Flags
        w.u32(length);
        w.u64(offset);
        write_file_id(&mut w, file_id);
        w.u32(0); // MinimumCount
        w.u32(0); // Channel
        w.u32(0); // RemainingBytes
        w.u16(0); // ReadChannelInfoOffset
        w.u16(0); // ReadChannelInfoLength
        w.into_vec()
    }

    #[test]
    fn read_returns_content_at_an_offset() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        let body = read_body(id, 0, 5);
        let resp = read(&body, &b, &mut h).unwrap();
        assert_eq!(u16::from_le_bytes(resp[0..2].try_into().unwrap()), 17);
        assert_eq!(resp[2] as usize, HEADER_LEN + 16, "DataOffset");
        let len = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;
        assert_eq!(len, 5);
        assert_eq!(&resp[16..16 + len], b"hello");

        let body = read_body(id, 6, 100);
        let resp = read(&body, &b, &mut h).unwrap();
        let len = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;
        assert_eq!(&resp[16..16 + len], b"world");
    }

    #[test]
    fn read_at_end_of_file_reports_end_of_file() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();
        let body = read_body(id, 11, 10);
        assert_eq!(read(&body, &b, &mut h).unwrap_err(), status::END_OF_FILE);
    }

    #[test]
    fn read_on_a_directory_or_closed_handle_is_refused() {
        let b = backing();
        let mut h = Handles::default();
        let dir_id = open_path(&b, &mut h, "dir").unwrap();
        let body = read_body(dir_id, 0, 10);
        assert_eq!(
            read(&body, &b, &mut h).unwrap_err(),
            status::INVALID_DEVICE_REQUEST
        );

        let body = read_body(9999, 0, 10);
        assert_eq!(read(&body, &b, &mut h).unwrap_err(), status::FILE_CLOSED);
    }

    fn close_body(file_id: u64, flags: u16) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(24);
        w.u16(flags);
        w.u32(0);
        write_file_id(&mut w, file_id);
        w.into_vec()
    }

    #[test]
    fn close_releases_the_handle_and_can_report_attributes() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();
        assert_eq!(h.len(), 1);

        let resp = close(&close_body(id, 0x0001), &mut h).unwrap();
        assert_eq!(u16::from_le_bytes(resp[0..2].try_into().unwrap()), 60);
        assert_eq!(resp.len(), 60);
        assert_eq!(u64::from_le_bytes(resp[48..56].try_into().unwrap()), 11);
        assert_eq!(h.len(), 0);

        assert_eq!(
            close(&close_body(id, 0), &mut h).unwrap_err(),
            status::FILE_CLOSED,
            "double close must be refused"
        );
    }

    #[test]
    fn close_without_postquery_zeroes_the_attribute_block() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();
        let resp = close(&close_body(id, 0), &mut h).unwrap();
        assert_eq!(resp.len(), 60);
        assert!(resp[8..60].iter().all(|b| *b == 0));
    }

    fn query_dir_body(
        file_id: u64,
        class: u8,
        flags: u8,
        pattern: &str,
        output_len: u32,
    ) -> Vec<u8> {
        let encoded = utf16le(pattern);
        let mut w = Writer::new();
        w.u16(33);
        w.u8(class);
        w.u8(flags);
        w.u32(0); // FileIndex
        write_file_id(&mut w, file_id);
        w.u16((HEADER_LEN + 32) as u16); // FileNameOffset
        w.u16(encoded.len() as u16);
        w.u32(output_len);
        w.bytes(&encoded);
        w.into_vec()
    }

    fn listed_names(resp: &[u8]) -> Vec<String> {
        let buf_len = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;
        let buf = &resp[8..8 + buf_len];
        let mut names = Vec::new();
        let mut offset = 0usize;
        loop {
            let next = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap()) as usize;
            let name_len =
                u32::from_le_bytes(buf[offset + 60..offset + 64].try_into().unwrap()) as usize;
            let start = offset + 104;
            let units: Vec<u16> = buf[start..start + name_len]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            names.push(String::from_utf16_lossy(&units));
            if next == 0 {
                break;
            }
            offset += next;
        }
        names
    }

    #[test]
    fn query_directory_lists_entries_with_dot_and_dotdot() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir").unwrap();

        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*", 65536);
        let resp = query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap();
        assert_eq!(u16::from_le_bytes(resp[0..2].try_into().unwrap()), 9);
        assert_eq!(
            u16::from_le_bytes(resp[2..4].try_into().unwrap()) as usize,
            HEADER_LEN + 8
        );
        assert_eq!(listed_names(&resp), vec![".", "..", "a.txt", "b.log"]);

        // A second call must report exhaustion, not repeat the listing.
        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*", 65536);
        assert_eq!(
            query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap_err(),
            status::NO_MORE_FILES
        );
    }

    #[test]
    fn query_directory_resumes_where_it_stopped() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir").unwrap();

        let mut seen = Vec::new();
        loop {
            let body = query_dir_body(
                id,
                dir_class::ID_BOTH_DIRECTORY,
                query_dir_flags::RETURN_SINGLE_ENTRY,
                "*",
                65536,
            );
            match query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH) {
                Ok(resp) => seen.extend(listed_names(&resp)),
                Err(status::NO_MORE_FILES) => break,
                Err(e) => panic!("unexpected status {e:#x}"),
            }
            assert!(seen.len() <= 8, "enumeration must terminate");
        }
        assert_eq!(seen, vec![".", "..", "a.txt", "b.log"]);
    }

    #[test]
    fn restart_scans_rewinds_the_cursor() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir").unwrap();

        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*", 65536);
        let first = query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap();

        let body = query_dir_body(
            id,
            dir_class::ID_BOTH_DIRECTORY,
            query_dir_flags::RESTART_SCANS,
            "*",
            65536,
        );
        let again = query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap();
        assert_eq!(listed_names(&first), listed_names(&again));
    }

    #[test]
    fn query_directory_applies_a_search_pattern() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir").unwrap();
        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*.txt", 65536);
        let resp = query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap();
        assert_eq!(listed_names(&resp), vec!["a.txt"]);
    }

    /// The cursor indexes the unfiltered listing, so it has to skip the entries
    /// the pattern rejected as well as the ones it returned. `dir` enumerates as
    /// `[., .., a.txt, b.log]`, and `*.log` matches only the last of them:
    /// advancing by the match count would leave the cursor at 1 and hand back
    /// `b.log` on every call for ever.
    #[test]
    fn a_filtered_enumeration_terminates_instead_of_repeating() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir").unwrap();

        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*.log", 65536);
        let resp = query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap();
        assert_eq!(listed_names(&resp), vec!["b.log"]);

        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*.log", 65536);
        assert_eq!(
            query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap_err(),
            status::NO_MORE_FILES,
            "the match was already returned; a second call must report exhaustion"
        );
    }

    /// One entry at a time, with a pattern that skips entries in between: every
    /// match must come back exactly once.
    #[test]
    fn a_filtered_single_entry_enumeration_visits_each_match_once() {
        let b = MemBacking::new()
            .with_dir("d")
            .with_file("d\\keep1.log", b"1")
            .with_file("d\\skip.txt", b"2")
            .with_file("d\\keep2.log", b"3");
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "d").unwrap();

        let mut seen = Vec::new();
        loop {
            let body = query_dir_body(
                id,
                dir_class::ID_BOTH_DIRECTORY,
                query_dir_flags::RETURN_SINGLE_ENTRY,
                "*.log",
                65536,
            );
            match query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH) {
                Ok(resp) => seen.extend(listed_names(&resp)),
                Err(status::NO_MORE_FILES) => break,
                Err(e) => panic!("unexpected status {e:#x}"),
            }
            assert!(seen.len() <= 4, "enumeration must terminate");
        }
        assert_eq!(seen, vec!["keep1.log", "keep2.log"]);
    }

    #[test]
    fn tree_disconnect_releases_only_that_trees_handles() {
        let b = backing();
        let mut h = Handles::default();
        let kept = open_path_on(&b, &mut h, "dir\\a.txt", 1).unwrap();
        open_path_on(&b, &mut h, "dir\\b.log", 2).unwrap();
        open_path_on(&b, &mut h, "top.bin", 2).unwrap();
        assert_eq!(h.len(), 3);

        h.close_tree(2);
        assert_eq!(h.len(), 1, "only tree 2's handles go");
        assert!(
            close(&close_body(kept, 0), &mut h).is_ok(),
            "tree 1 survives"
        );

        // The compound placeholder pointed at a handle tree 2 owned; it must not
        // resolve onto anything now.
        let body = read_body(RELATED_FILE_ID, 0, 1);
        assert_eq!(
            super::read(&body, &b, &mut h, true).unwrap_err(),
            status::FILE_CLOSED
        );
    }

    #[test]
    fn close_all_releases_every_handle() {
        let b = backing();
        let mut h = Handles::default();
        open_path_on(&b, &mut h, "dir\\a.txt", 1).unwrap();
        open_path_on(&b, &mut h, "top.bin", 2).unwrap();
        h.close_all();
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn query_directory_on_a_file_is_refused() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "top.bin").unwrap();
        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*", 65536);
        assert_eq!(
            query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap_err(),
            status::NOT_A_DIRECTORY
        );
    }

    #[test]
    fn glob_matching_handles_the_usual_patterns() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("", "anything"));
        assert!(pattern_matches("*.*", "a.txt"));
        assert!(pattern_matches("*.txt", "a.txt"));
        assert!(!pattern_matches("*.txt", "a.log"));
        assert!(pattern_matches("a?c", "abc"));
        assert!(!pattern_matches("a?c", "abbc"));
        assert!(
            pattern_matches("A.TXT", "a.txt"),
            "SMB matching is case-insensitive"
        );
        assert!(pattern_matches("*a*b*", "xxayybzz"));
        assert!(!pattern_matches("*a*b*", "xxbyyazz"));
        assert!(pattern_matches("exact", "exact"));
        assert!(!pattern_matches("exact", "exactly"));
    }

    /// Windows never sends `*.txt`. Its runtime rewrites a Win32 mask into the
    /// DOS wildcards before it reaches the wire, so `dir *.txt` arrives as
    /// `<.txt`. Treating those three characters as literals — which is what not
    /// implementing them amounts to, since no filename may contain one — makes
    /// every wildcard listing from cmd.exe come back "File Not Found".
    #[test]
    fn dos_wildcards_match_what_windows_actually_sends() {
        // `dir *.txt` → `<.txt`. DOS_STAR spans anything but the final dot,
        // which is what keeps it from matching a doubled extension.
        assert!(pattern_matches("<.txt", "a.txt"));
        assert!(pattern_matches("<.txt", "notes.txt"));
        assert!(!pattern_matches("<.txt", "a.log"));
        assert!(!pattern_matches("<.txt", "a.txt.bak"));

        // `dir *.*` → `<"*`, which lists everything, extension or not.
        for name in ["a.txt", "plain", "a.b.c"] {
            assert!(pattern_matches("<\"*", name), "{name} must match <\"*");
        }

        // `dir x?.log` → `x>.log`. DOS_QM matches one character, or nothing at
        // all where the name ends or a dot begins.
        assert!(pattern_matches("x>.log", "x1.log"));
        assert!(
            pattern_matches("x>.log", "x.log"),
            "DOS_QM may match nothing"
        );
        assert!(!pattern_matches("x>.log", "x12.log"));

        // DOS_DOT matches a literal dot, or nothing at the end of a name — how
        // `a.` finds the extensionless `a`.
        assert!(pattern_matches("a\"", "a."));
        assert!(pattern_matches("a\"", "a"));
        assert!(!pattern_matches("a\"", "a.txt"));

        // Case-insensitive, like every other form.
        assert!(pattern_matches("<.TXT", "a.txt"));
    }

    /// The matcher backtracks, so a pattern with many `*`s explores every way of
    /// dividing the name between them — `**********b` against sixty-four `a`s is
    /// 64^10 attempts, and the pattern comes from the client. Both forms have to
    /// concede rather than run, and this test failing looks like a hang.
    #[test]
    fn a_pattern_built_to_backtrack_gives_up_rather_than_running_forever() {
        let name = "a".repeat(64);
        assert!(!pattern_matches("**********b", &name));
        assert!(!pattern_matches("<<<<<<<<<<b", &name));
        assert!(!pattern_matches("*a*a*a*a*a*a*a*a*a*b", &name));
    }

    /// Depth follows the pattern length, and the length field on the wire allows
    /// far more frames than the stack holds — which aborts the process rather
    /// than failing the request, so it is refused before it is walked.
    #[test]
    fn a_pattern_longer_than_any_name_is_refused() {
        assert!(!pattern_matches(&"*".repeat(MAX_PATTERN + 1), "a"));
        assert!(!pattern_matches(&">".repeat(MAX_PATTERN + 1), ""));
        // A pattern right at the limit is still matched as before.
        assert!(pattern_matches(&"*".repeat(MAX_PATTERN), "anything"));
    }

    /// The budget is generous enough that nothing a client sends notices it: a
    /// full-length name against a two-wildcard pattern is the realistic worst
    /// case, and it must still answer truthfully rather than concede.
    #[test]
    fn the_budget_does_not_disturb_a_realistic_worst_case() {
        let name = format!("{}.txt", "a".repeat(250));
        assert!(pattern_matches("<.txt", &name));
        assert!(pattern_matches("<\"*", &name));
        assert!(!pattern_matches("<.log", &name));
        // Two stars either side of a literal that is only present at the end.
        assert!(pattern_matches(&format!("*{}*", "a".repeat(200)), &name));
    }

    /// A first scan that matches nothing and an enumeration that has run out are
    /// different answers: Windows maps NO_SUCH_FILE to ERROR_FILE_NOT_FOUND,
    /// which is what FindFirstFile callers test for.
    #[test]
    fn an_unmatched_first_scan_is_no_such_file_not_no_more_files() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir").unwrap();

        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*.nope", 65536);
        assert_eq!(
            query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap_err(),
            status::NO_SUCH_FILE,
            "nothing ever matched"
        );

        // Once a scan has returned entries, exhaustion is the other status.
        let body = query_dir_body(id, dir_class::ID_BOTH_DIRECTORY, 0, "*", 65536);
        assert!(query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).is_ok());
        assert_eq!(
            query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap_err(),
            status::NO_MORE_FILES
        );

        // And a restart puts it back to a first scan.
        let body = query_dir_body(
            id,
            dir_class::ID_BOTH_DIRECTORY,
            query_dir_flags::RESTART_SCANS,
            "*.nope",
            65536,
        );
        assert_eq!(
            query_directory(&body, &message(&body), &b, &mut h, UNIX_EPOCH).unwrap_err(),
            status::NO_SUCH_FILE
        );
    }

    /// A read that asked for nothing succeeds empty; only a read that asked for
    /// data and got none is end-of-file.
    #[test]
    fn a_zero_length_read_succeeds_rather_than_reporting_end_of_file() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        let resp = read(&read_body(id, 0, 0), &b, &mut h).unwrap();
        assert_eq!(u32::from_le_bytes(resp[4..8].try_into().unwrap()), 0);

        // Past the end, having asked for data, is still END_OF_FILE.
        assert_eq!(
            read(&read_body(id, 11, 10), &b, &mut h).unwrap_err(),
            status::END_OF_FILE
        );
    }

    /// Windows sends MxAc on essentially every CREATE. Without an answer it
    /// assumes the maximum and offers rename and delete on a read-only share.
    #[test]
    fn a_maximal_access_request_is_answered_with_the_read_only_mask() {
        let b = backing();
        let mut h = Handles::default();

        // A CREATE carrying an MxAc context, appended after the name.
        let name = utf16le("dir\\a.txt");
        let mut ctx = Writer::new();
        ctx.u32(0); // Next
        ctx.u16(16); // NameOffset
        ctx.u16(4); // NameLength
        ctx.u16(0); // Reserved
        ctx.u16(24); // DataOffset
        ctx.u32(0); // DataLength — an MxAc request carries none
        ctx.bytes(MAX_ACCESS_TAG);
        ctx.zeros(4);
        let ctx = ctx.into_vec();

        let mut w = Writer::new();
        w.u16(57);
        w.u8(0);
        w.u8(0);
        w.u32(2);
        w.u64(0);
        w.u64(0);
        w.u32(access::READ_ONLY_FILE);
        w.u32(0);
        w.u32(7);
        w.u32(disposition::OPEN);
        w.u32(0);
        w.u16((HEADER_LEN + 56) as u16); // NameOffset
        w.u16(name.len() as u16);
        w.u32((HEADER_LEN + 56 + name.len()) as u32); // CreateContextsOffset
        w.u32(ctx.len() as u32);
        w.bytes(&name);
        w.bytes(&ctx);
        let body = w.into_vec();

        let resp = create(&body, &message(&body), &b, &mut h, TREE).unwrap();
        let off = u32::from_le_bytes(resp[80..84].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(resp[84..88].try_into().unwrap()) as usize;
        assert_eq!(off, HEADER_LEN + 88, "context follows the fixed part");
        assert_ne!(len, 0, "MxAc must be answered");

        let returned = &resp[88..88 + len];
        assert_eq!(&returned[16..20], MAX_ACCESS_TAG, "context is MxAc");
        assert_eq!(
            u32::from_le_bytes(returned[24..28].try_into().unwrap()),
            status::SUCCESS,
            "QueryStatus"
        );
        let maximal = u32::from_le_bytes(returned[28..32].try_into().unwrap());
        assert_eq!(maximal, access::READ_ONLY_FILE);
        assert_eq!(maximal & access::WRITE_BITS, 0, "never a write bit");

        // A CREATE without the context still gets none back.
        let plain = create_body("dir\\a.txt", access::READ_ONLY_FILE, disposition::OPEN, 0);
        let resp = create(&plain, &message(&plain), &b, &mut h, TREE).unwrap();
        assert_eq!(u32::from_le_bytes(resp[84..88].try_into().unwrap()), 0);
    }

    fn query_info_body(ty: u8, class: u8, file_id: u64, output_len: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(41);
        w.u8(ty);
        w.u8(class);
        w.u32(output_len);
        w.u16(0); // InputBufferOffset
        w.u16(0); // Reserved
        w.u32(0); // InputBufferLength
        w.u32(0); // AdditionalInformation
        w.u32(0); // Flags
        write_file_id(&mut w, file_id);
        w.into_vec()
    }

    #[test]
    fn query_info_answers_the_common_file_classes() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        for (class, want_len) in [
            (file_class::BASIC, 40),
            (file_class::STANDARD, 24),
            (file_class::INTERNAL, 8),
            (file_class::NETWORK_OPEN, 56),
            (file_class::ATTRIBUTE_TAG, 8),
        ] {
            let body = query_info_body(info_type::FILE, class, id, 4096);
            let resp = query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap().0;
            let len = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;
            assert_eq!(len, want_len, "class {class}");
            assert_eq!(resp.len(), 8 + len);
        }
    }

    #[test]
    fn query_info_answers_the_filesystem_classes() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir").unwrap();
        for class in [
            fs_class::VOLUME,
            fs_class::SIZE,
            fs_class::FULL_SIZE,
            fs_class::DEVICE,
            fs_class::ATTRIBUTE,
            fs_class::SECTOR_SIZE,
        ] {
            let body = query_info_body(info_type::FILESYSTEM, class, id, 4096);
            assert!(
                query_info(&body, &b, &h, UNIX_EPOCH, 1).is_ok(),
                "fs class {class} must be answered"
            );
        }
    }

    #[test]
    fn query_info_reports_a_buffer_that_is_too_small() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();
        let body = query_info_body(info_type::FILE, file_class::BASIC, id, 8);
        assert_eq!(
            query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap_err(),
            status::INFO_LENGTH_MISMATCH
        );
    }

    /// The Windows CRT queries FileFsVolumeInformation with a 24-byte buffer
    /// on every fstat(), which cannot hold any volume label. Hard-failing that
    /// query surfaced in 32-bit programs as EACCES — VLC reported "read error:
    /// Permission denied" for a file whose READs had all succeeded — because
    /// INFO_LENGTH_MISMATCH maps to ERROR_BAD_LENGTH, which the CRT lumps into
    /// EACCES. NT's rule for classes ending in a string is to return the part
    /// that fits with STATUS_BUFFER_OVERFLOW, a warning that carries data.
    #[test]
    fn a_small_buffer_truncates_string_classes_with_buffer_overflow() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        let body = query_info_body(info_type::FILESYSTEM, fs_class::VOLUME, id, 4096);
        let (full, st) = query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap();
        assert_eq!(st, status::SUCCESS);
        let full_len = u32::from_le_bytes(full[4..8].try_into().unwrap()) as usize;
        assert!(full_len > 24, "the label must overflow the CRT's buffer");

        let body = query_info_body(info_type::FILESYSTEM, fs_class::VOLUME, id, 24);
        let (resp, st) = query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap();
        assert_eq!(st, status::BUFFER_OVERFLOW);
        let len = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;
        assert_eq!(len, 24, "exactly the buffer, not a byte more");
        assert_eq!(
            resp[8..8 + 24],
            full[8..8 + 24],
            "the truncated answer is a prefix of the full one, so \
             VolumeLabelLength still reports the label's real size"
        );

        // A buffer below even the fixed part has no coherent partial answer.
        let body = query_info_body(info_type::FILESYSTEM, fs_class::VOLUME, id, 10);
        assert_eq!(
            query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap_err(),
            status::INFO_LENGTH_MISMATCH
        );

        // The same rule covers the FILE classes that end in the file's name.
        let body = query_info_body(info_type::FILE, file_class::NAME, id, 8);
        let (resp, st) = query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap();
        assert_eq!(st, status::BUFFER_OVERFLOW);
        assert_eq!(u32::from_le_bytes(resp[4..8].try_into().unwrap()), 8);
        let name_len = u32::from_le_bytes(resp[8..12].try_into().unwrap()) as usize;
        let full_name = utf16le("\\dir\\a.txt");
        assert_eq!(name_len, full_name.len(), "FileNameLength is the full name");
        assert_eq!(resp[12..16], full_name[..4], "then as much name as fits");
    }

    /// The minimum accepted buffer is the class's C-struct size — what the NT
    /// I/O manager itself enforces — not the wire offset of the trailing
    /// string, and truncation never splits a UTF-16 code unit.
    #[test]
    fn truncation_minimums_match_the_io_managers_and_keep_whole_code_units() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        // FileFsVolumeInformation: the label starts at byte 18, but the
        // kernel refuses anything under sizeof(FILE_FS_VOLUME_INFORMATION),
        // which is 24 — so 18 through 23 are mismatches, not truncations.
        for len in 18u32..24 {
            let body = query_info_body(info_type::FILESYSTEM, fs_class::VOLUME, id, len);
            assert_eq!(
                query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap_err(),
                status::INFO_LENGTH_MISMATCH,
                "volume buffer of {len}"
            );
        }

        // FileNameInformation: minimum is sizeof(FILE_NAME_INFORMATION) = 8.
        let body = query_info_body(info_type::FILE, file_class::NAME, id, 7);
        assert_eq!(
            query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap_err(),
            status::INFO_LENGTH_MISMATCH
        );

        // An 8-byte buffer holds the length field and two whole name units; a
        // 9-byte one must return the same, because the ninth byte would be
        // half a UTF-16 unit.
        for len in [8u32, 9] {
            let body = query_info_body(info_type::FILE, file_class::NAME, id, len);
            let (resp, st) = query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap();
            assert_eq!(st, status::BUFFER_OVERFLOW, "buffer of {len}");
            assert_eq!(
                u32::from_le_bytes(resp[4..8].try_into().unwrap()),
                8,
                "buffer of {len} returns whole code units only"
            );
        }
    }

    #[test]
    fn query_info_refuses_security_and_unknown_classes() {
        let b = backing();
        let mut h = Handles::default();
        let id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        let body = query_info_body(info_type::SECURITY, 0, id, 4096);
        assert_eq!(
            query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap_err(),
            status::NOT_SUPPORTED
        );

        // NOT_SUPPORTED rather than INVALID_INFO_CLASS: the latter is EIO on
        // the Linux client, which presents an unimplemented optional class as a
        // broken filesystem.
        let body = query_info_body(info_type::FILE, 200, id, 4096);
        assert_eq!(
            query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap_err(),
            status::NOT_SUPPORTED
        );

        // Extended attributes are probed by `ls -l` on every entry.
        let body = query_info_body(info_type::FILE, file_class::FULL_EA, id, 4096);
        assert_eq!(
            query_info(&body, &b, &h, UNIX_EPOCH, 1).unwrap_err(),
            status::NO_EAS_ON_FILE
        );
    }

    #[test]
    fn a_related_compound_file_id_resolves_to_the_last_create() {
        let b = backing();
        let mut h = Handles::default();
        let real_id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        // The placeholder must reach the same handle.
        let body = read_body(RELATED_FILE_ID, 0, 5);
        let resp = super::read(&body, &b, &mut h, true).unwrap();
        let len = u32::from_le_bytes(resp[4..8].try_into().unwrap()) as usize;
        assert_eq!(&resp[16..16 + len], b"hello");

        // And once that handle is closed, it resolves to nothing.
        close(&close_body(real_id, 0), &mut h).unwrap();
        let body = read_body(RELATED_FILE_ID, 0, 5);
        assert_eq!(
            super::read(&body, &b, &mut h, true).unwrap_err(),
            status::FILE_CLOSED
        );
    }

    /// The placeholder is only a placeholder inside a related chain. An
    /// unrelated request carrying it names nothing — resolving it onto the last
    /// CREATE would let a stray or replayed request reach a handle it was never
    /// given, and a CLOSE carrying it would shut a file the client still holds.
    #[test]
    fn the_placeholder_means_nothing_outside_a_related_chain() {
        let b = backing();
        let mut h = Handles::default();
        let real_id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        let body = read_body(RELATED_FILE_ID, 0, 5);
        assert_eq!(read(&body, &b, &mut h).unwrap_err(), status::FILE_CLOSED);

        let body = close_body(RELATED_FILE_ID, 0);
        assert_eq!(close(&body, &mut h).unwrap_err(), status::FILE_CLOSED);
        assert_eq!(h.len(), 1, "the live handle must survive");
        assert!(close(&close_body(real_id, 0), &mut h).is_ok());
    }

    /// `clear_chain` is what the dispatcher calls before every unrelated
    /// request, and it is the whole reason a placeholder cannot outlive its
    /// chain.
    #[test]
    fn clearing_the_chain_unbinds_the_placeholder() {
        let b = backing();
        let mut h = Handles::default();
        let real_id = open_path(&b, &mut h, "dir\\a.txt").unwrap();

        let body = read_body(RELATED_FILE_ID, 0, 5);
        assert!(super::read(&body, &b, &mut h, true).is_ok());

        h.clear_chain();
        assert_eq!(
            super::read(&body, &b, &mut h, true).unwrap_err(),
            status::FILE_CLOSED,
            "a new chain must not inherit the previous one's handle"
        );
        // The handle itself is untouched — only the placeholder binding went.
        assert!(read(&read_body(real_id, 0, 5), &b, &mut h).is_ok());
    }

    #[test]
    fn handles_are_distinct_across_opens_of_one_path() {
        let b = backing();
        let mut h = Handles::default();
        let a = open_path(&b, &mut h, "dir\\a.txt").unwrap();
        let c = open_path(&b, &mut h, "dir\\a.txt").unwrap();
        assert_ne!(a, c, "each open gets its own handle");
        assert_eq!(h.len(), 2);
        close(&close_body(a, 0), &mut h).unwrap();
        assert_eq!(h.len(), 1, "closing one must not close the other");
    }
}
