// Share enumeration, so the share can be *browsed* and not only addressed.
//
// Without this, a client that knows the full path works fine — `\\host\anything`,
// `smb://host/share` — but a client asked to list what a server offers gets
// nothing. In Explorer that is typing `\\host\` and getting an error after a
// long wait; in Finder it is connecting to `smb://host` and being shown no
// share to pick, leaving the user to navigate to the mount point by hand.
//
// Explorer is answered by this module. Finder is answered only when the share
// is served on port 445, and nothing here can widen that: macOS makes the
// srvsvc call on a *second* connection, to port 445 and then 139, dropping the
// port its URL was reached on. On any other port the client tree-connects to
// IPC$, fails to reach those two ports, and disconnects without ever opening
// the pipe — a trace that looks like a server giving up half way through and
// is not.
//
// Both go through the same mechanism: the client connects to the IPC$ tree,
// opens the well-known `srvsvc` named pipe, and makes a DCE/RPC call to
// NetrShareEnum.
//
// Scope, deliberately narrow: one interface (SRVSVC), one operation
// (NetrShareEnum, opnum 15), one info level (1). Everything else — every other
// opnum, every other interface — gets a DCE/RPC fault, which is a well-formed
// "no" that clients handle. This is not an RPC stack; it is the smallest thing
// that answers "what shares do you have?" truthfully.
//
// The read-only guarantee is preserved. `WRITE` remains
// MEDIA_WRITE_PROTECTED everywhere except a handle that is this pipe on an
// IPC$ tree, where it writes into a bounded in-memory buffer and never touches
// disk backing data. There is still no code path that could modify it.

use super::proto::status;
use super::wire::{Reader, Writer, from_utf16le, utf16le};

/// The file id the srvsvc pipe is opened as.
///
/// A fixed sentinel rather than an entry in `Handles`: that table is built
/// around disk files (paths, readers, directory cursors), none of which a
/// pipe has, and a connection can hold at most one IPC$ tree and therefore at
/// most one of these. Chosen far above anything `Handles` allocates — it counts
/// up from 1 — and clear of the `u64::MAX` compound placeholder.
pub(crate) const PIPE_FILE_ID: u64 = 0xFFFF_FFFF_FFFF_FFFE;

/// The pipe name clients open for share enumeration.
const PIPE_NAME: &str = "srvsvc";

/// Cap on a buffered DCE/RPC request. Real ones are a few hundred bytes; this
/// exists so a client cannot make the server hold memory by writing forever.
const MAX_REQUEST: usize = 64 * 1024;

/// What the server advertises it can send and receive in one fragment. Ours are
/// far smaller, but clients size their own buffers from these.
const MAX_FRAG: u16 = 4280;

mod ptype {
    pub(super) const REQUEST: u8 = 0;
    pub(super) const RESPONSE: u8 = 2;
    pub(super) const FAULT: u8 = 3;
    pub(super) const BIND: u8 = 11;
    pub(super) const BIND_ACK: u8 = 12;
    pub(super) const ALTER_CONTEXT: u8 = 14;
    pub(super) const ALTER_CONTEXT_RESP: u8 = 15;
}

/// PFC_FIRST_FRAG | PFC_LAST_FRAG. Every PDU here is a complete message.
const PFC_FIRST_LAST: u8 = 0x03;

/// NDR transfer syntax, 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0, in the
/// little-endian layout DCE/RPC puts on the wire.
const NDR_SYNTAX: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
const NDR_SYNTAX_VERSION: u32 = 2;

/// NetrShareEnum. The only operation implemented.
const OPNUM_NET_SHARE_ENUM: u16 = 15;

/// STYPE_DISKTREE — an ordinary file share.
const STYPE_DISKTREE: u32 = 0;

/// Win32 error codes returned in the NET_API_STATUS trailer.
const ERROR_SUCCESS: u32 = 0;
const ERROR_INVALID_LEVEL: u32 = 124;

/// DCE/RPC fault code for an opnum the interface does not implement.
const NCA_S_OP_RNG_ERROR: u32 = 0x1C01_0002;

/// State for one open srvsvc pipe.
#[derive(Default)]
pub(crate) struct Pipe {
    /// Response bytes waiting to be collected by a READ. A DCE/RPC exchange is
    /// strictly request-then-response, so at most one reply is ever pending.
    pending: Vec<u8>,
}

/// CREATE on the IPC$ tree.
///
/// Only `srvsvc` opens. Any other pipe name is reported as not found rather
/// than not supported, which is what a server with no such pipe would say.
pub(crate) fn create(body: &[u8], message: &[u8], pipe: &mut Option<Pipe>) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 57 {
        return Err(status::INVALID_PARAMETER);
    }
    // Everything up to the name offset is irrelevant for a pipe: there is no
    // path to resolve, no disposition that means anything, and no attributes.
    r.skip(2 + 4 + 8 + 8)
        .map_err(|_| status::INVALID_PARAMETER)?;
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // DesiredAccess
    r.skip(4 + 4 + 4 + 4)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let name_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let name_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;

    let msg = Reader::new(message);
    let raw = msg
        .slice_at(name_off, name_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let name = from_utf16le(raw).map_err(|_| status::OBJECT_NAME_NOT_FOUND)?;
    if !name.eq_ignore_ascii_case(PIPE_NAME) {
        return Err(status::OBJECT_NAME_NOT_FOUND);
    }
    if pipe.is_some() {
        // One pipe per connection, because both opens would answer to the same
        // fixed file id. Succeeding here instead would silently reset the first
        // binding's state under a client still using it.
        return Err(status::OBJECT_NAME_COLLISION);
    }

    *pipe = Some(Pipe::default());

    let mut w = Writer::with_capacity(89);
    w.u16(89); // StructureSize
    w.u8(0); // OplockLevel
    w.u8(0); // Flags
    w.u32(1); // CreateAction — FILE_OPENED
    // A pipe has no meaningful timestamps or size. Zeros are what a server
    // reports for one, and no client uses them for anything.
    w.u64(0); // CreationTime
    w.u64(0); // LastAccessTime
    w.u64(0); // LastWriteTime
    w.u64(0); // ChangeTime
    w.u64(0); // AllocationSize
    w.u64(0); // EndOfFile
    w.u32(0x0000_0080); // FileAttributes — FILE_ATTRIBUTE_NORMAL
    w.u32(0); // Reserved2
    w.u64(PIPE_FILE_ID); // FileId, persistent
    w.u64(PIPE_FILE_ID); // FileId, volatile
    w.u32(0); // CreateContextsOffset
    w.u32(0); // CreateContextsLength
    Ok(w.into_vec())
}

/// Check that a request naming a file id is naming *this* pipe.
///
/// The pipe lives outside `Handles` and answers to one fixed id, so without
/// this any id at all — a stale one, a disk handle's — would reach it once
/// an IPC$ tree was connected.
fn check_file_id(r: &mut Reader<'_>) -> Result<(), u32> {
    let persistent = r.u64().map_err(|_| status::INVALID_PARAMETER)?;
    let volatile = r.u64().map_err(|_| status::INVALID_PARAMETER)?;
    if persistent != PIPE_FILE_ID || volatile != PIPE_FILE_ID {
        return Err(status::FILE_CLOSED);
    }
    Ok(())
}

/// CLOSE on the pipe.
pub(crate) fn close(body: &[u8], pipe: &mut Option<Pipe>) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 24 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(2 + 4).map_err(|_| status::INVALID_PARAMETER)?; // Flags, Reserved
    check_file_id(&mut r)?;

    if pipe.take().is_none() {
        return Err(status::FILE_CLOSED);
    }
    let mut w = Writer::with_capacity(60);
    w.u16(60); // StructureSize
    w.u16(0); // Flags
    w.u32(0); // Reserved
    // Six 8-byte timestamps/sizes and a 4-byte FileAttributes, all zero, which
    // with the 8 bytes above is the 60 StructureSize declares.
    w.zeros(8 * 6 + 4);
    Ok(w.into_vec())
}

/// WRITE on the pipe: the client handing over a DCE/RPC request.
///
/// This is the one write smbanything accepts anywhere, and it lands in
/// `Pipe::pending` — an in-memory buffer bounded by `MAX_REQUEST`. It cannot
/// reach disk data: the caller only routes here for a handle that is this pipe
/// on an IPC$ tree.
pub(crate) fn write(
    body: &[u8],
    message: &[u8],
    pipe: &mut Option<Pipe>,
    share_name: &str,
) -> Result<Vec<u8>, u32> {
    let pipe = pipe.as_mut().ok_or(status::FILE_CLOSED)?;

    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 49 {
        return Err(status::INVALID_PARAMETER);
    }
    let data_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let length = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    if length > MAX_REQUEST {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(8).map_err(|_| status::INVALID_PARAMETER)?; // Offset
    check_file_id(&mut r)?;

    let msg = Reader::new(message);
    let data = msg
        .slice_at(data_off, length)
        .map_err(|_| status::INVALID_PARAMETER)?;
    pipe.pending = dispatch(data, share_name);

    let mut w = Writer::with_capacity(17);
    w.u16(17); // StructureSize
    w.u16(0); // Reserved
    w.u32(length as u32); // Count — the whole request was consumed
    w.u32(0); // Remaining
    w.u16(0); // WriteChannelInfoOffset
    w.u16(0); // WriteChannelInfoLength
    Ok(w.into_vec())
}

/// READ on the pipe: the client collecting the response its WRITE produced.
pub(crate) fn read(body: &[u8], pipe: &mut Option<Pipe>) -> Result<Vec<u8>, u32> {
    let pipe = pipe.as_mut().ok_or(status::FILE_CLOSED)?;

    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 49 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(1 + 1).map_err(|_| status::INVALID_PARAMETER)?; // Padding, Flags
    let length = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    r.skip(8).map_err(|_| status::INVALID_PARAMETER)?; // Offset
    check_file_id(&mut r)?;

    if length == 0 {
        // A zero-length read can never make progress: it would report success
        // having handed over nothing, and a client draining the queue would
        // spin on it forever.
        return Err(status::INVALID_PARAMETER);
    }
    if pipe.pending.is_empty() {
        // Nothing was asked, so there is nothing to collect. END_OF_FILE is how
        // a read past the end of a pipe's queued data is reported.
        return Err(status::END_OF_FILE);
    }
    let take = length.min(pipe.pending.len());
    let data: Vec<u8> = pipe.pending.drain(..take).collect();

    let mut w = Writer::with_capacity(16 + data.len());
    w.u16(17); // StructureSize
    w.u8((super::HEADER_LEN + 16) as u8); // DataOffset
    w.u8(0); // Reserved
    w.u32(data.len() as u32); // DataLength
    w.u32(pipe.pending.len() as u32); // DataRemaining
    w.u32(0); // Reserved2
    w.bytes(&data);
    Ok(w.into_vec())
}

/// FSCTL_PIPE_TRANSCEIVE — write and read in one round trip.
///
/// What Windows actually uses for RPC over a pipe; the separate WRITE/READ pair
/// above is what other clients do. Both have to work.
pub(crate) fn transceive(
    body: &[u8],
    message: &[u8],
    pipe: &mut Option<Pipe>,
    share_name: &str,
) -> Result<(Vec<u8>, u32), u32> {
    /// FSCTL_PIPE_TRANSCEIVE (MS-SMB2 2.2.31).
    const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;

    let pipe_state = pipe.as_mut().ok_or(status::FILE_CLOSED)?;

    let mut r = Reader::new(body);
    if r.u16().map_err(|_| status::INVALID_PARAMETER)? != 57 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // Reserved
    let ctl_code = r.u32().map_err(|_| status::INVALID_PARAMETER)?;
    if ctl_code != FSCTL_PIPE_TRANSCEIVE {
        // Every other FSCTL stays refused, as it always was.
        return Err(status::NOT_SUPPORTED);
    }
    check_file_id(&mut r)?;
    let input_off = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let input_len = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;
    if input_len > MAX_REQUEST {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // MaxInputResponse
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // OutputOffset
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // OutputCount
    let max_output = r.u32().map_err(|_| status::INVALID_PARAMETER)? as usize;

    let msg = Reader::new(message);
    let input = msg
        .slice_at(input_off, input_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let mut output = dispatch(input, share_name);
    // A transceive starts a fresh exchange, so anything the client never
    // collected from a previous one is gone.
    pipe_state.pending.clear();
    // Honour the client's buffer: the part that does not fit stays queued for a
    // follow-up READ, which is how a pipe reports a partial answer (MS-SMB2
    // 3.3.5.15.5; Samba's smb2_ioctl_named_pipe.c:136-186 does the same). One
    // share fits in every buffer a real client offers, so this only matters if
    // the enumeration ever grows — but the alternative is silently dropping the
    // remainder.
    let truncated = output.len() > max_output;
    if truncated {
        pipe_state.pending = output.split_off(max_output);
    }

    // OutputOffset counts from the start of the SMB2 header, and the output
    // follows the 48-byte IOCTL response body.
    let output_off = (super::HEADER_LEN + 48) as u32;
    let mut w = Writer::with_capacity(48 + output.len());
    w.u16(49); // StructureSize
    w.u16(0); // Reserved
    w.u32(ctl_code);
    w.u64(PIPE_FILE_ID); // FileId, persistent
    w.u64(PIPE_FILE_ID); // FileId, volatile
    w.u32(0); // InputOffset — no input is echoed back, so it points nowhere
    w.u32(0); // InputCount
    w.u32(output_off); // OutputOffset
    w.u32(output.len() as u32); // OutputCount
    w.u32(0); // Flags
    w.u32(0); // Reserved2
    w.bytes(&output);
    // BUFFER_OVERFLOW is a warning carrying a valid partial response, not an
    // error: it tells the client to come back with a READ for the rest.
    let st = if truncated {
        status::BUFFER_OVERFLOW
    } else {
        status::SUCCESS
    };
    Ok((w.into_vec(), st))
}

// ---------------------------------------------------------------------------
// DCE/RPC
// ---------------------------------------------------------------------------

/// Turn one DCE/RPC PDU into its reply.
///
/// Never fails: an unparseable or unsupported request becomes a fault, because
/// a client that gets a well-formed "no" moves on, while one that gets silence
/// or a dropped connection retries and stalls.
fn dispatch(request: &[u8], share_name: &str) -> Vec<u8> {
    let Some(hdr) = PduHeader::parse(request) else {
        return fault(0, 0, NCA_S_OP_RNG_ERROR);
    };
    match hdr.ptype {
        ptype::BIND => bind_ack(request, &hdr, ptype::BIND_ACK),
        ptype::ALTER_CONTEXT => bind_ack(request, &hdr, ptype::ALTER_CONTEXT_RESP),
        ptype::REQUEST => {
            // Request body: alloc_hint (4), context_id (2), opnum (2).
            let Some(stub) = request.get(16..) else {
                return fault(hdr.call_id, 0, NCA_S_OP_RNG_ERROR);
            };
            if stub.len() < 8 {
                return fault(hdr.call_id, 0, NCA_S_OP_RNG_ERROR);
            }
            // Echoed back rather than hardcoded to 0: the response identifies
            // the presentation context the call ran under, and now that a bind
            // can accept a context other than the first, 0 is no longer a safe
            // assumption.
            let context_id = u16::from_le_bytes([stub[4], stub[5]]);
            let opnum = u16::from_le_bytes([stub[6], stub[7]]);
            if opnum != OPNUM_NET_SHARE_ENUM {
                return fault(hdr.call_id, context_id, NCA_S_OP_RNG_ERROR);
            }
            let level = requested_level(&stub[8..]);
            response(hdr.call_id, context_id, &net_share_enum(share_name, level))
        }
        _ => fault(hdr.call_id, 0, NCA_S_OP_RNG_ERROR),
    }
}

struct PduHeader {
    ptype: u8,
    call_id: u32,
}

impl PduHeader {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 || buf[0] != 5 {
            return None;
        }
        // frag_length must describe exactly this buffer, and the PDU must be
        // both the first and the last fragment of its message. The length check
        // alone does not catch a fragment: in DCE/RPC each fragment carries its
        // *own* frag_length (C706 §12.6), so the first fragment of a multi-part
        // request passes it and would be dispatched as if complete, leaving the
        // continuation to be dispatched as a second request. The flags are what
        // actually establish the "one complete PDU" the dispatcher assumes.
        let frag_length = u16::from_le_bytes([buf[8], buf[9]]) as usize;
        if frag_length != buf.len() || buf[3] & PFC_FIRST_LAST != PFC_FIRST_LAST {
            return None;
        }
        Some(Self {
            ptype: buf[2],
            call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }
}

fn write_pdu_header(w: &mut Writer, ptype: u8, frag_len: u16, call_id: u32) {
    w.u8(5); // rpc_vers
    w.u8(0); // rpc_vers_minor
    w.u8(ptype);
    w.u8(PFC_FIRST_LAST);
    // Data representation: little-endian integers, ASCII characters, IEEE
    // floats. The only combination anything on this path uses.
    w.bytes(&[0x10, 0x00, 0x00, 0x00]);
    w.u16(frag_len);
    w.u16(0); // auth_length
    w.u32(call_id);
}

/// The bind-time feature negotiation pseudo-syntax (MS-RPCE 3.3.1.5.3). Its
/// first eight bytes are a fixed prefix; the rest carries the requested
/// features rather than identifying a syntax.
const BIND_TIME_FEATURE_PREFIX: [u8; 8] = [0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45];

/// Result codes for one presentation context in a bind_ack (C706 §12.6.4.4).
mod bind_result {
    pub(super) const ACCEPTANCE: u16 = 0;
    pub(super) const PROVIDER_REJECTION: u16 = 2;
    /// MS-RPCE's extension: the context was a feature request, and this is the
    /// answer to it rather than a syntax being accepted.
    pub(super) const NEGOTIATE_ACK: u16 = 3;
}

/// Reason code accompanying a rejection: the proposed transfer syntaxes are not
/// supported.
const REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED: u16 = 2;

/// What one presentation context in a BIND asked for.
enum Presented {
    /// Offers the NDR32 transfer syntax — the one this server speaks.
    Ndr32,
    /// The bind-time feature negotiation pseudo-syntax.
    FeatureRequest,
    /// Anything else, NDR64 above all.
    Unsupported,
}

/// Read the presentation contexts out of a BIND body.
///
/// Every client presents more than one: Windows rpcrt4 offers NDR32, NDR64 and
/// bind-time feature negotiation, and even smbclient offers two. Each one needs
/// its own result element in the reply, so they have to be counted rather than
/// assumed.
fn presented_contexts(buf: &[u8]) -> Vec<Presented> {
    // Bind body: max_xmit(2) max_recv(2) assoc_group(4) num_contexts(1)
    // reserved(3), then each context: id(2) n_transfer(1) reserved(1)
    // abstract_syntax(20), then n_transfer × 20 bytes of transfer syntax.
    let Some(body) = buf.get(16..) else {
        return Vec::new();
    };
    let Some(&count) = body.get(8) else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(count as usize);
    let mut at = 12usize;
    for _ in 0..count {
        let Some(n_transfer) = body.get(at + 2).copied() else {
            break;
        };
        let syntaxes_at = at + 4 + 20;
        let mut kind = Presented::Unsupported;
        for i in 0..n_transfer as usize {
            let off = syntaxes_at + i * 20;
            let Some(syntax) = body.get(off..off + 16) else {
                break;
            };
            if syntax == NDR_SYNTAX {
                kind = Presented::Ndr32;
                break;
            }
            if syntax[..8] == BIND_TIME_FEATURE_PREFIX {
                kind = Presented::FeatureRequest;
                break;
            }
        }
        out.push(kind);
        at = syntaxes_at + n_transfer as usize * 20;
    }
    out
}

/// BIND_ACK / ALTER_CONTEXT_RESP.
///
/// The reply must carry exactly one result per context the client presented,
/// in the same order (C706 §12.6.4.4; Samba builds `ack_ctx_list` sized
/// `num_contexts` and sets `num_results` from it, `dcesrv_core.c:1180-1322`).
/// Answering a three-context Windows bind with a single result is what a
/// stricter RPC runtime than smbclient's rejects.
///
/// The abstract syntax is still accepted without inspection: this pipe serves
/// exactly one interface, so a client that bound to another will fault on its
/// first call, which is a clearer failure than a bind_nak.
fn bind_ack(request: &[u8], hdr: &PduHeader, ptype: u8) -> Vec<u8> {
    let sec_addr = b"\\PIPE\\srvsvc\0";

    let contexts = presented_contexts(request);
    // A bind whose contexts could not be read at all still gets one acceptance,
    // which is what every client before this change received.
    let contexts = if contexts.is_empty() {
        vec![Presented::Ndr32]
    } else {
        contexts
    };

    let mut body = Writer::new();
    body.u16(MAX_FRAG); // max_xmit_frag
    body.u16(MAX_FRAG); // max_recv_frag
    body.u32(0x0000_1063); // assoc_group_id — any non-zero value
    body.u16(sec_addr.len() as u16);
    body.bytes(sec_addr);
    // The results list is 4-byte aligned from the start of the PDU. The header
    // is 16 bytes, so aligning the body is equivalent.
    body.align_to(4);
    body.u8(contexts.len() as u8); // num_results
    body.zeros(3); // reserved
    // Only the first context offering NDR32 is accepted; a second would bind
    // the same interface twice under a different id, which nothing here tracks.
    let mut accepted = false;
    for context in &contexts {
        match context {
            Presented::Ndr32 if !accepted => {
                accepted = true;
                body.u16(bind_result::ACCEPTANCE);
                body.u16(0); // reason
                body.bytes(&NDR_SYNTAX);
                body.u32(NDR_SYNTAX_VERSION);
            }
            Presented::FeatureRequest => {
                // No optional feature is supported, so the acknowledgement
                // carries an empty syntax — the answer itself is the result
                // code, and clients read no more than that.
                body.u16(bind_result::NEGOTIATE_ACK);
                body.u16(0); // reason — the negotiated feature bits, none here
                body.zeros(16);
                body.u32(0);
            }
            // NDR64, or a repeat of NDR32.
            _ => {
                body.u16(bind_result::PROVIDER_REJECTION);
                body.u16(REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED);
                body.zeros(16); // a rejected result names no syntax
                body.u32(0);
            }
        }
    }

    let body = body.into_vec();
    let mut w = Writer::with_capacity(16 + body.len());
    write_pdu_header(&mut w, ptype, (16 + body.len()) as u16, hdr.call_id);
    w.bytes(&body);
    w.into_vec()
}

fn response(call_id: u32, context_id: u16, stub: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(24 + stub.len());
    write_pdu_header(&mut w, ptype::RESPONSE, (24 + stub.len()) as u16, call_id);
    w.u32(stub.len() as u32); // alloc_hint
    w.u16(context_id);
    w.u8(0); // cancel_count
    w.u8(0); // reserved
    w.bytes(stub);
    w.into_vec()
}

fn fault(call_id: u32, context_id: u16, code: u32) -> Vec<u8> {
    let mut w = Writer::with_capacity(32);
    write_pdu_header(&mut w, ptype::FAULT, 32, call_id);
    w.u32(0); // alloc_hint
    w.u16(context_id);
    w.u8(0); // cancel_count
    w.u8(0); // reserved
    w.u32(code); // status
    w.u32(0); // reserved2
    w.into_vec()
}

// ---------------------------------------------------------------------------
// NetrShareEnum, NDR-encoded
// ---------------------------------------------------------------------------

/// Pull the requested info level out of a NetrShareEnum request.
///
/// The stub starts with a `[unique]` ServerName string, and skipping it
/// correctly means walking a conformant varying string. Rather than parse
/// something no answer depends on, look for the level in the two places it can
/// sit — immediately after a NULL ServerName, or after the string that follows
/// a non-NULL one — and fall back to level 1, which is what every client that
/// enumerates shares actually asks for.
fn requested_level(stub: &[u8]) -> u32 {
    let u32_at = |off: usize| -> Option<u32> {
        let b = stub.get(off..off + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let Some(server_ptr) = u32_at(0) else {
        return 1;
    };
    if server_ptr == 0 {
        // NULL ServerName: the level follows immediately.
        return u32_at(4).unwrap_or(1);
    }
    // Non-NULL: max_count, offset, actual_count, then actual_count UTF-16
    // characters padded to a 4-byte boundary.
    let Some(actual) = u32_at(12) else { return 1 };
    // A declared count is client-controlled and need not describe the bytes
    // actually sent, so every step is checked: on a 32-bit target the padding
    // arithmetic would otherwise overflow, and there is no offset to look at
    // when it does.
    let Some(offset) = (actual as usize)
        .checked_mul(2)
        .and_then(|chars| chars.div_ceil(4).checked_mul(4))
        .and_then(|padded| padded.checked_add(16))
    else {
        return 1;
    };
    u32_at(offset).unwrap_or(1)
}

/// Encode the NetrShareEnum reply listing the one share this server offers.
///
/// Only level 1 (name, type, remark) is produced. A client asking for another
/// level gets a well-formed reply carrying ERROR_INVALID_LEVEL and a NULL
/// container, which is the documented way to say so.
fn net_share_enum(share_name: &str, level: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(level); // SHARE_ENUM_STRUCT.Level
    w.u32(level); // union discriminant

    if level != 1 {
        w.u32(0); // NULL container
        w.u32(0); // TotalEntries
        w.u32(0); // ResumeHandle — NULL
        w.u32(ERROR_INVALID_LEVEL);
        return w.into_vec();
    }

    // Referent ids only have to be non-zero and distinct within the reply.
    w.u32(0x0002_0000); // container pointer
    w.u32(1); // EntriesRead
    w.u32(0x0002_0004); // array pointer
    w.u32(1); // conformant array max_count

    // Entry headers first, then the strings they point at, deferred in the same
    // order — that split is what NDR requires and what a client relies on.
    w.u32(0x0002_0008); // netname pointer
    w.u32(STYPE_DISKTREE);
    w.u32(0x0002_000c); // remark pointer

    ndr_string(&mut w, share_name);
    // A remark is required to be present but may be empty; nothing useful can
    // be said about this share that its name does not already say.
    ndr_string(&mut w, "");

    w.u32(1); // TotalEntries
    // ResumeHandle returned as NULL: every share is in this one reply, so there
    // is nothing for a client to resume from.
    w.u32(0);
    w.u32(ERROR_SUCCESS);
    w.into_vec()
}

/// A conformant, varying, NUL-terminated NDR string.
fn ndr_string(w: &mut Writer, s: &str) {
    let mut units = utf16le(s);
    units.extend_from_slice(&[0, 0]); // NUL terminator, counted below
    let chars = (units.len() / 2) as u32;
    w.u32(chars); // max_count
    w.u32(0); // offset
    w.u32(chars); // actual_count
    w.bytes(&units);
    w.align_to(4);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stamp the real frag_length into a finished PDU. The fixtures only know
    /// their length once the body is built, and `parse` rejects a PDU whose
    /// frag_length does not match the bytes delivered.
    fn seal(mut pdu: Vec<u8>) -> Vec<u8> {
        let len = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&len.to_le_bytes());
        pdu
    }

    fn bind_pdu(call_id: u32) -> Vec<u8> {
        let mut w = Writer::new();
        write_pdu_header(&mut w, ptype::BIND, 0, call_id);
        w.u16(MAX_FRAG);
        w.u16(MAX_FRAG);
        w.u32(0);
        w.u8(1);
        w.zeros(3);
        w.u16(0);
        w.u8(1);
        w.u8(0);
        w.zeros(20); // abstract syntax
        w.bytes(&NDR_SYNTAX);
        w.u32(NDR_SYNTAX_VERSION);
        seal(w.into_vec())
    }

    fn enum_request(call_id: u32, level: u32) -> Vec<u8> {
        let mut w = Writer::new();
        write_pdu_header(&mut w, ptype::REQUEST, 0, call_id);
        w.u32(0); // alloc_hint
        w.u16(0); // context_id
        w.u16(OPNUM_NET_SHARE_ENUM);
        w.u32(0); // NULL ServerName
        w.u32(level);
        seal(w.into_vec())
    }

    #[test]
    fn bind_is_accepted_and_echoes_the_call_id() {
        let reply = dispatch(&bind_pdu(0x1234), "snap");
        assert_eq!(reply[2], ptype::BIND_ACK);
        assert_eq!(&reply[12..16], &0x1234u32.to_le_bytes());
        // frag_length must describe the whole PDU, or the client waits for more.
        assert_eq!(
            u16::from_le_bytes([reply[8], reply[9]]) as usize,
            reply.len()
        );
        // The accepted transfer syntax has to come back, or the bind is useless.
        assert!(
            reply.windows(16).any(|w| w == NDR_SYNTAX),
            "bind_ack must echo the NDR transfer syntax"
        );
    }

    /// Build a BIND presenting several contexts, the way a real client does.
    /// Each entry is that context's list of transfer syntaxes.
    fn bind_pdu_with(call_id: u32, contexts: &[&[[u8; 16]]]) -> Vec<u8> {
        let mut w = Writer::new();
        write_pdu_header(&mut w, ptype::BIND, 0, call_id);
        w.u16(MAX_FRAG);
        w.u16(MAX_FRAG);
        w.u32(0); // assoc_group_id
        w.u8(contexts.len() as u8);
        w.zeros(3); // reserved
        for (i, syntaxes) in contexts.iter().enumerate() {
            w.u16(i as u16); // context id
            w.u8(syntaxes.len() as u8); // n_transfer_syn
            w.u8(0); // reserved
            w.zeros(20); // abstract syntax
            for syntax in syntaxes.iter() {
                w.bytes(syntax);
                w.u32(NDR_SYNTAX_VERSION);
            }
        }
        seal(w.into_vec())
    }

    /// NDR64, which every Windows client offers and this server does not speak.
    const NDR64_SYNTAX: [u8; 16] = [
        0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc,
        0x36,
    ];

    /// The bind-time feature negotiation pseudo-syntax.
    fn feature_syntax() -> [u8; 16] {
        let mut s = [0u8; 16];
        s[..8].copy_from_slice(&BIND_TIME_FEATURE_PREFIX);
        s
    }

    /// Read the results list out of a bind_ack: (num_results, [(result, reason)]).
    fn bind_results(reply: &[u8]) -> (usize, Vec<(u16, u16)>) {
        // Body: max_xmit(2) max_recv(2) assoc_group(4) sec_addr_len(2)
        // sec_addr, padded to 4, then num_results(1) reserved(3), then results.
        let body = &reply[16..];
        let sec_len = u16::from_le_bytes([body[8], body[9]]) as usize;
        let mut at = 10 + sec_len;
        at = at.next_multiple_of(4);
        let count = body[at] as usize;
        at += 4;
        let results = (0..count)
            .map(|i| {
                let off = at + i * 24;
                (
                    u16::from_le_bytes([body[off], body[off + 1]]),
                    u16::from_le_bytes([body[off + 2], body[off + 3]]),
                )
            })
            .collect();
        (count, results)
    }

    /// Windows rpcrt4 presents three contexts — NDR32, NDR64 and bind-time
    /// feature negotiation — and the reply must carry one result per context,
    /// in order. Answering with a single acceptance is what a stricter runtime
    /// than smbclient's rejects.
    #[test]
    fn a_multi_context_bind_gets_one_result_per_context() {
        let bind = bind_pdu_with(0x99, &[&[NDR_SYNTAX], &[NDR64_SYNTAX], &[feature_syntax()]]);
        let reply = dispatch(&bind, "snap");
        assert_eq!(reply[2], ptype::BIND_ACK);
        assert_eq!(
            u16::from_le_bytes([reply[8], reply[9]]) as usize,
            reply.len(),
            "frag_length must describe the whole PDU"
        );

        let (count, results) = bind_results(&reply);
        assert_eq!(count, 3, "one result per presented context");
        assert_eq!(
            results[0],
            (bind_result::ACCEPTANCE, 0),
            "NDR32 is the syntax this server speaks"
        );
        assert_eq!(
            results[1],
            (
                bind_result::PROVIDER_REJECTION,
                REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED
            ),
            "NDR64 must be refused, not silently accepted"
        );
        assert_eq!(
            results[2].0,
            bind_result::NEGOTIATE_ACK,
            "the feature request gets an acknowledgement, not a syntax"
        );
    }

    /// The single-context bind smbclient sends still works unchanged.
    #[test]
    fn a_single_context_bind_is_accepted() {
        let reply = dispatch(&bind_pdu_with(1, &[&[NDR_SYNTAX]]), "snap");
        let (count, results) = bind_results(&reply);
        assert_eq!(count, 1);
        assert_eq!(results[0], (bind_result::ACCEPTANCE, 0));
        assert!(reply.windows(16).any(|w| w == NDR_SYNTAX));
    }

    /// Two contexts both offering NDR32. Only the first can be accepted: a
    /// second acceptance would bind the same interface again under a different
    /// context id, and nothing here tracks more than one binding. The reply
    /// still has to account for the context rather than omit it.
    #[test]
    fn a_repeated_ndr32_context_is_rejected_rather_than_bound_twice() {
        let reply = dispatch(
            &bind_pdu_with(0x55, &[&[NDR_SYNTAX], &[NDR_SYNTAX]]),
            "snap",
        );
        assert_eq!(reply[2], ptype::BIND_ACK);

        let (count, results) = bind_results(&reply);
        assert_eq!(count, 2, "one result per presented context");
        assert_eq!(results[0], (bind_result::ACCEPTANCE, 0));
        assert_eq!(
            results[1],
            (
                bind_result::PROVIDER_REJECTION,
                REASON_TRANSFER_SYNTAXES_NOT_SUPPORTED
            ),
            "the second binding must be refused, not silently accepted"
        );
    }

    /// A client that offers only NDR64 gets a well-formed refusal rather than
    /// an acceptance naming a syntax it never proposed.
    #[test]
    fn a_bind_without_ndr32_is_refused_per_context() {
        let reply = dispatch(&bind_pdu_with(2, &[&[NDR64_SYNTAX]]), "snap");
        let (count, results) = bind_results(&reply);
        assert_eq!(count, 1);
        assert_eq!(results[0].0, bind_result::PROVIDER_REJECTION);
    }

    /// Each DCE/RPC fragment carries its own frag_length, so a length check
    /// alone cannot tell a complete PDU from the first fragment of a larger
    /// one. The PFC first/last flags are what actually establish it.
    #[test]
    fn a_fragment_of_a_larger_pdu_faults() {
        let mut req = enum_request(8, 1);
        // Well-formed and self-consistent, but flagged as only the first
        // fragment — the rest of the request is still to come.
        req[3] = 0x01; // PFC_FIRST_FRAG without PFC_LAST_FRAG
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);

        let mut req = enum_request(9, 1);
        req[3] = 0x02; // PFC_LAST_FRAG without PFC_FIRST_FRAG
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);
    }

    /// The response identifies the presentation context the call ran under.
    #[test]
    fn a_response_echoes_the_requests_context_id() {
        let mut req = enum_request(10, 1);
        req[20..22].copy_from_slice(&7u16.to_le_bytes()); // context_id
        let reply = dispatch(&req, "snap");
        assert_eq!(reply[2], ptype::RESPONSE);
        assert_eq!(
            u16::from_le_bytes([reply[20], reply[21]]),
            7,
            "context_id must be echoed, not hardcoded"
        );
    }

    #[test]
    fn enumeration_lists_the_share_by_name() {
        let reply = dispatch(&enum_request(7, 1), "snap");
        assert_eq!(reply[2], ptype::RESPONSE);
        assert_eq!(
            u16::from_le_bytes([reply[8], reply[9]]) as usize,
            reply.len()
        );

        let stub = &reply[24..];
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 1); // Level
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 1); // EntriesRead
        // The name has to survive as UTF-16, since that is what a client shows.
        let wanted = utf16le("snap");
        assert!(
            stub.windows(wanted.len()).any(|w| w == wanted),
            "share name missing from the reply"
        );
        // Trailing NET_API_STATUS must be success, or the client discards it all.
        let tail = u32::from_le_bytes(stub[stub.len() - 4..].try_into().unwrap());
        assert_eq!(tail, ERROR_SUCCESS);
    }

    /// The share name is whatever the server is serving, not a constant — a
    /// hardcoded "snap" here would list a share that does not exist if the name
    /// ever became configurable.
    #[test]
    fn enumeration_reports_the_configured_share_name() {
        let reply = dispatch(&enum_request(1, 1), "backup-2024");
        let wanted = utf16le("backup-2024");
        assert!(reply.windows(wanted.len()).any(|w| w == wanted));
    }

    /// An unsupported level must still produce a parseable reply carrying the
    /// error, not a fault: a client that asked for level 2 should learn the
    /// level is wrong, not that the call does not exist.
    #[test]
    fn an_unsupported_level_reports_invalid_level() {
        let reply = dispatch(&enum_request(2, 502), "snap");
        assert_eq!(reply[2], ptype::RESPONSE);
        let stub = &reply[24..];
        assert_eq!(u32::from_le_bytes(stub[0..4].try_into().unwrap()), 502);
        assert_eq!(u32::from_le_bytes(stub[8..12].try_into().unwrap()), 0); // NULL container
        let tail = u32::from_le_bytes(stub[stub.len() - 4..].try_into().unwrap());
        assert_eq!(tail, ERROR_INVALID_LEVEL);
    }

    /// Everything outside the one implemented operation gets a fault, which is
    /// a "no" the client can act on rather than a hang.
    #[test]
    fn other_opnums_fault() {
        let mut req = enum_request(3, 1);
        // opnum sits at offset 22, right after alloc_hint and context_id.
        req[22..24].copy_from_slice(&16u16.to_le_bytes()); // NetrShareGetInfo
        let reply = dispatch(&req, "snap");
        assert_eq!(reply[2], ptype::FAULT);
        assert_eq!(
            u32::from_le_bytes(reply[24..28].try_into().unwrap()),
            NCA_S_OP_RNG_ERROR
        );
    }

    /// An IOCTL request carrying `input`, and the message it sits in. Buffer
    /// offsets count the SMB2 header, and the fixed part of the request is 56
    /// bytes, so the input follows at that distance.
    fn transceive_request(input: &[u8], max_output: u32) -> (Vec<u8>, Vec<u8>) {
        const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
        let mut w = Writer::new();
        w.u16(57); // StructureSize
        w.u16(0); // Reserved
        w.u32(FSCTL_PIPE_TRANSCEIVE);
        w.u64(PIPE_FILE_ID); // FileId, persistent
        w.u64(PIPE_FILE_ID); // FileId, volatile
        w.u32((crate::smb::proto::HEADER_LEN + 56) as u32); // InputOffset
        w.u32(input.len() as u32); // InputCount
        w.u32(0); // MaxInputResponse
        w.u32(0); // OutputOffset
        w.u32(0); // OutputCount
        w.u32(max_output); // MaxOutputResponse
        w.u32(0); // Flags
        w.u32(0); // Reserved2
        w.bytes(input);
        let body = w.into_vec();

        let mut message = vec![0u8; crate::smb::proto::HEADER_LEN];
        message.extend_from_slice(&body);
        (body, message)
    }

    /// A READ collecting whatever the pipe still has queued.
    fn read_request(length: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(49); // StructureSize
        w.u8(0); // Padding
        w.u8(0); // Flags
        w.u32(length);
        w.u64(0); // Offset
        w.u64(PIPE_FILE_ID); // FileId, persistent
        w.u64(PIPE_FILE_ID); // FileId, volatile
        w.u32(0); // MinimumCount
        w.u32(0); // Channel
        w.u32(0); // RemainingBytes
        w.u16(0); // ReadChannelInfoOffset
        w.u16(0); // ReadChannelInfoLength
        w.into_vec()
    }

    /// The client's output buffer is not a promise about the answer's size. What
    /// does not fit stays queued for a follow-up READ, and BUFFER_OVERFLOW is
    /// the warning that sends the client back for it — dropping the remainder
    /// instead hands over a truncated NDR structure that parses as garbage.
    #[test]
    fn a_transceive_past_the_output_buffer_queues_the_remainder_for_a_read() {
        let mut pipe = Some(Pipe::default());
        // A reply from an earlier exchange that the client never collected. A
        // transceive starts a fresh one, so this must not be prepended to it.
        pipe.as_mut().expect("open").pending = b"stale".to_vec();

        let whole = dispatch(&enum_request(11, 1), "snap");
        const MAX_OUTPUT: usize = 16;
        assert!(
            whole.len() > MAX_OUTPUT,
            "the reply has to overflow the buffer or nothing here is tested"
        );

        let (body, message) = transceive_request(&enum_request(11, 1), MAX_OUTPUT as u32);
        let (resp, st) = transceive(&body, &message, &mut pipe, "snap").unwrap();
        assert_eq!(
            st,
            status::BUFFER_OVERFLOW,
            "a partial answer, not an error"
        );

        // OutputCount, then the output itself after the 48-byte response body.
        let count = u32::from_le_bytes(resp[36..40].try_into().unwrap()) as usize;
        assert_eq!(count, MAX_OUTPUT, "exactly what the client made room for");
        assert_eq!(&resp[48..48 + count], &whole[..MAX_OUTPUT]);

        let read_resp = read(&read_request(4096), &mut pipe).unwrap();
        let data_len = u32::from_le_bytes(read_resp[4..8].try_into().unwrap()) as usize;
        assert_eq!(
            &read_resp[16..16 + data_len],
            &whole[MAX_OUTPUT..],
            "the READ must return the rest of this answer, not the stale one"
        );
        assert_eq!(
            u32::from_le_bytes(read_resp[8..12].try_into().unwrap()),
            0,
            "and nothing is left queued behind it"
        );
    }

    /// An answer that fits is delivered whole, with nothing left over to make a
    /// later READ hand back a fragment of a finished exchange.
    #[test]
    fn a_transceive_that_fits_leaves_nothing_queued() {
        let mut pipe = Some(Pipe::default());
        let whole = dispatch(&enum_request(12, 1), "snap");

        let (body, message) = transceive_request(&enum_request(12, 1), 4096);
        let (resp, st) = transceive(&body, &message, &mut pipe, "snap").unwrap();
        assert_eq!(st, status::SUCCESS);
        let count = u32::from_le_bytes(resp[36..40].try_into().unwrap()) as usize;
        assert_eq!(count, whole.len());
        assert_eq!(&resp[48..48 + count], whole.as_slice());
        assert_eq!(
            read(&read_request(4096), &mut pipe).unwrap_err(),
            status::END_OF_FILE
        );
    }

    /// A read that asks for nothing cannot drain anything, so it is refused
    /// rather than answered with an empty success a client would loop on.
    #[test]
    fn a_zero_length_read_is_refused() {
        let mut pipe = Some(Pipe::default());
        pipe.as_mut().expect("open").pending = b"queued".to_vec();
        assert_eq!(
            read(&read_request(0), &mut pipe).unwrap_err(),
            status::INVALID_PARAMETER
        );
        assert_eq!(
            pipe.as_ref().expect("open").pending,
            b"queued",
            "the refusal must not consume the queue"
        );
    }

    /// The CLOSE response body is 60 bytes, which is what its StructureSize
    /// declares; a longer one is trailing rubbish the client parses as a field.
    #[test]
    fn the_close_response_is_sixty_bytes() {
        let mut pipe = Some(Pipe::default());
        let mut w = Writer::new();
        w.u16(24); // StructureSize
        w.u16(0); // Flags
        w.u32(0); // Reserved
        w.u64(PIPE_FILE_ID);
        w.u64(PIPE_FILE_ID);
        let resp = close(&w.into_vec(), &mut pipe).unwrap();
        assert_eq!(resp.len(), 60);
        assert_eq!(u16::from_le_bytes([resp[0], resp[1]]), 60);
    }

    #[test]
    fn a_malformed_pdu_faults_rather_than_panicking() {
        for junk in [vec![], vec![0u8; 4], vec![9u8; 32], vec![5, 0, 0, 3]] {
            let reply = dispatch(&junk, "snap");
            assert_eq!(reply[2], ptype::FAULT, "junk {junk:?} must fault");
        }
    }

    /// A frag_length that does not match the delivered bytes is either a
    /// malformed PDU or a fragment of a larger one; both are refused, since
    /// nothing here reassembles fragments.
    #[test]
    fn a_wrong_frag_length_faults() {
        // Claims zero.
        let mut req = enum_request(4, 1);
        req[8..10].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);

        // Claims more than was delivered.
        let mut req = enum_request(5, 1);
        let claim = ((req.len() + 4) as u16).to_le_bytes();
        req[8..10].copy_from_slice(&claim);
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);

        // Claims less: the trailing bytes would be silently dropped.
        let mut req = enum_request(6, 1);
        let claim = ((req.len() - 4) as u16).to_le_bytes();
        req[8..10].copy_from_slice(&claim);
        assert_eq!(dispatch(&req, "snap")[2], ptype::FAULT);
    }

    /// The level is read from the request, and a non-NULL ServerName shifts
    /// where it sits — get that wrong and every enumeration silently answers
    /// the wrong level.
    #[test]
    fn level_is_found_past_a_non_null_server_name() {
        // `\\host` is 6 characters, and the counts include the NUL terminator,
        // so both are 7 — declaring 6 while writing 7 units is exactly the kind
        // of drift that puts the level in the wrong place.
        let name = "\\\\host";
        let units = (name.chars().count() + 1) as u32;
        let mut w = Writer::new();
        w.u32(0x0002_0000); // non-NULL ServerName referent
        w.u32(units); // max_count
        w.u32(0); // offset
        w.u32(units); // actual_count
        w.bytes(&utf16le(name));
        w.bytes(&[0, 0]);
        w.align_to(4);
        w.u32(1); // Level
        assert_eq!(requested_level(&w.into_vec()), 1);

        // An even-length name lands the string on a 4-byte boundary with no
        // padding, which is the other half of the arithmetic.
        let name = "\\\\hosts";
        let units = (name.chars().count() + 1) as u32;
        let mut w = Writer::new();
        w.u32(0x0002_0000);
        w.u32(units);
        w.u32(0);
        w.u32(units);
        w.bytes(&utf16le(name));
        w.bytes(&[0, 0]);
        w.align_to(4);
        w.u32(2); // a different level, so a wrong offset cannot pass by luck
        assert_eq!(requested_level(&w.into_vec()), 2);
    }

    /// NDR strings are 4-byte aligned; a missing pad shifts everything after it
    /// and the client reads garbage.
    #[test]
    fn ndr_strings_are_padded_to_four_bytes() {
        for name in ["a", "ab", "abc", "abcd", "snap"] {
            let mut w = Writer::new();
            ndr_string(&mut w, name);
            let out = w.into_vec();
            assert_eq!(out.len() % 4, 0, "{name} left the stream unaligned");
            let actual = u32::from_le_bytes(out[8..12].try_into().unwrap());
            assert_eq!(actual as usize, name.chars().count() + 1, "{name}");
        }
    }
}
