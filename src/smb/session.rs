// Connection setup: NEGOTIATE, SESSION_SETUP, TREE_CONNECT and the trivial
// session-scoped commands.
//
// Authentication is mandatory. The NTLMSSP exchange runs in full: the client's
// user name must match the configured account, its NTLMv2 response is checked
// against the challenge this connection issued (`ntlm::verify`), and the session
// key that falls out becomes the signing key for every later message. There is
// no guest path — SessionFlags stays 0, never SMB2_SESSION_FLAG_IS_GUEST.
//
// That is what Windows 11 24H2 requires: it insists on signing, and a guest
// session cannot sign. Linux and macOS accept the same configuration, so one
// authenticated path serves all three.

use std::collections::HashMap;

use anyhow::Result;

use super::proto::{
    CAP_LARGE_MTU, DIALECT_SMB_2_1, DIALECT_WILDCARD, HEADER_LEN, SHARE_TYPE_DISK, SHARE_TYPE_PIPE,
    SIGNING_ENABLED, SIGNING_REQUIRED, access, status, to_filetime,
};
use super::wire::{Reader, Writer, der_tlv, from_utf16le, utf16le};

/// Ceiling on a single READ, and on the transact/write sizes we advertise.
/// Bounds one response allocation; also caps how much a client asks for at once.
pub(crate) const MAX_READ_SIZE: u32 = 1024 * 1024;

/// OID 1.3.6.1.5.5.2 — SPNEGO.
const OID_SPNEGO: &[u8] = &[0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// OID 1.3.6.1.4.1.311.2.2.10 — NTLMSSP.
const OID_NTLMSSP: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A,
];

const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
const NTLMSSP_NEGOTIATE: u32 = 1;
const NTLMSSP_AUTHENTICATE: u32 = 3;

/// The name reported as the NTLM target and the SMB volume label.
const SERVER_NAME: &str = "SMBANYTHING";

/// Build the SPNEGO `NegTokenInit` advertised in the NEGOTIATE response: a
/// mechTypes list containing NTLMSSP and nothing else. Offering only one
/// mechanism keeps the client from trying Kerberos first and stalling on a KDC
/// lookup that cannot succeed.
pub(crate) fn spnego_neg_token_init() -> Vec<u8> {
    let mech_types = der_tlv(0x30, OID_NTLMSSP);
    let mech_types_ctx = der_tlv(0xA0, &mech_types);
    let inner = der_tlv(0x30, &mech_types_ctx);
    let neg_ctx = der_tlv(0xA0, &inner);

    let mut body = Vec::with_capacity(OID_SPNEGO.len() + neg_ctx.len());
    body.extend_from_slice(OID_SPNEGO);
    body.extend_from_slice(&neg_ctx);
    der_tlv(0x60, &body)
}

/// SPNEGO `NegTokenResp` carrying the NTLMSSP challenge, with negState
/// accept-incomplete (1) — "keep going, here is my half".
fn spnego_challenge(ntlmssp: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&der_tlv(0xA0, &[0x0A, 0x01, 0x01]));
    inner.extend_from_slice(&der_tlv(0xA1, OID_NTLMSSP));
    inner.extend_from_slice(&der_tlv(0xA2, &der_tlv(0x04, ntlmssp)));
    der_tlv(0xA1, &der_tlv(0x30, &inner))
}

/// SPNEGO `NegTokenResp` with negState accept-completed (0) — "you're in".
fn spnego_accept() -> Vec<u8> {
    let inner = der_tlv(0xA0, &[0x0A, 0x01, 0x00]);
    der_tlv(0xA1, &der_tlv(0x30, &inner))
}

/// How the client framed its NTLMSSP token — and therefore how the reply must
/// be framed.
///
/// This is not a detail we get to choose. `smbclient` negotiates SPNEGO and
/// expects a `NegTokenResp` back; the Linux kernel client with `sec=none` uses
/// **raw** NTLMSSP and rejects an SPNEGO-wrapped reply outright with
/// "blob signature incorrect", because it parses the response buffer by
/// checking for the NTLMSSP magic at offset zero. Mirroring whatever the client
/// sent satisfies both without having to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// The token is the security buffer, starting at offset zero.
    Raw,
    /// The token is wrapped in a SPNEGO NegTokenInit/NegTokenResp.
    Spnego,
}

/// Locate an NTLMSSP message inside a security blob, and note how it was
/// framed.
///
/// The SPNEGO case is DER, but writing a DER parser to reach a field we accept
/// unconditionally would be pure ceremony. The NTLMSSP signature is an 8-byte
/// magic that cannot appear in the surrounding ASN.1 at this nesting depth, so
/// scanning for it is unambiguous in practice — and its *position* is exactly
/// the signal needed to tell the two framings apart.
fn find_ntlmssp(blob: &[u8]) -> Option<(u32, Framing, &[u8])> {
    let start = blob
        .windows(NTLMSSP_SIGNATURE.len())
        .position(|w| w == NTLMSSP_SIGNATURE)?;
    let msg = &blob[start..];
    if msg.len() < 12 {
        return None;
    }
    let msg_type = u32::from_le_bytes(msg[8..12].try_into().unwrap());
    let framing = if start == 0 {
        Framing::Raw
    } else {
        Framing::Spnego
    };
    Some((msg_type, framing, msg))
}

/// The account a client must present to get an authenticated, signed session.
#[derive(Debug, Clone)]
pub(crate) struct Credentials {
    pub(crate) user: String,
    pub(crate) password: String,
}

/// Build an NTLMSSP CHALLENGE (type 2) message.
///
/// The nonce is what makes the exchange more than a password echo: the client's
/// response is a MAC over it, so a capture from one connection cannot be
/// replayed against another. It is generated fresh per connection and discarded
/// once used.
fn ntlmssp_challenge(nonce: [u8; 8]) -> Vec<u8> {
    use super::ntlm::flags as nf;

    // EXTENDED_SESSIONSECURITY and TARGET_INFO are what modern clients expect;
    // without them macOS drops to a legacy path.
    let flags = nf::NEGOTIATE_UNICODE
        | nf::REQUEST_TARGET
        | nf::NEGOTIATE_NTLM
        | nf::NEGOTIATE_ALWAYS_SIGN
        | nf::TARGET_TYPE_SERVER
        | nf::EXTENDED_SESSIONSECURITY
        | nf::NEGOTIATE_TARGET_INFO
        | nf::NEGOTIATE_128
        | nf::NEGOTIATE_56
        // KEY_EXCH makes the client generate the session key and send it RC4-
        // wrapped, which is what Windows expects; without it cifs.ko warns that
        // "authentication has been weakened as server does not support key
        // exchange".
        | nf::NEGOTIATE_KEY_EXCH
        | nf::NEGOTIATE_SIGN;

    let target_name = utf16le(SERVER_NAME);

    // TargetInfo is a list of AV_PAIRs terminated by MsvAvEOL. Two entries plus
    // the terminator is the minimum clients accept.
    let mut target_info = Vec::new();
    for (av_id, value) in [(2u16, &target_name), (1u16, &target_name)] {
        // 2 = MsvAvNbDomainName, 1 = MsvAvNbComputerName
        target_info.extend_from_slice(&av_id.to_le_bytes());
        target_info.extend_from_slice(&(value.len() as u16).to_le_bytes());
        target_info.extend_from_slice(value);
    }
    target_info.extend_from_slice(&0u16.to_le_bytes()); // MsvAvEOL id
    target_info.extend_from_slice(&0u16.to_le_bytes()); // MsvAvEOL length

    // Fixed part is 56 bytes; payload follows.
    const FIXED: usize = 56;
    let target_name_off = FIXED;
    let target_info_off = FIXED + target_name.len();

    let mut w = Writer::with_capacity(FIXED + target_name.len() + target_info.len());
    w.bytes(NTLMSSP_SIGNATURE);
    w.u32(2); // MessageType = CHALLENGE
    w.u16(target_name.len() as u16); // TargetNameLen
    w.u16(target_name.len() as u16); // TargetNameMaxLen
    w.u32(target_name_off as u32);
    w.u32(flags);
    w.bytes(&nonce); // ServerChallenge
    w.zeros(8); // Reserved
    w.u16(target_info.len() as u16); // TargetInfoLen
    w.u16(target_info.len() as u16); // TargetInfoMaxLen
    w.u32(target_info_off as u32);
    w.zeros(8); // Version — zeroed; we do not set NEGOTIATE_VERSION
    w.bytes(&target_name);
    w.bytes(&target_info);
    w.into_vec()
}

/// Per-connection negotiation state.
#[derive(Debug, Default)]
pub(crate) struct SessionState {
    /// The connection this state belongs to, for the trace. Zero in unit tests,
    /// which build a state by hand and have no connection.
    pub(crate) conn_id: u64,
    /// Consecutive refused logons on this connection. Reset by a successful
    /// one, and capped by `MAX_FAILED_LOGONS`.
    pub(crate) failed_logons: u32,
    pub(crate) negotiated: bool,
    pub(crate) session_id: u64,
    pub(crate) authenticated: bool,
    /// The nonce sent in the NTLMSSP CHALLENGE, needed to check the response.
    ///
    /// `None` until one is issued, and `None` again the moment it is spent.
    /// Both matter: an AUTHENTICATE arriving as the first leg would otherwise be
    /// checked against a default nonce the server never sent, and a spent one
    /// left in place would let the same AUTHENTICATE be replayed on this
    /// connection for as long as it stayed open.
    pub(crate) server_challenge: Option<[u8; 8]>,
    /// Set once a client authenticates with NTLMv2. Its presence is what makes
    /// the connection sign responses and require signatures on requests.
    pub(crate) signing_key: Option<[u8; 16]>,
    /// Every tree id handed out by TREE_CONNECT, mapped to what it points at.
    ///
    /// A table rather than one id per kind, because a client may hold several
    /// connects to the same share at once and macOS routinely does: it connects
    /// the tree again while the mount is still live. Remembering only the newest
    /// id retired the one the mount was using, so every command on it answered
    /// NETWORK_NAME_DELETED and the share read as having vanished — an empty
    /// directory in Finder and `ls`. Samba keeps a per-session tcon table for
    /// the same reason (`smbXsrv_tcon_table`, source3/smbd/smbXsrv_tcon.c).
    trees: HashMap<u32, TreeKind>,
    next_tree_id: u32,
}

impl SessionState {
    /// State for a fresh connection. `Default` stays available for tests, which
    /// have no connection to name.
    pub(crate) fn new(conn_id: u64) -> Self {
        Self {
            conn_id,
            ..Self::default()
        }
    }

    /// The next tree id, or None once the space is spent.
    ///
    /// Tree id 0 is reserved for "no tree", so this starts at 1. Ids are never
    /// reused within a connection: a stale id from a disconnected tree must
    /// stay unrecognised rather than resolve to whatever was connected next.
    /// Wrapping would break exactly that — it hands back 0 and then re-issues
    /// ids a client may still be holding — so an exhausted space refuses the
    /// connect instead. In a debug build the increment would have panicked.
    fn alloc_tree_id(&mut self) -> Option<u32> {
        self.next_tree_id = self.next_tree_id.checked_add(1)?;
        Some(self.next_tree_id)
    }

    /// What `tree_id` points at, or None if it was never handed out on this
    /// connection or has since been disconnected.
    pub(crate) fn tree_kind(&self, tree_id: u32) -> Option<TreeKind> {
        self.trees.get(&tree_id).copied()
    }

    /// Retire a tree id, reporting what it pointed at. None means it was not
    /// live, which is the caller's cue to answer NETWORK_NAME_DELETED.
    pub(crate) fn remove_tree(&mut self, tree_id: u32) -> Option<TreeKind> {
        self.trees.remove(&tree_id)
    }
}

/// Ceiling on trees connected at once on one connection.
///
/// Every TREE_CONNECT costs a table entry that only the client can release, so
/// without a bound an authenticated client could grow the table until the
/// process ran out of memory. Real clients hold a handful — macOS peaked at
/// five during a single mount — so this is far above any legitimate use, and it
/// is per connection, not global.
const MAX_TREES: usize = 64;

/// Build the fixed part of a NEGOTIATE response for `dialect`.
///
/// Shared by the real SMB2 negotiate and by the SMB1 multi-protocol reply
/// below, which is byte-identical apart from the dialect field.
fn negotiate_response_body(
    dialect: u16,
    server_guid: &[u8; 16],
    boot_time: std::time::SystemTime,
) -> Vec<u8> {
    let security_buffer = spnego_neg_token_init();

    let mut w = Writer::with_capacity(64 + security_buffer.len());
    w.u16(65); // StructureSize
    w.u16(SIGNING_ENABLED | SIGNING_REQUIRED); // SecurityMode
    w.u16(dialect);
    w.u16(0); // NegotiateContextCount (3.1.1 only)
    w.bytes(server_guid);
    w.u32(CAP_LARGE_MTU);
    w.u32(MAX_READ_SIZE); // MaxTransactSize
    w.u32(MAX_READ_SIZE); // MaxReadSize
    // MaxWriteSize is deliberately small. Every WRITE is refused, so this only
    // decides how large a doomed request a client may build — and a maximal one
    // at MAX_READ_SIZE would exceed the inbound cap (header and body sit on top
    // of the data), so it would be answered by a dropped connection rather than
    // by MEDIA_WRITE_PROTECTED. Advertising a size the transport can actually
    // receive keeps the refusal legible.
    w.u32(64 * 1024); // MaxWriteSize
    w.u64(to_filetime(std::time::SystemTime::now())); // SystemTime
    w.u64(to_filetime(boot_time)); // ServerStartTime
    // Offsets are measured from the start of this response's SMB2 header, and
    // the fixed part of this structure is 64 bytes.
    w.u16((HEADER_LEN + 64) as u16); // SecurityBufferOffset
    w.u16(security_buffer.len() as u16); // SecurityBufferLength
    w.u32(0); // NegotiateContextOffset (3.1.1 only)
    w.bytes(&security_buffer);
    w.into_vec()
}

/// True if `msg` is an SMB1 message, i.e. begins with the `\xFFSMB` protocol id.
pub(crate) fn is_smb1(msg: &[u8]) -> bool {
    msg.len() >= 5 && msg[..4] == [0xFF, b'S', b'M', b'B']
}

/// SMB1 `SMB_COM_NEGOTIATE`.
const SMB1_COM_NEGOTIATE: u8 = 0x72;

pub(crate) fn is_smb1_negotiate(msg: &[u8]) -> bool {
    is_smb1(msg) && msg[4] == SMB1_COM_NEGOTIATE
}

/// Answer an SMB1 multi-protocol NEGOTIATE with an SMB2 response.
///
/// macOS opens every connection this way: a legacy SMB1 negotiate whose dialect
/// list includes the strings "SMB 2.002" and "SMB 2.???". Dropping it — which is
/// what a server that only parses SMB2 does — leaves the client waiting until it
/// times out, with no error on either side.
///
/// MS-SMB2 3.3.5.3.1 says to reply with an *SMB2* NEGOTIATE response carrying
/// the wildcard revision 0x02FF, meaning "I speak SMB2, ask me again properly".
/// The client then sends a real SMB2 NEGOTIATE and the normal path takes over.
/// Note this is not SMB1 support: the reply is SMB2, and no other SMB1 command
/// is answered.
pub(crate) fn smb1_negotiate_response(
    server_guid: &[u8; 16],
    boot_time: std::time::SystemTime,
) -> Vec<u8> {
    let body = negotiate_response_body(DIALECT_WILDCARD, server_guid, boot_time);

    let mut w = Writer::with_capacity(HEADER_LEN + body.len());
    w.bytes(&super::proto::SMB2_MAGIC);
    w.u16(HEADER_LEN as u16); // StructureSize
    w.u16(0); // CreditCharge
    w.u32(status::SUCCESS);
    w.u16(super::proto::cmd::NEGOTIATE);
    w.u16(1); // CreditResponse — must be at least one or the client cannot ask again
    w.u32(super::proto::flags::SERVER_TO_REDIR);
    w.u32(0); // NextCommand
    w.u64(0); // MessageId — the SMB1 request had no SMB2 id, and 0 is expected here
    w.u32(0); // Reserved
    w.u32(0); // TreeId
    w.u64(0); // SessionId
    w.zeros(16); // Signature
    w.bytes(&body);
    w.into_vec()
}

/// Read just the dialect list out of a NEGOTIATE request, for logging. Returns
/// an empty list rather than an error: this only ever feeds a diagnostic.
pub(crate) fn peek_dialects(body: &[u8]) -> Vec<u16> {
    let mut r = Reader::new(body);
    // StructureSize, DialectCount, SecurityMode, Reserved, Capabilities,
    // ClientGuid, ClientStartTime.
    if r.u16().is_err() {
        return Vec::new();
    }
    let Ok(count) = r.u16() else {
        return Vec::new();
    };
    if r.skip(2 + 2 + 4 + 16 + 8).is_err() {
        return Vec::new();
    }
    (0..count).map_while(|_| r.u16().ok()).collect()
}

/// NEGOTIATE (MS-SMB2 2.2.3 request, 2.2.4 response).
///
/// The client sends a list of dialects it supports; we insist on 2.1 being in
/// that list and answer with 2.1 alone. A client that only offers 3.x is
/// refused rather than accommodated.
pub(crate) fn negotiate(
    body: &[u8],
    server_guid: &[u8; 16],
    boot_time: std::time::SystemTime,
    state: &mut SessionState,
) -> Result<Vec<u8>, u32> {
    let mut r = Reader::new(body);
    let structure_size = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    if structure_size != 36 {
        return Err(status::INVALID_PARAMETER);
    }
    let dialect_count = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // SecurityMode
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // Reserved
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Capabilities
    r.skip(16).map_err(|_| status::INVALID_PARAMETER)?; // ClientGuid
    r.skip(8).map_err(|_| status::INVALID_PARAMETER)?; // ClientStartTime

    let mut offers_2_1 = false;
    for _ in 0..dialect_count {
        let d = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
        if d == DIALECT_SMB_2_1 {
            offers_2_1 = true;
        }
    }
    if !offers_2_1 {
        // MS-SMB2 says to answer a dialect mismatch with NOT_SUPPORTED. On
        // Linux this surfaces as a mount failure naming the dialect, which is
        // the clearest signal we can give that `vers=2.1` is required.
        return Err(status::NOT_SUPPORTED);
    }

    state.negotiated = true;
    Ok(negotiate_response_body(
        DIALECT_SMB_2_1,
        server_guid,
        boot_time,
    ))
}

/// SESSION_SETUP (MS-SMB2 2.2.5 request, 2.2.6 response).
///
/// Two round trips: the client's NTLMSSP NEGOTIATE gets a CHALLENGE back with
/// STATUS_MORE_PROCESSING_REQUIRED, then its AUTHENTICATE is verified against
/// that challenge and either yields a signing key or is refused with
/// LOGON_FAILURE. Returns `(status, body)` because the first leg is deliberately
/// not a success status.
pub(crate) fn session_setup(
    body: &[u8],
    message: &[u8],
    state: &mut SessionState,
    credentials: &Credentials,
) -> Result<(u32, Vec<u8>), u32> {
    let mut r = Reader::new(body);
    let structure_size = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    if structure_size != 25 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // Flags
    r.skip(1).map_err(|_| status::INVALID_PARAMETER)?; // SecurityMode
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Capabilities
    r.skip(4).map_err(|_| status::INVALID_PARAMETER)?; // Channel
    let sec_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let sec_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;

    // Security buffer offsets are relative to the SMB2 header, so they index
    // the whole message rather than the body.
    let msg_reader = Reader::new(message);
    let blob = msg_reader
        .slice_at(sec_off, sec_len)
        .map_err(|_| status::INVALID_PARAMETER)?;

    let (msg_type, framing, ntlmssp) = find_ntlmssp(blob).ok_or(status::INVALID_PARAMETER)?;

    let (resp_status, session_flags, token) = match msg_type {
        NTLMSSP_NEGOTIATE => {
            if state.session_id == 0 {
                // Any non-zero value works; the client echoes it back on every
                // later request. Randomised so two servers in one process never
                // hand out the same id.
                state.session_id = u64::from_le_bytes(rand::random::<[u8; 8]>()) | 1;
            }
            let nonce = rand::random::<[u8; 8]>();
            state.server_challenge = Some(nonce);
            let challenge = ntlmssp_challenge(nonce);
            let token = match framing {
                Framing::Raw => challenge,
                Framing::Spnego => spnego_challenge(&challenge),
            };
            (status::MORE_PROCESSING_REQUIRED, 0u16, token)
        }
        NTLMSSP_AUTHENTICATE => {
            // Every session authenticates. There is no guest path: all three
            // client platforms do NTLMv2, Windows *only* accepts an
            // authenticated signed session, and keeping a second unauthenticated
            // path alongside it would mean the password protected nothing —
            // anyone could simply ask to be a guest instead.
            //
            // Spend the challenge here, before anything can fail: a response is
            // only ever valid against the nonce it was computed for, and once
            // that nonce is gone a replay of the same AUTHENTICATE has nothing
            // to match. A client that gets it wrong starts a fresh exchange,
            // which is what every real one does anyway.
            let challenge = state.server_challenge.take().ok_or_else(|| {
                conn_log!(
                    state.conn_id,
                    "SESSION_SETUP: AUTHENTICATE with no challenge outstanding"
                );
                status::LOGON_FAILURE
            })?;
            let auth = super::ntlm::Authenticate::parse(ntlmssp).ok_or(status::LOGON_FAILURE)?;
            // Which identity was offered, and how it failed. Windows tries the
            // interactive user against a server it has no stored credential for
            // before it tries the one you typed, so "a rejected logon" and "the
            // wrong account was rejected" look identical without this — and the
            // second is the client's credential store, not the server.
            //
            // The name only. Never the response, the challenge or the key: a
            // trace is written to a terminal and pasted into bug reports.
            if auth.is_anonymous() {
                conn_log!(state.conn_id, "SESSION_SETUP: anonymous logon refused");
                return Err(status::LOGON_FAILURE);
            }
            if !auth.user.eq_ignore_ascii_case(&credentials.user) {
                conn_log!(
                    state.conn_id,
                    "SESSION_SETUP: user {:?} (domain {:?}) is not {:?}",
                    auth.user,
                    auth.domain,
                    credentials.user
                );
                return Err(status::LOGON_FAILURE);
            }
            let key =
                super::ntlm::verify(&auth, &credentials.password, &challenge).ok_or_else(|| {
                    conn_log!(
                        state.conn_id,
                        "SESSION_SETUP: wrong password for user {:?}",
                        auth.user
                    );
                    status::LOGON_FAILURE
                })?;
            state.signing_key = Some(key);
            // SessionFlags stays 0: not a guest, not a null session.
            let session_flags = 0u16;

            state.authenticated = true;
            let token = match framing {
                // Raw NTLMSSP has no "accept" message: the exchange ends with
                // the AUTHENTICATE, and the response carries an empty buffer.
                Framing::Raw => Vec::new(),
                Framing::Spnego => spnego_accept(),
            };
            (status::SUCCESS, session_flags, token)
        }
        _ => return Err(status::INVALID_PARAMETER),
    };

    let mut w = Writer::with_capacity(8 + token.len());
    w.u16(9); // StructureSize
    w.u16(session_flags);
    w.u16((HEADER_LEN + 8) as u16); // SecurityBufferOffset
    w.u16(token.len() as u16); // SecurityBufferLength
    w.bytes(&token);
    Ok((resp_status, w.into_vec()))
}

/// What a connected tree points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeKind {
    /// The ZIP archive share.
    Disk,
    /// IPC$. Accepted because macOS connects to it during mount, but every
    /// operation on it is refused.
    Ipc,
}

/// TREE_CONNECT (MS-SMB2 2.2.9 request, 2.2.10 response).
///
/// The path is a UNC of the form `\\host\share`; only the last component is
/// meaningful to us.
pub(crate) fn tree_connect(
    body: &[u8],
    message: &[u8],
    share_name: &str,
    state: &mut SessionState,
) -> Result<(Vec<u8>, TreeKind, u32), u32> {
    let mut r = Reader::new(body);
    let structure_size = r.u16().map_err(|_| status::INVALID_PARAMETER)?;
    if structure_size != 9 {
        return Err(status::INVALID_PARAMETER);
    }
    r.skip(2).map_err(|_| status::INVALID_PARAMETER)?; // Reserved / Flags
    let path_off = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;
    let path_len = r.u16().map_err(|_| status::INVALID_PARAMETER)? as usize;

    let msg_reader = Reader::new(message);
    let raw = msg_reader
        .slice_at(path_off, path_len)
        .map_err(|_| status::INVALID_PARAMETER)?;
    let path = from_utf16le(raw).map_err(|_| status::OBJECT_PATH_SYNTAX_BAD)?;

    let requested = path.rsplit('\\').next().unwrap_or_default();

    let kind = if requested.eq_ignore_ascii_case(share_name) {
        TreeKind::Disk
    } else if requested.eq_ignore_ascii_case("IPC$") {
        TreeKind::Ipc
    } else {
        return Err(status::BAD_NETWORK_NAME);
    };

    if state.trees.len() >= MAX_TREES {
        return Err(status::REQUEST_NOT_ACCEPTED);
    }
    let tree_id = state.alloc_tree_id().ok_or(status::REQUEST_NOT_ACCEPTED)?;
    state.trees.insert(tree_id, kind);

    let mut w = Writer::with_capacity(16);
    w.u16(16); // StructureSize
    w.u8(match kind {
        TreeKind::Disk => SHARE_TYPE_DISK,
        TreeKind::Ipc => SHARE_TYPE_PIPE,
    });
    w.u8(0); // Reserved
    w.u32(0); // ShareFlags: manual caching, no DFS, no encryption
    w.u32(0); // Capabilities
    w.u32(match kind {
        // Advertising the read-only mask here is what makes a client show the
        // mount as read-only before it ever attempts a write. The share root is
        // a directory, so this is the directory mask — per-file opens still get
        // the file mask, which carries no execute bit.
        TreeKind::Disk => access::READ_ONLY_DIR,
        TreeKind::Ipc => 0,
    });
    Ok((w.into_vec(), kind, tree_id))
}

/// ECHO, LOGOFF and TREE_DISCONNECT all have the same 4-byte shape:
/// StructureSize followed by a reserved u16.
pub(crate) fn simple_ack() -> Vec<u8> {
    let mut w = Writer::with_capacity(4);
    w.u16(4); // StructureSize
    w.u16(0); // Reserved
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb::proto::HEADER_LEN;

    // Wrap a body so that message-relative offsets (which count the 64-byte
    // header) line up the way a real request's would.
    fn as_message(body: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; HEADER_LEN];
        m.extend_from_slice(body);
        m
    }

    fn negotiate_request(dialects: &[u16]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(36);
        w.u16(dialects.len() as u16);
        w.u16(0); // SecurityMode
        w.u16(0); // Reserved
        w.u32(0); // Capabilities
        w.zeros(16); // ClientGuid
        w.u64(0); // ClientStartTime
        for d in dialects {
            w.u16(*d);
        }
        w.into_vec()
    }

    #[test]
    fn negotiate_selects_2_1_from_a_multi_dialect_offer() {
        let mut state = SessionState::default();
        let body = negotiate_request(&[0x0202, 0x0210, 0x0300, 0x0302, 0x0311]);
        let resp = negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap();

        let mut r = Reader::new(&resp);
        assert_eq!(r.u16().unwrap(), 65, "StructureSize");
        assert_eq!(r.u16().unwrap(), SIGNING_ENABLED | SIGNING_REQUIRED);
        assert_eq!(r.u16().unwrap(), DIALECT_SMB_2_1);
        assert!(state.negotiated);
    }

    #[test]
    fn negotiate_refuses_a_client_that_omits_2_1() {
        let mut state = SessionState::default();
        let body = negotiate_request(&[0x0300, 0x0311]);
        let err =
            negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap_err();
        assert_eq!(err, status::NOT_SUPPORTED);
        assert!(!state.negotiated);
    }

    #[test]
    fn negotiate_response_security_buffer_offset_is_header_relative() {
        let mut state = SessionState::default();
        let body = negotiate_request(&[DIALECT_SMB_2_1]);
        let resp = negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap();

        let off = u16::from_le_bytes(resp[56..58].try_into().unwrap()) as usize;
        let len = u16::from_le_bytes(resp[58..60].try_into().unwrap()) as usize;
        assert_eq!(off, HEADER_LEN + 64, "offset counts the SMB2 header");
        // The buffer sits right after the 64-byte fixed part of the body.
        assert_eq!(&resp[64..64 + len], spnego_neg_token_init().as_slice());
    }

    #[test]
    fn negotiate_rejects_a_bad_structure_size() {
        let mut state = SessionState::default();
        let mut body = negotiate_request(&[DIALECT_SMB_2_1]);
        body[0] = 35;
        assert_eq!(
            negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    #[test]
    fn negotiate_rejects_a_dialect_count_that_overruns_the_body() {
        let mut state = SessionState::default();
        let mut body = negotiate_request(&[DIALECT_SMB_2_1]);
        body[2..4].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(
            negotiate(&body, &[0u8; 16], std::time::SystemTime::now(), &mut state).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    fn session_setup_request(token: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut w = Writer::new();
        w.u16(25);
        w.u8(0); // Flags
        w.u8(0); // SecurityMode
        w.u32(0); // Capabilities
        w.u32(0); // Channel
        w.u16((HEADER_LEN + 24) as u16); // SecurityBufferOffset
        w.u16(token.len() as u16);
        w.u64(0); // PreviousSessionId
        w.bytes(token);
        let body = w.into_vec();
        let message = as_message(&body);
        (body, message)
    }

    fn ntlmssp_message(msg_type: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(NTLMSSP_SIGNATURE);
        v.extend_from_slice(&msg_type.to_le_bytes());
        v.extend_from_slice(&[0u8; 32]);
        v
    }

    fn creds() -> Credentials {
        Credentials {
            user: "wrustic".to_string(),
            password: "hunter2".to_string(),
        }
    }

    /// Drive both legs of a successful login and return the response to each.
    fn login(state: &mut SessionState, creds: &Credentials) -> (Vec<u8>, Vec<u8>) {
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let (st, first) = session_setup(&body, &message, state, creds).unwrap();
        assert_eq!(st, status::MORE_PROCESSING_REQUIRED);

        let auth = super::super::ntlm::tests_support::build_authenticate(
            &creds.user,
            "",
            &creds.password,
            &state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let (body, message) = session_setup_request(&auth);
        let (st, second) = session_setup(&body, &message, state, creds).unwrap();
        assert_eq!(st, status::SUCCESS);
        (first, second)
    }

    #[test]
    fn session_setup_challenges_then_authenticates() {
        let creds = creds();
        let mut state = SessionState::default();

        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let (st, resp) = session_setup(&body, &message, &mut state, &creds).unwrap();
        assert_eq!(st, status::MORE_PROCESSING_REQUIRED);
        assert_ne!(state.session_id, 0, "a session id is assigned on leg one");
        assert!(!state.authenticated);
        assert_eq!(u16::from_le_bytes(resp[2..4].try_into().unwrap()), 0);

        let first_session = state.session_id;
        let auth = super::super::ntlm::tests_support::build_authenticate(
            "wrustic",
            "",
            "hunter2",
            &state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let (body, message) = session_setup_request(&auth);
        let (st, resp) = session_setup(&body, &message, &mut state, &creds).unwrap();
        assert_eq!(st, status::SUCCESS);
        assert!(state.authenticated);
        assert_eq!(state.session_id, first_session, "id is stable across legs");
        assert_eq!(
            u16::from_le_bytes(resp[2..4].try_into().unwrap()),
            0,
            "an authenticated session is never flagged guest"
        );
        assert!(state.signing_key.is_some());
    }

    #[test]
    fn session_setup_rejects_a_blob_with_no_ntlmssp_token() {
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(b"not a token at all");
        assert_eq!(
            session_setup(&body, &message, &mut state, &creds()).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    #[test]
    fn session_setup_rejects_an_unknown_ntlmssp_message_type() {
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(&ntlmssp_message(2));
        assert_eq!(
            session_setup(&body, &message, &mut state, &creds()).unwrap_err(),
            status::INVALID_PARAMETER
        );
    }

    /// A malformed AUTHENTICATE must be a logon failure, not a parse error that
    /// leaks how far the message got.
    #[test]
    fn session_setup_rejects_a_malformed_authenticate() {
        let mut state = SessionState::default();
        let creds = creds();
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let _ = session_setup(&body, &message, &mut state, &creds).unwrap();

        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_AUTHENTICATE));
        assert_eq!(
            session_setup(&body, &message, &mut state, &creds).unwrap_err(),
            status::LOGON_FAILURE
        );
    }

    #[test]
    fn find_ntlmssp_distinguishes_raw_from_spnego_framing() {
        let inner = ntlmssp_message(NTLMSSP_NEGOTIATE);

        let (ty, framing, _) = find_ntlmssp(&inner).unwrap();
        assert_eq!(ty, NTLMSSP_NEGOTIATE);
        assert_eq!(framing, Framing::Raw, "signature at offset zero is raw");

        let wrapped = spnego_challenge(&inner);
        let (ty, framing, _) = find_ntlmssp(&wrapped).unwrap();
        assert_eq!(ty, NTLMSSP_NEGOTIATE);
        assert_eq!(framing, Framing::Spnego);
    }

    /// The Linux kernel client sends raw NTLMSSP and rejects an SPNEGO-wrapped
    /// reply with "blob signature incorrect". The reply framing must mirror the
    /// request's.
    #[test]
    fn session_setup_mirrors_raw_ntlmssp_framing() {
        let creds = creds();
        let mut state = SessionState::default();
        let (first, second) = login(&mut state, &creds);

        let len = u16::from_le_bytes(first[6..8].try_into().unwrap()) as usize;
        let token = &first[8..8 + len];
        assert_eq!(
            &token[..NTLMSSP_SIGNATURE.len()],
            NTLMSSP_SIGNATURE,
            "a raw request must get a raw CHALLENGE back, not a NegTokenResp"
        );

        // The final leg carries no token at all under raw framing.
        assert_eq!(u16::from_le_bytes(second[6..8].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(second[2..4].try_into().unwrap()), 0);
    }

    /// The full authenticated handshake: challenge, then a real NTLMv2
    /// response, yielding a signing key and a session that is *not* guest.
    #[test]
    fn a_valid_ntlmv2_login_produces_a_signing_key() {
        let creds = creds();
        let mut state = SessionState::default();

        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let (st, _) = session_setup(&body, &message, &mut state, &creds).unwrap();
        assert_eq!(st, status::MORE_PROCESSING_REQUIRED);
        assert!(state.server_challenge.is_some(), "a nonce was issued");
        assert!(state.signing_key.is_none(), "not yet authenticated");

        let auth = super::super::ntlm::tests_support::build_authenticate(
            "wrustic",
            "",
            "hunter2",
            &state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let (body, message) = session_setup_request(&auth);
        let (st, resp) = session_setup(&body, &message, &mut state, &creds).unwrap();

        assert_eq!(st, status::SUCCESS);
        assert!(state.authenticated);
        assert!(state.signing_key.is_some(), "signing key must be derived");
        let flags = u16::from_le_bytes(resp[2..4].try_into().unwrap());
        assert_eq!(
            flags, 0,
            "an authenticated session must not be flagged guest — Windows blocks guest"
        );
    }

    /// An AUTHENTICATE that skips the challenge leg must be refused. Without a
    /// challenge to check against, the alternative is verifying the response
    /// against a default nonce the server never sent.
    #[test]
    fn an_authenticate_as_the_first_leg_is_refused() {
        let creds = creds();
        let mut state = SessionState::default();
        assert!(state.server_challenge.is_none(), "nothing issued yet");

        let auth = super::super::ntlm::tests_support::build_authenticate(
            "wrustic", "", "hunter2", &[0u8; 8], None,
        );
        let (body, message) = session_setup_request(&auth);
        assert_eq!(
            session_setup(&body, &message, &mut state, &creds).unwrap_err(),
            status::LOGON_FAILURE
        );
        assert!(!state.authenticated);
        assert!(state.signing_key.is_none());
    }

    /// The challenge is spent by the AUTHENTICATE that uses it, so replaying
    /// that same message on the connection cannot log in a second time.
    #[test]
    fn a_replayed_authenticate_is_refused_because_the_challenge_is_spent() {
        let creds = creds();
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let _ = session_setup(&body, &message, &mut state, &creds).unwrap();

        let auth = super::super::ntlm::tests_support::build_authenticate(
            "wrustic",
            "",
            "hunter2",
            &state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let (body, message) = session_setup_request(&auth);
        let (st, _) = session_setup(&body, &message, &mut state, &creds).unwrap();
        assert_eq!(st, status::SUCCESS);
        assert!(state.server_challenge.is_none(), "the nonce is consumed");

        assert_eq!(
            session_setup(&body, &message, &mut state, &creds).unwrap_err(),
            status::LOGON_FAILURE,
            "the same AUTHENTICATE must not verify twice"
        );
    }

    #[test]
    fn a_wrong_password_is_refused_with_logon_failure() {
        let creds = creds();
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let _ = session_setup(&body, &message, &mut state, &creds).unwrap();

        let auth = super::super::ntlm::tests_support::build_authenticate(
            "wrustic",
            "",
            "wrong-password",
            &state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let (body, message) = session_setup_request(&auth);
        assert_eq!(
            session_setup(&body, &message, &mut state, &creds).unwrap_err(),
            status::LOGON_FAILURE
        );
        assert!(state.signing_key.is_none());
        assert!(!state.authenticated);
    }

    #[test]
    fn an_unknown_user_is_refused() {
        let creds = creds();
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let _ = session_setup(&body, &message, &mut state, &creds).unwrap();

        let auth = super::super::ntlm::tests_support::build_authenticate(
            "someone-else",
            "",
            "hunter2",
            &state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let (body, message) = session_setup_request(&auth);
        assert_eq!(
            session_setup(&body, &message, &mut state, &creds).unwrap_err(),
            status::LOGON_FAILURE
        );
    }

    /// With a password configured, an anonymous request must not fall back to
    /// guest — otherwise the password protects nothing.
    #[test]
    fn anonymous_is_refused_when_a_password_is_configured() {
        let creds = creds();
        let mut state = SessionState::default();
        let (body, message) = session_setup_request(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let _ = session_setup(&body, &message, &mut state, &creds).unwrap();

        let mut auth = super::super::ntlm::tests_support::build_authenticate(
            "",
            "",
            "",
            &state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let f = u32::from_le_bytes(auth[60..64].try_into().unwrap());
        auth[60..64]
            .copy_from_slice(&(f | super::super::ntlm::flags::NEGOTIATE_ANONYMOUS).to_le_bytes());

        let (body, message) = session_setup_request(&auth);
        assert_eq!(
            session_setup(&body, &message, &mut state, &creds).unwrap_err(),
            status::LOGON_FAILURE
        );
    }

    #[test]
    fn the_challenge_offers_key_exchange_and_signing() {
        use super::super::ntlm::flags as nf;
        let msg = ntlmssp_challenge([0u8; 8]);
        let flags = u32::from_le_bytes(msg[20..24].try_into().unwrap());
        // Without KEY_EXCH the client will not send a session key, and cifs.ko
        // warns that authentication was weakened.
        assert_ne!(flags & nf::NEGOTIATE_KEY_EXCH, 0);
        assert_ne!(flags & nf::NEGOTIATE_SIGN, 0);
        assert_ne!(flags & nf::EXTENDED_SESSIONSECURITY, 0);
    }

    #[test]
    fn session_setup_mirrors_spnego_framing() {
        let mut state = SessionState::default();
        let wrapped = spnego_challenge(&ntlmssp_message(NTLMSSP_NEGOTIATE));
        let (body, message) = session_setup_request(&wrapped);
        let (_, resp) = session_setup(&body, &message, &mut state, &creds()).unwrap();

        let len = u16::from_le_bytes(resp[6..8].try_into().unwrap()) as usize;
        let token = &resp[8..8 + len];
        assert_eq!(
            token[0], 0xA1,
            "SPNEGO request must get a NegTokenResp back"
        );
    }

    #[test]
    fn ntlmssp_challenge_payload_offsets_are_in_range() {
        let msg = ntlmssp_challenge([0xAB; 8]);
        let target_name_len = u16::from_le_bytes(msg[12..14].try_into().unwrap()) as usize;
        let target_name_off = u32::from_le_bytes(msg[16..20].try_into().unwrap()) as usize;
        let target_info_len = u16::from_le_bytes(msg[40..42].try_into().unwrap()) as usize;
        let target_info_off = u32::from_le_bytes(msg[44..48].try_into().unwrap()) as usize;

        assert_eq!(target_name_off, 56, "fixed part of a CHALLENGE is 56 bytes");
        assert!(target_name_off + target_name_len <= msg.len());
        assert!(target_info_off + target_info_len <= msg.len());
        assert_eq!(&msg[24..32], &[0xAB; 8], "ServerChallenge nonce");
        assert_eq!(
            from_utf16le(&msg[target_name_off..target_name_off + target_name_len]).unwrap(),
            SERVER_NAME
        );
        // TargetInfo must end with the MsvAvEOL pair.
        let info_end = target_info_off + target_info_len;
        assert_eq!(&msg[info_end - 4..info_end], &[0, 0, 0, 0]);
    }

    fn tree_connect_request(path: &str) -> (Vec<u8>, Vec<u8>) {
        let encoded = utf16le(path);
        let mut w = Writer::new();
        w.u16(9);
        w.u16(0); // Reserved
        w.u16((HEADER_LEN + 8) as u16); // PathOffset
        w.u16(encoded.len() as u16);
        w.bytes(&encoded);
        let body = w.into_vec();
        let message = as_message(&body);
        (body, message)
    }

    #[test]
    fn session_state_carries_the_connection_id_for_the_trace() {
        // Every refusal in `session_setup` logs against this, so a state that
        // lost it would attribute a failed logon to connection 0 — which is the
        // one thing the trace exists to distinguish.
        assert_eq!(SessionState::new(7).conn_id, 7);
        assert_eq!(
            SessionState::default().conn_id,
            0,
            "no connection in a test"
        );
    }

    #[test]
    fn tree_connect_accepts_the_share_case_insensitively() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\SNAP");
        let (resp, kind, tree_id) = tree_connect(&body, &message, "snap", &mut state).unwrap();
        assert_eq!(kind, TreeKind::Disk);
        assert_ne!(tree_id, 0, "tree id 0 means no tree");
        assert_eq!(state.tree_kind(tree_id), Some(TreeKind::Disk));

        assert_eq!(u16::from_le_bytes(resp[0..2].try_into().unwrap()), 16);
        assert_eq!(resp[2], SHARE_TYPE_DISK);
        let maximal = u32::from_le_bytes(resp[12..16].try_into().unwrap());
        assert_eq!(maximal, access::READ_ONLY_DIR);
        assert_eq!(maximal & access::WRITE_BITS, 0);
    }

    #[test]
    fn tree_connect_accepts_ipc_as_a_pipe_share() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\IPC$");
        let (resp, kind, tree_id) = tree_connect(&body, &message, "snap", &mut state).unwrap();
        assert_eq!(kind, TreeKind::Ipc);
        assert_eq!(resp[2], SHARE_TYPE_PIPE);
        assert_eq!(state.tree_kind(tree_id), Some(TreeKind::Ipc));
        assert_eq!(u32::from_le_bytes(resp[12..16].try_into().unwrap()), 0);
    }

    #[test]
    fn tree_connect_refuses_an_unknown_share() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\secrets");
        assert_eq!(
            tree_connect(&body, &message, "snap", &mut state).unwrap_err(),
            status::BAD_NETWORK_NAME
        );
    }

    #[test]
    fn tree_connect_hands_out_distinct_tree_ids() {
        let mut state = SessionState::default();
        let (b1, m1) = tree_connect_request(r"\\127.0.0.1\snap");
        let (_, _, first) = tree_connect(&b1, &m1, "snap", &mut state).unwrap();
        let (b2, m2) = tree_connect_request(r"\\127.0.0.1\IPC$");
        let (_, _, second) = tree_connect(&b2, &m2, "snap", &mut state).unwrap();
        assert_ne!(first, second);
    }

    /// macOS connects the same share several times over one mount. Each connect
    /// has to stay usable until the client disconnects it by name: retiring the
    /// earlier id when a later one arrives is what made the mount go blank.
    #[test]
    fn repeated_connects_to_one_share_all_stay_live() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\snap");

        let ids: Vec<u32> = (0..4)
            .map(|_| tree_connect(&body, &message, "snap", &mut state).unwrap().2)
            .collect();

        for &id in &ids {
            assert_eq!(
                state.tree_kind(id),
                Some(TreeKind::Disk),
                "tree {id} must survive the connects that followed it"
            );
        }

        // Disconnecting one leaves the rest alone, and its id never comes back.
        assert_eq!(state.remove_tree(ids[1]), Some(TreeKind::Disk));
        assert_eq!(state.tree_kind(ids[1]), None);
        assert_eq!(state.remove_tree(ids[1]), None, "a stale id is not live");
        for &id in [ids[0], ids[2], ids[3]].iter() {
            assert_eq!(state.tree_kind(id), Some(TreeKind::Disk));
        }
    }

    #[test]
    fn the_tree_table_is_bounded() {
        let mut state = SessionState::default();
        let (body, message) = tree_connect_request(r"\\127.0.0.1\snap");
        for _ in 0..MAX_TREES {
            tree_connect(&body, &message, "snap", &mut state).expect("under the cap");
        }
        assert_eq!(
            tree_connect(&body, &message, "snap", &mut state).unwrap_err(),
            status::REQUEST_NOT_ACCEPTED
        );

        // Disconnecting frees a slot, so a client that cleans up is never stuck.
        let live = *state.trees.keys().next().expect("table is full");
        state.remove_tree(live);
        tree_connect(&body, &message, "snap", &mut state).expect("a slot was freed");
    }

    /// Ids are never reused, so the space can run out rather than wrap. Wrapping
    /// would hand back 0 — which means "no tree" — and then re-issue ids a
    /// client may still be holding, which is the bug the table exists to fix.
    #[test]
    fn an_exhausted_tree_id_space_refuses_the_connect() {
        let mut state = SessionState {
            next_tree_id: u32::MAX,
            ..Default::default()
        };
        let (body, message) = tree_connect_request(r"\\127.0.0.1\snap");
        assert_eq!(
            tree_connect(&body, &message, "snap", &mut state).unwrap_err(),
            status::REQUEST_NOT_ACCEPTED
        );
        assert!(state.trees.is_empty(), "nothing was recorded for a refusal");
        assert_eq!(state.tree_kind(0), None, "0 is never handed out");
    }

    #[test]
    fn spnego_tokens_are_well_formed_der() {
        let init = spnego_neg_token_init();
        assert_eq!(init[0], 0x60, "NegTokenInit is APPLICATION 0");
        assert!(
            init.windows(OID_NTLMSSP.len()).any(|w| w == OID_NTLMSSP),
            "the mech list must advertise NTLMSSP"
        );

        let accept = spnego_accept();
        assert_eq!(accept[0], 0xA1, "NegTokenResp is context 1");
        // negState accept-completed is ENUMERATED 0.
        assert!(accept.windows(3).any(|w| w == [0x0A, 0x01, 0x00]));
    }

    #[test]
    fn simple_ack_is_the_four_byte_shape() {
        assert_eq!(simple_ack(), vec![4, 0, 0, 0]);
    }
}
