// A read-only SMB 2.1 server for an immutable ZIP archive.
//
// Why this exists: a ZIP archive is immutable while this process serves it, so
// exporting one over a real
// network filesystem needs no invalidation, no file-level locking and no write
// path. That makes a read-only server small enough to hand-roll, and a mounted
// filesystem is far more useful than a download link for browsing a backup.
//
// Scope, deliberately: SMB 2.1 only, mandatory NTLMv2 authentication, mandatory
// signing, no encryption, loopback by default. 2.1 is the newest dialect that
// avoids pre-auth integrity hashes, negotiate contexts and AES-GCM; NTLMv2 plus
// signing is the floor Windows 11 24H2 accepts, and all three client platforms
// support it, so there is no guest path to keep working. Write commands are
// refused at the protocol level in addition to there being no code that could
// perform one — with a single, bounded exception: a WRITE to the `srvsvc` pipe
// on IPC$, which is how a client asks what shares exist (see `srvsvc.rs`). It
// buffers in memory, is gated on the tree being IPC$ and the pipe being open,
// and has no route to the ZIP archive.
//
// One protocol detail is worth stating up front because three parts of this
// module depend on it. A client may pack several requests into one message and
// flag the later ones RELATED; per MS-SMB2 3.3.5.2.7.1 such a request may carry
// 0xFF..FF in place of the session, tree and file ids and inherit the real ones
// from the request before it. So a chain is treated as a unit: identity flows
// along it (`Chain` in `handle_message`), a CREATE that fails poisons the rest
// of it rather than letting the survivors resolve onto some other handle, and
// none of that state outlives the message that established it.
//
// Measured, so nobody has to guess how load-bearing this is: Windows 11 (26200)
// over this share sends RELATED on a couple of QUERY_INFOs per session and
// *still fills in the real session, tree and file ids* — it never sends a
// placeholder. cifs.ko does not chain at all. So the inheritance path is
// conformance rather than something a tested client needs; what it buys is that
// a client which does use placeholders (the spec allows it, Samba implements
// it, and smbtorture's compound tests emulate a Windows client that does) is
// not answered with USER_SESSION_DELETED. The chain-scoping of the file-id
// placeholder is worth having on its own terms: it is what stops a stale
// 0xFF..FF from resolving onto an unrelated live handle and closing it.
//
// A mount is for browsing an archive, not for restoring or running one:
// symlinks cannot survive SMB 2.1 anyway, so nothing here pretends to be a
// faithful copy of the original tree. Files come out 0444 and directories 0555
// — on Linux from the mode options in the mount command below (SMB 2.1 carries
// no POSIX mode of its own), and on Windows from the READONLY attribute plus a
// CREATE that refuses FILE_EXECUTE on files. A macOS Finder mount shows the
// client's default modes instead; the server refuses writes regardless.
//
// Mount it with — each prompts for the password, which is never passed as an
// argument: a command line is readable by every other process while it runs,
// and lands in shell (or console) history afterwards.
//   Linux    sudo mount -t cifs -o port=<p>,vers=2.1,username=smbzip,ro,\
//                       file_mode=0444,dir_mode=0555 //127.0.0.1/zip /mnt
//   macOS    Finder → Go → Connect to Server (Cmd+K): smb://smbzip@127.0.0.1:<p>/zip
//   Windows  net use Z: \\127.0.0.1\zip * /user:smbzip   (add /TCPPORT:<p>)

/// Whether to trace protocol traffic to stderr. Enabled by setting
/// `SMBZIP_LOG` to anything.
///
/// Worth having permanently rather than as scaffolding: when a client refuses a
/// mount it says nothing useful (Linux reports a bare -EIO or -EINVAL, macOS
/// just times out), and the server is the only place that can see which command
/// was rejected and why.
pub(crate) fn log_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("SMBZIP_LOG").is_some())
}

/// Wall-clock stamp for a trace line, to millisecond resolution.
///
/// Not decoration: a burst of failed logons and the same number spread over ten
/// minutes are different problems — a client hammering a stale credential
/// versus one retrying on a timer — and without a clock the log cannot tell
/// them apart. Local time, because the reader is looking at their own screen
/// and correlating with what they just clicked.
pub(crate) fn log_stamp() -> String {
    jiff::Zoned::now().strftime("%H:%M:%S%.3f").to_string()
}

// Defined above the module declarations on purpose: a `macro_rules!` is in
// scope only for what follows it, and the modules below need it too.
macro_rules! smb_log {
    ($($arg:tt)*) => {
        if $crate::smb::log_enabled() {
            eprintln!(
                "[smb {}] {}",
                $crate::smb::log_stamp(),
                format!($($arg)*)
            );
        }
    };
}

/// The same, prefixed with the connection it happened on.
///
/// Not cosmetic. A Windows client opens several connections per mount and
/// spreads work across them, so in a flat trace a failed SESSION_SETUP on one
/// connection sits between two successful operations on another — which reads
/// as a server that intermittently refuses folders, rather than as a client
/// whose extra connections never authenticated.
macro_rules! conn_log {
    ($id:expr, $($arg:tt)*) => {
        smb_log!("conn {}: {}", $id, format_args!($($arg)*))
    };
}

mod backing;
mod files;
mod info;
mod ntlm;
mod path;
mod proto;
mod session;
mod sign;
mod srvsvc;
mod wire;

use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::thread;
use std::time::SystemTime;

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::local_server;
pub(crate) use backing::{Backing, ZipBacking};
use files::Handles;
use proto::{HEADER_LEN, Header, NEXT_COMMAND_OFFSET, cmd, flags, status, write_error_body};
pub(crate) use session::Credentials;
use session::{SessionState, TreeKind};
use wire::{MAX_INBOUND_MESSAGE, NBSS_HEADER_LEN, Reader, Writer, nbss_header, nbss_len};

/// Render an NTSTATUS for a log line.
fn status_name(status: u32) -> String {
    let name = match status {
        status::SUCCESS => "SUCCESS",
        status::MORE_PROCESSING_REQUIRED => "MORE_PROCESSING_REQUIRED",
        status::NO_MORE_FILES => "NO_MORE_FILES",
        status::NO_SUCH_FILE => "NO_SUCH_FILE",
        status::OBJECT_NAME_COLLISION => "OBJECT_NAME_COLLISION",
        status::LOGON_FAILURE => "LOGON_FAILURE",
        status::END_OF_FILE => "END_OF_FILE",
        status::NO_EAS_ON_FILE => "NO_EAS_ON_FILE",
        status::NOT_SUPPORTED => "NOT_SUPPORTED",
        status::ACCESS_DENIED => "ACCESS_DENIED",
        status::MEDIA_WRITE_PROTECTED => "MEDIA_WRITE_PROTECTED",
        status::OBJECT_NAME_NOT_FOUND => "OBJECT_NAME_NOT_FOUND",
        status::OBJECT_PATH_NOT_FOUND => "OBJECT_PATH_NOT_FOUND",
        status::OBJECT_PATH_SYNTAX_BAD => "OBJECT_PATH_SYNTAX_BAD",
        status::OBJECT_NAME_INVALID => "OBJECT_NAME_INVALID",
        status::INVALID_PARAMETER => "INVALID_PARAMETER",
        status::INVALID_INFO_CLASS => "INVALID_INFO_CLASS",
        status::INFO_LENGTH_MISMATCH => "INFO_LENGTH_MISMATCH",
        status::BUFFER_OVERFLOW => "BUFFER_OVERFLOW",
        status::FILE_CLOSED => "FILE_CLOSED",
        status::FILE_IS_A_DIRECTORY => "FILE_IS_A_DIRECTORY",
        status::NOT_A_DIRECTORY => "NOT_A_DIRECTORY",
        status::BAD_NETWORK_NAME => "BAD_NETWORK_NAME",
        status::NETWORK_NAME_DELETED => "NETWORK_NAME_DELETED",
        status::USER_SESSION_DELETED => "USER_SESSION_DELETED",
        status::INVALID_DEVICE_REQUEST => "INVALID_DEVICE_REQUEST",
        status::UNEXPECTED_IO_ERROR => "UNEXPECTED_IO_ERROR",
        _ => return format!("{status:#010x}"),
    };
    name.to_string()
}

/// Upper bound on credits granted per request. Credits are SMB2's flow control:
/// each one lets the client keep one more request in flight. Granting too few
/// stalls the client outright, so we are generous — the ceiling exists only to
/// keep a client from claiming an unbounded window.
const MAX_CREDITS: u16 = 512;

/// The default share name clients connect to: `\\127.0.0.1\zip`.
pub(crate) const DEFAULT_SHARE_NAME: &str = "zip";

/// SMB's registered port, and the only one a Windows UNC path will ever try.
/// A share reachable here needs no port option in any mount command, and works
/// in Explorer's address bar rather than only as a mapped drive.
pub(crate) const STANDARD_SMB_PORT: u16 = 445;

/// The default account clients authenticate as; the CLI can override it.
pub(crate) const DEFAULT_SHARE_USER: &str = "smbzip";

/// A short random password for a share.
///
/// Generated per server rather than defaulted, because a fixed default password
/// is the same as no password.
///
/// The alphabet is lower case, upper case, digits and the four RFC 3986
/// *unreserved* symbols. Unreserved is the point: those four need no
/// percent-encoding in a URL, no quoting in a shell, and no escaping in
/// mount.cifs's comma-separated option list, so the password stays literal
/// wherever it is typed. The visually ambiguous characters are left out
/// (`l`/`1`/`I`, `O`/`0`), because this is read off a screen and typed into a
/// credential prompt by hand.
///
/// One character of each class is placed first and the result shuffled, so a
/// password is never all one case by chance — a client or policy that demands
/// mixed case cannot be handed a draw that happens not to have it.
pub(crate) fn random_password() -> String {
    use rand::RngExt;
    use rand::seq::SliceRandom;

    const LOWER: &[u8] = b"abcdefghijkmnpqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    /// The unreserved marks of RFC 3986 §2.3, the whole set.
    const SYMBOLS: &[u8] = b"-._~";
    const LEN: usize = 16;

    let mut rng = rand::rng();
    // `random_range` rejects out-of-range draws rather than taking a modulus,
    // which would favour the first `256 % len` characters of an alphabet whose
    // length does not divide 256. 16 characters over 60 is ~94 bits.
    let mut pick = |set: &[u8]| set[rng.random_range(0..set.len())] as char;

    let all: Vec<u8> = [LOWER, UPPER, DIGITS, SYMBOLS].concat();
    let mut chars: Vec<char> = vec![pick(LOWER), pick(UPPER), pick(DIGITS), pick(SYMBOLS)];
    chars.extend((chars.len()..LEN).map(|_| pick(&all)));
    chars.shuffle(&mut rng);
    chars.into_iter().collect()
}

/// Immutable per-server state shared by every connection.
struct Ctx {
    share_name: String,
    /// What the share serves. Shared across connections; the ZIP is
    /// immutable, so concurrent readers need no coordination beyond this Arc.
    backing: Arc<dyn Backing>,
    /// The account every client must authenticate as. There is no guest path:
    /// all three client platforms support NTLMv2, and Windows accepts nothing
    /// less.
    credentials: Credentials,
    /// Reported as the volume serial number. Clients key their metadata caches
    /// on it, so it must be stable for the server's lifetime and differ between
    /// servers.
    volume_serial: u32,
    /// Identifies this server instance in NEGOTIATE. Random per start, as the
    /// spec requires it be stable for a server's lifetime and distinct between
    /// servers.
    server_guid: [u8; 16],
    boot_time: SystemTime,
    /// Refused logons across every connection this server has seen, shared with
    /// the `SmbHandle` so the owner can stop a server being worked over. See
    /// `MAX_SERVER_LOGON_FAILURES`.
    failed_logons: Arc<std::sync::atomic::AtomicU32>,
}

impl Ctx {
    /// Count one refusal, returning the running total. Saturating: a server
    /// left running for a very long time must not wrap the counter back under
    /// the limit and start accepting logons again.
    fn record_failed_logon(&self) -> u32 {
        use std::sync::atomic::Ordering;
        self.failed_logons
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            })
            .unwrap_or(0)
            .saturating_add(1)
    }

    fn clear_failed_logons(&self) {
        self.failed_logons
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    fn logon_limit_reached(&self) -> bool {
        logon_limit_reached(&self.failed_logons)
    }
}

/// Where a client should point, which is not the socket the server bound when
/// the tun transport fronts the share: there the SMB code listens on an
/// ephemeral loopback port while clients connect to the tun address on 445.
#[derive(Debug, Clone)]
pub(crate) struct MountPoint {
    pub(crate) host: String,
    pub(crate) port: u16,
}

pub(crate) struct SmbHandle {
    /// The TCP port the SMB listener bound.
    pub(crate) port: u16,
    pub(crate) share_name: String,
    mount: MountPoint,
    /// Shared with `Ctx`. Read by the owner to decide whether to stop.
    failed_logons: Arc<std::sync::atomic::AtomicU32>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl SmbHandle {
    /// UNC path for a Linux `mount -t cifs`.
    #[cfg(test)]
    pub(crate) fn unc(&self) -> String {
        format!(r"\\{}\{}", self.mount.host, self.share_name)
    }

    /// Host and port a client mounts, as opposed to the bound listener.
    pub(crate) fn mount(&self) -> &MountPoint {
        &self.mount
    }

    /// Whether the share is reachable on SMB's standard port, and so mountable
    /// as a plain UNC path with no port option anywhere in the command.
    pub(crate) fn on_standard_port(&self) -> bool {
        self.mount.port == STANDARD_SMB_PORT
    }

    /// True once refused logons since the last successful one have reached
    /// `MAX_SERVER_LOGON_FAILURES`. The server has already stopped accepting
    /// logons at this point; the owner is expected to stop it outright.
    pub(crate) fn logon_limit_reached(&self) -> bool {
        logon_limit_reached(&self.failed_logons)
    }

    /// Refused logons since the last successful one, for the message the owner
    /// shows when it stops.
    pub(crate) fn failed_logons(&self) -> u32 {
        self.failed_logons
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }
}

impl Drop for SmbHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Turn a bind failure on a privileged port into an actionable message. Ports
/// below 1024 need CAP_NET_BIND_SERVICE, and the bare "Permission denied" that
/// the OS returns says nothing about how to fix it.
fn privileged_hint(e: anyhow::Error, port: u16) -> anyhow::Error {
    if port >= 1024 {
        return e;
    }
    anyhow!(
        "{e}\n\nPort {port} is privileged. Either run the whole command under \
sudo -E, or grant the binary the capability once:\n  \
sudo setcap cap_net_bind_service=+ep <path-to-smbzip>\n\
(setcap must be re-applied after every rebuild.)"
    )
}

/// Which interfaces to accept connections on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Bind {
    /// 127.0.0.1 and ::1 only. The default, and the only one the shipped binary
    /// ever asks for.
    #[default]
    Loopback,
    /// Every interface. Clients still have to authenticate, but nothing is
    /// encrypted, so anyone on the network can read file contents in transit.
    ///
    /// This must be selected explicitly because SMB 2.1 traffic is signed but
    /// not encrypted, so file contents are visible on the network.
    AllInterfaces,
}

/// Start the server on `port` (0 picks an ephemeral one). Binding happens
/// synchronously so that a port conflict is reported to the caller rather than
/// swallowed by the server thread.
pub(crate) fn start(
    port: u16,
    share_name: impl Into<String>,
    backing: Arc<dyn Backing>,
    bind: Bind,
    credentials: Credentials,
) -> Result<SmbHandle> {
    let listeners_std = match &bind {
        Bind::Loopback => {
            local_server::bind_localhost(port).map_err(|e| privileged_hint(e, port))?
        }
        Bind::AllInterfaces => {
            let listener = StdTcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, port))
                .or_else(|_| StdTcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)))
                .map_err(|e| anyhow!("binding all interfaces on port {port}: {e}"));
            let listener = listener.map_err(|e| privileged_hint(e, port))?;
            listener
                .set_nonblocking(true)
                .map_err(|e| anyhow!("set_nonblocking: {e}"))?;
            vec![listener]
        }
    };
    let bound_port = listeners_std
        .first()
        .ok_or_else(|| anyhow!("bind_localhost returned no listeners"))?
        .local_addr()
        .map_err(|e| anyhow!("read bound listener address: {e}"))?
        .port();

    let mount = MountPoint {
        host: "127.0.0.1".to_string(),
        port: bound_port,
    };

    let share_name = share_name.into();
    let failed_logons = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let ctx = Arc::new(Ctx {
        share_name: share_name.clone(),
        backing,
        credentials,
        volume_serial: rand::random::<u32>(),
        server_guid: rand::random::<[u8; 16]>(),
        boot_time: SystemTime::now(),
        failed_logons: failed_logons.clone(),
    });

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let join = thread::Builder::new()
        .name(format!("smbzip-{bound_port}"))
        .spawn(move || {
            // Multi-thread rather than current-thread: ZIP decompression is
            // blocking, and `block_in_place` (below) requires a runtime that can
            // hand the reactor to another worker while one is stalled on a
            // backend fetch.
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(_) => return,
            };
            rt.block_on(async move {
                accept_loop(listeners_std, ctx, shutdown_rx).await;
            });
        })
        .map_err(|e| anyhow!("spawning smb thread: {e}"))?;

    Ok(SmbHandle {
        port: bound_port,
        share_name,
        mount,
        failed_logons,
        shutdown_tx: Some(shutdown_tx),
        join_handle: Some(join),
    })
}

async fn accept_loop(
    listeners_std: Vec<StdTcpListener>,
    ctx: Arc<Ctx>,
    shutdown_rx: oneshot::Receiver<()>,
) {
    for listener_std in listeners_std {
        let listener = match TcpListener::from_std(listener_std) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                let stream = match listener.accept().await {
                    Ok((s, _)) => s,
                    // A per-connection failure (the peer went away between the
                    // SYN and the accept, or a signal interrupted the call) is
                    // gone by the next iteration, so retry at once. Anything
                    // else — EMFILE and ENFILE above all — is a condition that
                    // persists, and retrying immediately spins a core at full
                    // tilt until a descriptor frees up.
                    Err(e) => {
                        use std::io::ErrorKind;
                        if !matches!(
                            e.kind(),
                            ErrorKind::Interrupted | ErrorKind::ConnectionAborted
                        ) {
                            smb_log!("accept failed: {e}; backing off");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                        continue;
                    }
                };
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    // Nagle hurts here: SMB2 is request/response with small
                    // headers, and the client is on loopback.
                    let _ = stream.set_nodelay(true);
                    serve_connection(stream, ctx).await;
                });
            }
        });
    }

    let _ = shutdown_rx.await;
}

/// How long a connection may sit without sending anything before it is dropped.
///
/// Generous on purpose. Every client that holds a mount open sends keepalives
/// far more often than this — cifs.ko echoes once a minute by default — so a
/// connection silent this long is one whose peer is gone, and without a bound
/// it would hold its task and socket for as long as the server ran.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Refused logons across the whole server, since the last successful one,
/// before it stops serving.
///
/// Deliberately far above anything a working setup produces. A client replaying
/// a credential that went stale across a restart is *normal* here — the share
/// password is generated per run — and one was observed sending 85 refused
/// logons during a single browsing session without anything being wrong. A
/// limit that a mount could trip by accident would turn a cosmetic annoyance
/// into a share that stops mid-read, which is worse than the thing it guards
/// against.
///
/// It resets on every successful logon, so a working mount holds it near zero
/// indefinitely, and only a client that never authenticates can walk it up.
/// That is what makes a high ceiling safe: 1000 refusals with not one success
/// in between is not a stale credential, it is something trying passwords.
///
/// This is defence in depth rather than the defence. The password is ~94 bits
/// of entropy over a loopback socket; guessing it is not the threat model. The
/// limit exists so a server left running cannot be ground against indefinitely,
/// and so the owner is told.
const MAX_SERVER_LOGON_FAILURES: u32 = 1000;

/// Whether a refusal counter has reached the server-wide limit. Shared by the
/// two readers — the server, deciding whether to accept a logon, and the owning
/// handle, deciding whether to stop — so they cannot drift apart on either the
/// threshold or the ordering.
fn logon_limit_reached(failed: &std::sync::atomic::AtomicU32) -> bool {
    failed.load(std::sync::atomic::Ordering::Relaxed) >= MAX_SERVER_LOGON_FAILURES
}

/// Consecutive refused logons before a connection is dropped.
///
/// A real client tries a small number of identities: the interactive user, then
/// a saved credential, then whatever it prompts for. Anything past that is a
/// client replaying a credential the server will never accept — one was
/// observed sending the same stale password 84 times on a single connection,
/// which is both pointless work and a trace full of noise hiding the connection
/// that was actually failing. Dropping it does not lock anything out: the
/// client is free to reconnect and try again, with the round trip as the only
/// cost.
const MAX_FAILED_LOGONS: u32 = 5;

async fn serve_connection(mut stream: tokio::net::TcpStream, ctx: Arc<Ctx>) {
    let mut conn = Conn::new(ctx);
    if log_enabled() {
        // How many connections a mount opens, and when, is half the story when
        // one of them misbehaves: a client that spreads work across several
        // shows up here as several ids, not as one busy session.
        let peer = match stream.peer_addr() {
            Ok(a) => a.to_string(),
            Err(_) => "<unknown>".to_string(),
        };
        conn_log!(conn.id, "connected from {peer}");
    }
    let mut nb = [0u8; NBSS_HEADER_LEN];
    loop {
        // Only the wait for a *new* message is bounded. Once a header has
        // arrived the rest of that message is already in flight, so timing out
        // partway through it would drop a connection that is working fine.
        match tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut nb)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                conn_log!(conn.id, "dropping: idle for {}s", IDLE_TIMEOUT.as_secs());
                return;
            }
        }
        let Some(len) = nbss_len(&nb) else {
            conn_log!(conn.id, "dropping: NetBIOS message type {:#04x}", nb[0]);
            return;
        };
        if len == 0 {
            // Zero-length NetBIOS message: a keepalive. Nothing to answer.
            continue;
        }
        if len > MAX_INBOUND_MESSAGE {
            return;
        }
        let mut msg = vec![0u8; len];
        if stream.read_exact(&mut msg).await.is_err() {
            return;
        }
        // The file handlers call into ZIP decompression, which blocks — on a cache
        // miss that is an S3 round trip. `block_in_place` moves the reactor to
        // another worker for the duration instead of stalling every other
        // connection on this one. It is applied here, at the single call site,
        // rather than inside the handlers, so the protocol code stays sync and
        // directly unit-testable without a runtime.
        // Verify with the key held *before* this message is processed: the
        // SESSION_SETUP that establishes the key is itself unsigned, and its
        // response is the first thing signed.
        if let Some(key) = conn.state.signing_key {
            let verdict = sign::verify(&key, &msg);
            if !verdict.is_valid() {
                conn_log!(conn.id, "dropping: {}", verdict.describe());
                return;
            }
        }

        let Some(mut resp) = tokio::task::block_in_place(|| conn.handle_message(&msg)) else {
            conn_log!(
                conn.id,
                "dropping: unparseable message, first bytes {:02x?}",
                &msg[..msg.len().min(8)]
            );
            // Unparseable, or an SMB1 negotiate. Dropping the connection is the
            // correct answer: clients retry as SMB2.
            return;
        };
        if resp.is_empty() {
            // CANCEL is answered with silence.
            continue;
        }
        // Sign with the key as it stands *after* processing, so the
        // SESSION_SETUP response that completes authentication carries a
        // signature — Windows verifies that one.
        if let Some(key) = conn.state.signing_key {
            sign::sign(&key, &mut resp);
            // LOGOFF keeps its key just long enough to sign its own reply. It
            // tears the session down, and a client that required signing —
            // which is every client, since we advertise SIGNING_REQUIRED —
            // rejects an unsigned response to it. Now that the signature is
            // written, the key goes.
            if !conn.state.authenticated {
                conn.state.signing_key = None;
            }
        }
        if stream.write_all(&nbss_header(resp.len())).await.is_err() {
            return;
        }
        if stream.write_all(&resp).await.is_err() {
            return;
        }
        // Checked after the reply is on the wire, so the client still learns why
        // its last attempt was refused rather than seeing a bare disconnect.
        if conn.state.failed_logons >= MAX_FAILED_LOGONS {
            conn_log!(
                conn.id,
                "dropping: {} refused logons in a row",
                conn.state.failed_logons
            );
            return;
        }
    }
}

/// One request out of a (possibly compounded) message, with the identity it
/// actually runs under.
///
/// The ids here are not always the ones in `hdr`: a related request carries
/// 0xFF..FF placeholders and inherits the real values from the request before
/// it in the chain. Handlers read them from here so that no handler has to know
/// whether it is part of a chain.
struct Request<'a> {
    hdr: &'a Header,
    body: &'a [u8],
    /// The slice this request's offsets are relative to — its own header
    /// onwards, not the whole compound message.
    message: &'a [u8],
    session_id: u64,
    tree_id: u32,
    /// Whether SMB2_FLAGS_RELATED_OPERATIONS was set, which is what makes the
    /// 0xFF..FF FileId placeholder meaningful.
    related: bool,
    is_only: bool,
}

/// State carried along one compound message.
struct Chain {
    /// Identity a related request inherits. Initialised to values no session or
    /// tree ever has, so a chain that opens with a related request — which no
    /// client sends — is refused rather than inheriting whatever ran last.
    session_id: u64,
    tree_id: u32,
    /// The status of the first CREATE in this chain that failed, if any.
    create_error: Option<u32>,
}

impl Default for Chain {
    fn default() -> Self {
        Self {
            session_id: u64::MAX,
            tree_id: u32::MAX,
            create_error: None,
        }
    }
}

/// Ceiling on the responses assembled from one compound message. Well above any
/// real chain — a Windows CREATE+QUERY+CLOSE answers in a few hundred bytes, and
/// a single READ is capped at `MAX_READ_SIZE` — so it bounds only the
/// pathological case of a long chain of maximal reads.
const MAX_COMPOUND_RESPONSE: usize = 8 * 1024 * 1024;

/// A successful response: body plus any header fields the handler needs to
/// override. Most commands echo the request's session and tree ids, but
/// SESSION_SETUP and TREE_CONNECT report ids the request could not have known.
struct Reply {
    status: u32,
    body: Vec<u8>,
    session_id: Option<u64>,
    tree_id: Option<u32>,
}

impl Reply {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: status::SUCCESS,
            body,
            session_id: None,
            tree_id: None,
        }
    }

    fn status(mut self, status: u32) -> Self {
        self.status = status;
        self
    }

    fn session(mut self, session_id: u64) -> Self {
        self.session_id = Some(session_id);
        self
    }

    fn tree(mut self, tree_id: u32) -> Self {
        self.tree_id = Some(tree_id);
        self
    }
}

/// Per-connection protocol state.
struct Conn {
    ctx: Arc<Ctx>,
    /// Identifies this connection in the trace. Process-wide and monotonic
    /// rather than derived from the socket: a peer address is reused as soon as
    /// a port is, and two connections from the same client are exactly what has
    /// to be told apart.
    id: u64,
    state: SessionState,
    /// Open handles are per-connection: SMB2 file ids are scoped to the
    /// connection that created them and do not survive a reconnect.
    handles: Handles,
    /// The srvsvc pipe, when one is open on this connection's IPC$ tree.
    ///
    /// Kept out of `Handles`, which is built around archive files — paths,
    /// readers, directory cursors — none of which a pipe has. A connection can
    /// hold at most one IPC$ tree and so at most one of these.
    pipe: Option<srvsvc::Pipe>,
}

/// Hands out `Conn::id`. Starts at 1 so id 0 can mean "no connection" in the
/// session state a unit test builds by hand.
fn next_conn_id() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Conn {
    fn new(ctx: Arc<Ctx>) -> Self {
        let id = next_conn_id();
        Self {
            ctx,
            id,
            state: SessionState::new(id),
            handles: Handles::default(),
            pipe: None,
        }
    }

    /// Process one NetBIOS message, which may carry several compounded SMB2
    /// requests chained by `NextCommand`. Returns the assembled response, an
    /// empty vector if the message warrants no reply, or `None` to drop the
    /// connection.
    fn handle_message(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        // macOS opens with an SMB1 multi-protocol negotiate. Answering it with
        // the SMB2 wildcard dialect is what gets the client to re-negotiate in
        // SMB2; dropping it leaves the client waiting for a timeout.
        if session::is_smb1_negotiate(msg) {
            conn_log!(
                self.id,
                "SMB1 multi-protocol NEGOTIATE -> SMB2 wildcard 0x02ff"
            );
            return Some(session::smb1_negotiate_response(
                &self.ctx.server_guid,
                self.ctx.boot_time,
            ));
        }
        if session::is_smb1(msg) {
            // Any other SMB1 command. We do not speak SMB1, and there is no
            // SMB2 status that means "wrong protocol", so the connection goes.
            conn_log!(self.id, "dropping: SMB1 command {:#04x}", msg[4]);
            return None;
        }

        let mut out = Writer::with_capacity(msg.len().max(256));
        let mut offset = 0usize;
        // Identity carried along a related chain, and the failure that poisons
        // the rest of it. Scoped to this message: a chain cannot reach back into
        // the one before it.
        let mut chain = Chain::default();

        loop {
            let chunk = msg.get(offset..)?;
            let mut r = Reader::new(chunk);
            let hdr = Header::parse(&mut r).ok()?;

            let next = hdr.next_command as usize;
            // A request runs to the next chained command, or to the end.
            let end = if next == 0 {
                chunk.len()
            } else {
                if next < HEADER_LEN || next > chunk.len() {
                    return None;
                }
                next
            };
            let body = chunk.get(HEADER_LEN..end)?;
            let is_only = offset == 0 && next == 0;

            // A related request inherits the session and tree of the one before
            // it (MS-SMB2 3.3.5.2.7.1), which is how a client avoids repeating
            // ids it may not know yet. Every client tested here fills in the
            // real ids anyway, so this substitution is a no-op for them — it
            // exists so that one which sends the 0xFF..FF placeholders is not
            // refused. Samba substitutes unconditionally on the flag
            // (smb2_server.c:2580-2582, :2629-2631). The placeholders are *not*
            // echoed back: the response header carries whatever the request
            // carried, as Samba's does (smb2_server.c:1192-1195).
            // A second NEGOTIATE once the dialect is settled is a protocol
            // error, not a re-negotiation: MS-SMB2 3.3.5.3 has the server drop
            // the connection, and Samba does (smb2_server.c:3070-3088).
            // Otherwise a peer could reset the connection's negotiated state
            // from under an authenticated session. Checked here rather than in
            // `execute`, because only this level can actually drop — `execute`
            // returning None means "answer with silence", which is CANCEL's
            // contract and would leave this client waiting for a timeout.
            if hdr.command == cmd::NEGOTIATE && self.state.negotiated {
                conn_log!(self.id, "dropping: NEGOTIATE after the dialect was settled");
                return None;
            }

            let related = hdr.flags & flags::RELATED_OPERATIONS != 0;
            let req = Request {
                hdr: &hdr,
                body,
                message: chunk,
                session_id: if related {
                    chain.session_id
                } else {
                    hdr.session_id
                },
                tree_id: if related { chain.tree_id } else { hdr.tree_id },
                related,
                is_only,
            };
            if !related {
                // The compound placeholder is only meaningful inside a chain.
                // Samba clears its equivalent on every unchained request
                // (smb2_server.c:3183-3185); leaving it set would let a later
                // stray 0xFF..FF resolve onto a handle from an earlier chain.
                self.handles.clear_chain();
            }

            if log_enabled() && hdr.command == cmd::NEGOTIATE {
                conn_log!(
                    self.id,
                    "client offers dialects {:04x?}",
                    session::peek_dialects(body)
                );
            }
            if log_enabled()
                && hdr.command == cmd::CREATE
                && let Some((name, access)) = files::peek_create(body, chunk)
            {
                conn_log!(self.id, "CREATE \"{name}\" access {access:#010x}");
            }
            if log_enabled()
                && hdr.command == cmd::QUERY_INFO
                && let Some((ty, class, output_len)) = files::peek_query_info(body)
            {
                conn_log!(
                    self.id,
                    "QUERY_INFO type {ty} class {class} buffer {output_len}"
                );
            }

            let start = out.len();
            // A CREATE that failed earlier in this chain poisons every related
            // request after it: those name its handle, which does not exist.
            // Answering them individually is what lets a CLOSE addressed to the
            // failed open resolve onto some *other* live handle and shut it —
            // Samba returns the original failure instead (smb2_server.c:3319-3325).
            let outcome = match chain.create_error {
                Some(st) if related => Some(Err(st)),
                _ => self.execute(&req),
            };
            match outcome {
                Some(Ok(reply)) => {
                    conn_log!(
                        self.id,
                        "{} -> {} ({} bytes)",
                        cmd::name(hdr.command),
                        status_name(reply.status),
                        reply.body.len()
                    );
                    // A command that establishes an identity hands it to the
                    // rest of the chain; everything else confirms the one it
                    // ran under.
                    chain.session_id = reply.session_id.unwrap_or(req.session_id);
                    if hdr.command != cmd::TREE_DISCONNECT {
                        chain.tree_id = reply.tree_id.unwrap_or(req.tree_id);
                    }
                    hdr.write_response(
                        &mut out,
                        reply.status,
                        grant_credits(&hdr),
                        reply.session_id.unwrap_or(hdr.session_id),
                        reply.tree_id.unwrap_or(hdr.tree_id),
                    );
                    out.bytes(&reply.body);
                }
                Some(Err(st)) => {
                    conn_log!(self.id, "{} -> {}", cmd::name(hdr.command), status_name(st));
                    if hdr.command == cmd::CREATE && chain.create_error.is_none() {
                        chain.create_error = Some(st);
                    }
                    hdr.write_response(
                        &mut out,
                        st,
                        grant_credits(&hdr),
                        hdr.session_id,
                        hdr.tree_id,
                    );
                    write_error_body(&mut out);
                }
                // No response at all (CANCEL). Only reachable when this is the
                // sole request, so the chain bookkeeping below is unaffected.
                None => {}
            }

            if next == 0 {
                break;
            }
            // One inbound message is capped at MAX_INBOUND_MESSAGE, but its
            // responses are not bounded by it: a chain of READs is tiny on the
            // way in and a megabyte each on the way out. Stop assembling rather
            // than let one message ask for an unbounded allocation.
            if out.len() > MAX_COMPOUND_RESPONSE {
                conn_log!(
                    self.id,
                    "dropping: compound response exceeded {MAX_COMPOUND_RESPONSE} bytes"
                );
                return None;
            }
            // Each compounded response starts on an 8-byte boundary, and its
            // NextCommand holds the distance to the one that follows.
            out.align_to(8);
            let this_len = (out.len() - start) as u32;
            out.patch_u32(start + NEXT_COMMAND_OFFSET, this_len);

            offset += next;
            if offset >= msg.len() {
                break;
            }
        }

        Some(out.into_vec())
    }

    /// Run one request.
    fn execute(&mut self, req: &Request<'_>) -> Option<Result<Reply, u32>> {
        let hdr = req.hdr;
        let (body, message) = (req.body, req.message);

        // CANCEL is answered with silence (MS-SMB2 3.3.5.16), including when it
        // names a session that is gone — checked before the session gate, which
        // would otherwise turn it into an error response and desynchronise the
        // client's message-id tracking.
        if hdr.command == cmd::CANCEL {
            return if req.is_only {
                None
            } else {
                // Compounded CANCEL is not a thing a client sends; refusing it
                // keeps the chain's response count matching its request count.
                Some(Err(status::NOT_SUPPORTED))
            };
        }

        // Anything except NEGOTIATE, SESSION_SETUP and ECHO needs a live
        // session. Skipping this check would let an unauthenticated peer reach
        // the file handlers, which is the whole reason a session exists.
        //
        // ECHO is exempt because cifs.ko's keepalive carries no session id at
        // all — it builds the header with a NULL tcon, so SessionId is 0 — and
        // an idle mount sends one every `echo_interval` (60s by default).
        // Refusing it kills the connection the keepalive exists to hold open.
        // Samba's dispatch table marks SMB2_OP_KEEPALIVE with neither
        // need_session nor need_tcon (smb2_server.c:139-140).
        let needs_session = !matches!(hdr.command, cmd::NEGOTIATE | cmd::SESSION_SETUP | cmd::ECHO);
        if needs_session && (!self.state.authenticated || req.session_id != self.state.session_id) {
            return Some(Err(status::USER_SESSION_DELETED));
        }

        let result = match hdr.command {
            cmd::NEGOTIATE => session::negotiate(
                body,
                &self.ctx.server_guid,
                self.ctx.boot_time,
                &mut self.state,
            )
            .map(Reply::ok),

            // The mirror of the rule above: nothing may precede NEGOTIATE. A
            // SESSION_SETUP without one would run the whole NTLM exchange on a
            // connection that never agreed a dialect.
            cmd::SESSION_SETUP if !self.state.negotiated => {
                conn_log!(self.id, "SESSION_SETUP before NEGOTIATE");
                return Some(Err(status::INVALID_PARAMETER));
            }

            cmd::SESSION_SETUP => {
                // Once the server-wide limit is reached, nothing authenticates
                // again — not even the right password. The owner stops the
                // server on its next poll; this closes the window in between,
                // so the limit is a limit rather than a notification.
                if self.ctx.logon_limit_reached() {
                    conn_log!(
                        self.id,
                        "SESSION_SETUP refused: server logon limit ({MAX_SERVER_LOGON_FAILURES}) reached"
                    );
                    return Some(Err(status::LOGON_FAILURE));
                }
                let result =
                    session::session_setup(body, message, &mut self.state, &self.ctx.credentials);
                // Count consecutive refusals so a client replaying a credential
                // that will never work cannot do it indefinitely.
                //
                // Only a *successful* logon clears the count. The intermediate
                // leg must not, tempting as it looks: a client retrying a stale
                // credential runs the whole two-leg exchange every time, so
                // clearing on the challenge would put the count back to zero
                // before each refusal and make the cap unreachable — which is
                // precisely the client this exists for. A client trying a
                // second identity after a refused first one is unaffected;
                // MAX_FAILED_LOGONS leaves room for several.
                if matches!(&result, Err(st) if *st == status::LOGON_FAILURE) {
                    self.state.failed_logons += 1;
                    let total = self.ctx.record_failed_logon();
                    if total >= MAX_SERVER_LOGON_FAILURES {
                        conn_log!(
                            self.id,
                            "server logon limit reached: {total} refused logons with no \
                             successful one in between — refusing every logon from here"
                        );
                    }
                } else if matches!(&result, Ok((st, _)) if *st == status::SUCCESS) {
                    self.state.failed_logons = 0;
                    self.ctx.clear_failed_logons();
                }
                result.map(|(st, b)| {
                    // Both legs must carry the server-assigned session id: the
                    // client reads it off the first response and uses it from
                    // then on.
                    Reply::ok(b).status(st).session(self.state.session_id)
                })
            }

            cmd::LOGOFF => {
                self.state.authenticated = false;
                self.state.session_id = 0;
                // `signing_key` deliberately survives this: the LOGOFF response
                // still has to be signed. `serve_connection` drops it once the
                // signature is on, and `authenticated` being false is what
                // refuses every later command in the meantime.
                self.handles.close_all();
                // Same reasoning as the handles: the session is gone, so no
                // file id in it can ever be named again.
                self.pipe = None;
                Ok(Reply::ok(session::simple_ack()))
            }

            cmd::TREE_CONNECT => {
                session::tree_connect(body, message, &self.ctx.share_name, &mut self.state).map(
                    |(b, kind, tree_id)| {
                        // A second IPC$ connect replaces the tree id the pipe was
                        // opened under. The pipe itself is per-connection, so leaving
                        // it open would have it answer under the new tree while the
                        // client believes it opened nothing there yet.
                        if kind == TreeKind::Ipc {
                            self.pipe = None;
                        }
                        Reply::ok(b).tree(tree_id)
                    },
                )
            }

            cmd::TREE_DISCONNECT => match self.state.remove_tree(req.tree_id) {
                None => Err(status::NETWORK_NAME_DELETED),
                Some(kind) => {
                    // Handles opened through this tree die with it. A client is
                    // supposed to CLOSE each one first, but nothing makes it,
                    // and a handle left behind is unreachable — its tree id is
                    // gone — while still pinning an open file and its blob
                    // index for as long as the connection lasts. Only this
                    // tree's handles: another tree may still be connected to
                    // the same share, and its opens have to survive.
                    self.handles.close_tree(req.tree_id);
                    if kind == TreeKind::Ipc {
                        // The pipe lives on that tree; leaving it open would
                        // strand a buffer no command could reach again. There
                        // is one pipe per connection, so a second IPC$ tree
                        // would have to reopen it — which is what a client that
                        // wants one does anyway, and TREE_CONNECT to IPC$
                        // already clears it for that reason.
                        self.pipe = None;
                    }
                    Ok(Reply::ok(session::simple_ack()))
                }
            },

            cmd::ECHO => Ok(Reply::ok(session::simple_ack())),

            // The one write smbzip accepts: a DCE/RPC request handed to the
            // srvsvc pipe on IPC$, which lands in a bounded in-memory buffer.
            // Everything else, on any tree, stays refused at the protocol level
            // so a client learns the share is read-only from the operation
            // itself rather than from a confusing failure further along. The
            // archive tree has no writable path at all, here or below.
            cmd::WRITE if self.is_srvsvc_pipe(req.tree_id) => {
                srvsvc::write(body, message, &mut self.pipe, &self.ctx.share_name).map(Reply::ok)
            }
            // A WRITE to IPC$ with no pipe open is a closed handle, not a
            // read-only medium — IPC$ has no medium to protect.
            cmd::WRITE if matches!(self.tree_kind(req.tree_id), Some(TreeKind::Ipc)) => {
                Err(status::FILE_CLOSED)
            }
            cmd::WRITE | cmd::SET_INFO | cmd::FLUSH => Err(status::MEDIA_WRITE_PROTECTED),

            // File commands. All of them need the disk tree, except the handful
            // that drive the srvsvc pipe: reaching them through IPC$ otherwise,
            // or through a tree id that was never connected, is refused before
            // any path is resolved.
            cmd::CREATE | cmd::CLOSE | cmd::READ | cmd::QUERY_DIRECTORY | cmd::QUERY_INFO => {
                match self.tree_kind(req.tree_id) {
                    Some(TreeKind::Disk) => self.file_command(req),
                    Some(TreeKind::Ipc) => self.ipc_command(req),
                    None => Err(status::NETWORK_NAME_DELETED),
                }
            }

            // IOCTL exists for exactly one FSCTL: PIPE_TRANSCEIVE on the srvsvc
            // pipe, which is how Windows carries RPC. macOS probes
            // FSCTL_DFS_GET_REFERRALS and a couple of others during mount;
            // NOT_SUPPORTED is the answer that makes a client move on, and
            // `srvsvc::transceive` returns it for every code but its own.
            cmd::IOCTL if self.is_srvsvc_pipe(req.tree_id) => {
                srvsvc::transceive(body, message, &mut self.pipe, &self.ctx.share_name)
                    .map(|(body, st)| Reply::ok(body).status(st))
            }
            cmd::IOCTL => Err(status::NOT_SUPPORTED),

            // Byte-range locks on immutable data protect nothing, and there is
            // nothing to notify about in an archive that cannot change.
            cmd::LOCK | cmd::CHANGE_NOTIFY | cmd::OPLOCK_BREAK => Err(status::NOT_SUPPORTED),

            _ => Err(status::NOT_SUPPORTED),
        };

        Some(result)
    }

    /// Dispatch to the file handlers. Split out so the tree check above stays
    /// legible and so every one of these shares a single entry point.
    fn file_command(&mut self, req: &Request<'_>) -> Result<Reply, u32> {
        let backing = self.ctx.backing.as_ref();
        let (body, message, related) = (req.body, req.message, req.related);
        match req.hdr.command {
            cmd::CREATE => {
                files::create(body, message, backing, &mut self.handles, req.tree_id).map(Reply::ok)
            }
            cmd::CLOSE => files::close(body, &mut self.handles, related).map(Reply::ok),
            cmd::READ => files::read(body, backing, &mut self.handles, related).map(Reply::ok),
            cmd::QUERY_DIRECTORY => files::query_directory(
                body,
                message,
                backing,
                &mut self.handles,
                self.ctx.boot_time,
                related,
            )
            .map(Reply::ok),
            cmd::QUERY_INFO => files::query_info(
                body,
                backing,
                &self.handles,
                self.ctx.boot_time,
                self.ctx.volume_serial,
                related,
            )
            .map(|(body, st)| Reply::ok(body).status(st)),
            _ => Err(status::NOT_SUPPORTED),
        }
    }

    /// Whether this request is addressed to an open srvsvc pipe.
    ///
    /// The gate on the WRITE and IOCTL arms above, and the whole extent of the
    /// exception to "nothing is writable": the tree must be IPC$ *and* a pipe
    /// must already have been opened on it by CREATE. A request on the archive
    /// tree can never satisfy this.
    fn is_srvsvc_pipe(&self, tree_id: u32) -> bool {
        matches!(self.tree_kind(tree_id), Some(TreeKind::Ipc)) && self.pipe.is_some()
    }

    /// Commands on the IPC$ tree, which exists only to carry share enumeration.
    fn ipc_command(&mut self, req: &Request<'_>) -> Result<Reply, u32> {
        match req.hdr.command {
            cmd::CREATE => srvsvc::create(req.body, req.message, &mut self.pipe).map(Reply::ok),
            cmd::CLOSE => srvsvc::close(req.body, &mut self.pipe).map(Reply::ok),
            cmd::READ => srvsvc::read(req.body, &mut self.pipe).map(Reply::ok),
            // A pipe is not a directory and has no file metadata worth
            // reporting; clients ask neither of these on one.
            _ => Err(status::NOT_SUPPORTED),
        }
    }

    fn tree_kind(&self, tree_id: u32) -> Option<TreeKind> {
        self.state.tree_kind(tree_id)
    }
}

/// Grant what the client asked for, never zero (which would deadlock it) and
/// never more than our ceiling.
fn grant_credits(hdr: &Header) -> u16 {
    hdr.credits.clamp(1, MAX_CREDITS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use backing::test_support::MemBacking;
    use wire::utf16le;

    /// A small tree the end-to-end tests can list and read.
    fn test_backing() -> Arc<dyn Backing> {
        Arc::new(
            MemBacking::new()
                .with_dir("docs")
                .with_file("docs\\readme.txt", b"hello from a ZIP\n")
                .with_file("docs\\notes.md", b"# notes\n")
                .with_file("data.bin", &[0xAB; 9000]),
        )
    }

    const TEST_USER: &str = "wrustic";
    const TEST_PASSWORD: &str = "hunter2";

    fn test_credentials() -> Credentials {
        Credentials {
            user: TEST_USER.to_string(),
            password: TEST_PASSWORD.to_string(),
        }
    }

    fn ctx() -> Arc<Ctx> {
        Arc::new(Ctx {
            share_name: DEFAULT_SHARE_NAME.to_string(),
            backing: test_backing(),
            credentials: test_credentials(),
            volume_serial: 0x1234_5678,
            server_guid: [7u8; 16],
            boot_time: SystemTime::UNIX_EPOCH,
            failed_logons: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        })
    }

    /// Build one SMB2 request message: header followed by `body`.
    fn request(command: u16, session_id: u64, tree_id: u32, body: &[u8]) -> Vec<u8> {
        request_with(command, session_id, tree_id, body, 0, 0)
    }

    fn request_with(
        command: u16,
        session_id: u64,
        tree_id: u32,
        body: &[u8],
        next_command: u32,
        flags: u32,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&proto::SMB2_MAGIC);
        w.u16(HEADER_LEN as u16);
        w.u16(1); // CreditCharge
        w.u32(0); // Status
        w.u16(command);
        w.u16(64); // CreditRequest
        w.u32(flags);
        w.u32(next_command);
        w.u64(1); // MessageId
        w.u32(0); // Reserved
        w.u32(tree_id);
        w.u64(session_id);
        w.zeros(16); // Signature
        w.bytes(body);
        w.into_vec()
    }

    fn negotiate_body(dialects: &[u16]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(36);
        w.u16(dialects.len() as u16);
        w.u16(0);
        w.u16(0);
        w.u32(0);
        w.zeros(16);
        w.u64(0);
        for d in dialects {
            w.u16(*d);
        }
        w.into_vec()
    }

    fn session_setup_body(msg_type: u32) -> Vec<u8> {
        let mut token = Vec::new();
        token.extend_from_slice(b"NTLMSSP\0");
        token.extend_from_slice(&msg_type.to_le_bytes());
        token.extend_from_slice(&[0u8; 32]);
        session_setup_body_with(&token)
    }

    fn session_setup_body_with(token: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(25);
        w.u8(0);
        w.u8(0);
        w.u32(0);
        w.u32(0);
        w.u16((HEADER_LEN + 24) as u16);
        w.u16(token.len() as u16);
        w.u64(0);
        w.bytes(token);
        w.into_vec()
    }

    fn tree_connect_body(path: &str) -> Vec<u8> {
        let encoded = utf16le(path);
        let mut w = Writer::new();
        w.u16(9);
        w.u16(0);
        w.u16((HEADER_LEN + 8) as u16);
        w.u16(encoded.len() as u16);
        w.bytes(&encoded);
        w.into_vec()
    }

    fn parse_response(resp: &[u8]) -> Header {
        Header::parse(&mut Reader::new(resp)).expect("response header parses")
    }

    /// Drive a connection through negotiate + both session-setup legs,
    /// returning the connection and its session id.
    fn connected() -> (Conn, u64) {
        connected_with(ctx())
    }

    fn connected_with(ctx: Arc<Ctx>) -> (Conn, u64) {
        let mut conn = Conn::new(ctx);

        let resp = conn
            .handle_message(&request(
                cmd::NEGOTIATE,
                0,
                0,
                &negotiate_body(&[0x0210, 0x0311]),
            ))
            .expect("negotiate answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        let resp = conn
            .handle_message(&request(cmd::SESSION_SETUP, 0, 0, &session_setup_body(1)))
            .expect("session setup leg one answered");
        let h = parse_response(&resp);
        assert_eq!(h.status, status::MORE_PROCESSING_REQUIRED);
        let session_id = h.session_id;

        // A real NTLMv2 response against the challenge just issued. There is no
        // guest path any more, so tests authenticate exactly as a client does.
        let auth = crate::smb::ntlm::tests_support::build_authenticate(
            TEST_USER,
            "",
            TEST_PASSWORD,
            &conn.state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let body = session_setup_body_with(&auth);
        let resp = conn
            .handle_message(&request(cmd::SESSION_SETUP, session_id, 0, &body))
            .expect("session setup leg two answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);
        assert!(conn.state.signing_key.is_some(), "session must be signed");

        (conn, session_id)
    }

    /// One bad-credential exchange: NEGOTIATE leg, then an AUTHENTICATE built
    /// with the wrong password. Mirrors a client replaying a stale saved
    /// credential, which is what ran a real connection up to 84 attempts.
    fn refused_logon(conn: &mut Conn) {
        let resp = conn
            .handle_message(&request(cmd::SESSION_SETUP, 0, 0, &session_setup_body(1)))
            .expect("challenge leg answered");
        let session_id = parse_response(&resp).session_id;
        let auth = crate::smb::ntlm::tests_support::build_authenticate(
            TEST_USER,
            "",
            "not-the-password",
            &conn.state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let resp = conn
            .handle_message(&request(
                cmd::SESSION_SETUP,
                session_id,
                0,
                &session_setup_body_with(&auth),
            ))
            .expect("refusal is answered, not dropped");
        assert_eq!(parse_response(&resp).status, status::LOGON_FAILURE);
    }

    #[test]
    fn refused_logons_are_counted_up_to_the_cap() {
        let mut conn = Conn::new(ctx());
        let _ = conn.handle_message(&request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210])));

        for expected in 1..=MAX_FAILED_LOGONS {
            refused_logon(&mut conn);
            assert_eq!(
                conn.state.failed_logons, expected,
                "every consecutive refusal counts"
            );
        }
        // `serve_connection` drops the connection at this point, having already
        // written the refusal so the client learns why.
        assert!(conn.state.failed_logons >= MAX_FAILED_LOGONS);
    }

    #[test]
    fn a_successful_logon_clears_the_refusal_count() {
        // A client may try an identity or two before the one that works, and
        // must not be dropped mid-mount for the ones that came first.
        let mut conn = Conn::new(ctx());
        let _ = conn.handle_message(&request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210])));
        refused_logon(&mut conn);
        refused_logon(&mut conn);
        assert_eq!(conn.state.failed_logons, 2);

        let resp = conn
            .handle_message(&request(cmd::SESSION_SETUP, 0, 0, &session_setup_body(1)))
            .expect("challenge leg answered");
        let session_id = parse_response(&resp).session_id;
        let auth = crate::smb::ntlm::tests_support::build_authenticate(
            TEST_USER,
            "",
            TEST_PASSWORD,
            &conn.state.server_challenge.expect("a challenge was issued"),
            None,
        );
        let resp = conn
            .handle_message(&request(
                cmd::SESSION_SETUP,
                session_id,
                0,
                &session_setup_body_with(&auth),
            ))
            .expect("session setup answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);
        assert_eq!(conn.state.failed_logons, 0, "success clears the count");
    }

    #[test]
    fn the_server_refuses_every_logon_once_its_limit_is_reached() {
        use std::sync::atomic::Ordering;

        let ctx = ctx();
        // Fast-forward to one below the limit rather than sending a thousand
        // messages: the counting itself is covered above, and the behaviour
        // under test is what happens at the boundary.
        ctx.failed_logons
            .store(MAX_SERVER_LOGON_FAILURES - 1, Ordering::Relaxed);
        assert!(!ctx.logon_limit_reached(), "one short of the limit");

        let mut conn = Conn::new(ctx.clone());
        let _ = conn.handle_message(&request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210])));
        refused_logon(&mut conn);
        assert!(ctx.logon_limit_reached(), "the last refusal trips it");

        // From here even the right password is refused, on a fresh connection,
        // starting with the very first leg of the exchange. Waiting for the
        // owner to poll would leave a window in which the limit was advice.
        let mut fresh = Conn::new(ctx.clone());
        let _ = fresh.handle_message(&request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210])));
        let resp = fresh
            .handle_message(&request(cmd::SESSION_SETUP, 0, 0, &session_setup_body(1)))
            .expect("refused, not dropped");
        assert_eq!(parse_response(&resp).status, status::LOGON_FAILURE);
        assert!(
            fresh.state.server_challenge.is_none(),
            "no challenge issued"
        );
    }

    #[test]
    fn a_successful_logon_clears_the_server_counter() {
        use std::sync::atomic::Ordering;

        // What makes a high limit safe: a working mount holds the count at zero
        // however much noise a client makes in between, so only a client that
        // never authenticates can walk it up to the limit.
        let ctx = ctx();
        ctx.failed_logons
            .store(MAX_SERVER_LOGON_FAILURES - 1, Ordering::Relaxed);
        let (_conn, _session_id) = connected_with(ctx.clone());
        assert_eq!(ctx.failed_logons.load(Ordering::Relaxed), 0);
        assert!(!ctx.logon_limit_reached());
    }

    #[test]
    fn the_server_logon_counter_saturates_rather_than_wrapping() {
        use std::sync::atomic::Ordering;

        // Wrapping past u32::MAX would drop the count back under the limit and
        // quietly start accepting logons again on a long-lived server.
        let ctx = ctx();
        ctx.failed_logons.store(u32::MAX, Ordering::Relaxed);
        assert_eq!(ctx.record_failed_logon(), u32::MAX);
        assert!(ctx.logon_limit_reached());
    }

    #[test]
    fn random_password_covers_every_class_and_stays_url_safe() {
        // RFC 3986 §2.3 unreserved: safe unencoded in a URL, unquoted in a
        // shell, and unescaped in mount.cifs's comma-separated option list.
        const SYMBOLS: [char; 4] = ['-', '.', '_', '~'];
        let mut symbol_positions = std::collections::HashSet::new();

        for _ in 0..200 {
            let pw = random_password();
            assert_eq!(pw.chars().count(), 16);
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()), "{pw}");
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()), "{pw}");
            assert!(pw.chars().any(|c| c.is_ascii_digit()), "{pw}");
            assert!(pw.chars().any(|c| SYMBOLS.contains(&c)), "{pw}");

            for c in pw.chars() {
                assert!(
                    c.is_ascii_alphanumeric() || SYMBOLS.contains(&c),
                    "{c:?} would need escaping somewhere"
                );
                assert!(!"lIO01".contains(c), "{c:?} is ambiguous read off a screen");
            }
            symbol_positions.extend(
                pw.char_indices()
                    .filter(|(_, c)| SYMBOLS.contains(c))
                    .map(|(i, _)| i),
            );
        }

        // The guaranteed characters are generated in class order, so without the
        // shuffle the symbol would sit at index 3 every time — which leaks the
        // shape of every password the server ever issues.
        assert!(
            symbol_positions.len() > 1,
            "guaranteed characters must be shuffled, not left in class order"
        );
        assert_ne!(random_password(), random_password());
    }

    #[test]
    fn connections_get_distinct_ids_for_the_trace() {
        let a = Conn::new(ctx());
        let b = Conn::new(ctx());
        assert_ne!(a.id, b.id);
        assert_eq!(a.state.conn_id, a.id, "state logs against the same id");
        assert_ne!(a.id, 0, "id 0 means 'no connection'");
    }

    #[test]
    fn log_stamp_is_a_wall_clock_time_to_milliseconds() {
        let s = log_stamp();
        assert_eq!(s.len(), 12, "HH:MM:SS.mmm, got {s:?}");
        assert_eq!(s.as_bytes()[2], b':');
        assert_eq!(s.as_bytes()[8], b'.');
    }

    #[test]
    fn full_handshake_reaches_a_connected_tree() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id,
                0,
                &tree_connect_body(r"\\127.0.0.1\zip"),
            ))
            .expect("tree connect answered");
        let h = parse_response(&resp);
        assert_eq!(h.status, status::SUCCESS);
        assert_ne!(h.tree_id, 0);
    }

    #[test]
    fn commands_before_authentication_are_refused() {
        let mut conn = Conn::new(ctx());
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                0,
                0,
                &tree_connect_body("zip"),
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::USER_SESSION_DELETED);
    }

    #[test]
    fn a_forged_session_id_is_refused() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id ^ 0xFFFF,
                0,
                &tree_connect_body(r"\\127.0.0.1\zip"),
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::USER_SESSION_DELETED);
    }

    #[test]
    fn write_commands_report_a_write_protected_medium() {
        let (mut conn, session_id) = connected();
        for command in [cmd::WRITE, cmd::SET_INFO, cmd::FLUSH] {
            let resp = conn
                .handle_message(&request(command, session_id, 0, &[0u8; 8]))
                .expect("answered");
            assert_eq!(
                parse_response(&resp).status,
                status::MEDIA_WRITE_PROTECTED,
                "command {}",
                cmd::name(command)
            );
        }
    }

    #[test]
    fn logoff_invalidates_the_session() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(cmd::LOGOFF, session_id, 0, &[4, 0, 0, 0]))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);
        // The key has to outlive the handler: `serve_connection` signs this very
        // response with it, and a client that required signing rejects an
        // unsigned reply. It is dropped there, once the signature is written.
        assert!(
            conn.state.signing_key.is_some(),
            "the LOGOFF response still has to be signed"
        );
        assert!(!conn.state.authenticated, "but the session is gone");

        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id,
                0,
                &tree_connect_body(r"\\127.0.0.1\zip"),
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::USER_SESSION_DELETED);
    }

    /// cifs.ko sends its keepalive with a NULL tcon, so SessionId is 0 and the
    /// header is unsigned. Requiring a session for ECHO turns the one message
    /// that exists to hold an idle mount open into the thing that drops it —
    /// every `echo_interval`, silently. Samba's dispatch table marks
    /// SMB2_OP_KEEPALIVE with neither need_session nor need_tcon.
    #[test]
    fn a_session_less_echo_is_answered_rather_than_refused() {
        let (mut conn, _session_id) = connected();
        let resp = conn
            .handle_message(&request(cmd::ECHO, 0, 0, &[4, 0, 0, 0]))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);
    }

    /// The signing counterpart: that same keepalive carries no signature, and a
    /// connection that has a key must still not drop it.
    #[test]
    fn an_unsigned_session_less_echo_passes_verification() {
        let (conn, _session_id) = connected();
        let key = conn.state.signing_key.expect("session is signed");

        let echo = request(cmd::ECHO, 0, 0, &[4, 0, 0, 0]);
        assert!(
            sign::verify(&key, &echo).is_valid(),
            "an unsigned session-0 ECHO must be accepted: {}",
            sign::verify(&key, &echo).describe()
        );

        // The exemption is exactly that narrow: the same PDU on a real session
        // is still refused, and so is any other command at session 0.
        let echo = request(cmd::ECHO, 1, 0, &[4, 0, 0, 0]);
        assert!(!sign::verify(&key, &echo).is_valid());
        let read = request(cmd::READ, 0, 0, &[49, 0]);
        assert!(!sign::verify(&key, &read).is_valid());
    }

    #[test]
    fn cancel_alone_produces_no_response() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(cmd::CANCEL, session_id, 0, &[4, 0, 0, 0]))
            .expect("connection stays open");
        assert!(resp.is_empty(), "CANCEL is answered with silence");
    }

    /// macOS opens every connection with an SMB1 multi-protocol negotiate.
    /// It must be answered with the SMB2 wildcard dialect, not dropped — a
    /// dropped connection is an invisible failure that ends in a client-side
    /// timeout.
    #[test]
    fn an_smb1_multi_protocol_negotiate_gets_the_smb2_wildcard() {
        let mut conn = Conn::new(ctx());
        // \xFFSMB followed by SMB_COM_NEGOTIATE.
        let mut msg = vec![0xFF, b'S', b'M', b'B', 0x72];
        msg.extend_from_slice(&[0u8; 32]);

        let resp = conn.handle_message(&msg).expect("must be answered");
        let hdr = parse_response(&resp);
        assert_eq!(hdr.command, cmd::NEGOTIATE);
        assert_eq!(hdr.status, status::SUCCESS);
        assert_eq!(hdr.message_id, 0);
        assert!(
            hdr.credits >= 1,
            "zero credits would stall the re-negotiation"
        );

        let dialect = u16::from_le_bytes(resp[HEADER_LEN + 4..HEADER_LEN + 6].try_into().unwrap());
        assert_eq!(dialect, proto::DIALECT_WILDCARD);

        // The client now re-negotiates in SMB2 and the normal path takes over.
        let resp = conn
            .handle_message(&request(
                cmd::NEGOTIATE,
                0,
                0,
                &negotiate_body(&[0x0210, 0x0311]),
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);
        let dialect = u16::from_le_bytes(resp[HEADER_LEN + 4..HEADER_LEN + 6].try_into().unwrap());
        assert_eq!(dialect, proto::DIALECT_SMB_2_1);
    }

    /// NEGOTIATE settles the dialect once. A second one is a protocol error,
    /// and answering it would let a peer reset the connection's negotiated
    /// state from under an authenticated session.
    #[test]
    fn a_second_negotiate_drops_the_connection() {
        let mut conn = Conn::new(ctx());
        let neg = request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210]));
        assert!(conn.handle_message(&neg).is_some(), "the first is answered");
        assert!(
            conn.handle_message(&neg).is_none(),
            "the second must drop the connection, not be answered"
        );
    }

    /// The mirror: the NTLM exchange must not run on a connection that never
    /// agreed a dialect.
    #[test]
    fn session_setup_before_negotiate_is_refused() {
        let mut conn = Conn::new(ctx());
        let resp = conn
            .handle_message(&request(cmd::SESSION_SETUP, 0, 0, &session_setup_body(1)))
            .expect("answered rather than dropped");
        assert_eq!(parse_response(&resp).status, status::INVALID_PARAMETER);
        assert!(conn.state.server_challenge.is_none(), "no challenge issued");
    }

    #[test]
    fn other_smb1_commands_drop_the_connection() {
        let mut conn = Conn::new(ctx());
        let mut msg = request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210]));
        msg[0] = 0xFF; // \xFFSMB with a command byte that is not NEGOTIATE
        assert!(conn.handle_message(&msg).is_none());
    }

    #[test]
    fn a_truncated_message_drops_the_connection() {
        let mut conn = Conn::new(ctx());
        let msg = request(cmd::NEGOTIATE, 0, 0, &negotiate_body(&[0x0210]));
        assert!(conn.handle_message(&msg[..HEADER_LEN - 1]).is_none());
    }

    #[test]
    fn compounded_requests_produce_a_chained_response() {
        let (mut conn, session_id) = connected();

        // Two ECHOs in one message: the first chains to the second.
        let echo_body = [4u8, 0, 0, 0];
        let mut first = request_with(cmd::ECHO, session_id, 0, &echo_body, 0, 0);
        // Pad the first request to an 8-byte boundary and point NextCommand at
        // the second, exactly as a client does.
        while !first.len().is_multiple_of(8) {
            first.push(0);
        }
        let next_command = first.len() as u32;
        first[NEXT_COMMAND_OFFSET..NEXT_COMMAND_OFFSET + 4]
            .copy_from_slice(&next_command.to_le_bytes());
        let second = request_with(
            cmd::ECHO,
            session_id,
            0,
            &echo_body,
            0,
            proto::flags::RELATED_OPERATIONS,
        );
        let mut msg = first;
        msg.extend_from_slice(&second);

        let resp = conn.handle_message(&msg).expect("answered");

        let h1 = parse_response(&resp);
        assert_eq!(h1.status, status::SUCCESS);
        assert_ne!(h1.next_command, 0, "first response must chain");
        assert!(
            h1.next_command.is_multiple_of(8),
            "chained responses start on an 8-byte boundary, got {}",
            h1.next_command
        );

        let h2 = parse_response(&resp[h1.next_command as usize..]);
        assert_eq!(h2.status, status::SUCCESS);
        assert_eq!(h2.next_command, 0, "last response terminates the chain");
        assert_eq!(
            h2.flags & proto::flags::RELATED_OPERATIONS,
            proto::flags::RELATED_OPERATIONS,
            "RELATED_OPERATIONS is echoed so the client can match the chain"
        );
    }

    /// Build a compound message from a list of (command, body, related)
    /// requests, chaining them the way a client does: each padded to an 8-byte
    /// boundary with NextCommand pointing at the one after it, and every
    /// related request carrying the 0xFF..FF session and tree placeholders.
    fn compound(session_id: u64, tree_id: u32, parts: &[(u16, Vec<u8>, bool)]) -> Vec<u8> {
        let mut msg: Vec<u8> = Vec::new();
        let mut starts: Vec<usize> = Vec::new();
        for (command, body, related) in parts {
            let start = msg.len();
            starts.push(start);
            let (sid, tid, flags) = if *related {
                (u64::MAX, u32::MAX, proto::flags::RELATED_OPERATIONS)
            } else {
                (session_id, tree_id, 0)
            };
            msg.extend_from_slice(&request_with(*command, sid, tid, body, 0, flags));
            while !msg.len().is_multiple_of(8) {
                msg.push(0);
            }
        }
        // Patch each NextCommand to the distance to its successor.
        for (i, &start) in starts.iter().enumerate() {
            let end = starts.get(i + 1).copied().unwrap_or(msg.len());
            let next = if i + 1 < starts.len() {
                (end - start) as u32
            } else {
                0
            };
            msg[start + NEXT_COMMAND_OFFSET..start + NEXT_COMMAND_OFFSET + 4]
                .copy_from_slice(&next.to_le_bytes());
        }
        msg
    }

    /// Walk a compound response into its per-request headers.
    fn chained_responses(resp: &[u8]) -> Vec<Header> {
        let mut out = Vec::new();
        let mut at = 0usize;
        loop {
            let h = parse_response(&resp[at..]);
            let next = h.next_command as usize;
            out.push(h);
            if next == 0 {
                break;
            }
            at += next;
        }
        out
    }

    fn create_body_for(name: &str) -> Vec<u8> {
        let encoded = utf16le(name);
        let mut w = Writer::new();
        w.u16(57);
        w.u8(0); // SecurityFlags
        w.u8(0); // RequestedOplockLevel
        w.u32(2); // ImpersonationLevel
        w.u64(0); // SmbCreateFlags
        w.u64(0); // Reserved
        w.u32(0x0012_0089); // DesiredAccess — read
        w.u32(0); // FileAttributes
        w.u32(7); // ShareAccess
        w.u32(1); // CreateDisposition — OPEN
        w.u32(0); // CreateOptions
        w.u16((HEADER_LEN + 56) as u16); // NameOffset
        w.u16(encoded.len() as u16);
        w.u32(0); // CreateContextsOffset
        w.u32(0); // CreateContextsLength
        w.bytes(&encoded);
        w.into_vec()
    }

    fn close_body_for(file_id: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(24);
        w.u16(0); // Flags
        w.u32(0); // Reserved
        w.u64(file_id); // Persistent
        w.u64(file_id); // Volatile
        w.into_vec()
    }

    fn query_info_body_for(file_id: u64) -> Vec<u8> {
        let mut w = Writer::new();
        w.u16(41);
        w.u8(1); // InfoType — FILE
        w.u8(5); // FileStandardInformation
        w.u32(4096); // OutputBufferLength
        w.u16(0);
        w.u16(0);
        w.u32(0);
        w.u32(0);
        w.u32(0);
        w.u64(file_id);
        w.u64(file_id);
        w.into_vec()
    }

    /// Connect the disk tree and return its id.
    fn connect_tree(conn: &mut Conn, session_id: u64) -> u32 {
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id,
                0,
                &tree_connect_body(r"\\127.0.0.1\zip"),
            ))
            .expect("tree connect answered");
        parse_response(&resp).tree_id
    }

    /// A compound in the fully-placeholder form the spec allows: CREATE, then
    /// QUERY_INFO and CLOSE chained behind it with placeholder session, tree
    /// and file ids.
    ///
    /// No client tested against this server sends that form — Windows 11 fills
    /// in the real ids even on the requests it flags RELATED — but the spec
    /// permits it and Samba implements it, and checking the header's own
    /// SessionId against the session answers the whole chain with
    /// USER_SESSION_DELETED. MS-SMB2 3.3.5.2.7.1 has the server inherit them
    /// from the previous request; Samba substitutes unconditionally on the
    /// CHAINED flag (smb2_server.c:2580-2582, :2629-2631).
    #[test]
    fn a_related_compound_inherits_the_session_and_tree_of_its_chain() {
        let (mut conn, session_id) = connected();
        let tree_id = connect_tree(&mut conn, session_id);

        let msg = compound(
            session_id,
            tree_id,
            &[
                (cmd::CREATE, create_body_for("docs\\readme.txt"), false),
                (cmd::QUERY_INFO, query_info_body_for(u64::MAX), true),
                (cmd::CLOSE, close_body_for(u64::MAX), true),
            ],
        );
        let resp = conn.handle_message(&msg).expect("answered");
        let headers = chained_responses(&resp);

        assert_eq!(headers.len(), 3, "one response per request");
        for (h, name) in headers.iter().zip(["CREATE", "QUERY_INFO", "CLOSE"]) {
            assert_eq!(
                h.status,
                status::SUCCESS,
                "{name} in a related chain must succeed, got {}",
                status_name(h.status)
            );
        }
        assert_eq!(
            conn.handles.len(),
            0,
            "the chain's CLOSE released the handle"
        );
    }

    /// A CREATE that fails poisons the rest of its chain. The requests after it
    /// name a handle that was never opened; answering them individually is what
    /// lets a CLOSE carrying the placeholder resolve onto some *other* live
    /// handle and shut it. Windows probes for desktop.ini and Thumbs.db with
    /// exactly this shape constantly, so a failing one is routine.
    #[test]
    fn a_failed_create_poisons_the_rest_of_its_chain() {
        let (mut conn, session_id) = connected();
        let tree_id = connect_tree(&mut conn, session_id);

        // A handle the client still holds, opened by an earlier message.
        let resp = conn
            .handle_message(&request(
                cmd::CREATE,
                session_id,
                tree_id,
                &create_body_for("docs\\readme.txt"),
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);
        assert_eq!(conn.handles.len(), 1);

        // Now the probe: CREATE a path that does not exist, with QUERY_INFO and
        // CLOSE chained behind it on the placeholder.
        let msg = compound(
            session_id,
            tree_id,
            &[
                (cmd::CREATE, create_body_for("docs\\desktop.ini"), false),
                (cmd::QUERY_INFO, query_info_body_for(u64::MAX), true),
                (cmd::CLOSE, close_body_for(u64::MAX), true),
            ],
        );
        let resp = conn.handle_message(&msg).expect("answered");
        let headers = chained_responses(&resp);

        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].status, status::OBJECT_NAME_NOT_FOUND);
        for h in &headers[1..] {
            assert_eq!(
                h.status,
                status::OBJECT_NAME_NOT_FOUND,
                "the failed CREATE's status must carry down the chain"
            );
        }
        assert_eq!(
            conn.handles.len(),
            1,
            "the unrelated handle the client still holds must survive"
        );
    }

    /// TREE_CONNECT hands its new tree id to the rest of the chain, which is
    /// how a client mounts and opens in one round trip. Samba does the same
    /// (`req->last_tid = tcon->global->tcon_wire_id`, smb2_tcon.c:510).
    #[test]
    fn a_related_request_inherits_a_tree_the_same_chain_connected() {
        let (mut conn, session_id) = connected();
        let msg = compound(
            session_id,
            0,
            &[
                (
                    cmd::TREE_CONNECT,
                    tree_connect_body(r"\\127.0.0.1\zip"),
                    false,
                ),
                (cmd::CREATE, create_body_for("docs"), true),
            ],
        );
        let resp = conn.handle_message(&msg).expect("answered");
        let headers = chained_responses(&resp);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].status, status::SUCCESS, "tree connect");
        assert_eq!(
            headers[1].status,
            status::SUCCESS,
            "the CREATE must run on the tree its chain just connected, got {}",
            status_name(headers[1].status)
        );
    }

    /// The placeholder must not survive the message that set it. Two separate
    /// messages are two separate chains, however they are flagged.
    #[test]
    fn the_compound_placeholder_does_not_leak_between_messages() {
        let (mut conn, session_id) = connected();
        let tree_id = connect_tree(&mut conn, session_id);

        let resp = conn
            .handle_message(&request(
                cmd::CREATE,
                session_id,
                tree_id,
                &create_body_for("docs\\readme.txt"),
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        // A fresh message whose first request carries the placeholder inherits
        // nothing — there is no previous request in *this* chain.
        let msg = compound(
            session_id,
            tree_id,
            &[(cmd::CLOSE, close_body_for(u64::MAX), true)],
        );
        let resp = conn.handle_message(&msg).expect("answered");
        assert_ne!(
            parse_response(&resp).status,
            status::SUCCESS,
            "a chain cannot reach back into the one before it"
        );
        assert_eq!(conn.handles.len(), 1, "the handle must still be open");
    }

    #[test]
    fn a_compound_chain_pointing_out_of_bounds_drops_the_connection() {
        let (mut conn, session_id) = connected();
        let msg = request_with(cmd::ECHO, session_id, 0, &[4, 0, 0, 0], 0xFFFF, 0);
        assert!(conn.handle_message(&msg).is_none());
    }

    #[test]
    fn credits_are_granted_within_bounds() {
        let mut hdr = Header::parse(&mut Reader::new(&request(cmd::ECHO, 1, 0, &[]))).unwrap();
        hdr.credits = 0;
        assert_eq!(
            grant_credits(&hdr),
            1,
            "zero credits would stall the client"
        );
        hdr.credits = 10_000;
        assert_eq!(grant_credits(&hdr), MAX_CREDITS);
        hdr.credits = 64;
        assert_eq!(grant_credits(&hdr), 64);
    }

    #[test]
    fn tree_disconnect_releases_the_tree() {
        let (mut conn, session_id) = connected();
        let resp = conn
            .handle_message(&request(
                cmd::TREE_CONNECT,
                session_id,
                0,
                &tree_connect_body(r"\\127.0.0.1\zip"),
            ))
            .unwrap();
        let tree_id = parse_response(&resp).tree_id;

        let resp = conn
            .handle_message(&request(
                cmd::TREE_DISCONNECT,
                session_id,
                tree_id,
                &[4, 0, 0, 0],
            ))
            .unwrap();
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        let resp = conn
            .handle_message(&request(
                cmd::TREE_DISCONNECT,
                session_id,
                tree_id,
                &[4, 0, 0, 0],
            ))
            .unwrap();
        assert_eq!(parse_response(&resp).status, status::NETWORK_NAME_DELETED);
    }

    /// macOS connects the share again while the mount is still live, then drops
    /// the extra tree. Remembering a single disk tree id per session meant the
    /// second connect retired the first, so everything the mount did afterwards
    /// answered NETWORK_NAME_DELETED — Finder and `ls` reported an empty share
    /// over a mount that was otherwise fine. Measured against macOS 26.6 smbfs,
    /// which opened and dropped five trees over one mount.
    #[test]
    fn a_later_connect_to_the_same_share_leaves_the_earlier_tree_usable() {
        let (mut conn, session_id) = connected();
        let first = connect_tree(&mut conn, session_id);
        let second = connect_tree(&mut conn, session_id);
        assert_ne!(first, second, "each connect gets its own id");

        let opens = |conn: &mut Conn, tree: u32| {
            let resp = conn
                .handle_message(&request(
                    cmd::CREATE,
                    session_id,
                    tree,
                    &create_body_for("docs"),
                ))
                .expect("answered");
            parse_response(&resp).status
        };

        assert_eq!(
            opens(&mut conn, first),
            status::SUCCESS,
            "the earlier tree must survive a later connect to the same share"
        );

        let resp = conn
            .handle_message(&request(
                cmd::TREE_DISCONNECT,
                session_id,
                second,
                &[4, 0, 0, 0],
            ))
            .expect("answered");
        assert_eq!(parse_response(&resp).status, status::SUCCESS);

        assert_eq!(
            opens(&mut conn, first),
            status::SUCCESS,
            "disconnecting one tree must not take another one down with it"
        );
    }

    #[test]
    fn server_starts_on_an_ephemeral_port_and_stops() {
        let handle = start(
            0,
            DEFAULT_SHARE_NAME,
            test_backing(),
            Bind::Loopback,
            test_credentials(),
        )
        .expect("server starts");
        assert_ne!(handle.port, 0);
        assert_eq!(handle.unc(), r"\\127.0.0.1\zip");
        handle.stop();
    }

    /// End-to-end handshake against a real SMB client. Unit tests can only
    /// confirm the bytes match our reading of the spec; this confirms they
    /// match what a client actually accepts, which is the part that matters.
    ///
    /// Skipped when smbclient is not installed rather than failing, so the
    /// suite still runs on a machine without Samba's client tools.
    #[test]
    fn smbclient_completes_the_handshake() {
        use std::process::Command;

        if Command::new("smbclient").arg("--version").output().is_err() {
            eprintln!("skipping: smbclient is not installed");
            return;
        }

        let handle = start(
            0,
            DEFAULT_SHARE_NAME,
            test_backing(),
            Bind::Loopback,
            test_credentials(),
        )
        .expect("server starts");
        let target = format!("//127.0.0.1/{}", handle.share_name);

        let out = Command::new("smbclient")
            .arg(&target)
            .args(["-p", &handle.port.to_string()])
            .args(["-U", &format!("{TEST_USER}%{TEST_PASSWORD}")])
            // Pin the client to 2.1 so a dialect mismatch shows up here as a
            // clear failure rather than as a confusing later error.
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .args(["-c", "quit"])
            .output()
            .expect("smbclient runs");

        handle.stop();

        assert!(
            out.status.success(),
            "smbclient failed to connect\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// Run one smbclient command against a fresh server, returning its stdout.
    /// Returns None when smbclient is not installed.
    fn smbclient(command: &str) -> Option<String> {
        use std::process::Command;

        if Command::new("smbclient").arg("--version").output().is_err() {
            eprintln!("skipping: smbclient is not installed");
            return None;
        }

        let handle = start(
            0,
            DEFAULT_SHARE_NAME,
            test_backing(),
            Bind::Loopback,
            test_credentials(),
        )
        .expect("server starts");
        let target = format!("//127.0.0.1/{}", handle.share_name);
        let out = Command::new("smbclient")
            .arg(&target)
            .args(["-p", &handle.port.to_string()])
            .args(["-U", &format!("{TEST_USER}%{TEST_PASSWORD}")])
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .args(["-c", command])
            .output()
            .expect("smbclient runs");
        handle.stop();

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            out.status.success(),
            "smbclient `{command}` failed\nstdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        Some(stdout)
    }

    /// Hold a server open on a fixed port so an external client can be pointed
    /// at it. Run with: cargo test --all-features smb_manual_server -- --ignored --nocapture
    #[test]
    #[ignore]
    fn smb_manual_server() {
        let port: u16 = std::env::var("SMBZIP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4455);
        let handle = start(
            port,
            DEFAULT_SHARE_NAME,
            test_backing(),
            Bind::Loopback,
            test_credentials(),
        )
        .expect("server starts");
        eprintln!("serving \\\\127.0.0.1\\zip on port {}", handle.port);
        std::thread::sleep(std::time::Duration::from_secs(120));
        handle.stop();
    }

    #[test]
    fn smbclient_lists_the_share_root() {
        let Some(out) = smbclient("ls") else { return };
        assert!(out.contains("docs"), "missing directory in listing:\n{out}");
        assert!(out.contains("data.bin"), "missing file in listing:\n{out}");
        // The size column must reflect the real file size.
        assert!(out.contains("9000"), "wrong size reported:\n{out}");
    }

    #[test]
    fn smbclient_lists_a_subdirectory() {
        let Some(out) = smbclient("cd docs; ls") else {
            return;
        };
        assert!(out.contains("readme.txt"), "missing entry:\n{out}");
        assert!(out.contains("notes.md"), "missing entry:\n{out}");
    }

    #[test]
    fn smbclient_reads_file_content() {
        let dir = ScratchDir::new("smb-read");
        let dest = dir.join("readme.txt");
        // Quoted: the scratch path runs through CARGO_MANIFEST_DIR, and
        // smbclient splits its -c command on whitespace.
        let Some(_) = smbclient(&format!("get docs\\readme.txt \"{}\"", dest.display())) else {
            return;
        };
        let got = std::fs::read(&dest).expect("downloaded file exists");
        assert_eq!(
            got, b"hello from a ZIP\n",
            "content read over SMB must match the source"
        );
    }

    #[test]
    fn smbclient_refuses_to_write() {
        use std::process::Command;

        if Command::new("smbclient").arg("--version").output().is_err() {
            return;
        }
        let handle = start(
            0,
            DEFAULT_SHARE_NAME,
            test_backing(),
            Bind::Loopback,
            test_credentials(),
        )
        .expect("server starts");
        let target = format!("//127.0.0.1/{}", handle.share_name);

        let src = ScratchDir::new("smb-write");
        let file = src.join("payload.txt");
        std::fs::write(&file, b"should not land").expect("write scratch file");

        let out = Command::new("smbclient")
            .arg(&target)
            .args(["-p", &handle.port.to_string()])
            .args(["-U", &format!("{TEST_USER}%{TEST_PASSWORD}")])
            .arg("--option=client min protocol=SMB2_10")
            .arg("--option=client max protocol=SMB2_10")
            .args(["-c", &format!("put {} payload.txt", file.display())])
            .output()
            .expect("smbclient runs");
        handle.stop();

        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            combined.contains("NT_STATUS_MEDIA_WRITE_PROTECTED")
                || combined.contains("NT_STATUS_ACCESS_DENIED"),
            "a write must be refused with a read-only status, got:\n{combined}"
        );
    }

    /// A scratch directory under tmp/, removed when the test ends — including
    /// the early return every one of these tests takes when smbclient is not
    /// installed, which is always the case on Windows.
    struct ScratchDir(std::path::PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            // Per the project convention, scratch data lives under tmp/.
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tmp")
                .join(format!("{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&path).expect("scratch dir");
            Self(path)
        }

        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
