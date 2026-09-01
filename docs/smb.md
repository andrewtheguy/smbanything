# The SMB server

`smbanything_core` is a hand-rolled read-only SMB 2.1 server — no SMB crate —
because the read-only half of SMB 2.1 against immutable backing data is small:
no write path, no file locking, no cache invalidation, no oplocks worth
honouring. The `smbanything` binary serves archives over it; other projects
(wrustic serves restic snapshots) embed the same crate with their own
[`Backing`](../smbanything_core/src/smb/backing.rs) implementation.

## Security

**Every client authenticates.** NTLMv2 (MS-NLMP) with a per-server random
password; there is no guest path. All three client platforms support NTLMv2 and
Windows accepts nothing less, so a second unauthenticated path would only
weaken the first one.

**Every message is signed.** HMAC-SHA256 over each PDU. Unsigned messages on an
authenticated session are rejected rather than skipped — accepting them would
make signing trivially bypassable. `SIGNING_REQUIRED` is advertised alongside
`SIGNING_ENABLED`, without which a client is free to sign the handshake and then
stop.

**Nothing is encrypted.** SMB 3.x encryption is not implemented. Signing stops
tampering, not reading. This is why loopback is the default bind: on a real
interface, anyone on the network can read file contents in transit.
`Bind::AllInterfaces` is an explicit opt-in.

**Writes are impossible, and also refused.** The `Backing` trait contains no
mutation operations, so there is no code that could write through the share. On
top of that, the protocol layer refuses write access bits (`ACCESS_DENIED`),
write dispositions and `DELETE_ON_CLOSE` (`MEDIA_WRITE_PROTECTED`), so a client
sees "read-only filesystem" at the point it asks rather than an error partway
through.

`SMB2 WRITE` has exactly one destination that is not an outright refusal: the
`srvsvc` pipe on the IPC$ tree, where a client writes the DCE/RPC request that
asks what shares exist (see [Share enumeration](#share-enumeration)). It lands
in a bounded in-memory buffer, is gated on the tree being IPC$ *and* the pipe
having been opened, and has no path to backing data — the disk tree still has
no writable route at all. The "impossible" half of the guarantee is unchanged;
only "every WRITE is refused" needed qualifying.

## Share enumeration

A client that knows the full path has always worked — `\\host\<share>`,
`smb://host/<share>`. A client asked to *list* what the server offers had
nothing to go on, because IPC$ was accepted (macOS connects to it during mount)
but answered `NOT_SUPPORTED` to every command, so the `srvsvc` pipe could never
be opened. In Explorer that was typing `\\host\` and waiting; in Finder it was
connecting to `smb://host` and being offered no share to pick, leaving the user
to reach the mount point by hand. Explorer is answered now. Finder is answered
only on port 445, for a client-side reason covered
[below](#macos-only-ever-enumerates-the-standard-port).

`srvsvc.rs` answers the one call that question needs: **NetrShareEnum**
(opnum 15), info level 1, over DCE/RPC on the pipe. Windows carries RPC with
`FSCTL_PIPE_TRANSCEIVE`; other clients use a WRITE/READ pair — both are
supported, and a Windows `net view` was observed using both in one exchange.

Everything else — every other opnum, every other interface — gets a DCE/RPC
fault. That is a well-formed "no" a client acts on, as opposed to silence,
which makes it retry and stall. This is not an RPC stack; it is the smallest
thing that answers "what shares do you have?" truthfully.

One thing enumeration does *not* fix: an **unauthenticated** `net view` still
takes tens of seconds before it gets anywhere, because Windows spends that time
on credential negotiation before it sends a single byte we would see. Measured
on the same build, authenticated enumeration takes ~70 ms and lists the share;
unauthenticated took 18.9 s. That wait is the client's, not the server's.

### macOS only ever enumerates the standard port

Finder lists this share when it is served on 445 and never otherwise, and the
reason is entirely client-side. Connect to `smb://127.0.0.1:4456` and the
negotiate, the NTLM sign-on and the `IPC$` TREE_CONNECT all succeed on that
port — and then macOS opens a **second TCP connection** for the `srvsvc` call,
to `127.0.0.1:445`, and when that is refused to `127.0.0.1:139`. The port the
URL was reached on is not carried into that step. Both connections are refused,
`smbutil view` reports `unable to list resources: Broken pipe`, and the server
log shows the IPC$ tree connected and disconnected again with nothing in
between:

```
[smb 20:51:35.636] conn 1: TREE_CONNECT -> SUCCESS (16 bytes)
[smb 20:51:35.795] conn 1: TREE_DISCONNECT -> SUCCESS (4 bytes)
[smb 20:51:35.796] conn 1: LOGOFF -> SUCCESS (4 bytes)
```

That trace reads exactly like a server that gave up half way through a tree it
had just accepted, which is why it is written down here: the 159 ms gap is the
client failing to reach two ports this server was never on. Nothing in
`srvsvc.rs` participates — the client never gets as far as opening the pipe.
The same build served on 445 instead (which is what the
[packet tunnel](smb-tun.md) is for) lists the share in ~60 ms, over
`CREATE srvsvc` and two `FSCTL_PIPE_TRANSCEIVE`s carried on the connection
that was already open.

`smbutil view` and Finder's own browsing both go through
`SMBClient.framework`, so this is not a quirk of the command-line tool, and an
already-mounted share on the custom port does not prime it either — the
enumeration redials regardless of what is mounted. Mounting is unaffected,
because that whole exchange stays on the connection the URL opened: a full
`smb://user@127.0.0.1:4456/<share>` URL mounts, lists and reads normally. That
is why an embedder should print the full path and not the server on its own.
Measured against macOS 26.6 (Darwin 25.6.0).

## Scope

SMB **2.1 only** (`0x0210`). Deliberate: 2.1 is the newest dialect that avoids
pre-auth integrity hashes, negotiate contexts, AES-CMAC signing and AES-GCM
encryption — a large amount of cryptographic machinery for a loopback share of
an immutable tree. A client opening with an SMB1 `SMB_COM_NEGOTIATE` (macOS and
Windows both do) gets the SMB2 wildcard dialect `0x02FF` back and retries as
SMB2.

Implemented: NEGOTIATE, SESSION_SETUP, TREE_CONNECT/DISCONNECT, CREATE, CLOSE,
READ, QUERY_DIRECTORY, QUERY_INFO, LOGOFF, ECHO. Compound requests
(`NextCommand`) and credit-based flow control are handled. Everything else is
refused with a specific NTSTATUS.

### Known limitations

- **Only "file" and "directory" exist.** SMB2 without POSIX extensions has no
  other answer, so whatever a backing chooses to present a symlink, device or
  FIFO as, the distinction cannot survive the protocol. Regular files and
  directories round-trip exactly.
- **No reparse points, no extended attributes, no alternate data streams.**
- **One loaded backing at a time.** A server starts with an empty root.
  `SmbHandle::load` replaces the complete root without rebuilding the
  listener, transport, authentication, sessions, or connected trees. It
  invalidates open disk handles and releases cached file readers before
  returning.
- **A filename SMB2 cannot express must not reach the wire intact.** SMB2
  filenames carry no path separator, and the Windows redirector answers a
  listing that carries one by discarding the *whole response* — one such file
  hides every other file in its directory. Keeping names legal is the backing
  implementation's responsibility: the archive backing rejects them during
  load, wrustic's snapshot backing substitutes U+FFFD and logs.

## Module map

All under `smbanything_core/src/smb/`:

| file | what it holds |
|------|---------------|
| `mod.rs` | server entry, accept loop, compound dispatch, tracing |
| `wire.rs` | bounds-checked `Reader`/`Writer`, NetBIOS framing, UTF-16LE |
| `proto.rs` | SMB2 header codec, NTSTATUS / command / access-mask tables |
| `session.rs` | NEGOTIATE, SESSION_SETUP, TREE_CONNECT, SPNEGO framing |
| `ntlm.rs` | NTLMv2 challenge/response, session key derivation |
| `sign.rs` | HMAC-SHA256 signing and verification over compound chains |
| `srvsvc.rs` | share enumeration: the IPC$ `srvsvc` pipe, DCE/RPC, NetrShareEnum |
| `path.rs` | the trust boundary — SMB path parsing and rejection |
| `backing.rs` | the `Backing`/`FileReader` seam an embedder implements |
| `info.rs` | MS-FSCC info-class encoders |
| `files.rs` | CREATE / CLOSE / READ / QUERY_DIRECTORY / QUERY_INFO, handle table |
| `tun.rs` | the [packet tunnel](smb-tun.md) serving the standard port (`tun` feature) |

`Backing` is a trait so the byte-exact encoders can be tested against an
in-memory tree without standing up any real data source — and so the whole
server is reusable over any immutable tree: the `smbanything` binary implements
it over ZIP/TAR archives (`src/archive/`), wrustic over restic snapshots.

## When a mount fails

Client-side errors are close to useless: Linux reports a bare `-EIO` or
`-EINVAL`, macOS times out with no message, Windows gives a generic system
error. The server is the only place that can see which command was rejected and
why, so set `SMBANYTHING_LOG=1` (an embedder with its own switch calls
`smb::enable_log()`) and it traces every command to stderr:

```
[smb 04:35:34.087] conn 1: connected from 127.0.0.1:45456
[smb 04:35:34.090] conn 1: client offers dialects [0202, 0210, 0300, 0302, 0311]
[smb 04:35:34.090] conn 1: NEGOTIATE -> SUCCESS (94 bytes)
[smb 04:35:34.092] conn 1: SESSION_SETUP -> MORE_PROCESSING_REQUIRED (147 bytes)
[smb 04:35:34.093] conn 1: SESSION_SETUP -> SUCCESS (17 bytes)
[smb 04:35:34.093] conn 1: TREE_CONNECT -> SUCCESS (16 bytes)
[smb 04:35:34.094] conn 2: connected from 127.0.0.1:60874
[smb 04:35:34.094] conn 1: CREATE "docs\readme.txt" access 0x00120089
[smb 04:35:34.095] conn 1: CREATE -> SUCCESS (88 bytes)
```

**Every line names its connection**, because a client opens several per mount
and spreads work across them. Without the id, a failure on one connection sits
between two successes on another and reads as a server that intermittently
refuses things — the trace above is four concurrent connections from one
`smbclient` run. CREATE also logs the path and the requested access mask, since
"CREATE -> ACCESS_DENIED" alone does not say which path, or what it asked for.
The timestamp separates a burst from a slow retry loop: the same number of
failures means different things at 10 ms apart and at 10 minutes apart.

Rejections name the command and the reason:

```
[smb 04:41:02.310] conn 3: dropping: CREATE arrived unsigned
[smb 04:41:02.311] conn 3: dropping: READ signature mismatch
[smb 04:41:07.884] conn 4: SESSION_SETUP: user "andrew" (domain "") is not "smbanything"
[smb 04:41:07.902] conn 4: SESSION_SETUP: wrong password for user "smbanything"
[smb 04:41:07.915] conn 4: SESSION_SETUP: anonymous logon refused
[smb 04:41:09.006] conn 5: stat "\Users\andrew\Documents" failed: <the backing error>
```

A logon failure names the identity that was offered, never the response or the
key. That distinction is the whole point: a burst of `LOGON_FAILURE` naming
*someone else's* username is Windows trying the interactive user against a
server it has no stored credential for, while a burst naming the share user
with the wrong password is a **saved credential from an earlier run** — a
generated share password is fresh each time the server starts, so a client
that ticked "remember" replays one that will never work again. Clear it and
re-map:

```bat
cmdkey /list | findstr <server>
cmdkey /delete:<server>
net use * /delete
```

A connection is dropped after five consecutive refusals (`MAX_FAILED_LOGONS`).
One real client sent the same stale password 84 times on a single connection,
which buries the connection that is actually failing. Dropping locks nothing
out — the client may reconnect immediately — it just stops one socket being used
as a retry loop.

Across the whole server, 1000 refusals with **no successful logon in between**
(`MAX_SERVER_LOGON_FAILURES`) stop the share: every further logon is refused
from that moment, and the embedder is expected to poll
`SmbHandle::logon_limit_reached` and stop the server outright. The number is
deliberately far above anything a working setup produces — a client replaying a
credential that went stale across a restart is normal here, and one was seen
producing 85 refusals in a single browsing session — and any successful logon
resets it, so a working mount holds it at zero indefinitely. Only a client that
never authenticates can walk it to the limit.

This is defence in depth, not the defence: the password is ~94 bits over a
loopback socket, so guessing it is not the threat model. It exists so a server
left running cannot be ground against indefinitely, and so its owner is told.

The `stat`/`list`/`open` lines exist because a backing error and a genuinely
missing path return the same NTSTATUS — a client can do nothing different with
them — so without the trace a backend hiccup is indistinguishable from "that
folder is not in this tree", right down to the wording the client shows.

On Linux, `sudo dmesg | tail` adds cifs.ko's own complaint, which is often more
specific than the mount error.

Worth knowing: unit tests and `smbclient` both passed while several real
protocol bugs were live. Every one was found by a real kernel or OS client.
Treat "the tests pass" as necessary and not sufficient here, and mount from all
three platforms before believing a protocol change.
