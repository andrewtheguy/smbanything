# Serving the standard SMB port through a packet tunnel

`Bind::Tun` (the `--smb-tun` flag, and the `tun` cargo feature of
`smbanything_core`) serves the share on SMB's standard port 445. That buys two
things, and neither is a legacy concern alone:

- **A real UNC path.** `\\169.254.255.1\<share>` works in Explorer's address
  bar and in any program that takes a UNC path, not only as a mapped drive
  letter. No UNC syntax can carry a port, so the standard port is the *only*
  way to get one — including on Windows 11 24H2, where `net use /TCPPORT:` does
  reach a custom port, but only ever as a mapped drive.
- **Windows before 11 24H2.** Those builds speak to no port but 445, so a share
  on any other port is unreachable from them at all.

On Linux and macOS the tunnel runs over the native TUN facilities
(`/dev/net/tun` and utun); Windows has no native TUN API, so there it loads the
Wintun driver. Creating a network adapter needs elevation on every platform.

## Why a normal socket cannot do this on Windows

While `srvnet.sys` is loaded — the normal state of every Windows install —
port 445 cannot be bound through the socket layer. The driver holds it as an
exclusive, system-wide reservation, so a bind fails with `WSAEACCES` rather
than the `WSAEADDRINUSE` you would expect — on `127.0.0.1` and on every other
local address alike.

Measured on Windows 11 (build 26200), in order of increasing desperation:

| Attempt | Result |
| --- | --- |
| Bind `127.0.0.1:445` | `AccessDenied` |
| Add an interface and bind its address | `AccessDenied` — the reservation is not per-interface |
| Unbind `ms_server` ("File and Printer Sharing") from an adapter | `AccessDenied` — no effect |
| Stop the `LanmanServer` service | `AccessDenied` — `srvnet.sys` stays loaded and keeps the port |
| Stop `srvnet.sys` itself | **Frees 445** — and takes all host file sharing with it |

Only the last one works, and paying for a read-only share by disabling the
machine's file sharing is a bad trade. The service dependency chain explains
the rest: `LanmanServer` → `srv2` → `srvnet`, and only the leaf owns the
socket.

On Unix the problem is smaller — 445 is merely privileged — but the same
transport still earns its place: it claims the port inside a private link-local
address that collides with nothing, instead of competing with whatever the host
itself runs on 445.

## What it does instead

The same thing a VM guest or a WireGuard peer does — it terminates the
connection in a TCP/IP stack that is not the host's. A TUN adapter provides an
L3 device; [smoltcp](https://docs.rs/smoltcp) provides the stack. The host
never sees a socket bound to 445, so there is nothing for `srvnet` (or a Unix
host's own SMB daemon) to arbitrate, and host file sharing is untouched for the
share's whole lifetime.

The routing trick that makes it work, and the part that is easy to get wrong:

- the **adapter** is assigned `169.254.255.2/32`;
- the server answers for `169.254.255.1`, which is assigned to **nothing** — an
  explicit on-link `/32` host route (on Windows `CreateIpForwardEntry2` against
  the interface LUID, next hop unspecified — the same shape WireGuard and
  Tailscale install) points it at the tun.

The host pushes packets for `.1` out through the tun; there is no subnet, and
the two host routes are the transport's entire routing footprint. Assign `.1`
to the adapter instead and the host treats it as a local address, loops the
traffic back internally, and (on Windows) the port reservation applies again —
the exact failure the design exists to avoid.

The addresses live in IPv4 link-local space on purpose, and in a corner of it
APIPA can never touch: RFC 3927 reserves `169.254.0.x` and `169.254.255.x`, and
autoconfiguration only ever self-assigns from `169.254.1.0`–`169.254.254.255`.
So the defaults collide with nothing — not with an interface waiting on DHCP
(its `169.254.0.0/16` on-link route loses to our `/32`s on longest-prefix
match), and not with any routed network, because link-local traffic never
leaves the machine at all. A private-range default like `10.99.0.0/24` could
shadow a corporate VPN subnet; this cannot. `--smb-tun-ip` moves the pair (the
next address up goes on the adapter) when the default is taken.

The SMB protocol code is deliberately untouched by all of this. smoltcp
terminates the connection and proxies it to the ordinary loopback listener
`smb::bind` already creates, so the async server, its tests and its wire
handling never learn a tun exists. The extra loopback hop costs a memcpy per
buffer, which is nothing next to a backing read.

The packet thread sleeps only until something needs it. Each round drains the
adapter into smoltcp and moves what it can between smoltcp and the loopback
bridges; a round that moved nothing waits on everything that could change that,
with smoltcp's next timer (`poll_delay`) as the timeout:

- on Linux and macOS, one `poll(2)` over the tun descriptor, each bridge socket
  that has room to read or bytes to write, and a socketpair that wakes it for
  shutdown;
- on Windows, one `WSAWaitForMultipleEvents` over Wintun's read-wait event, a
  single Winsock event every bridge socket is `WSAEventSelect`ed onto, and a
  shutdown event. The read-wait event is waited on only once a receive has
  found the ring empty — Wintun's documented pattern — which smoltcp's `poll`
  guarantees, since it drains the device before returning.

An idle share costs no wakeups, mounted or not. Against the 1 ms sleep loop
this replaced, with a bridged connection left idle and a 64 MiB file read
through the tunnel:

| | Idle cost | 64 MiB read |
| --- | --- | --- |
| Linux (`smbclient`) | 0 wakeups in 2 s, was ~1,700 | 0.6 s, was 0.7 s |
| macOS (`mount_smbfs`) | no CPU time in 10 s, was 0.19 s | 0.22 s, was 0.91 s |

The Linux smoke test holds the idle wakeups under 20.

## Requirements and side effects

- **Elevation to start, not to run.** Creating a network adapter always needs
  it, and nothing else does, so on Linux and macOS the process gives root back
  as soon as the adapter exists and the private listener is bound: under sudo
  it switches to `SUDO_UID`/`SUDO_GID` (with that user's supplementary
  groups) for good before it starts a single server thread, so it never opens
  an archive or reads a client's byte as root, and stops if it cannot. The
  banner says so (`Runs as:  uid 1000`). The adapter's file descriptor keeps
  working, because the kernel checked privilege when it was opened. Run as
  root without sudo, there is nobody to switch to and it stays root. Windows
  has no cheap equivalent — an elevated token cannot be narrowed back to the
  user's for a running process — so there the whole share runs elevated. No
  existing service, binding or adapter is modified.
- **Two host routes.** While a share is open, `169.254.255.1/32` and
  `169.254.255.2/32` route to the tun adapter — nothing wider. The server
  refuses to start if either exact address is already owned by the machine.
- **Only the adapter's own client is served.** The host sends to `.1` from the
  adapter's `.2`, so the stack drops every packet from any other source before
  it is processed — no reply, not even a reset. Without that, a host with IP
  forwarding on would serve the share to a neighbour that routes `.1` through
  it — see [Forwarded neighbours](#forwarded-neighbours).
- **No network state persists**, and not only on the tidy path. Dropping the
  share removes the adapter, and with it the address and the routes. A crash or
  a forced kill does the same: see below. The one thing that outlives a share
  is on Windows: the first adapter installs the Wintun driver into the driver
  store, and it stays there, as it does for every program that uses Wintun —
  see [The driver store](#the-driver-store).

### What happens if the process crashes

Nothing is left behind, and this is measured rather than assumed. Killing the
process with `taskkill /T /F` — `TerminateProcess`, so no destructor and no
cleanup code runs — was followed immediately by:

```
share running     adapter=up   address=169.254.255.2 route=169.254.255.1/32,169.254.255.2/32
right after kill  adapter=none address=none          route=none
```

The cleanup does not depend on `Drop`. A TUN adapter is owned by the handle
that created it, so when the process dies the kernel closes that handle and the
adapter goes away, taking its addresses and routes with it — on Windows
including the explicitly added `169.254.255.1/32`, because a route created
against an interface LUID is owned by that interface. The same holds for a
failure part-way through startup: if address assignment fails after the adapter
exists, the error path drops the adapter and the address goes with it.

So there is no stale-adapter recovery procedure, because there is no stale
adapter. An adapter that does show up belongs to a *live* process — a hung or
suspended one still holds its handle. Stop that process and the adapter goes
with it; there is nothing to remove by hand.

### Forwarded neighbours

Link-local addresses are not supposed to be forwarded (RFC 3927 §2.7), and it is
tempting to rely on that. macOS does not: with IP forwarding on — which
Internet Sharing turns on — it forwards a neighbour's SYN for `169.254.255.1`
into the utun like any other packet. Measured on macOS by a neighbour played
through a peered `feth` pair, three SYNs from `198.51.100.7` each time:

| Build | Tunnel pair | SYNs into the tunnel | SYN-ACKs back |
| --- | --- | --- | --- |
| before the source check | default `169.254.255.1` | 3 | 2 |
| before the source check | `--smb-tun-ip 192.0.2.1` | 3 | 2 |
| with it | either | 3 | 0 |

So before the check, a Mac sharing its connection offered the share's login to
its LAN, default addresses included; a chosen pair outside link-local space
widens that to anything able to route to it. The share still demanded the
password, but nothing beyond the machine itself should have been able to ask.

The smoke test repeats the measurement on every run, watching the tunnel
interface with tcpdump, and fails both when the tunnel answers and when no SYN
reaches it, so it cannot pass vacuously. On Linux the SYNs come from a spare
loopback address instead, because Linux routes a locally sourced packet from it
into the tunnel the same way; macOS refuses to, whether the alias is on `lo0` or
`en0`, which is why it needs the forwarded neighbour.

## The Windows driver

Linux and macOS need no driver file. On Windows, `wintun-amd64.dll` (427 KB,
signed by WireGuard LLC) is vendored in `vendor/wintun/` and must sit next to
the executable at runtime, which is where the Windows MSI installs it.
`smbanything_core/src/smb/tun.rs` loads it by full path from there, so the DLL
search order never picks up another copy. The Wintun *Prebuilt Binaries
License* §3(d) permits redistribution alongside software that uses it only
through the documented API, which is all `tun.rs` does; `vendor/wintun/LICENSE.txt`
is the copy that governs it.

### Provenance

| | |
| --- | --- |
| Source | `wintun-0.14.1.zip` from <https://www.wintun.net/builds/> |
| Archive SHA-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` — matches the value published on wintun.net |
| `wintun-amd64.dll` SHA-256 | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| Authenticode | Valid, `CN=WireGuard LLC`, thumbprint `DF98E075A012ED8C86FBCF14854B8F9555CB3D45` |

**Updating the driver:** verify the new archive against the SHA2-256 published
on wintun.net *and* its Authenticode signature, then replace
`vendor/wintun/wintun-amd64.dll` with the archive's `bin/amd64/wintun.dll` —
renamed, because `tun.rs` loads exactly the name `wintun-amd64.dll` — and
update the table above and `vendor/wintun/README.md`.

### The driver store

Wintun installs its driver into the Windows driver store (`wintun.inf`, as an
`oemN.inf`) the first time an adapter is created, and the package stays there
after every adapter is gone. smbanything leaves it there, as programs that ship
Wintun generally do; uninstalling the MSI removes only the files it installed.
The package is shared: every Wintun program on the machine uses the same one,
and Wintun's own `WintunDeleteDriver` removes every Wintun package that no
adapter is using, whichever program staged it. Unused, it costs nothing, and
the next adapter any program creates reuses it or installs a newer one. To
remove it by hand, find its `oemN.inf` in `pnputil /enum-drivers` and run
`pnputil /delete-driver oemN.inf` from an elevated terminal.

## Known limitations

- The MTU is 1500, set explicitly on every platform — on Windows too, where
  Wintun would otherwise leave the adapter at 65535. Raising it would cut
  per-packet overhead on bulk reads; it has to change on the adapter and in
  smoltcp together.
- IPv4 only.

One trap worth knowing on Windows, because it cost 272 seconds a run before it
was understood: `net use \\host\share /delete` against an address with **no
route** blocks for a full TCP timeout. List mappings first and only delete when
one exists.
