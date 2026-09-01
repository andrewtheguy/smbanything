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
`smb::start` already creates, so the async server, its tests and its wire
handling never learn a tun exists. The extra loopback hop costs a memcpy per
buffer, which is nothing next to a backing read.

## Requirements and side effects

- **Elevation**, because creating a network adapter always requires it. Nothing
  else needs it, and no existing service, binding or adapter is modified.
- **Two host routes.** While a share is open, `169.254.255.1/32` and
  `169.254.255.2/32` route to the tun adapter — nothing wider. The server
  refuses to start if either exact address is already owned by the machine.
- **Nothing persists**, and not only on the tidy path. Dropping the share
  removes the adapter, and with it the address and the routes. A crash or a
  forced kill does the same: see below.

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

## The Windows driver

Linux and macOS need no driver file. On Windows, `wintun-amd64.dll` (427 KB,
signed by WireGuard LLC) is vendored in `vendor/wintun/` and must sit next to
the executable at runtime; `smbanything_core/src/smb/tun.rs` loads it from
there and re-verifies it against a pinned SHA-256 before each load — a stale or
altered copy is refused rather than trusted. The Wintun *Prebuilt Binaries
License* §3(d) permits redistribution alongside software that uses it only
through the documented API, which is all `tun.rs` does; `vendor/wintun/LICENSE.txt`
is the copy that governs it.

### Provenance and integrity

| | |
| --- | --- |
| Source | `wintun-0.14.1.zip` from <https://www.wintun.net/builds/> |
| Archive SHA-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` — matches the value published on wintun.net |
| `wintun-amd64.dll` SHA-256 | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| Authenticode | Valid, `CN=WireGuard LLC`, thumbprint `DF98E075A012ED8C86FBCF14854B8F9555CB3D45` |

A checksum verified only at download time protects nothing afterwards, so the
DLL hash is pinned as `WINTUN_DLL_SHA256` and checked twice:

- `vendored_driver_matches_the_runtime_digest` fails the build if the vendored
  binary ever changes without the constant changing with it;
- `locate_dll` hashes the file next to the executable and refuses it unless it
  is byte-for-byte the pinned driver. Nothing is passed to `LoadLibrary` that
  has not just been verified.

An embedder that vendors and ships the DLL itself pins its own copy with
`smb::verify_driver` in a test of its own, so a driver update that forgets one
side fails that build too.

It narrows the window rather than closing it. Between the hash check and the
load, a writer could still swap the file. Anything able to write the install
directory can already replace the executable itself; this defends against a
stale or corrupted copy, not against an attacker who is already inside that
trust boundary.

**Updating the driver:** verify the new archive against the SHA2-256 published
on wintun.net *and* its Authenticode signature, then replace
`vendor/wintun/wintun-amd64.dll` with the archive's `bin/amd64/wintun.dll` —
renamed, because `tun.rs` loads exactly the name `wintun-amd64.dll` — and
update `WINTUN_DLL_SHA256`. The test will fail until they agree, which is the
point.

## Known limitations

- The poll loop polls rather than waiting on an event, because no single wait
  primitive spans both the tun device and the loopback sockets everywhere. It
  sleeps 1 ms while a mount is live and 20 ms when idle. Measured cost is not
  visible next to backing reads — a mount, a file read and a directory listing
  are all well under 250 ms — but this is the first place to look if throughput
  ever matters.
- MTU is left at the platform default of 1500. Raising it would cut per-packet
  overhead on bulk reads.
- IPv4 only.

One trap worth knowing on Windows, because it cost 272 seconds a run before it
was understood: `net use \\host\share /delete` against an address with **no
route** blocks for a full TCP timeout. List mappings first and only delete when
one exists.
