//! SMB over a private L3 packet tunnel.
//!
//! The host routes the client-visible address to a TUN interface, but that
//! address is assigned to nothing. A smoltcp stack answers it and proxies each
//! TCP connection to the ordinary loopback SMB listener. The host therefore
//! never binds port 445: on Windows this avoids srvnet.sys's reservation, and
//! on Unix it avoids both a privileged socket and any local SMB daemon.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant as StdInstant};

use anyhow::{Result, anyhow};
#[cfg(unix)]
use anyhow::Context as _;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use super::TunAddrs;

#[cfg(windows)]
const ADAPTER_NAME: &str = "smbanything";
const MTU: usize = 1500;
const MAX_CONNS: usize = 8;
const SOCKET_BUF: usize = 256 * 1024;
const PROXY_HIGH_WATER: usize = 512 * 1024;

/// A running packet-tunnel front end for the private SMB listener.
pub(super) struct TunShare {
    virtual_ip: Ipv4Addr,
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl TunShare {
    pub(super) fn start(port: u16, forward_to: SocketAddr, addrs: TunAddrs) -> Result<Self> {
        if port == 0 {
            return Err(anyhow!("the packet tunnel needs a fixed client-visible port"));
        }

        let device = PlatformTun::create(addrs).map_err(adapter_hint)?;
        smb_log!(
            "tun: adapter up, {}/32, serving {}:{port}",
            addrs.adapter_ip(),
            addrs.virtual_ip()
        );

        let shutdown = Arc::new(AtomicBool::new(false));
        let join = {
            let shutdown = shutdown.clone();
            std::thread::Builder::new()
                .name(format!("smbanything-tun-{port}"))
                .spawn(move || {
                    poll_loop(device, addrs.virtual_ip(), port, forward_to, shutdown)
                })
                .map_err(|e| anyhow!("spawning the packet-tunnel thread: {e}"))?
        };

        Ok(Self {
            virtual_ip: addrs.virtual_ip(),
            shutdown,
            join: Some(join),
        })
    }

    pub(super) fn virtual_ip(&self) -> Ipv4Addr {
        self.virtual_ip
    }
}

impl Drop for TunShare {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        smb_log!("tun: adapter removed");
    }
}

fn adapter_hint(error: anyhow::Error) -> anyhow::Error {
    #[cfg(unix)]
    let privilege = "Run smbanything through sudo; creating and routing a native TUN interface requires root.";
    #[cfg(windows)]
    let privilege = "Run smbanything from an elevated terminal; creating a Wintun adapter requires administrator rights.";

    anyhow!("starting the SMB packet tunnel: {error}\n\n{privilege}")
}

// Linux and macOS both expose their native packet adapter as a file
// descriptor. `tun` performs the platform ioctls and normalizes macOS's
// four-byte utun packet header away, leaving raw IP packets here.
#[cfg(unix)]
struct PlatformTun {
    device: tun::Device,
}

#[cfg(unix)]
impl PlatformTun {
    fn create(addrs: TunAddrs) -> Result<Self> {
        reject_unix_addresses_in_use(addrs)?;
        let mut config = tun::Configuration::default();
        config
            .address(addrs.adapter_ip())
            .destination(addrs.virtual_ip())
            .netmask(Ipv4Addr::new(255, 255, 255, 255))
            .mtu(MTU as u16)
            .up();

        // Let the kernel choose an unused number. Linux accepts a `%d`
        // template; macOS allocates the first free utun when no name is set.
        #[cfg(target_os = "linux")]
        config.tun_name("smbany%d");

        let device = tun::create(&config).context("creating the native TUN interface")?;
        device
            .set_nonblock()
            .context("making the native TUN interface nonblocking")?;
        Ok(Self { device })
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        let mut packet = vec![0; MTU];
        match self.device.read(&mut packet) {
            Ok(0) => None,
            Ok(len) => {
                packet.truncate(len);
                Some(packet)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => None,
            Err(error) => {
                smb_log!("tun: packet receive failed: {error}");
                None
            }
        }
    }

    fn send(&mut self, packet: &[u8]) {
        match self.device.write(packet) {
            Ok(written) if written == packet.len() => {}
            Ok(written) => smb_log!(
                "tun: short packet write: wrote {written} of {} bytes",
                packet.len()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                smb_log!("tun: transmit queue full; dropping one packet")
            }
            Err(error) => smb_log!("tun: packet send failed: {error}"),
        }
    }
}

/// Refuse a pair when either address already belongs to a local interface.
///
/// A second tunnel with the same pair can otherwise create another adapter on
/// Linux while the original /32 route keeps winning, making startup appear to
/// succeed even though every packet still reaches the first process.
#[cfg(unix)]
fn reject_unix_addresses_in_use(addrs: TunAddrs) -> Result<()> {
    struct IfAddrs(*mut libc::ifaddrs);

    impl Drop for IfAddrs {
        fn drop(&mut self) {
            // SAFETY: getifaddrs initialized this list and it is freed once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    let mut head = std::ptr::null_mut();
    // SAFETY: `head` is a valid out pointer. A successful call owns the list
    // until freeifaddrs, guarded above.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error()).context("listing local interface addresses");
    }
    let list = IfAddrs(head);
    let wanted = [addrs.virtual_ip(), addrs.adapter_ip()];
    let mut current = list.0;
    while !current.is_null() {
        // SAFETY: every non-null node in the getifaddrs list is valid until the
        // list guard drops. ifa_addr itself is allowed to be null.
        let address = unsafe { (*current).ifa_addr };
        if !address.is_null() && unsafe { (*address).sa_family as i32 } == libc::AF_INET {
            // SAFETY: AF_INET guarantees sockaddr_in layout.
            let address = unsafe { &*(address.cast::<libc::sockaddr_in>()) };
            let address = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            if wanted.contains(&address) {
                return Err(anyhow!(
                    "{address} is already assigned to a local interface; choose another --smb-tun-ip"
                ));
            }
        }
        // SAFETY: next belongs to the same guarded linked list.
        current = unsafe { (*current).ifa_next };
    }
    Ok(())
}

// Windows has no native TUN API. Keep the Wintun-specific setup and route
// calls here; the packet stack and proxy below are identical on every OS.
#[cfg(windows)]
mod windows {
    use std::path::{Path, PathBuf};

    use anyhow::{Result, anyhow};

    use super::{ADAPTER_NAME, Ipv4Addr, TunAddrs};

    const TUNNEL_TYPE: &str = "smbanything archive share";
    const ADAPTER_GUID: u128 = 0xa7e1_6f81_6465_40c9_8e28_4a90_91db_43fc;
    const WINTUN_DLL_NAME: &str = "wintun-amd64.dll";
    const WINTUN_DLL_SHA256: [u8; 32] = [
        0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18,
        0x85, 0xc1, 0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3,
        0x22, 0x0d, 0xaf, 0xce,
    ];

    pub(super) struct PlatformTun {
        // Field order matters: the session must close before its adapter.
        session: std::sync::Arc<wintun::Session>,
        _adapter: std::sync::Arc<wintun::Adapter>,
    }

    impl PlatformTun {
        pub(super) fn create(addrs: TunAddrs) -> Result<Self> {
            reject_addresses_in_use(addrs)?;
            let dll = locate_dll()?;
            // SAFETY: only the DLL with the pinned digest is passed to the
            // loader. The release archive places that file beside the binary.
            let wintun = unsafe { wintun::load_from_path(&dll) }
                .map_err(|e| anyhow!("loading {}: {e}", dll.display()))?;
            let adapter = wintun::Adapter::create(
                &wintun,
                ADAPTER_NAME,
                TUNNEL_TYPE,
                Some(ADAPTER_GUID),
            )
            .map_err(|e| anyhow!("creating the `{ADAPTER_NAME}` Wintun adapter: {e}"))?;
            let luid = unsafe { adapter.get_luid().Value };
            assign_address(luid, addrs.adapter_ip())?;
            add_virtual_route(luid, addrs.virtual_ip())?;
            let session = adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| anyhow!("starting the Wintun session: {e}"))?;
            Ok(Self {
                session: std::sync::Arc::new(session),
                _adapter: adapter,
            })
        }

        pub(super) fn receive(&mut self) -> Option<Vec<u8>> {
            match self.session.try_receive() {
                Ok(Some(packet)) => Some(packet.bytes().to_vec()),
                Ok(None) => None,
                Err(error) => {
                    smb_log!("tun: packet receive failed: {error}");
                    None
                }
            }
        }

        pub(super) fn send(&mut self, packet: &[u8]) {
            match self.session.allocate_send_packet(packet.len() as u16) {
                Ok(mut outgoing) => {
                    outgoing.bytes_mut().copy_from_slice(packet);
                    self.session.send_packet(outgoing);
                }
                Err(error) => smb_log!("tun: packet send failed: {error}"),
            }
        }
    }

    fn locate_dll() -> Result<PathBuf> {
        let exe = std::env::current_exe()
            .map_err(|e| anyhow!("resolving the smbanything executable: {e}"))?;
        let dir = exe
            .parent()
            .ok_or_else(|| anyhow!("{} has no parent directory", exe.display()))?;
        let path = dir.join(WINTUN_DLL_NAME);
        verify_dll(&path)?;
        Ok(path)
    }

    pub(super) fn verify_dll(path: &Path) -> Result<()> {
        use sha2::{Digest, Sha256};

        let bytes = std::fs::read(path).map_err(|error| {
            anyhow!(
                "{} was not found ({error}); Windows packet tunneling needs the release's {WINTUN_DLL_NAME} beside smbanything.exe",
                path.display()
            )
        })?;
        let found = Sha256::digest(&bytes);
        if found.as_slice() != WINTUN_DLL_SHA256 {
            return Err(anyhow!(
                "{} does not match the Wintun driver shipped by smbanything; refusing to load it",
                path.display()
            ));
        }
        Ok(())
    }

    fn reject_addresses_in_use(addrs: TunAddrs) -> Result<()> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetBestRoute2, MIB_IPFORWARD_ROW2,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

        for addr in [addrs.virtual_ip(), addrs.adapter_ip()] {
            // SAFETY: all structures are initialized before the API reads
            // them; the destination is IPv4 and the remaining fields are
            // documented outputs.
            let (status, prefix_len) = unsafe {
                let mut destination: SOCKADDR_INET = std::mem::zeroed();
                destination.si_family = AF_INET;
                destination.Ipv4.sin_family = AF_INET;
                destination.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
                let mut route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
                let mut source: SOCKADDR_INET = std::mem::zeroed();
                let status = GetBestRoute2(
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &destination,
                    0,
                    &mut route,
                    &mut source,
                );
                (status, route.DestinationPrefix.PrefixLength)
            };
            if status == 0 && prefix_len == 32 {
                return Err(anyhow!(
                    "{addr} already has an exact host route; choose another --smb-tun-ip"
                ));
            }
        }
        Ok(())
    }

    const ALREADY_EXISTS: u32 = 5010;

    fn assign_address(luid: u64, addr: Ipv4Addr) -> Result<()> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry,
            MIB_UNICASTIPADDRESS_ROW,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, IpDadStatePreferred};

        // SAFETY: the API initializer prepares the row before the documented
        // caller-supplied fields are filled.
        let status = unsafe {
            let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
            InitializeUnicastIpAddressEntry(&mut row);
            row.InterfaceLuid.Value = luid;
            row.Address.si_family = AF_INET;
            row.Address.Ipv4.sin_family = AF_INET;
            row.Address.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(addr.octets());
            row.OnLinkPrefixLength = 32;
            row.DadState = IpDadStatePreferred;
            CreateUnicastIpAddressEntry(&row)
        };
        if status != 0 && status != ALREADY_EXISTS {
            return Err(anyhow!(
                "assigning {addr}/32 to Wintun failed with Win32 error {status}"
            ));
        }
        Ok(())
    }

    fn add_virtual_route(luid: u64, addr: Ipv4Addr) -> Result<()> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        // SAFETY: the API initializer prepares the row before the documented
        // route fields are filled.
        let status = unsafe {
            let mut row: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
            InitializeIpForwardEntry(&mut row);
            row.InterfaceLuid.Value = luid;
            row.DestinationPrefix.PrefixLength = 32;
            row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
            row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr =
                u32::from_ne_bytes(addr.octets());
            row.NextHop.Ipv4.sin_family = AF_INET;
            CreateIpForwardEntry2(&row)
        };
        if status != 0 && status != ALREADY_EXISTS {
            return Err(anyhow!(
                "routing {addr}/32 through Wintun failed with Win32 error {status}"
            ));
        }
        Ok(())
    }

    #[test]
    fn vendored_driver_matches_the_runtime_digest() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("vendor")
            .join("wintun")
            .join(WINTUN_DLL_NAME);
        verify_dll(&path).expect("the vendored Wintun DLL must match its pinned digest");
        let bytes = std::fs::read(path).expect("read Wintun DLL");
        assert_eq!(&bytes[..2], b"MZ");
        assert!(bytes.len() > 100_000);
    }
}

#[cfg(windows)]
use windows::PlatformTun;

/// Check that the Wintun driver at `path` is byte-for-byte the one this crate
/// pins and will load. For an embedder that vendors the DLL and ships it next
/// to its own executable: run this over the vendored copy in a test, so a
/// driver update that forgets one side fails the build rather than the first
/// tun share started in the field.
#[cfg(windows)]
pub fn verify_driver(path: &std::path::Path) -> anyhow::Result<()> {
    windows::verify_dll(path)
}

struct SmolDevice {
    io: PlatformTun,
}

struct PacketRx {
    packet: Vec<u8>,
}

struct PacketTx<'a> {
    io: &'a mut PlatformTun,
}

impl RxToken for PacketRx {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.packet)
    }
}

impl TxToken for PacketTx<'_> {
    fn consume<R, F>(self, len: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = function(&mut packet);
        self.io.send(&packet);
        result
    }
}

impl Device for SmolDevice {
    type RxToken<'a>
        = PacketRx
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.io.receive().map(|packet| {
            (
                PacketRx { packet },
                PacketTx {
                    io: &mut self.io,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PacketTx { io: &mut self.io })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = MTU;
        capabilities
    }
}

struct Bridge {
    handle: SocketHandle,
    upstream: Option<TcpStream>,
    to_upstream: VecDeque<u8>,
    to_client: VecDeque<u8>,
    upstream_eof: bool,
    upstream_write_closed: bool,
}

impl Bridge {
    fn reset(&mut self) {
        self.upstream = None;
        self.to_upstream.clear();
        self.to_client.clear();
        self.upstream_eof = false;
        self.upstream_write_closed = false;
    }
}

fn recycle(bridge: &mut Bridge, socket: &mut tcp::Socket<'_>, port: u16) {
    bridge.reset();
    if let Err(error) = socket.listen(port) {
        smb_log!("tun: re-listen failed: {error:?}");
    }
}

fn poll_loop(
    device: PlatformTun,
    virtual_ip: Ipv4Addr,
    port: u16,
    forward_to: SocketAddr,
    shutdown: Arc<AtomicBool>,
) {
    let mut device = SmolDevice { io: device };
    let started = StdInstant::now();
    let now = || Instant::from_micros(started.elapsed().as_micros() as i64);

    let config = Config::new(HardwareAddress::Ip);
    let mut interface = Interface::new(config, &mut device, now());
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(virtual_ip), 32))
            .expect("one address fits");
    });

    let mut sockets = SocketSet::new(Vec::new());
    let mut bridges: Vec<Bridge> = (0..MAX_CONNS)
        .map(|_| {
            let rx = tcp::SocketBuffer::new(vec![0; SOCKET_BUF]);
            let tx = tcp::SocketBuffer::new(vec![0; SOCKET_BUF]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket.set_nagle_enabled(false);
            if let Err(error) = socket.listen(port) {
                smb_log!("tun: listen on port {port} failed: {error:?}");
            }
            Bridge {
                handle: sockets.add(socket),
                upstream: None,
                to_upstream: VecDeque::new(),
                to_client: VecDeque::new(),
                upstream_eof: false,
                upstream_write_closed: false,
            }
        })
        .collect();

    while !shutdown.load(Ordering::Relaxed) {
        interface.poll(now(), &mut device, &mut sockets);

        let mut did_work = false;
        let mut any_active = false;
        for bridge in &mut bridges {
            did_work |= pump(bridge, &mut sockets, forward_to, port);
            any_active |= bridge.upstream.is_some();
        }
        if did_work {
            continue;
        }
        std::thread::sleep(Duration::from_millis(if any_active { 1 } else { 20 }));
    }

    for bridge in &mut bridges {
        sockets.get_mut::<tcp::Socket>(bridge.handle).abort();
    }
    interface.poll(now(), &mut device, &mut sockets);
}

fn pump(
    bridge: &mut Bridge,
    sockets: &mut SocketSet<'_>,
    forward_to: SocketAddr,
    port: u16,
) -> bool {
    let mut did_work = false;
    let socket = sockets.get_mut::<tcp::Socket>(bridge.handle);

    // CloseWait as well as Established: a client whose handshake, request and
    // FIN are all processed in one `interface.poll` never appears here as
    // Established, but its request is buffered and still has to be served.
    if bridge.upstream.is_none()
        && matches!(
            socket.state(),
            tcp::State::Established | tcp::State::CloseWait
        )
    {
        match TcpStream::connect(forward_to) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                if let Err(error) = stream.set_nonblocking(true) {
                    smb_log!("tun: cannot make loopback bridge nonblocking: {error}");
                    socket.abort();
                    return true;
                }
                smb_log!("tun: connection from {:?} bridged", socket.remote_endpoint());
                bridge.upstream = Some(stream);
                did_work = true;
            }
            Err(error) => {
                smb_log!("tun: cannot reach private SMB listener {forward_to}: {error}");
                socket.abort();
                return true;
            }
        }
    }

    let Some(upstream) = bridge.upstream.as_mut() else {
        return match socket.state() {
            // Waiting for a client, or mid-handshake: nothing to bridge yet.
            tcp::State::Listen | tcp::State::SynReceived => did_work,
            // Closed or TimeWait: the slot is free for the next client.
            _ if !socket.is_open() => {
                recycle(bridge, socket, port);
                true
            }
            // Every other state is a connection that ended before it could be
            // bridged. Aborting returns the slot; leaving it open would retire
            // one of the MAX_CONNS bridges for the life of the process.
            _ => {
                socket.abort();
                true
            }
        };
    };

    while socket.can_recv() && bridge.to_upstream.len() < PROXY_HIGH_WATER {
        let mut buffer = [0; 16 * 1024];
        match socket.recv_slice(&mut buffer) {
            Ok(0) => break,
            Ok(len) => {
                bridge.to_upstream.extend(&buffer[..len]);
                did_work = true;
            }
            Err(_) => break,
        }
    }
    while !bridge.to_upstream.is_empty() {
        let (head, _) = bridge.to_upstream.as_slices();
        match upstream.write(head) {
            Ok(0) => break,
            Ok(len) => {
                bridge.to_upstream.drain(..len);
                did_work = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                bridge.to_upstream.clear();
                bridge.upstream_write_closed = true;
                break;
            }
        }
    }

    while !bridge.upstream_eof && bridge.to_client.len() < PROXY_HIGH_WATER {
        let mut buffer = [0; 16 * 1024];
        match upstream.read(&mut buffer) {
            Ok(0) => {
                bridge.upstream_eof = true;
                did_work = true;
                break;
            }
            Ok(len) => {
                bridge.to_client.extend(&buffer[..len]);
                did_work = true;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                bridge.upstream_eof = true;
                did_work = true;
                break;
            }
        }
    }
    while socket.can_send() && !bridge.to_client.is_empty() {
        let (head, _) = bridge.to_client.as_slices();
        match socket.send_slice(head) {
            Ok(0) => break,
            Ok(len) => {
                bridge.to_client.drain(..len);
                did_work = true;
            }
            Err(_) => break,
        }
    }

    if bridge.upstream_eof && bridge.to_client.is_empty() && socket.may_send() {
        socket.close();
        did_work = true;
    }
    if !socket.may_recv()
        && bridge.to_upstream.is_empty()
        && !bridge.upstream_write_closed
    {
        let _ = upstream.shutdown(std::net::Shutdown::Write);
        bridge.upstream_write_closed = true;
        did_work = true;
    }
    if !socket.is_open() {
        recycle(bridge, socket, port);
        did_work = true;
    }
    did_work
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_never_assigns_the_address_it_answers_for() {
        for address in ["169.254.255.1", "10.99.0.1", "192.168.77.5"] {
            let addrs: TunAddrs = address.parse().unwrap();
            assert_ne!(addrs.virtual_ip(), addrs.adapter_ip());
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_local_interface_address_cannot_be_claimed() {
        let addrs = TunAddrs {
            virtual_ip: Ipv4Addr::LOCALHOST,
        };
        let error = reject_unix_addresses_in_use(addrs).unwrap_err();
        assert!(error.to_string().contains("already assigned"), "{error:#}");
    }
}
