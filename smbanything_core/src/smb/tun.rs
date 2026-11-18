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
use std::time::Instant as StdInstant;

use anyhow::{Result, anyhow};
#[cfg(unix)]
use anyhow::Context as _;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

use super::TunAddrs;

#[cfg(windows)]
const ADAPTER_NAME: &str = "smbanything";
/// The link MTU, set explicitly on the adapter on every platform so that the
/// host and smoltcp agree on it. Wintun would otherwise default to 65535.
const MTU: usize = 1500;
const MAX_CONNS: usize = 8;
const SOCKET_BUF: usize = 256 * 1024;
const PROXY_HIGH_WATER: usize = 512 * 1024;

/// A packet-tunnel adapter that is up and routed, but whose packets nothing
/// reads yet: whatever arrives waits in the adapter's queue until
/// [`TunAdapter::start`]. Dropping it removes the adapter.
pub(super) struct TunAdapter {
    device: PlatformTun,
    addrs: TunAddrs,
    port: u16,
    forward_to: SocketAddr,
}

impl TunAdapter {
    pub(super) fn create(port: u16, forward_to: SocketAddr, addrs: TunAddrs) -> Result<Self> {
        if port == 0 {
            return Err(anyhow!("the packet tunnel needs a fixed client-visible port"));
        }

        let device = PlatformTun::create(addrs).map_err(adapter_hint)?;
        smb_log!(
            "tun: adapter up, {}/32, serving {}:{port}",
            addrs.adapter_ip(),
            addrs.virtual_ip()
        );
        Ok(Self {
            device,
            addrs,
            port,
            forward_to,
        })
    }

    pub(super) fn virtual_ip(&self) -> Ipv4Addr {
        self.addrs.virtual_ip()
    }

    /// Start answering clients on the adapter's packet thread.
    pub(super) fn start(self) -> Result<TunShare> {
        let Self {
            device,
            addrs,
            port,
            forward_to,
        } = self;
        let (poller, waker) = Poller::new()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let join = {
            let shutdown = shutdown.clone();
            std::thread::Builder::new()
                .name(format!("smbanything-tun-{port}"))
                .spawn(move || poll_loop(device, poller, addrs, port, forward_to, shutdown))
                .map_err(|e| anyhow!("spawning the packet-tunnel thread: {e}"))?
        };

        Ok(TunShare {
            shutdown,
            waker,
            join: Some(join),
        })
    }
}

/// A running packet-tunnel front end for the private SMB listener.
pub(super) struct TunShare {
    shutdown: Arc<AtomicBool>,
    waker: Waker,
    join: Option<JoinHandle<()>>,
}

impl Drop for TunShare {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        self.waker.wake();
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

/// Round a smoltcp timer up to whole milliseconds, the unit both platform
/// waits take. Rounding down would wake just before the timer is due and spin
/// until it is.
fn wait_millis(timeout: Duration) -> u64 {
    timeout.total_micros().div_ceil(1000)
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

/// Wakes the packet thread out of its wait, so that stopping the share does
/// not have to wait for the next packet or timer.
#[cfg(unix)]
struct Waker(std::os::unix::net::UnixStream);

#[cfg(unix)]
impl Waker {
    fn wake(&self) {
        let _ = (&self.0).write(&[0]);
    }
}

/// What the packet thread sleeps on between rounds: the adapter, the loopback
/// bridges, the shutdown waker, and smoltcp's next timer, all in one poll(2).
#[cfg(unix)]
struct Poller {
    wake: std::os::unix::net::UnixStream,
    fds: Vec<libc::pollfd>,
}

#[cfg(unix)]
impl Poller {
    fn new() -> Result<(Self, Waker)> {
        let (wake, waker) = std::os::unix::net::UnixStream::pair()
            .context("creating the packet-tunnel waker")?;
        waker
            .set_nonblocking(true)
            .context("making the packet-tunnel waker nonblocking")?;
        Ok((
            Self {
                wake,
                fds: Vec::with_capacity(2 + MAX_CONNS),
            },
            Waker(waker),
        ))
    }

    /// poll(2) is level-triggered and takes its interest list on every call,
    /// so a new bridge needs no registration.
    fn register(&self, _stream: &TcpStream) -> std::io::Result<()> {
        Ok(())
    }

    fn wait(&mut self, device: &PlatformTun, bridges: &[Bridge], timeout: Option<Duration>) {
        use std::os::fd::AsRawFd;

        let pollfd = |fd, events| libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        self.fds.clear();
        self.fds.push(pollfd(self.wake.as_raw_fd(), libc::POLLIN));
        self.fds.push(pollfd(device.device.as_raw_fd(), libc::POLLIN));
        for bridge in bridges {
            let Some(upstream) = &bridge.upstream else {
                continue;
            };
            let mut events = 0;
            if bridge.wants_upstream_read() {
                events |= libc::POLLIN;
            }
            if bridge.wants_upstream_write() {
                events |= libc::POLLOUT;
            }
            // A socket with no interest is left out entirely: poll(2) reports
            // a hung-up one regardless of `events`, and that would spin.
            if events != 0 {
                self.fds.push(pollfd(upstream.as_raw_fd(), events));
            }
        }
        let timeout = timeout.map_or(-1, |timeout| {
            i32::try_from(wait_millis(timeout)).unwrap_or(i32::MAX)
        });
        // SAFETY: `fds` is a live, initialized array of `fds.len()` pollfds.
        let ready = unsafe {
            libc::poll(
                self.fds.as_mut_ptr(),
                self.fds.len() as libc::nfds_t,
                timeout,
            )
        };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                smb_log!("tun: poll failed: {error}");
                // Never spin on a wait that keeps failing.
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
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

// Windows has no native TUN API. Keep the Wintun-specific setup, route and
// wait calls here; the packet stack and proxy below are identical on every OS.
#[cfg(windows)]
mod windows {
    use std::io::Read as _;
    use std::net::TcpStream;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    use anyhow::{Result, anyhow};
    use windows_sys::Win32::Networking::WinSock::{
        WSACloseEvent, WSACreateEvent, WSAEVENT, WSAResetEvent, WSASetEvent,
    };

    use super::{ADAPTER_NAME, Bridge, Duration, Ipv4Addr, MTU, TunAddrs, wait_millis};

    const TUNNEL_TYPE: &str = "smbanything archive share";
    const ADAPTER_GUID: u128 = 0xa7e1_6f81_6465_40c9_8e28_4a90_91db_43fc;
    const WINTUN_DLL_NAME: &str = "wintun-amd64.dll";
    const WINTUN_DLL_SHA256: [u8; 32] = [
        0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18,
        0x85, 0xc1, 0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3,
        0x22, 0x0d, 0xaf, 0xce,
    ];

    pub(super) struct PlatformTun {
        /// The session's read-wait event, owned by `session`. Wintun signals
        /// it when packets arrive in a ring that a receive found empty.
        read_event: isize,
        // Field order matters: the session must close before its adapter.
        session: Arc<wintun::Session>,
        _adapter: Arc<wintun::Adapter>,
    }

    impl PlatformTun {
        pub(super) fn create(addrs: TunAddrs) -> Result<Self> {
            reject_addresses_in_use(addrs)?;
            let wintun = load_pinned_dll()?;
            let adapter = wintun::Adapter::create(
                &wintun,
                ADAPTER_NAME,
                TUNNEL_TYPE,
                Some(ADAPTER_GUID),
            )
            .map_err(|e| anyhow!("creating the `{ADAPTER_NAME}` Wintun adapter: {e}"))?;
            let luid = unsafe { adapter.get_luid().Value };
            set_mtu(luid, MTU as u32)?;
            assign_address(luid, addrs.adapter_ip())?;
            add_virtual_route(luid, addrs.virtual_ip())?;
            let session = adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| anyhow!("starting the Wintun session: {e}"))?;
            let read_event = session
                .get_read_wait_event()
                .map_err(|e| anyhow!("getting the Wintun read event: {e}"))?;
            Ok(Self {
                read_event,
                session: Arc::new(session),
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

    /// A Winsock event object: manual-reset, and waitable alongside Wintun's
    /// read event in one call.
    struct Event(WSAEVENT);

    // SAFETY: an event handle may be signalled, reset and waited on from any
    // thread; the wrapper only closes it once, on drop.
    unsafe impl Send for Event {}
    unsafe impl Sync for Event {}

    impl Event {
        fn new() -> Result<Self> {
            // SAFETY: no arguments; failure is reported as WSA_INVALID_EVENT.
            let event = unsafe { WSACreateEvent() };
            if event == 0 {
                return Err(anyhow!(
                    "creating a packet-tunnel event: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self(event))
        }
    }

    impl Drop for Event {
        fn drop(&mut self) {
            // SAFETY: the handle is valid and closed exactly once.
            unsafe { WSACloseEvent(self.0) };
        }
    }

    /// Wakes the packet thread out of its wait, so that stopping the share
    /// does not have to wait for the next packet or timer.
    pub(super) struct Waker(Arc<Event>);

    impl Waker {
        pub(super) fn wake(&self) {
            // SAFETY: the event outlives this call through the Arc.
            unsafe { WSASetEvent(self.0.0) };
        }
    }

    /// What the packet thread sleeps on between rounds: the shutdown event,
    /// one event shared by every loopback bridge socket, Wintun's read event,
    /// and smoltcp's next timer, all in one WaitForMultipleObjects.
    pub(super) struct Poller {
        wake: Arc<Event>,
        upstream: Event,
    }

    impl Poller {
        pub(super) fn new() -> Result<(Self, Waker)> {
            let wake = Arc::new(Event::new()?);
            let poller = Self {
                wake: wake.clone(),
                upstream: Event::new()?,
            };
            Ok((poller, Waker(wake)))
        }

        /// Signal the shared upstream event whenever `stream` becomes readable,
        /// writable or closed. Winsock re-arms each of those only after the
        /// matching call would block, which is exactly when the bridge stops
        /// pumping, so nothing is missed between two waits.
        pub(super) fn register(&self, stream: &TcpStream) -> std::io::Result<()> {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                FD_CLOSE, FD_READ, FD_WRITE, SOCKET, WSAEventSelect, WSAGetLastError,
            };

            // SAFETY: the socket and the event are both live handles.
            let status = unsafe {
                WSAEventSelect(
                    stream.as_raw_socket() as SOCKET,
                    self.upstream.0,
                    (FD_READ | FD_WRITE | FD_CLOSE) as i32,
                )
            };
            if status != 0 {
                // SAFETY: reads this thread's last Winsock error.
                return Err(std::io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
            }
            Ok(())
        }

        /// Wintun's documented receive pattern: wait on the read event only
        /// once a receive has found the ring empty. smoltcp's `poll` drains the
        /// device before returning, and nothing reads it between that and
        /// this wait.
        pub(super) fn wait(
            &mut self,
            device: &PlatformTun,
            _bridges: &[Bridge],
            timeout: Option<Duration>,
        ) {
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Networking::WinSock::{
                WSA_INFINITE, WSA_WAIT_FAILED, WSAWaitForMultipleEvents,
            };

            let handles: [HANDLE; 3] = [
                self.wake.0 as HANDLE,
                self.upstream.0 as HANDLE,
                device.read_event as HANDLE,
            ];
            let timeout = timeout.map_or(WSA_INFINITE, |timeout| {
                u32::try_from(wait_millis(timeout)).map_or(WSA_INFINITE - 1, |ms| {
                    ms.min(WSA_INFINITE - 1)
                })
            });
            // SAFETY: three live event handles; wait for any, not alertable.
            let woke = unsafe {
                WSAWaitForMultipleEvents(handles.len() as u32, handles.as_ptr(), 0, timeout, 0)
            };
            if woke == WSA_WAIT_FAILED {
                smb_log!(
                    "tun: waiting for packets failed: {}",
                    std::io::Error::last_os_error()
                );
                // Never spin on a wait that keeps failing.
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // Reset before the bridges are pumped, not after: a socket event
            // that lands while they are being pumped must survive to the next
            // wait.
            // SAFETY: a live event handle.
            unsafe { WSAResetEvent(self.upstream.0) };
        }
    }

    /// The pinned Wintun DLL, held open so that it cannot change between the
    /// hash check and the load.
    ///
    /// The handle shares read access only: while it lives, nobody can open
    /// the file for writing, nor rename or delete it (both need delete
    /// access). The loader's own open asks for read and execute, which that
    /// sharing allows. `load_path` is the file's final path, read back from
    /// the handle: no junction or symlink is left in it to retarget, and no
    /// directory along it can be renamed while a file inside is open, so
    /// `LoadLibrary` maps exactly the bytes hashed here.
    struct PinnedDll {
        path: PathBuf,
        load_path: PathBuf,
        _file: std::fs::File,
    }

    impl PinnedDll {
        fn beside_exe() -> Result<Self> {
            let exe = std::env::current_exe()
                .map_err(|e| anyhow!("resolving the smbanything executable: {e}"))?;
            let dir = exe
                .parent()
                .ok_or_else(|| anyhow!("{} has no parent directory", exe.display()))?;
            Self::open(dir.join(WINTUN_DLL_NAME))
        }

        fn open(path: PathBuf) -> Result<Self> {
            use sha2::{Digest, Sha256};
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

            let mut file = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&path)
                .map_err(|error| {
                    anyhow!(
                        "{} could not be opened ({error}); Windows packet tunneling needs the release's {WINTUN_DLL_NAME} beside smbanything.exe",
                        path.display()
                    )
                })?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|error| anyhow!("reading {}: {error}", path.display()))?;
            if Sha256::digest(&bytes).as_slice() != WINTUN_DLL_SHA256 {
                return Err(anyhow!(
                    "{} does not match the Wintun driver shipped by smbanything; refusing to load it",
                    path.display()
                ));
            }
            let load_path = final_path(&file)
                .map_err(|error| anyhow!("resolving {}: {error}", path.display()))?;
            Ok(Self {
                path,
                load_path,
                _file: file,
            })
        }
    }

    /// The path the handle actually reached, with every junction and
    /// symlink resolved. The `\\?\` prefix is dropped from a drive path,
    /// which means the same file without it.
    fn final_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
        use std::os::windows::ffi::OsStringExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
        };

        let mut buffer = vec![0u16; 512];
        loop {
            // SAFETY: a live file handle, and a buffer of the length passed.
            let len = unsafe {
                GetFinalPathNameByHandleW(
                    file.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
            } as usize;
            if len == 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Too small: `len` is the size needed, terminator included.
            if len >= buffer.len() {
                buffer.resize(len, 0);
                continue;
            }
            let path = std::ffi::OsString::from_wide(&buffer[..len]);
            let text = path.to_string_lossy();
            let bytes = text.as_bytes();
            let drive_path = bytes.len() > 6
                && bytes.starts_with(br"\\?\")
                && bytes[4].is_ascii_alphabetic()
                && bytes[5] == b':';
            return Ok(if drive_path {
                PathBuf::from(&text[4..])
            } else {
                PathBuf::from(path)
            });
        }
    }

    fn load_pinned_dll() -> Result<wintun::Wintun> {
        let dll = PinnedDll::beside_exe()?;
        // SAFETY: only the DLL with the pinned digest is passed to the loader,
        // and `dll` keeps it from changing until the load has mapped it.
        let wintun = unsafe { wintun::load_from_path(&dll.load_path) }
            .map_err(|e| anyhow!("loading {}: {e}", dll.path.display()))?;
        drop(dll);
        Ok(wintun)
    }

    pub(super) fn verify_dll(path: &Path) -> Result<()> {
        PinnedDll::open(path.to_path_buf()).map(drop)
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

    /// Wintun creates its adapter with an MTU of 65535. Set the IPv4 interface
    /// to the MTU smoltcp is configured with, as Linux and macOS already are.
    fn set_mtu(luid: u64, mtu: u32) -> Result<()> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW,
            SetIpInterfaceEntry,
        };
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        // SAFETY: the API initializer prepares the row, and the lookup fills
        // it before the one changed field is written back.
        let (lookup, status) = unsafe {
            let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            InitializeIpInterfaceEntry(&mut row);
            row.Family = AF_INET;
            row.InterfaceLuid.Value = luid;
            let lookup = GetIpInterfaceEntry(&mut row);
            row.NlMtu = mtu;
            // SetIpInterfaceEntry rejects an IPv4 row that carries the site
            // prefix length GetIpInterfaceEntry reports.
            row.SitePrefixLength = 0;
            let status = if lookup == 0 {
                SetIpInterfaceEntry(&mut row)
            } else {
                lookup
            };
            (lookup, status)
        };
        if status != 0 {
            let call = if lookup == 0 { "setting" } else { "reading" };
            return Err(anyhow!(
                "{call} the Wintun interface MTU failed with Win32 error {status}"
            ));
        }
        Ok(())
    }

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

    #[cfg(test)]
    fn vendored_dll() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("vendor")
            .join("wintun")
            .join(WINTUN_DLL_NAME)
    }

    #[test]
    fn vendored_driver_matches_the_runtime_digest() {
        let path = vendored_dll();
        verify_dll(&path).expect("the vendored Wintun DLL must match its pinned digest");
        let bytes = std::fs::read(path).expect("read Wintun DLL");
        assert_eq!(&bytes[..2], b"MZ");
        assert!(bytes.len() > 100_000);
    }

    #[test]
    fn the_pinned_driver_cannot_be_written_while_it_is_held() {
        let dir = std::env::temp_dir().join(format!("smbanything-pinned-dll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(WINTUN_DLL_NAME);
        std::fs::copy(vendored_dll(), &path).expect("copy the vendored DLL");

        let held = PinnedDll::open(path.clone()).expect("the copy is the pinned driver");
        let write = std::fs::OpenOptions::new().write(true).open(&path);
        assert!(write.is_err(), "a writer opened the DLL while it was held");
        let renamed = dir.join("moved.dll");
        assert!(
            std::fs::rename(&path, &renamed).is_err(),
            "the DLL was renamed while it was held"
        );
        assert!(std::fs::remove_file(&path).is_err(), "the DLL was deleted while it was held");
        // Nor can the path the loader is given be pointed elsewhere.
        assert!(
            std::fs::rename(&dir, dir.with_extension("moved")).is_err(),
            "the DLL's directory was renamed while it was held"
        );
        assert!(!held.load_path.to_string_lossy().starts_with(r"\\?\"));
        assert_eq!(
            std::fs::canonicalize(&held.load_path).unwrap(),
            std::fs::canonicalize(&path).unwrap()
        );
        // Readers are still let in: the loader is one.
        std::fs::File::open(&path).expect("a reader opens the held DLL");

        drop(held);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("a writer opens the DLL once it is released");
        std::fs::remove_dir_all(&dir).expect("remove the temp dir");
    }
}

#[cfg(windows)]
use windows::{PlatformTun, Poller, Waker};

/// Check that the Wintun driver at `path` is byte-for-byte the one this crate
/// pins and will load. For an embedder that vendors the DLL and ships it next
/// to its own executable: run this over the vendored copy in a test, so a
/// driver update that forgets one side fails the build rather than the first
/// tun share started in the field.
#[cfg(windows)]
pub fn verify_driver(path: &std::path::Path) -> anyhow::Result<()> {
    windows::verify_dll(path)
}

/// Whether `packet` is IPv4 from `peer`, the adapter's own address.
///
/// The host sends to the virtual address from the adapter address, so nothing
/// else is a client. On a host that forwards IP, a neighbour routing the
/// virtual address through it would otherwise reach the share; dropping those
/// packets before smoltcp sees them also means they get no reply at all, not
/// even a reset.
fn sent_by(packet: &[u8], peer: Ipv4Addr) -> bool {
    packet.len() >= 20 && packet[0] >> 4 == 4 && packet[12..16] == peer.octets()
}

struct SmolDevice {
    io: PlatformTun,
    peer: Ipv4Addr,
    ignored_any: bool,
    shutdown: Arc<AtomicBool>,
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
        loop {
            let packet = self.io.receive()?;
            if sent_by(&packet, self.peer) {
                return Some((PacketRx { packet }, PacketTx { io: &mut self.io }));
            }
            // IPv6 the host sends on its own (router and multicast listener
            // traffic) is routine and not worth a line; another IPv4 source is.
            if !self.ignored_any && packet.len() >= 20 && packet[0] >> 4 == 4 {
                self.ignored_any = true;
                let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                smb_log!(
                    "tun: ignoring IPv4 packets not sent from {}, the first from {source}",
                    self.peer
                );
            }
            // Ignored packets arriving as fast as they are read would keep
            // this loop, and so the packet thread, from ever seeing shutdown.
            if self.shutdown.load(Ordering::Relaxed) {
                return None;
            }
        }
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

    /// The loopback side has something to read that the bridge has room for.
    #[cfg(unix)]
    fn wants_upstream_read(&self) -> bool {
        !self.upstream_eof && self.to_client.len() < PROXY_HIGH_WATER
    }

    /// Bytes from the client are waiting for the loopback side to take them.
    #[cfg(unix)]
    fn wants_upstream_write(&self) -> bool {
        !self.to_upstream.is_empty() && !self.upstream_write_closed
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
    mut poller: Poller,
    addrs: TunAddrs,
    port: u16,
    forward_to: SocketAddr,
    shutdown: Arc<AtomicBool>,
) {
    let mut device = SmolDevice {
        io: device,
        peer: addrs.adapter_ip(),
        ignored_any: false,
        shutdown: shutdown.clone(),
    };
    let started = StdInstant::now();
    let now = || Instant::from_micros(started.elapsed().as_micros() as i64);

    let config = Config::new(HardwareAddress::Ip);
    let mut interface = Interface::new(config, &mut device, now());
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(addrs.virtual_ip()), 32))
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

    // Each round drains the adapter into smoltcp, moves what it can between
    // smoltcp and the loopback bridges, and repeats while that moved anything.
    // Only a round that changed nothing sleeps, until a packet, a bridge
    // socket, the shutdown waker or smoltcp's next timer needs it.
    while !shutdown.load(Ordering::Relaxed) {
        interface.poll(now(), &mut device, &mut sockets);

        let mut did_work = false;
        for bridge in &mut bridges {
            did_work |= pump(bridge, &mut sockets, &poller, forward_to, port);
        }
        if did_work {
            continue;
        }
        let delay = interface.poll_delay(now(), &sockets);
        poller.wait(&device.io, &bridges, delay);
    }

    for bridge in &mut bridges {
        sockets.get_mut::<tcp::Socket>(bridge.handle).abort();
    }
    interface.poll(now(), &mut device, &mut sockets);
}

fn pump(
    bridge: &mut Bridge,
    sockets: &mut SocketSet<'_>,
    poller: &Poller,
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
                let ready = stream
                    .set_nonblocking(true)
                    .and_then(|()| poller.register(&stream));
                if let Err(error) = ready {
                    smb_log!("tun: cannot set up the loopback bridge: {error}");
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

    #[test]
    fn only_the_adapter_address_is_a_client() {
        let peer = Ipv4Addr::new(169, 254, 255, 2);
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&peer.octets());
        packet[16..20].copy_from_slice(&[169, 254, 255, 1]);
        assert!(sent_by(&packet, peer));

        // A forwarded packet from a neighbour, addressed to the same server.
        let mut forwarded = packet;
        forwarded[12..16].copy_from_slice(&[192, 168, 1, 50]);
        assert!(!sent_by(&forwarded, peer));

        // IPv6, and anything too short to carry an IPv4 header.
        let mut ipv6 = packet;
        ipv6[0] = 0x60;
        assert!(!sent_by(&ipv6, peer));
        assert!(!sent_by(&packet[..19], peer));
    }

    #[test]
    fn timers_round_up_to_the_next_millisecond() {
        assert_eq!(wait_millis(Duration::from_micros(0)), 0);
        assert_eq!(wait_millis(Duration::from_micros(1)), 1);
        assert_eq!(wait_millis(Duration::from_micros(1000)), 1);
        assert_eq!(wait_millis(Duration::from_micros(1001)), 2);
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
