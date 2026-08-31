use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};

use anyhow::{Result, anyhow};

const MAX_EPHEMERAL_BIND_RETRIES: u32 = 64;

pub(crate) fn bind_localhost(port: u16) -> Result<Vec<TcpListener>> {
    if port == 0 {
        // While a fresh ephemeral port can still be drawn, a v6 loopback that is
        // already taken on the port v4 landed on is a reason to try another
        // port, not to give up half the server.
        for _ in 0..MAX_EPHEMERAL_BIND_RETRIES {
            if let Ok(listeners) = bind_localhost_once(0, true) {
                return Ok(listeners);
            }
        }
        // No port was free on both families. On a host with IPv6 disabled that
        // is the expected outcome after every retry, so fall back to IPv4 only —
        // and if even that fails, its error is the one worth reporting.
        return bind_localhost_once(0, false);
    }

    bind_localhost_once(port, false)
}

/// Bind both loopback families on one port. With `require_v6`, a v6 failure is
/// fatal so that the caller can retry on a different ephemeral port.
fn bind_localhost_once(port: u16, require_v6: bool) -> Result<Vec<TcpListener>> {
    let v4_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let v4 = bind_one(v4_addr, "IPv4")?;
    let bound_port = v4
        .local_addr()
        .map_err(|e| anyhow!("read bound IPv4 listener address: {e}"))?
        .port();

    // A host with IPv6 disabled, or one where only the v6 loopback of this port
    // is taken, must still get a working server: the v4 listener is already
    // bound and serving it is strictly better than failing the whole startup.
    // Only a v4 failure — handled above — is unconditionally fatal.
    let v6_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, bound_port, 0, 0));
    match bind_one(v6_addr, "IPv6") {
        Ok(v6) => Ok(vec![v4, v6]),
        Err(e) if require_v6 => Err(e),
        Err(e) => {
            eprintln!("smbanything: {e}; serving IPv4 loopback only");
            Ok(vec![v4])
        }
    }
}

fn bind_one(addr: SocketAddr, family: &'static str) -> Result<TcpListener> {
    let listener = TcpListener::bind(addr).map_err(|e| {
        if e.kind() == ErrorKind::AddrInUse {
            anyhow!(
                "localhost port {} is already in use on {family} ({addr})",
                addr.port()
            )
        } else {
            anyhow!("bind localhost {family} ({addr}): {e}")
        }
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|e| anyhow!("set_nonblocking {family} ({addr}): {e}"))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both loopback families on one port, except on a host with no IPv6 at
    /// all — there the documented IPv4-only fallback is what comes back, and
    /// demanding two listeners would fail the test rather than the code.
    #[test]
    fn binds_ipv4_and_ipv6_loopback_on_same_port() {
        let listeners = bind_localhost(0).expect("bind localhost");
        let addrs = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect::<Vec<_>>();
        let port = addrs[0].port();

        assert!(
            addrs.contains(&SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                port
            ))),
            "the IPv4 loopback listener is mandatory: {addrs:?}"
        );
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0));
        assert!(
            addrs == vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))]
                || addrs.contains(&v6),
            "IPv6 must be bound on the same port when it is available: {addrs:?}"
        );
    }

    #[test]
    fn fails_when_ipv4_port_is_in_use() {
        let blocker = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind IPv4 blocker");
        let port = blocker.local_addr().unwrap().port();

        let err = bind_localhost(port).expect_err("IPv4 conflict should fail");
        let msg = err.to_string();

        assert!(msg.contains("already in use"), "{msg}");
        assert!(msg.contains("IPv4"), "{msg}");
        assert!(msg.contains(&format!("127.0.0.1:{port}")), "{msg}");
    }

    /// An IPv6 loopback that cannot be bound is not fatal: the IPv4 listener is
    /// already up, and dropping it would refuse service on a host that only
    /// happens to have `[::1]` taken — or no IPv6 at all.
    #[test]
    fn ipv6_conflict_still_serves_ipv4() {
        let blocker = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind IPv6 blocker");
        let port = blocker.local_addr().unwrap().port();

        let listeners = bind_localhost(port).expect("IPv4-only startup is allowed");
        let addrs = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            addrs,
            vec![SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))]
        );
    }
}
