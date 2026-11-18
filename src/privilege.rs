//! Hand root back once the server is bound, before it serves anyone.
//!
//! Root is needed only to create the `--smb-tun` adapter, or to bind a
//! privileged `--port`, and both happen inside `smb::bind`, before any thread
//! reads from a client. Everything after that — archive parsing, NTLM, the SMB
//! server — needs no more than the invoking user could do themselves, so under
//! sudo the whole process becomes that user again. The adapter's file
//! descriptor stays open and keeps working: the kernel checked privilege when
//! it was opened, not on each read.
//!
//! Windows has no equivalent that is cheap: an elevated token cannot be
//! narrowed back to the user's for a running process, so an elevated share
//! stays elevated there.

use std::ffi::CString;

use anyhow::{Context, Result, bail};

/// If this is root by way of sudo, become the invoking user for good and
/// return their uid. Otherwise change nothing: a process that is not root has
/// nothing to drop, and one that is root without sudo has nobody to drop to.
pub(crate) fn drop_root() -> Result<Option<u32>> {
    // SAFETY: no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let Some(uid) = id_from_env("SUDO_UID")? else {
        return Ok(None);
    };
    if uid == 0 {
        return Ok(None);
    }
    let gid = id_from_env("SUDO_GID")?.context("sudo set SUDO_UID but not SUDO_GID")?;
    let user = std::env::var("SUDO_USER").context("sudo set SUDO_UID but not SUDO_USER")?;
    let user = CString::new(user).context("SUDO_USER contains a NUL byte")?;

    // Supplementary groups, then the group, then the user: each step gives up
    // the right to take the ones before it. No server thread exists yet, and
    // the C library would apply each change to every thread if one did.
    // SAFETY: `user` is a valid C string for the duration of the call.
    if unsafe { libc::initgroups(user.as_ptr(), gid as _) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("setting the groups of {user:?}"));
    }
    // SAFETY: no pointer arguments.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("switching to group {gid}"));
    }
    // SAFETY: no pointer arguments.
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("switching to user {uid}"));
    }
    // From root, setuid sets the real, effective and saved IDs alike, so there
    // is no way back. Prove it rather than trust it.
    // SAFETY: no pointer arguments.
    if unsafe { libc::setuid(0) } == 0 {
        bail!("root could be regained after switching to user {uid}");
    }
    Ok(Some(uid))
}

fn id_from_env(name: &str) -> Result<Option<u32>> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map(Some)
            .with_context(|| format!("{name} is not a numeric id: {value:?}")),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} is not valid UTF-8"),
    }
}

