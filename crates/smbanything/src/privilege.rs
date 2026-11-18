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

use std::ffi::{CStr, CString, OsStr};
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result, bail};

use crate::connection::RunsAs;

/// If this is root by way of sudo, become the invoking user for good, with
/// their HOME, USER and LOGNAME, and say so. Otherwise change nothing: a
/// process that is not root has nothing to drop, and one that is root without
/// sudo has nobody to drop to.
pub(crate) fn drop_root() -> Result<RunsAs> {
    // SAFETY: no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(RunsAs::Starter);
    }
    let Some(uid) = id_from_env("SUDO_UID")? else {
        return Ok(RunsAs::Root);
    };
    if uid == 0 {
        return Ok(RunsAs::Root);
    }
    let gid = id_from_env("SUDO_GID")?.context("sudo set SUDO_UID but not SUDO_GID")?;
    let name = std::env::var("SUDO_USER").context("sudo set SUDO_UID but not SUDO_USER")?;
    let user = CString::new(name.clone()).context("SUDO_USER contains a NUL byte")?;
    // sudo leaves HOME naming root's home (Debian and Ubuntu set HOME=/root),
    // so `~` would still mean /root once the process is the user.
    // SAFETY: `user` is a valid C string; the entry is copied out before any
    // other passwd lookup can overwrite it.
    let home = unsafe {
        let entry = libc::getpwnam(user.as_ptr());
        if entry.is_null() || (*entry).pw_dir.is_null() {
            None
        } else {
            Some(CStr::from_ptr((*entry).pw_dir).to_owned())
        }
    }
    .with_context(|| format!("{name} has no home directory in the user database"))?;

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
    // SAFETY: no other thread exists yet (smb::bind starts none), so nothing
    // reads the environment while it changes.
    unsafe {
        std::env::set_var("HOME", OsStr::from_bytes(home.to_bytes()));
        std::env::set_var("USER", &name);
        std::env::set_var("LOGNAME", &name);
    }
    Ok(RunsAs::DroppedTo(uid))
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
