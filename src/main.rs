mod local_server;
mod smb;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use anyhow::{Result, bail};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Serve an unencrypted ZIP archive as an authenticated, read-only SMB 2.1 share"
)]
struct Args {
    /// Unencrypted ZIP archive to serve
    archive: PathBuf,

    /// TCP port to listen on (0 chooses an ephemeral port)
    #[arg(short, long, default_value_t = 4456)]
    port: u16,

    /// SMB share name
    #[arg(short, long, default_value = smb::DEFAULT_SHARE_NAME)]
    share: String,

    /// SMB account name
    #[arg(short, long, default_value = smb::DEFAULT_SHARE_USER)]
    user: String,

    /// Listen on every interface instead of IPv4/IPv6 loopback
    #[arg(long)]
    bind_all: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_simple_name("share", &args.share)?;
    validate_simple_name("user", &args.user)?;

    let password = password()?;
    let generated_password = std::env::var_os("SMBZIP_PASSWORD").is_none();
    let label = archive_label(&args.archive);
    let backing = smb::ZipBacking::open(&args.archive, label)?;
    let file_count = backing.file_count();
    let total_size = smb::Backing::total_size(&backing);

    let bind = if args.bind_all {
        smb::Bind::AllInterfaces
    } else {
        smb::Bind::Loopback
    };
    let handle = smb::start(
        args.port,
        &args.share,
        Arc::new(backing),
        bind,
        smb::Credentials {
            user: args.user.clone(),
            password: password.clone(),
        },
    )?;

    let host = if args.bind_all {
        "<server-ip>"
    } else {
        &handle.mount().host
    };
    let port = handle.port;
    println!(
        "Serving {} file{} ({} bytes) from {}",
        file_count,
        if file_count == 1 { "" } else { "s" },
        total_size,
        args.archive.display()
    );
    println!("Share:    \\\\{host}\\{}", handle.share_name);
    println!("Port:     {port}");
    println!("Username: {}", args.user);
    println!("Password: {password}");
    if generated_password {
        println!("(generated for this run; set SMBZIP_PASSWORD to choose it)");
    }
    if args.bind_all {
        println!();
        println!("WARNING: file data is signed but not encrypted and is visible in transit.");
    }

    println!();
    println!("Mount examples (the clients prompt for the password):");
    println!(
        "  Linux:  sudo mount -t cifs -o port={port},vers=2.1,username={},ro,file_mode=0444,dir_mode=0555 //{host}/{} /mnt/zip",
        args.user, handle.share_name
    );
    println!(
        "  macOS:  smb://{}@{host}:{port}/{}",
        args.user, handle.share_name
    );
    if handle.on_standard_port() {
        println!(
            "  Windows: net use Z: \\\\{host}\\{} * /user:{}",
            handle.share_name, args.user
        );
    } else {
        println!(
            "  Windows: net use Z: \\\\{host}\\{} * /user:{} /TCPPORT:{port}",
            handle.share_name, args.user
        );
    }
    println!();
    println!("Press Ctrl-C to stop.");

    let (stop_tx, stop_rx) = mpsc::sync_channel(1);
    ctrlc::set_handler(move || {
        let _ = stop_tx.try_send(());
    })?;

    loop {
        match stop_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) if handle.logon_limit_reached() => {
                bail!(
                    "stopping after {} consecutive refused logons",
                    handle.failed_logons()
                );
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    handle.stop();
    Ok(())
}

fn password() -> Result<String> {
    let password = match std::env::var("SMBZIP_PASSWORD") {
        Ok(password) => password,
        Err(std::env::VarError::NotPresent) => smb::random_password(),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("SMBZIP_PASSWORD must be valid UTF-8")
        }
    };
    if password.is_empty() || password.chars().any(char::is_control) {
        bail!("SMBZIP_PASSWORD must be non-empty and contain no control characters");
    }
    Ok(password)
}

fn validate_simple_name(kind: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 80
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '$'))
    {
        bail!(
            "{kind} name must be 1-80 characters using only ASCII letters, digits, '-', '_', or '$'"
        );
    }
    Ok(())
}

fn archive_label(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("archive");
    let mut label = String::from("zip-");
    label.extend(stem.chars().filter(|ch| !ch.is_control()).take(28));
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_and_user_names_are_shell_and_url_safe() {
        for valid in ["zip", "my-archive", "share_2", "DATA$"] {
            validate_simple_name("share", valid).unwrap();
        }
        for invalid in ["", "has space", "a/b", "a\\b", "bad:name"] {
            assert!(
                validate_simple_name("share", invalid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn archive_labels_are_bounded() {
        assert_eq!(archive_label(Path::new("/tmp/photos.zip")), "zip-photos");
        assert!(
            archive_label(Path::new("/tmp/a\nname.zip"))
                .chars()
                .all(|ch| !ch.is_control())
        );
        assert!(
            archive_label(Path::new("/tmp/abcdefghijklmnopqrstuvwxyz123456.zip"))
                .chars()
                .count()
                <= 32
        );
    }
}
