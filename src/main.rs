mod archive;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use sha2::{Digest, Sha256};
use smbanything_core::smb;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Serve a ZIP or TAR archive as an authenticated, read-only SMB 2.1 share"
)]
struct Args {
    /// ZIP, TAR, or gzip-compressed TAR archive to serve
    archive: PathBuf,

    /// TCP port to listen on (0 chooses an ephemeral port)
    #[arg(short, long, default_value_t = 4456, conflicts_with = "smb_tun")]
    port: u16,

    /// SMB share name
    #[arg(short, long, default_value = smb::DEFAULT_SHARE_NAME)]
    share: String,

    /// SMB account name
    #[arg(short, long, default_value = smb::DEFAULT_SHARE_USER)]
    user: String,

    /// Listen on every interface instead of IPv4/IPv6 loopback
    #[arg(long, conflicts_with = "smb_tun")]
    bind_all: bool,

    /// Serve port 445 through a private packet tunnel at 169.254.255.1
    #[arg(long)]
    smb_tun: bool,

    /// Client address for --smb-tun; the next address is assigned to the adapter
    #[arg(
        long,
        default_value_t = smb::DEFAULT_TUN_ADDRS,
        requires = "smb_tun"
    )]
    smb_tun_ip: smb::TunAddrs,
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_simple_name("share", &args.share)?;
    validate_simple_name("user", &args.user)?;

    let password = password()?;
    let generated_password = std::env::var_os("SMBANYTHING_PASSWORD").is_none();
    let archive = absolute_archive_path(&args.archive)?;
    let folder_name = archive_folder_name(&archive);
    let label = archive_label(&archive);
    let backing = Arc::new(archive::ArchiveBacking::open(&archive, label)?);
    let file_count = backing.file_count();
    let total_size = smb::Backing::total_size(backing.as_ref());
    let backing = archive::FolderBacking::new(&folder_name, backing);

    let bind = if args.smb_tun {
        smb::Bind::Tun(smb::TunConfig {
            port: smb::STANDARD_SMB_PORT,
            addrs: args.smb_tun_ip,
        })
    } else if args.bind_all {
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

    // A wildcard bind names no reachable machine, so the UNC path printed for
    // it has to be completed by the user.
    let host = if handle.mount().is_wildcard() {
        "<server-ip>"
    } else {
        handle.mount().host()
    };
    let port = handle.mount().port();
    println!(
        "Serving {} file{} ({} bytes) from {}",
        file_count,
        if file_count == 1 { "" } else { "s" },
        total_size,
        archive.display()
    );
    println!(
        "Folder:   \\\\{host}\\{}\\{folder_name}",
        handle.share_name()
    );
    println!("Port:     {port}");
    println!("Username: {}", args.user);
    println!("Password: {password}");
    if generated_password {
        println!("(generated for this run; set SMBANYTHING_PASSWORD to choose it)");
    }
    if args.bind_all {
        println!();
        println!("WARNING: file data is signed but not encrypted and is visible in transit.");
    }

    println!();
    println!("Mount examples (the clients prompt for the password):");
    println!(
        "  Linux:  sudo mount -t cifs -o port={port},vers=2.1,username={},ro,file_mode=0444,dir_mode=0555 //{host}/{}/{folder_name} /mnt/smbanything",
        args.user, handle.share_name()
    );
    println!(
        "  macOS:  smb://{}@{host}:{port}/{}/{folder_name}",
        args.user, handle.share_name()
    );
    if handle.on_standard_port() {
        println!(
            "  Windows: net use Z: \\\\{host}\\{}\\{folder_name} * /user:{}",
            handle.share_name(), args.user
        );
    } else {
        println!(
            "  Windows: net use Z: \\\\{host}\\{}\\{folder_name} * /user:{} /TCPPORT:{port}",
            handle.share_name(), args.user
        );
    }
    println!();
    println!("Press Ctrl-C to stop.");

    // Handles SIGTERM and SIGHUP as well as SIGINT (the `termination` feature),
    // so that every ordinary way of stopping the server unwinds to the end of
    // main. Expanded ZIP entries live in a temporary directory that is removed
    // when the backing drops, and a signal that kills the process outright
    // leaves that directory behind.
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

fn absolute_archive_path(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path)
        .with_context(|| format!("making archive path absolute: {}", path.display()))
}

fn archive_folder_name(absolute_path: &Path) -> String {
    use std::fmt::Write as _;

    debug_assert!(absolute_path.is_absolute());
    let digest = Sha256::digest(absolute_path.as_os_str().as_encoded_bytes());
    let mut folder_name = String::with_capacity(8);
    for byte in &digest[..4] {
        write!(&mut folder_name, "{byte:02x}").expect("writing to a String cannot fail");
    }
    folder_name
}

fn password() -> Result<String> {
    let password = match std::env::var("SMBANYTHING_PASSWORD") {
        Ok(password) => password,
        Err(std::env::VarError::NotPresent) => smb::random_password(),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("SMBANYTHING_PASSWORD must be valid UTF-8")
        }
    };
    if password.is_empty() || password.chars().any(char::is_control) {
        bail!("SMBANYTHING_PASSWORD must be non-empty and contain no control characters");
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
    let mut label = String::from("smbanything-");
    label.extend(stem.chars().filter(|ch| !ch.is_control()).take(20));
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
        assert_eq!(
            archive_label(Path::new("/tmp/photos.zip")),
            "smbanything-photos"
        );
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

    #[test]
    fn archive_folder_is_the_sha256_prefix_of_the_absolute_path() {
        // The digest covers the path's own bytes, so the fixture has to be
        // spelled the way the platform spells an absolute path — `/tmp/...` is
        // rooted but not absolute on Windows, which needs a drive prefix — and
        // each spelling hashes to its own folder name.
        #[cfg(unix)]
        let (path, expected) = ("/tmp/photos.zip", "488b0141");
        #[cfg(windows)]
        let (path, expected) = (r"C:\tmp\photos.zip", "765fbe48");

        let path = Path::new(path);
        assert!(path.is_absolute(), "{path:?} is not absolute here");
        assert_eq!(archive_folder_name(path), expected);
    }

    #[test]
    fn relative_archive_paths_are_made_absolute_before_hashing() {
        let absolute = absolute_archive_path(Path::new("photos.zip")).unwrap();
        assert!(absolute.is_absolute());
        assert_eq!(
            absolute.file_name().and_then(|name| name.to_str()),
            Some("photos.zip")
        );
    }

    #[test]
    fn packet_tunnel_uses_the_reserved_link_local_pair() {
        let default = smb::DEFAULT_TUN_ADDRS;
        assert_eq!(
            default.virtual_ip(),
            std::net::Ipv4Addr::new(169, 254, 255, 1)
        );
        assert_eq!(
            default.adapter_ip(),
            std::net::Ipv4Addr::new(169, 254, 255, 2)
        );
        for address in [default.virtual_ip(), default.adapter_ip()] {
            assert!(address.is_link_local());
            assert_eq!(address.octets()[2], 255);
        }
    }

    #[test]
    fn packet_tunnel_cli_rejects_incompatible_listener_options() {
        assert!(Args::try_parse_from(["smbanything", "a.zip", "--smb-tun"]).is_ok());
        assert!(
            Args::try_parse_from(["smbanything", "a.zip", "--smb-tun", "--bind-all"])
                .is_err()
        );
        assert!(
            Args::try_parse_from(["smbanything", "a.zip", "--smb-tun", "--port", "445"])
                .is_err()
        );
        assert!(
            Args::try_parse_from([
                "smbanything",
                "a.zip",
                "--smb-tun-ip",
                "169.254.255.3"
            ])
            .is_err()
        );
    }
}
