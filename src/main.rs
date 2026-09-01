mod archive;
mod tui;

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use sha2::{Digest, Sha256};
use smbanything_core::smb;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Browse ZIP and TAR archives through a persistent, authenticated, read-only SMB 2.1 share"
)]
struct Args {
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
        bind,
        smb::Credentials {
            user: args.user.clone(),
            password: password.clone(),
        },
    )?;

    let host = if handle.mount().is_wildcard() {
        "<server-ip>".to_string()
    } else {
        handle.mount().host().to_string()
    };
    let server = tui::ServerView {
        host,
        port: handle.mount().port(),
        share: handle.share_name().to_string(),
        user: args.user,
        password,
        generated_password,
        bind_all: args.bind_all,
        standard_port: handle.on_standard_port(),
    };

    // The termination handler only wakes the UI loop. Cleanup remains on the
    // main thread, where the terminal is restored before the SMB transport is
    // stopped and its thread joined.
    let (stop_tx, stop_rx) = mpsc::sync_channel(1);
    ctrlc::set_handler(move || {
        let _ = stop_tx.try_send(());
    })?;

    let mut terminal = ratatui::init();
    let result = tui::run(&mut terminal, &handle, &server, stop_rx);
    ratatui::restore();
    handle.stop();
    result
}

pub(crate) fn absolute_archive_path(path: &Path) -> Result<PathBuf> {
    std::path::absolute(path)
        .with_context(|| format!("making archive path absolute: {}", path.display()))
}

pub(crate) fn archive_folder_name(absolute_path: &Path) -> String {
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

pub(crate) fn archive_label(path: &Path) -> String {
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
        assert!(Args::try_parse_from(["smbanything", "archive.zip"]).is_err());
        assert!(Args::try_parse_from(["smbanything", "--smb-tun"]).is_ok());
        assert!(Args::try_parse_from(["smbanything", "--smb-tun", "--bind-all"]).is_err());
        assert!(
            Args::try_parse_from(["smbanything", "--smb-tun", "--port", "445"]).is_err()
        );
        assert!(
            Args::try_parse_from(["smbanything", "--smb-tun-ip", "169.254.255.3"]).is_err()
        );
    }
}
