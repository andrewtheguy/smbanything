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
    /// ZIP or uncompressed TAR archive to serve
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
    let generated_password = std::env::var_os("SMBANYTHING_PASSWORD").is_none();
    let archive = absolute_archive_path(&args.archive)?;
    let folder_name = archive_folder_name(&archive);
    let label = archive_label(&archive);
    let backing = Arc::new(archive::ArchiveBacking::open(&archive, label)?);
    let file_count = backing.file_count();
    let total_size = smb::Backing::total_size(backing.as_ref());
    let backing = archive::FolderBacking::new(&folder_name, backing);

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
        handle.mount().host()
    };
    let port = handle.port();
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
        assert_eq!(
            archive_folder_name(Path::new("/tmp/photos.zip")),
            "488b0141"
        );
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
}
