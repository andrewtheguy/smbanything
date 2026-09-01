mod archive;
mod connection;
mod picker;
mod tui;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use ratatui::{
    Terminal,
    crossterm::{
        cursor::Show,
        event::{DisableBracketedPaste, EnableBracketedPaste},
        execute,
        terminal::{
            EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
        },
    },
    prelude::CrosstermBackend,
};
use sha2::{Digest, Sha256};
use smbanything_core::smb::{self, Backing};

use crate::archive::{ArchiveBacking, FolderBacking};
use crate::connection::{Kind, ServerView};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Browse ZIP and TAR archives through a persistent, authenticated, read-only SMB 2.1 share"
)]
struct Args {
    /// ZIP, TAR, or gzip-compressed TAR archive to serve; with none, the
    /// browser starts on an empty share and archives are loaded from its UI
    archive: Option<PathBuf>,

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

    let wildcard_host = handle.mount().is_wildcard();
    let host = if wildcard_host {
        "<server-ip>".to_string()
    } else {
        handle.mount().host().to_string()
    };
    let server = ServerView {
        host,
        wildcard_host,
        port: handle.mount().port(),
        share: handle.share_name().to_string(),
        user: args.user,
        password,
        generated_password,
        bind_all: args.bind_all,
        standard_port: handle.on_standard_port(),
        tun: args.smb_tun.then_some(args.smb_tun_ip),
    };

    // The termination handler only wakes the loop below. Cleanup remains on
    // the main thread, where the terminal is restored before the SMB transport
    // is stopped and its thread joined.
    let (stop_tx, stop_rx) = mpsc::sync_channel(1);
    ctrlc::set_handler(move || {
        let _ = stop_tx.try_send(());
    })?;

    let result = match args.archive {
        Some(archive) => serve(&handle, &server, &archive, &stop_rx),
        None => browse(&handle, &server, stop_rx),
    };
    handle.stop();
    result
}

/// Serve one archive named on the command line: print where it is mounted and
/// wait for a termination signal. Scripts drive the server this way, and they
/// have no terminal for the browser UI to draw on.
fn serve(
    handle: &smb::SmbHandle,
    server: &ServerView,
    archive: &Path,
    stop_rx: &mpsc::Receiver<()>,
) -> Result<()> {
    let opened = open_archive(archive)?;
    let folder = opened.folder.clone();
    handle.load(opened.share_backing());

    println!(
        "Serving {} file{} ({} bytes) from {}",
        opened.file_count,
        if opened.file_count == 1 { "" } else { "s" },
        opened.total_size,
        opened.path.display()
    );
    // No path here: the listener is what this reports, and every path a client
    // can use is in the mount commands below in its own platform's spelling.
    let reach = if server.bind_all {
        "read-only, every interface"
    } else {
        "read-only, this machine only"
    };
    println!(
        "Server:   listening on {}:{}  ({reach})",
        server.host, server.port
    );
    println!("Folder:   {folder}");
    if let Some(addrs) = server.tun {
        println!(
            "Tun:      private adapter, standard SMB port. The machine's own file sharing is \
             untouched; {}/32 and {}/32 route here until this process stops.",
            addrs.virtual_ip(),
            addrs.adapter_ip()
        );
    }
    if server.bind_all {
        println!("Warning:  file data is signed but not encrypted and is visible in transit.");
    }
    println!("Username: {}", server.user);
    if server.generated_password {
        println!(
            "Password: {}  (generated for this run; set SMBANYTHING_PASSWORD to choose it)",
            server.password
        );
    } else {
        println!("Password: {}", server.password);
    }
    println!();
    // The same mount details the browser UI shows, so the two descriptions
    // cannot drift apart.
    for detail in connection::details(server) {
        match detail.kind {
            Kind::Heading => println!("{}:", detail.text),
            _ => println!("{}", detail.text),
        }
    }
    println!();
    println!("Press Ctrl-C to stop.");

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
    Ok(())
}

/// Run the interactive browser, which starts on an empty share and loads and
/// unloads archives while the server keeps running.
fn browse(
    handle: &smb::SmbHandle,
    server: &ServerView,
    stop_rx: mpsc::Receiver<()>,
) -> Result<()> {
    enable_raw_mode().context("entering raw mode")?;
    let entered = execute!(io::stdout(), EnterAlternateScreen).context("entering the UI screen");
    if let Err(e) = entered {
        let _ = disable_raw_mode();
        return Err(e);
    }
    // Bracketed paste makes a dropped or pasted archive path arrive as one
    // event instead of a burst of key presses, so a trailing newline in it
    // cannot act as Enter. Terminals without it still deliver the text.
    let bracketed_paste = execute!(io::stdout(), EnableBracketedPaste).is_ok();
    // A panic on the UI thread must leave the terminal usable, cursor
    // included. One on the archive loader thread must not: the UI is still
    // running there, and pulling the screen out from under it is worse than
    // the "loader stopped" notice it already reports.
    let ui_thread = thread::current().id();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if thread::current().id() == ui_thread {
            restore_terminal(bracketed_paste);
        }
        hook(info);
    }));

    let result = Terminal::new(CrosstermBackend::new(io::stdout()))
        .context("starting the UI")
        .and_then(|mut terminal| tui::run(&mut terminal, handle, server, stop_rx));
    restore_terminal(bracketed_paste);
    result
}

/// Put the terminal back the way it was found. Raw mode goes first, having
/// the most side effects; the cursor is shown last and unconditionally, since
/// the UI never draws with the real cursor and some terminals leave it hidden
/// on leaving the alternate screen.
fn restore_terminal(bracketed_paste: bool) {
    let _ = disable_raw_mode();
    if bracketed_paste {
        let _ = execute!(io::stdout(), DisableBracketedPaste);
    }
    let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
}

/// An archive opened and indexed, ready to be published to the share.
pub(crate) struct OpenedArchive {
    pub(crate) path: PathBuf,
    pub(crate) folder: String,
    pub(crate) file_count: usize,
    pub(crate) total_size: u64,
    backing: Arc<ArchiveBacking>,
}

impl OpenedArchive {
    /// The share-visible backing: the archive under its own folder.
    pub(crate) fn share_backing(&self) -> Arc<dyn Backing> {
        Arc::new(FolderBacking::new(
            &self.folder,
            Arc::clone(&self.backing) as Arc<dyn Backing>,
        ))
    }
}

/// Open and index an archive. This reads the whole archive directory and is
/// slow enough on a large one that callers with a UI run it off their event
/// thread.
pub(crate) fn open_archive(path: &Path) -> Result<OpenedArchive> {
    let path = absolute_archive_path(path)?;
    let folder = archive_folder_name(&path);
    let backing = Arc::new(ArchiveBacking::open(&path, archive_label(&path))?);
    Ok(OpenedArchive {
        file_count: backing.file_count(),
        total_size: backing.total_size(),
        path,
        folder,
        backing,
    })
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
        // The archive is optional: named, it is served without a UI; omitted,
        // the browser starts empty.
        assert!(Args::try_parse_from(["smbanything", "a.zip", "--smb-tun"]).is_ok());
        assert!(Args::try_parse_from(["smbanything", "--smb-tun"]).is_ok());
        assert!(Args::try_parse_from(["smbanything", "a.zip", "--smb-tun", "--bind-all"]).is_err());
        assert!(
            Args::try_parse_from(["smbanything", "a.zip", "--smb-tun", "--port", "445"]).is_err()
        );
        assert!(
            Args::try_parse_from(["smbanything", "a.zip", "--smb-tun-ip", "169.254.255.3"]).is_err()
        );
    }
}
