//! The mount details shown to the user: one description of how to reach the
//! share, rendered by the browser UI and printed by the non-interactive
//! `serve` path so the two can never drift apart.

use smbanything_core::smb::TunAddrs;

pub(crate) struct ServerView {
    pub(crate) host: String,
    /// The bind address names no reachable machine, so `host` is a placeholder
    /// the reader has to substitute an address of their own for.
    pub(crate) wildcard_host: bool,
    pub(crate) port: u16,
    pub(crate) share: String,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) generated_password: bool,
    pub(crate) bind_all: bool,
    pub(crate) standard_port: bool,
    /// The packet tunnel's addresses, when one fronts this server.
    pub(crate) tun: Option<TunAddrs>,
}

/// How a line is meant to read, so the UI can colour it and stdout can ignore
/// it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Heading,
    Command,
    Note,
    Warning,
}

pub(crate) struct DetailLine {
    pub(crate) kind: Kind,
    pub(crate) text: String,
}

fn line(kind: Kind, text: impl Into<String>) -> DetailLine {
    DetailLine {
        kind,
        text: text.into(),
    }
}

impl ServerView {
    /// The share as a UNC, for Explorer and `net use`.
    fn unc(&self) -> String {
        format!(r"\\{}\{}", self.host, self.share)
    }
}

/// Per-OS mount instructions for the share, and what the reader has to know
/// about them: which of them the current listener supports, what the tunnel
/// changes, and what the server refuses.
pub(crate) fn details(server: &ServerView) -> Vec<DetailLine> {
    let ServerView {
        host, port, user, ..
    } = server;
    let path = &server.share;
    let unc = server.unc();
    let mut lines = Vec::new();

    // Always the base share, never an archive's folder: the mount outlives any
    // one archive, and a loaded archive simply appears inside it.
    lines.push(line(
        Kind::Note,
        "These mount the base share. A loaded archive appears inside it under its own \
         <8-hex-id> folder, so loading and unloading need no remount.",
    ));
    lines.push(line(Kind::Note, ""));
    if server.wildcard_host {
        lines.push(line(
            Kind::Warning,
            format!("Substitute an address of this machine for {host} in every command below."),
        ));
        lines.push(line(Kind::Note, ""));
    }

    lines.push(line(
        Kind::Note,
        "Mount it with (each prompts for the password above):",
    ));
    lines.push(line(Kind::Note, ""));

    lines.push(line(Kind::Heading, "Linux"));
    let port_option = if server.standard_port {
        String::new()
    } else {
        format!("port={port},")
    };
    lines.push(line(
        Kind::Command,
        format!(
            "  sudo mount -t cifs -o {port_option}vers=2.1,username={user},ro,\
             uid=$(id -u),gid=$(id -g),file_mode=0444,dir_mode=0555 //{host}/{path} \
             /mnt/smbanything"
        ),
    ));
    lines.push(line(Kind::Note, ""));

    lines.push(line(Kind::Heading, "macOS"));
    lines.push(line(
        Kind::Note,
        "  Finder → Go → Connect to Server (Cmd+K), then enter:",
    ));
    if server.standard_port {
        lines.push(line(Kind::Command, format!("  smb://{user}@{host}/{path}")));
    } else {
        lines.push(line(
            Kind::Command,
            format!("  smb://{user}@{host}:{port}/{path}"),
        ));
        // Finder asks for the share list on the standard port only, so on any
        // other port the full path is the only way in.
        lines.push(line(
            Kind::Note,
            "  Enter the whole path: Finder only lists a server's shares on port 445.",
        ));
    }
    lines.push(line(Kind::Note, ""));

    lines.push(line(Kind::Heading, "Windows"));
    if server.standard_port {
        // On the standard port there is no port option to carry, which is the
        // entire reason the tunnel exists: a UNC path works in Explorer's
        // address bar and in any program that takes one, not only as a mapped
        // drive letter.
        lines.push(line(
            Kind::Command,
            format!("  net use Z: {unc} * /user:{user}"),
        ));
        lines.push(line(
            Kind::Note,
            format!("  Or paste {unc} straight into Explorer's address bar."),
        ));
    } else {
        lines.push(line(
            Kind::Command,
            format!("  net use Z: {unc} * /user:{user} /TCPPORT:{port}"),
        ));
        // A custom port is reachable only as a mapped drive, and only from
        // 24H2 or newer — two separate limits, both lifted by serving the
        // standard port, so --smb-tun is not just the older-Windows fallback.
        lines.push(line(
            Kind::Note,
            format!(
                "  A mapped drive is the only way in: no UNC path can carry a port, so \
                 {unc} on its own goes to 445 and never reaches this share."
            ),
        ));
        lines.push(line(
            Kind::Note,
            "  /TCPPORT: also needs Windows 11 24H2 or newer. Starting smbanything with \
             --smb-tun serves the standard port instead — a UNC path Explorer accepts, \
             and the only way in from older builds.",
        ));
    }
    lines.push(line(Kind::Note, ""));

    lines.push(line(
        Kind::Note,
        "Every client authenticates and authenticated session messages are signed. Writes \
         are refused at the protocol level, and so is opening a file for execute. Nothing \
         is encrypted: signing stops tampering, not reading.",
    ));

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(port: u16, standard_port: bool) -> ServerView {
        ServerView {
            host: "127.0.0.1".to_string(),
            wildcard_host: false,
            port,
            share: "anything".to_string(),
            user: "smbanything".to_string(),
            password: "hunter2".to_string(),
            generated_password: true,
            bind_all: false,
            standard_port,
            tun: None,
        }
    }

    fn text(server: &ServerView) -> String {
        details(server)
            .into_iter()
            .map(|detail| detail.text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn every_client_platform_gets_a_command() {
        let text = text(&view(4456, false));
        for heading in ["Linux", "macOS", "Windows"] {
            assert!(text.contains(heading), "{heading} missing from:\n{text}");
        }
        assert!(text.contains("mount -t cifs"));
        assert!(text.contains("smb://smbanything@127.0.0.1:4456/anything"));
        assert!(text.contains(r"net use Z: \\127.0.0.1\anything"));
    }

    #[test]
    fn a_custom_port_is_carried_by_every_command_that_needs_it() {
        let text = text(&view(4456, false));
        assert!(text.contains("port=4456,vers=2.1"));
        assert!(text.contains("/TCPPORT:4456"));
        assert!(text.contains("24H2"), "the Windows version floor is worth saying");
    }

    #[test]
    fn the_standard_port_drops_the_port_options_and_offers_a_unc_path() {
        let text = text(&view(445, true));
        assert!(!text.contains("port="), "no port option belongs on 445:\n{text}");
        assert!(!text.contains("/TCPPORT"));
        assert!(text.contains("smb://smbanything@127.0.0.1/anything"));
        assert!(text.contains("Explorer's address bar"));
    }

    #[test]
    fn the_commands_mount_the_base_share_and_never_an_archive_folder() {
        // The archive's folder is reported elsewhere; baking it into a mount
        // would tie the mount to one archive the user can unload at any time.
        let text = text(&view(4456, false));
        assert!(text.contains("//127.0.0.1/anything /mnt/smbanything"));
        assert!(text.contains("<8-hex-id> folder"));
        assert!(
            !text.contains("anything/4") && !text.contains(r"anything\4"),
            "no folder belongs in a mount path:\n{text}"
        );
    }

    #[test]
    fn a_wildcard_bind_tells_the_reader_to_substitute_an_address() {
        let mut server = view(4456, false);
        server.host = "<server-ip>".to_string();
        server.wildcard_host = true;
        let lines = details(&server);
        let warning = lines
            .iter()
            .find(|detail| detail.kind == Kind::Warning)
            .expect("a wildcard bind warns");
        assert!(warning.text.contains("<server-ip>"));
    }
}
