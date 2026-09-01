use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use smbanything_core::smb;

use crate::connection::{self, Kind, ServerView};
use crate::picker::{self, Choice, Picker};
use crate::root::{Control, RootBacking};
use crate::{OpenedArchive, open_archive};

struct LoadedArchive {
    path: PathBuf,
    folder: String,
    file_count: usize,
    total_size: u64,
}

enum Mode {
    Normal,
    /// Choosing an archive in the directory picker.
    Picking(Picker),
}

struct App {
    mode: Mode,
    /// Where the picker opens next: the loaded archive, or wherever it was
    /// last left, so a cancelled pick does not start over from the top.
    picker_start: PathBuf,
    loaded: Option<LoadedArchive>,
    notice: Option<Notice>,
    /// First visible line of the mount details, which are longer than the
    /// panel on most terminals.
    scroll: u16,
    /// Lines the details panel could not show at the last draw, so scrolling
    /// stops at the end of the text instead of running past it.
    scroll_max: u16,
}

struct Notice {
    error: bool,
    text: String,
}

enum Action {
    None,
    Load(PathBuf),
    Unload,
    ScrollBy(i32),
    Quit,
}

pub(crate) fn run(
    terminal: &mut DefaultTerminal,
    handle: &smb::SmbHandle,
    server: &ServerView,
    stop_rx: Receiver<()>,
) -> Result<()> {
    let mut app = App {
        mode: Mode::Normal,
        picker_start: picker::default_dir(),
        loaded: None,
        notice: None,
        scroll: 0,
        scroll_max: 0,
    };
    // Opening an archive indexes the whole of it, which on a large one takes
    // long enough to freeze the UI. A worker does it and hands the result
    // back here, so the loop keeps drawing and keeps answering quit and the
    // termination signal while the archive opens.
    let mut opening: Option<Receiver<Result<OpenedArchive>>> = None;

    loop {
        terminal.draw(|frame| render(frame, &mut app, server))?;

        match stop_rx.try_recv() {
            Ok(()) | Err(TryRecvError::Disconnected) => return Ok(()),
            Err(TryRecvError::Empty) => {}
        }
        if handle.logon_limit_reached() {
            bail!(
                "stopping after {} consecutive refused logons",
                handle.failed_logons()
            );
        }

        if let Some(rx) = &opening {
            match rx.try_recv() {
                Ok(opened) => {
                    opening = None;
                    finish_load(&mut app, handle, opened);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    opening = None;
                    app.notice = Some(Notice {
                        error: true,
                        text: "the archive loader stopped without a result".to_string(),
                    });
                }
            }
        }

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }

        let action = match event::read()? {
            Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
                handle_key(&mut app, key)
            }
            // A dropped or pasted path lands in the filter as one event, so
            // a newline on its end cannot fire Enter halfway through it.
            Event::Paste(text) => {
                if let Mode::Picking(picker) = &mut app.mode {
                    picker.push_filter_str(&text);
                }
                Action::None
            }
            _ => Action::None,
        };
        match action {
            Action::None => {}
            Action::ScrollBy(delta) => {
                let target = i64::from(app.scroll) + i64::from(delta);
                app.scroll = target.clamp(0, i64::from(app.scroll_max)) as u16;
            }
            Action::Quit => return Ok(()),
            Action::Unload => {
                // Also abandons an archive still opening: its result arrives
                // on a receiver nobody holds, so it is never published.
                opening = None;
                handle.load(Arc::new(RootBacking::empty(Control::Ui)));
                app.loaded = None;
                app.scroll = 0;
                app.notice = Some(Notice {
                    error: false,
                    text: "Archive unloaded; the SMB share is still running.".to_string(),
                });
            }
            Action::Load(path) => {
                close_picker(&mut app);
                // A second load while one is still opening: the first wins.
                if opening.is_some() {
                    app.notice = Some(Notice {
                        error: true,
                        text: "an archive is still loading".to_string(),
                    });
                    continue;
                }
                app.notice = Some(Notice {
                    error: false,
                    text: format!("Loading {}...", path.display()),
                });
                app.picker_start = path.clone();
                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    let _ = tx.send(open_archive(&path));
                });
                opening = Some(rx);
            }
        }
    }
}

fn finish_load(app: &mut App, handle: &smb::SmbHandle, opened: Result<OpenedArchive>) {
    match opened {
        Ok(opened) => {
            handle.load(Arc::new(RootBacking::with_archive(&opened, Control::Ui)));
            app.scroll = 0;
            app.notice = Some(Notice {
                error: false,
                text: format!("Loaded folder {}.", opened.folder),
            });
            app.loaded = Some(LoadedArchive {
                path: opened.path,
                folder: opened.folder,
                file_count: opened.file_count,
                total_size: opened.total_size,
            });
        }
        Err(e) => {
            app.notice = Some(Notice {
                error: true,
                text: format!("{e:#}"),
            });
        }
    }
}

/// Leave the picker, remembering where it was for next time.
fn close_picker(app: &mut App) {
    if let Mode::Picking(picker) = &app.mode {
        app.picker_start = picker.dir().to_path_buf();
        app.mode = Mode::Normal;
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> Action {
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    if key.code == KeyCode::Char('c') && control {
        return Action::Quit;
    }

    match &mut app.mode {
        Mode::Normal => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Char('l') | KeyCode::Enter => {
                let start = app
                    .loaded
                    .as_ref()
                    .map_or(app.picker_start.clone(), |loaded| loaded.path.clone());
                app.mode = Mode::Picking(Picker::open(&start));
                app.notice = None;
                Action::None
            }
            KeyCode::Char('u') => Action::Unload,
            KeyCode::Down | KeyCode::Char('j') => Action::ScrollBy(1),
            KeyCode::Up | KeyCode::Char('k') => Action::ScrollBy(-1),
            KeyCode::PageDown => Action::ScrollBy(10),
            KeyCode::PageUp => Action::ScrollBy(-10),
            KeyCode::Home => Action::ScrollBy(i32::MIN / 2),
            KeyCode::End => Action::ScrollBy(i32::MAX / 2),
            _ => Action::None,
        },
        Mode::Picking(picker) => match key.code {
            KeyCode::Esc => {
                close_picker(app);
                Action::None
            }
            KeyCode::Enter => match picker.enter() {
                Choice::Load(path) => Action::Load(path),
                Choice::Rejected(reason) => {
                    app.notice = Some(Notice {
                        error: true,
                        text: reason,
                    });
                    Action::None
                }
                Choice::None | Choice::Moved => Action::None,
            },
            KeyCode::Up => {
                picker.move_by(-1);
                Action::None
            }
            KeyCode::Down => {
                picker.move_by(1);
                Action::None
            }
            KeyCode::PageUp => {
                picker.move_by(-10);
                Action::None
            }
            KeyCode::PageDown => {
                picker.move_by(10);
                Action::None
            }
            KeyCode::Home => {
                picker.move_by(i64::MIN / 2);
                Action::None
            }
            KeyCode::End => {
                picker.move_by(i64::MAX / 2);
                Action::None
            }
            KeyCode::Left => {
                picker.parent();
                Action::None
            }
            KeyCode::Right => {
                picker.descend();
                Action::None
            }
            KeyCode::Backspace => {
                picker.backspace();
                Action::None
            }
            KeyCode::Tab => {
                picker.toggle_hidden();
                Action::None
            }
            KeyCode::F(5) => {
                picker.refresh();
                Action::None
            }
            KeyCode::Char('u') if control => {
                picker.clear_filter();
                Action::None
            }
            KeyCode::Char('r') if control => {
                picker.refresh();
                Action::None
            }
            // Alt-anything is left alone: a terminal spells it as Esc then
            // the key, and a stray letter in the filter is worse than a lost
            // key press when the two were meant separately.
            KeyCode::Char(ch) if !control && !key.modifiers.contains(KeyModifiers::ALT) => {
                picker.push_filter(ch);
                Action::None
            }
            _ => Action::None,
        },
    }
}

fn render(frame: &mut Frame, app: &mut App, server: &ServerView) {
    // Every panel above the middle is sized to the text it actually holds,
    // wrapping included, so the mount commands or the picker get every row
    // the terminal can spare.
    let width = frame.area().width.saturating_sub(2);
    let server_lines = server_lines(server);
    let contents_lines = contents_lines(app);
    let notice_lines = app.notice.as_ref().map_or(0, |notice| {
        wrapped_rows(&notice.text, width + 2).min(3)
    });
    let picking = matches!(app.mode, Mode::Picking(_));

    let [server_area, contents_area, middle_area, filter_area, notice_area, footer_area] =
        Layout::vertical([
            Constraint::Length(boxed_height(&server_lines, width)),
            Constraint::Length(boxed_height(&contents_lines, width)),
            Constraint::Fill(1),
            Constraint::Length(if picking { 3 } else { 0 }),
            Constraint::Length(notice_lines),
            Constraint::Length(1),
        ])
        .areas(frame.area());

    render_block(frame, server_lines, " SMB server ", server_area);
    render_block(frame, contents_lines, " Contents ", contents_area);
    let footer = match &mut app.mode {
        Mode::Picking(picker) => {
            render_picker(frame, picker, middle_area);
            render_filter(frame, picker, filter_area);
            "↑/↓ choose  Enter open/load  ←/Backspace up  type to filter  Tab hidden  Esc cancel"
        }
        Mode::Normal => {
            render_details(frame, app, server, middle_area);
            "l/Enter load or replace  u unload  ↑/↓ PgUp/PgDn scroll  q/Esc quit"
        }
    };
    render_notice(frame, app, notice_area);
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        footer_area,
    );
}

/// Rows a bordered panel needs to show `lines` in full at `width`.
fn boxed_height(lines: &[Line<'_>], width: u16) -> u16 {
    lines
        .iter()
        .map(|line| wrapped_rows(&line.to_string(), width))
        .sum::<u16>()
        .saturating_add(2)
}

fn render_block(frame: &mut Frame, lines: Vec<Line>, title: &str, area: Rect) {
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn server_lines(server: &ServerView) -> Vec<Line<'static>> {
    // No path here: the listener is what this box reports, and every path a
    // client can actually use is in the mount commands below, spelled the way
    // its own platform wants it. A headline UNC would be wrong on any port but
    // 445 anyway, since no UNC syntax can carry one.
    let reach = if server.bind_all {
        "read-only, every interface"
    } else {
        "read-only, this machine only"
    };
    let mut lines = vec![
        Line::from(vec![
            Span::raw("Server:   "),
            Span::styled(
                format!("listening on {}:{}", server.host, server.port),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  ({reach})")),
        ]),
    ];
    // Keyed on the transport actually in use, not on the port number: --port
    // 445 reaches the standard port with no tunnel anywhere, and claiming a
    // private adapter exists when none does would simply be wrong.
    if let Some(addrs) = server.tun {
        lines.push(Line::from(format!(
            "Tun:      private adapter, standard SMB port. The machine's own file sharing is \
             untouched; {}/32 and {}/32 route here until this process stops.",
            addrs.virtual_ip(),
            addrs.adapter_ip()
        )));
    }
    if server.bind_all {
        lines.push(Line::styled(
            "Warning:  file data is signed but not encrypted and is visible in transit.",
            Style::default().fg(Color::Yellow),
        ));
    }
    lines.push(Line::from(format!("Username: {}", server.user)));
    lines.push(Line::from(if server.generated_password {
        format!(
            "Password: {}  (generated for this run; set SMBANYTHING_PASSWORD to choose it)",
            server.password
        )
    } else {
        format!("Password: {}", server.password)
    }));
    lines
}

fn contents_lines(app: &App) -> Vec<Line<'static>> {
    match &app.loaded {
        Some(loaded) => vec![
            Line::styled("Archive loaded", Style::default().fg(Color::Green)),
            Line::from(format!("Source: {}", loaded.path.display())),
            Line::from(format!("Folder: {}", loaded.folder)),
            Line::from(format!(
                "Files: {}    Total size: {} bytes",
                loaded.file_count, loaded.total_size
            )),
        ],
        None => vec![
            Line::styled("Empty", Style::default().fg(Color::Yellow)),
            Line::from(
                "The SMB base share is running with only README.txt. Load an archive to add its <8-hex-id> folder.",
            ),
        ],
    }
}

/// The per-OS mount commands. They rarely fit, so the panel scrolls and says
/// how much is left below.
fn render_details(frame: &mut Frame, app: &mut App, server: &ServerView, area: Rect) {
    let lines: Vec<Line> = connection::details(server)
        .into_iter()
        .map(|detail| {
            let style = match detail.kind {
                Kind::Heading => Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                Kind::Command => Style::default().fg(Color::White),
                Kind::Note => Style::default().fg(Color::Gray),
                Kind::Warning => Style::default().fg(Color::Yellow),
            };
            Line::styled(detail.text, style)
        })
        .collect();

    let inner_height = area.height.saturating_sub(2);
    let inner_width = area.width.saturating_sub(2);
    let wrapped: u16 = lines
        .iter()
        .map(|line| wrapped_rows(&line.to_string(), inner_width))
        .sum();
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });
    app.scroll_max = wrapped.saturating_sub(inner_height);
    app.scroll = app.scroll.min(app.scroll_max);
    let hidden = app.scroll_max - app.scroll;
    let title = match hidden {
        0 => " Connecting ".to_string(),
        1 => " Connecting  (1 more line below) ".to_string(),
        n => format!(" Connecting  ({n} more lines below) "),
    };
    frame.render_widget(
        paragraph
            .block(Block::default().title(title).borders(Borders::ALL))
            .scroll((app.scroll, 0)),
        area,
    );
}

/// Rows one line of text occupies once wrapped at `width`, matching how the
/// paragraph widget breaks at spaces. Ratatui keeps its own line count behind
/// an unstable feature, and the scroll limit needs a number.
fn wrapped_rows(text: &str, width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let mut rows = 1u16;
    let mut col = 0usize;
    for (index, word) in text.split(' ').enumerate() {
        let word_width = word.chars().count();
        let needed = if index == 0 { word_width } else { word_width + 1 };
        if col > 0 && col + needed > width {
            rows = rows.saturating_add(1);
            col = word_width;
        } else {
            col += needed;
        }
        // A word longer than the panel is broken across as many rows as it
        // needs rather than pushed onto one.
        while col > width {
            col -= width;
            rows = rows.saturating_add(1);
        }
    }
    rows
}

/// The directory listing: folders first, then archives with their sizes, the
/// selection in reverse video.
fn render_picker(frame: &mut Frame, picker: &mut Picker, area: Rect) {
    let inner = Rect {
        x: area.x.saturating_add(1),
        y: area.y.saturating_add(1),
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    };
    // A long directory keeps its end, which is the part that changes.
    let label = if picker.show_hidden() {
        " Choose an archive (hidden shown)  "
    } else {
        " Choose an archive  "
    };
    let room = usize::from(area.width.saturating_sub(2)).saturating_sub(label.chars().count() + 1);
    let title = format!(
        "{label}{} ",
        tail(&picker.dir().display().to_string(), room)
    );
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    if let Some(problem) = picker.problem() {
        lines.push(Line::styled(
            tail(problem, usize::from(inner.width)),
            Style::default().fg(Color::Red),
        ));
    }
    let rows = usize::from(inner.height).saturating_sub(lines.len());
    picker.scroll_to_fit(rows);
    let window = picker.window(rows);
    if window.is_empty() {
        let text = if picker.filter().is_empty() {
            "No folders or archives here.".to_string()
        } else {
            format!("Nothing here matches \"{}\".", picker.filter())
        };
        lines.push(Line::styled(text, Style::default().fg(Color::DarkGray)));
    }
    for (entry, selected) in window {
        let (label, style) = match entry.kind {
            picker::Kind::Parent => ("../".to_string(), Style::default().fg(Color::Gray)),
            picker::Kind::Dir => (format!("{}/", entry.name), Style::default().fg(Color::Cyan)),
            picker::Kind::Archive => (entry.name.clone(), Style::default().fg(Color::White)),
        };
        let size = entry.size.map(human_size).unwrap_or_default();
        let width = usize::from(inner.width);
        let label_width = width.saturating_sub(size.chars().count() + 2);
        let mut label: String = label.chars().take(label_width).collect();
        let pad = width
            .saturating_sub(label.chars().count())
            .saturating_sub(size.chars().count());
        label.push_str(&" ".repeat(pad));
        label.push_str(&size);
        let style = if selected {
            style.add_modifier(Modifier::REVERSED | Modifier::BOLD)
        } else {
            style
        };
        lines.push(Line::styled(label, style));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The filter row. The cursor is a reverse-video cell drawn here rather than
/// the terminal's own, which some terminals lose track of across the
/// alternate screen; nothing in this UI ever moves the real cursor.
fn render_filter(frame: &mut Frame, picker: &Picker, area: Rect) {
    let block = Block::default()
        .title(" Filter, or a path to open ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let width = usize::from(inner.width);
    let text = picker.filter();
    let cursor = text.chars().count();
    if text.is_empty() {
        frame.render_widget(
            Paragraph::new(" type to narrow the list, or paste a path")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
    } else {
        let skip = cursor.saturating_sub(width - 1);
        let shown: String = text.chars().skip(skip).collect();
        frame.render_widget(Paragraph::new(shown), inner);
    }
    let column = cursor.min(width - 1) as u16;
    if let Some(cell) = frame
        .buffer_mut()
        .cell_mut((inner.x + column, inner.y))
    {
        cell.set_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .remove_modifier(Modifier::DIM),
        );
    }
}

/// The last `width` characters of `text`, marked when cut.
fn tail(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    let keep = width.saturating_sub(1);
    let mut out = String::from("…");
    out.extend(text.chars().skip(count - keep));
    out
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn render_notice(frame: &mut Frame, app: &App, area: Rect) {
    let Some(notice) = &app.notice else {
        return;
    };
    let color = if notice.error { Color::Red } else { Color::Cyan };
    frame.render_widget(
        Paragraph::new(notice.text.as_str())
            .style(Style::default().fg(color))
            .wrap(Wrap { trim: false }),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(port: u16, standard_port: bool) -> ServerView {
        ServerView {
            host: "127.0.0.1".to_string(),
            wildcard_host: false,
            port,
            share: "share".to_string(),
            user: "smbanything".to_string(),
            password: "hunter2".to_string(),
            generated_password: false,
            bind_all: false,
            standard_port,
            tun: None,
        }
    }

    fn text(server: &ServerView) -> String {
        server_lines(server)
            .iter()
            .map(Line::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_server_box_reports_the_listener_and_leaves_paths_to_the_commands() {
        let text = text(&view(4456, false));
        assert!(text.contains("Server:   listening on 127.0.0.1:4456"));
        assert!(text.contains("read-only, this machine only"));
        // A UNC in the header would name port 445 on any other port, and the
        // per-platform paths belong in the mount commands regardless.
        assert!(!text.contains(r"\\127.0.0.1"), "no path belongs here:\n{text}");
        assert!(!text.contains("//127.0.0.1"), "no path belongs here:\n{text}");
    }

    #[test]
    fn sizes_and_titles_are_kept_short() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(3 << 30), "3.0 GiB");
        assert_eq!(tail("abcdef", 10), "abcdef");
        assert_eq!(tail("abcdef", 4), "…def");
    }

    #[test]
    fn wrapped_rows_counts_the_rows_a_line_takes() {
        assert_eq!(wrapped_rows("", 10), 1);
        assert_eq!(wrapped_rows("short", 10), 1);
        assert_eq!(wrapped_rows("one two three", 7), 2);
        assert_eq!(wrapped_rows("one two three", 5), 3);
        // A command with no spaces long enough to break is still counted.
        assert_eq!(wrapped_rows(&"x".repeat(25), 10), 3);
    }
}
