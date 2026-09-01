use std::path::PathBuf;
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

use crate::{OpenedArchive, open_archive};

pub(crate) struct ServerView {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) share: String,
    pub(crate) user: String,
    pub(crate) password: String,
    pub(crate) generated_password: bool,
    pub(crate) bind_all: bool,
    pub(crate) standard_port: bool,
}

struct LoadedArchive {
    path: PathBuf,
    folder: String,
    file_count: usize,
    total_size: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    Editing,
}

struct App {
    mode: Mode,
    input: String,
    loaded: Option<LoadedArchive>,
    notice: Option<Notice>,
}

struct Notice {
    error: bool,
    text: String,
}

enum Action {
    None,
    Load,
    Unload,
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
        input: String::new(),
        loaded: None,
        notice: None,
    };
    // Opening an archive indexes the whole of it, which on a large one takes
    // long enough to freeze the UI. A worker does it and hands the result
    // back here, so the loop keeps drawing and keeps answering quit and the
    // termination signal while the archive opens.
    let mut opening: Option<Receiver<Result<OpenedArchive>>> = None;

    loop {
        terminal.draw(|frame| render(frame, &app, server))?;

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
            Event::Paste(text) if app.mode == Mode::Editing => {
                app.input.extend(text.chars().filter(|ch| !ch.is_control()));
                Action::None
            }
            _ => Action::None,
        };
        match action {
            Action::None => {}
            Action::Quit => return Ok(()),
            Action::Unload => {
                // Also abandons an archive still opening: its result arrives
                // on a receiver nobody holds, so it is never published.
                opening = None;
                handle.unload();
                app.loaded = None;
                app.notice = Some(Notice {
                    error: false,
                    text: "Archive unloaded; the SMB share is still running.".to_string(),
                });
            }
            Action::Load if opening.is_none() => {
                if app.input.is_empty() {
                    app.notice = Some(Notice {
                        error: true,
                        text: "enter an archive path".to_string(),
                    });
                    continue;
                }
                let input = PathBuf::from(app.input.clone());
                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    let _ = tx.send(open_archive(&input));
                });
                opening = Some(rx);
                app.notice = Some(Notice {
                    error: false,
                    text: "Loading archive...".to_string(),
                });
            }
            // A second load while one is still opening: the first one wins.
            Action::Load => {}
        }
    }
}

fn finish_load(app: &mut App, handle: &smb::SmbHandle, opened: Result<OpenedArchive>) {
    match opened {
        Ok(opened) => {
            handle.load(opened.share_backing());
            app.input = opened.path.display().to_string();
            app.mode = Mode::Normal;
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

fn handle_key(app: &mut App, key: KeyEvent) -> Action {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return Action::Quit;
    }

    match app.mode {
        Mode::Normal => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Char('l') | KeyCode::Enter => {
                if let Some(loaded) = &app.loaded {
                    app.input = loaded.path.display().to_string();
                }
                app.mode = Mode::Editing;
                app.notice = None;
                Action::None
            }
            KeyCode::Char('u') => Action::Unload,
            _ => Action::None,
        },
        Mode::Editing => match key.code {
            KeyCode::Esc => {
                app.mode = Mode::Normal;
                Action::None
            }
            KeyCode::Enter => Action::Load,
            KeyCode::Backspace => {
                app.input.pop();
                Action::None
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.input.clear();
                Action::None
            }
            KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.input.push(ch);
                Action::None
            }
            _ => Action::None,
        },
    }
}

fn render(frame: &mut Frame, app: &App, server: &ServerView) {
    let [server_area, contents_area, input_area, notice_area, footer_area] = Layout::vertical([
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_server(frame, server, server_area);
    render_contents(frame, app, server, contents_area);
    render_input(frame, app, input_area);
    render_notice(frame, app, notice_area);
    let footer = if app.mode == Mode::Editing {
        "Enter load/replace  Esc cancel  Ctrl-U clear"
    } else {
        "l/Enter load or replace  u unload  q/Esc quit"
    };
    frame.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        footer_area,
    );
}

fn render_server(frame: &mut Frame, server: &ServerView, area: Rect) {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                "Running  ",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(r"\\{}\{}", server.host, server.share)),
        ]),
        Line::from(format!("Port: {}", server.port)),
        Line::from(format!("Username: {}", server.user)),
        Line::from(format!("Password: {}", server.password)),
    ];
    if server.generated_password {
        lines.push(Line::from(
            "Password generated for this run (set SMBANYTHING_PASSWORD to choose it).",
        ));
    }
    if server.bind_all {
        lines.push(Line::styled(
            "WARNING: file data is signed but not encrypted and is visible in transit.",
            Style::default().fg(Color::Yellow),
        ));
    } else if server.standard_port {
        lines.push(Line::from(
            "Standard SMB port: plain UNC paths work without a port option.",
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" SMB server ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_contents(frame: &mut Frame, app: &App, server: &ServerView, area: Rect) {
    let lines = match &app.loaded {
        Some(loaded) => vec![
            Line::styled("Archive loaded", Style::default().fg(Color::Green)),
            Line::from(format!("Source: {}", loaded.path.display())),
            Line::from(format!("Folder: {}", loaded.folder)),
            Line::from(format!(
                "Files: {}    Total size: {} bytes",
                loaded.file_count, loaded.total_size
            )),
            Line::from(format!(
                r"UNC: \\{}\{}\{}",
                server.host, server.share, loaded.folder
            )),
        ],
        None => vec![
            Line::styled("Empty", Style::default().fg(Color::Yellow)),
            Line::from(
                "The SMB base share is running. Load an archive to add its <8-hex-id> folder.",
            ),
        ],
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Contents ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let title = if app.mode == Mode::Editing {
        " Archive path (editing) "
    } else {
        " Archive path "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(if app.mode == Mode::Editing {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        });
    let inner_width = area.width.saturating_sub(2) as usize;
    let cursor = app.input.chars().count();
    let scroll = cursor.saturating_sub(inner_width.saturating_sub(1)) as u16;
    frame.render_widget(
        Paragraph::new(app.input.as_str()).block(block).scroll((0, scroll)),
        area,
    );
    if app.mode == Mode::Editing && area.width > 2 && area.height > 2 {
        let visible = cursor.saturating_sub(scroll as usize).min(inner_width);
        frame.set_cursor_position((area.x + 1 + visible as u16, area.y + 1));
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
