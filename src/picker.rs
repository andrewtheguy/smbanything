//! The archive picker: a directory listing the browser UI walks with the
//! keyboard to choose an archive, so no path ever has to be typed or dropped
//! into the terminal. A typed or pasted path still works: one that names an
//! existing directory or archive is followed on Enter.

use std::fs;
use std::path::{Path, PathBuf};

use crate::archive::Format;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// The `..` row, present whenever the directory has a parent.
    Parent,
    Dir,
    Archive,
}

#[derive(Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) kind: Kind,
    /// Archive size in bytes; directories carry none.
    pub(crate) size: Option<u64>,
    hidden: bool,
}

/// What Enter did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    /// Nothing was selected, so nothing happened.
    None,
    /// The picker moved to another directory.
    Moved,
    /// An archive to load.
    Load(PathBuf),
    /// A typed path that could not be followed, with the reason.
    Rejected(String),
}

pub(crate) struct Picker {
    dir: PathBuf,
    entries: Vec<Entry>,
    filter: String,
    show_hidden: bool,
    /// Index into the rows `visible` returns, not into `entries`.
    selected: usize,
    /// First row shown, kept so the selection stays on screen.
    offset: usize,
    /// Why the directory could not be read, if it could not.
    problem: Option<String>,
}

impl Picker {
    /// Open the picker at `start`: the directory itself, or the directory
    /// holding it when it names a file, climbing to the nearest readable
    /// ancestor when it does not exist any more. A start that is a file in the
    /// listing comes up selected.
    pub(crate) fn open(start: &Path) -> Self {
        let start = std::path::absolute(start).unwrap_or_else(|_| start.to_path_buf());
        let mut dir = if start.is_dir() {
            start.clone()
        } else {
            start.parent().map_or_else(|| start.clone(), Path::to_path_buf)
        };
        while fs::read_dir(&dir).is_err() {
            match dir.parent() {
                Some(parent) => dir = parent.to_path_buf(),
                None => break,
            }
        }
        let mut picker = Self {
            dir: PathBuf::new(),
            entries: Vec::new(),
            filter: String::new(),
            show_hidden: false,
            selected: 0,
            offset: 0,
            problem: None,
        };
        picker.go_to(dir);
        picker.select_path(&start);
        picker
    }

    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(crate) fn filter(&self) -> &str {
        &self.filter
    }

    pub(crate) fn show_hidden(&self) -> bool {
        self.show_hidden
    }

    pub(crate) fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Re-read the directory, keeping the selection on the same name where it
    /// still exists.
    pub(crate) fn refresh(&mut self) {
        let keep = self.selected_entry().map(|entry| entry.path.clone());
        self.read(self.dir.clone());
        if let Some(path) = keep {
            self.select_path(&path);
        }
    }

    fn go_to(&mut self, dir: PathBuf) {
        self.filter.clear();
        self.selected = 0;
        self.offset = 0;
        self.read(dir);
    }

    fn read(&mut self, dir: PathBuf) {
        self.entries.clear();
        self.problem = None;
        if let Some(parent) = dir.parent() {
            self.entries.push(Entry {
                name: "..".to_string(),
                path: parent.to_path_buf(),
                kind: Kind::Parent,
                size: None,
                hidden: false,
            });
        }
        match fs::read_dir(&dir) {
            Ok(listing) => {
                for entry in listing.flatten() {
                    // Follows symlinks, so a link to a directory is walkable
                    // and a link to an archive is loadable; a dangling one is
                    // left out rather than shown as something it is not.
                    let path = entry.path();
                    let Ok(metadata) = fs::metadata(&path) else {
                        continue;
                    };
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let hidden = name.starts_with('.');
                    let (kind, size) = if metadata.is_dir() {
                        (Kind::Dir, None)
                    } else if metadata.is_file() && Format::of(&path).is_some() {
                        (Kind::Archive, Some(metadata.len()))
                    } else {
                        continue;
                    };
                    self.entries.push(Entry {
                        name,
                        path,
                        kind,
                        size,
                        hidden,
                    });
                }
            }
            Err(e) => self.problem = Some(format!("cannot read {}: {e}", dir.display())),
        }
        self.entries.sort_by(|a, b| {
            (a.kind as u8)
                .cmp(&(b.kind as u8))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.name.cmp(&b.name))
        });
        self.dir = dir;
        self.clamp();
    }

    /// The rows the filter and hidden-file setting leave, in display order.
    pub(crate) fn visible(&self) -> Vec<&Entry> {
        let needle = self.filter.to_lowercase();
        self.entries
            .iter()
            .filter(|entry| {
                if entry.kind == Kind::Parent {
                    return self.filter.is_empty();
                }
                (self.show_hidden || !entry.hidden)
                    && (needle.is_empty() || entry.name.to_lowercase().contains(&needle))
            })
            .collect()
    }

    pub(crate) fn selected_entry(&self) -> Option<&Entry> {
        self.visible().get(self.selected).copied()
    }

    /// Move the window as little as needed to keep the selection inside
    /// `height` rows; call before `window` for the same height.
    pub(crate) fn scroll_to_fit(&mut self, height: usize) {
        let count = self.visible().len();
        let height = height.max(1);
        if self.selected < self.offset {
            self.offset = self.selected;
        } else if self.selected >= self.offset + height {
            self.offset = self.selected + 1 - height;
        }
        self.offset = self.offset.min(count.saturating_sub(height));
    }

    /// The rows to draw in `height` lines, each with whether it is selected.
    pub(crate) fn window(&self, height: usize) -> Vec<(&Entry, bool)> {
        self.visible()
            .into_iter()
            .enumerate()
            .skip(self.offset)
            .take(height.max(1))
            .map(|(index, entry)| (entry, index == self.selected))
            .collect()
    }

    fn clamp(&mut self) {
        let count = self.visible().len();
        self.selected = self.selected.min(count.saturating_sub(1));
    }

    fn select_path(&mut self, path: &Path) {
        if let Some(index) = self
            .visible()
            .iter()
            .position(|entry| entry.kind != Kind::Parent && entry.path == path)
        {
            self.selected = index;
        }
    }

    pub(crate) fn move_by(&mut self, delta: i64) {
        let count = self.visible().len();
        if count == 0 {
            self.selected = 0;
            return;
        }
        let target = i64::try_from(self.selected).unwrap_or(0).saturating_add(delta);
        self.selected = target.clamp(0, i64::try_from(count - 1).unwrap_or(0)) as usize;
    }

    /// Follow the typed path if there is one, else act on the selection:
    /// step into a directory or hand back an archive to load.
    pub(crate) fn enter(&mut self) -> Choice {
        if let Some(target) = typed_path(&self.filter, &self.dir) {
            return self.follow(&target);
        }
        let Some(entry) = self.selected_entry() else {
            return Choice::None;
        };
        let path = entry.path.clone();
        match entry.kind {
            Kind::Parent | Kind::Dir => self.follow(&path),
            Kind::Archive => Choice::Load(path),
        }
    }

    fn follow(&mut self, target: &Path) -> Choice {
        let target = normalize(target);
        match fs::metadata(&target) {
            Ok(metadata) if metadata.is_dir() => {
                let from = self.dir.clone();
                self.go_to(target);
                // Going up leaves the directory just left selected, so Left
                // then Right returns to where the user was.
                self.select_path(&from);
                Choice::Moved
            }
            Ok(_) if Format::of(&target).is_some() => Choice::Load(target),
            Ok(_) => Choice::Rejected(format!(
                "{} is not a .zip, .tar, .tar.gz, or .tgz archive",
                target.display()
            )),
            Err(e) => Choice::Rejected(format!("{}: {e}", target.display())),
        }
    }

    /// Go up one directory. At the top there is nowhere to go.
    pub(crate) fn parent(&mut self) {
        if let Some(parent) = self.dir.parent().map(Path::to_path_buf) {
            self.follow(&parent);
        }
    }

    /// Step into the selected directory; an archive selection is left alone.
    pub(crate) fn descend(&mut self) {
        if let Some(entry) = self.selected_entry()
            && matches!(entry.kind, Kind::Parent | Kind::Dir)
        {
            let path = entry.path.clone();
            self.follow(&path);
        }
    }

    pub(crate) fn push_filter(&mut self, ch: char) {
        if ch.is_control() {
            return;
        }
        self.filter.push(ch);
        self.filter_changed();
    }

    pub(crate) fn push_filter_str(&mut self, text: &str) {
        self.filter.extend(text.chars().filter(|ch| !ch.is_control()));
        self.filter_changed();
    }

    /// Drop the last filter character; with no filter, go up instead, which
    /// is what Backspace means in a file dialog.
    pub(crate) fn backspace(&mut self) {
        if self.filter.pop().is_some() {
            self.filter_changed();
        } else {
            self.parent();
        }
    }

    pub(crate) fn clear_filter(&mut self) {
        self.filter.clear();
        self.filter_changed();
    }

    fn filter_changed(&mut self) {
        self.selected = 0;
        self.offset = 0;
    }

    pub(crate) fn toggle_hidden(&mut self) {
        let keep = self.selected_entry().map(|entry| entry.path.clone());
        self.show_hidden = !self.show_hidden;
        self.selected = 0;
        if let Some(path) = keep {
            self.select_path(&path);
        }
    }
}

/// An absolute path with `.` and `..` folded away, so the directory shown is
/// the one the user thinks of and the loaded archive's folder id (a hash of
/// its absolute path) is the same however it was reached.
fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;

    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// The path a filter names, if it reads as a path rather than a name to match:
/// absolute, home-relative, or containing a separator. Terminals that drop a
/// file in as text quote it or escape its spaces, and both spellings are
/// undone here.
fn typed_path(text: &str, dir: &Path) -> Option<PathBuf> {
    let text = text.trim();
    let text = text
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .or_else(|| {
            text.strip_prefix('\'')
                .and_then(|rest| rest.strip_suffix('\''))
        })
        .unwrap_or(text);
    let text = if cfg!(windows) {
        text.to_string()
    } else {
        text.replace("\\ ", " ")
    };
    if text.is_empty() {
        return None;
    }
    if let Some(rest) = text.strip_prefix('~')
        && (rest.is_empty() || rest.starts_with(['/', '\\']))
    {
        let home = std::env::home_dir()?;
        return Some(home.join(rest.trim_start_matches(['/', '\\'])));
    }
    let path = Path::new(&text);
    let looks_like_path =
        path.is_absolute() || text.contains(['/', '\\']) || text == "..";
    looks_like_path.then(|| dir.join(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("photos")).unwrap();
        fs::create_dir(root.path().join(".cache")).unwrap();
        fs::write(root.path().join("backup.tar.gz"), b"").unwrap();
        fs::write(root.path().join("Album.zip"), b"").unwrap();
        fs::write(root.path().join("notes.txt"), b"").unwrap();
        fs::write(root.path().join(".secret.zip"), b"").unwrap();
        fs::write(root.path().join("photos").join("trip.tgz"), b"").unwrap();
        root
    }

    fn names(picker: &Picker) -> Vec<String> {
        picker
            .visible()
            .iter()
            .map(|entry| entry.name.clone())
            .collect()
    }

    #[test]
    fn lists_directories_then_archives_and_hides_dotfiles() {
        let root = fixture();
        let mut picker = Picker::open(root.path());
        assert_eq!(names(&picker), ["..", "photos", "Album.zip", "backup.tar.gz"]);
        picker.toggle_hidden();
        assert_eq!(
            names(&picker),
            ["..", ".cache", "photos", ".secret.zip", "Album.zip", "backup.tar.gz"]
        );
    }

    #[test]
    fn opening_at_a_file_selects_it_in_its_directory() {
        let root = fixture();
        let picker = Picker::open(&root.path().join("backup.tar.gz"));
        assert_eq!(picker.dir(), root.path());
        assert_eq!(picker.selected_entry().unwrap().name, "backup.tar.gz");
    }

    #[test]
    fn opening_at_a_missing_path_climbs_to_the_nearest_directory() {
        let root = fixture();
        let picker = Picker::open(&root.path().join("gone").join("away.zip"));
        assert_eq!(picker.dir(), root.path());
    }

    #[test]
    fn enter_walks_directories_and_hands_back_archives() {
        let root = fixture();
        let mut picker = Picker::open(root.path());
        picker.move_by(1);
        assert_eq!(picker.enter(), Choice::Moved);
        assert_eq!(picker.dir(), root.path().join("photos"));
        assert_eq!(names(&picker), ["..", "trip.tgz"]);
        picker.move_by(1);
        assert_eq!(
            picker.enter(),
            Choice::Load(root.path().join("photos").join("trip.tgz"))
        );
        // Going up leaves the directory just left selected.
        picker.parent();
        assert_eq!(picker.dir(), root.path());
        assert_eq!(picker.selected_entry().unwrap().name, "photos");
    }

    #[test]
    fn the_filter_matches_names_case_insensitively_and_backspace_goes_up_when_empty() {
        let root = fixture();
        let mut picker = Picker::open(&root.path().join("photos"));
        picker.push_filter_str("TRIP");
        assert_eq!(names(&picker), ["trip.tgz"]);
        picker.push_filter('x');
        assert!(names(&picker).is_empty());
        picker.clear_filter();
        assert_eq!(names(&picker), ["..", "trip.tgz"]);
        picker.push_filter('t');
        picker.backspace();
        assert_eq!(names(&picker), ["..", "trip.tgz"]);
        picker.backspace();
        assert_eq!(picker.dir(), root.path());
    }

    #[test]
    fn a_typed_path_is_followed_with_quotes_and_escapes_undone() {
        let root = fixture();
        fs::create_dir(root.path().join("my albums")).unwrap();
        fs::write(root.path().join("my albums").join("a.zip"), b"").unwrap();
        let mut picker = Picker::open(root.path());

        let quoted = format!("\"{}\"", root.path().join("photos").display());
        picker.push_filter_str(&quoted);
        assert_eq!(picker.enter(), Choice::Moved);
        assert_eq!(picker.dir(), root.path().join("photos"));

        picker.push_filter_str("../my albums/a.zip");
        assert_eq!(
            picker.enter(),
            Choice::Load(root.path().join("my albums").join("a.zip"))
        );

        picker.clear_filter();
        picker.push_filter_str("../notes.txt");
        assert!(matches!(picker.enter(), Choice::Rejected(reason) if reason.contains("not a")));
        picker.clear_filter();
        picker.push_filter_str("../nowhere/");
        assert!(matches!(picker.enter(), Choice::Rejected(_)));
    }

    #[cfg(unix)]
    #[test]
    fn shell_escaped_spaces_are_undone() {
        let root = fixture();
        fs::create_dir(root.path().join("my albums")).unwrap();
        let mut picker = Picker::open(root.path());
        picker.push_filter_str("my\\ albums/");
        assert_eq!(picker.enter(), Choice::Moved);
        assert_eq!(picker.dir(), root.path().join("my albums"));
    }

    #[cfg(unix)]
    #[test]
    fn normalize_folds_dot_components_lexically() {
        assert_eq!(normalize(Path::new("/a/b/../c/./d")), PathBuf::from("/a/c/d"));
        assert_eq!(normalize(Path::new("/../a")), PathBuf::from("/a"));
    }

    #[test]
    fn a_plain_name_is_a_filter_not_a_path() {
        assert_eq!(typed_path("photos", Path::new("/x")), None);
        assert_eq!(typed_path("", Path::new("/x")), None);
        assert_eq!(
            typed_path("a/b", Path::new("/x")),
            Some(PathBuf::from("/x").join("a/b"))
        );
    }

    #[test]
    fn the_window_keeps_the_selection_on_screen() {
        let root = tempfile::tempdir().unwrap();
        for index in 0..20 {
            fs::write(root.path().join(format!("{index:02}.zip")), b"").unwrap();
        }
        let mut picker = Picker::open(root.path());
        picker.move_by(15);
        picker.scroll_to_fit(5);
        let rows = picker.window(5);
        assert_eq!(rows.len(), 5);
        assert!(rows.iter().any(|(entry, selected)| *selected && entry.name == "14.zip"));
        picker.move_by(-100);
        picker.scroll_to_fit(5);
        let rows = picker.window(5);
        assert_eq!(rows[0].0.name, "..");
        assert!(rows[0].1);
    }

    #[test]
    fn an_unreadable_directory_still_offers_the_way_up() {
        let root = fixture();
        let mut picker = Picker::open(root.path());
        picker.push_filter_str("photos");
        picker.enter();
        fs::remove_dir_all(root.path().join("photos")).unwrap();
        picker.refresh();
        assert!(picker.problem().is_some());
        assert_eq!(names(&picker), [".."]);
        picker.enter();
        assert_eq!(picker.dir(), root.path());
    }
}
