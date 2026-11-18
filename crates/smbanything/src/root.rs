//! The share root: a `README.txt` saying what the server is doing, beside the
//! folder holding the loaded archive when one is loaded.
//!
//! A client that mounts the share before anything is loaded, or after an
//! unload, would otherwise see an empty directory and have no way to tell a
//! working server from a broken mount. The README also carries the archive's
//! own path, which the eight-hex-character folder name deliberately hides.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use smbanything_core::smb::{Backing, FileReader, NodeInfo, NodeKind, SmbPath, status};

use crate::OpenedArchive;

pub(crate) const README_NAME: &str = "README.txt";

/// The volume label while no archive is loaded.
const EMPTY_LABEL: &str = "smbanything";

/// How the share's contents change over the server's life, which is what a
/// reader who found the share by its README most needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Control {
    /// Archives are loaded and unloaded from the terminal UI.
    Ui,
    /// One archive named on the command line, served until the process stops.
    CommandLine,
}

pub(crate) struct RootBacking {
    /// When this root was published, reported as every synthetic timestamp so
    /// a client sees the README change whenever the contents do.
    created: SystemTime,
    readme: Bytes,
    archive: Option<Folder>,
}

struct Folder {
    info: NodeInfo,
    backing: Arc<dyn Backing>,
}

/// Where a client path lands in the root.
enum Located<'a> {
    Root,
    Readme,
    /// Inside the archive folder; an empty path is the folder itself.
    Archive(&'a Folder, SmbPath),
}

impl RootBacking {
    /// A root holding only the README: nothing is loaded.
    pub(crate) fn empty(control: Control) -> Self {
        Self::build(None, control)
    }

    /// The README beside the archive under its own folder.
    pub(crate) fn with_archive(archive: &OpenedArchive, control: Control) -> Self {
        Self::build(Some(archive), control)
    }

    fn build(archive: Option<&OpenedArchive>, control: Control) -> Self {
        let created = SystemTime::now();
        Self {
            created,
            readme: Bytes::from(readme_text(archive, control)),
            archive: archive.map(|archive| Folder {
                info: NodeInfo::synthetic_dir(&archive.folder, created),
                backing: Arc::clone(&archive.backing),
            }),
        }
    }

    fn readme_info(&self) -> NodeInfo {
        NodeInfo {
            name: README_NAME.to_string(),
            kind: NodeKind::File,
            size: self.readme.len() as u64,
            mtime: self.created,
            atime: self.created,
            ctime: self.created,
        }
    }

    fn locate(&self, path: &SmbPath) -> Option<Located<'_>> {
        let Some((first, rest)) = path.split_first() else {
            return Some(Located::Root);
        };
        if first.eq_ignore_ascii_case(README_NAME) {
            return rest.is_root().then_some(Located::Readme);
        }
        self.archive
            .as_ref()
            .filter(|folder| first.eq_ignore_ascii_case(&folder.info.name))
            .map(|folder| Located::Archive(folder, rest))
    }
}

impl Backing for RootBacking {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
        match self.locate(path).ok_or(status::OBJECT_NAME_NOT_FOUND)? {
            Located::Root => Ok(NodeInfo::synthetic_dir("", self.created)),
            Located::Readme => Ok(self.readme_info()),
            Located::Archive(folder, inner) if inner.is_root() => Ok(folder.info.clone()),
            Located::Archive(folder, inner) => folder.backing.stat(&inner),
        }
    }

    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
        match self.locate(path).ok_or(status::OBJECT_PATH_NOT_FOUND)? {
            Located::Root => Ok(std::iter::once(self.readme_info())
                .chain(self.archive.iter().map(|folder| folder.info.clone()))
                .collect()),
            Located::Readme => Err(status::NOT_A_DIRECTORY),
            Located::Archive(folder, inner) => folder.backing.list(&inner),
        }
    }

    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
        match self.locate(path).ok_or(status::OBJECT_NAME_NOT_FOUND)? {
            // The root and the folder are the directories `stat` and `list`
            // report them to be; saying they do not exist contradicts that.
            Located::Root => Err(status::FILE_IS_A_DIRECTORY),
            Located::Readme => Ok(Arc::new(Readme(self.readme.clone()))),
            Located::Archive(_, inner) if inner.is_root() => Err(status::FILE_IS_A_DIRECTORY),
            Located::Archive(folder, inner) => folder.backing.open(&inner),
        }
    }

    fn label(&self) -> &str {
        self.archive
            .as_ref()
            .map_or(EMPTY_LABEL, |folder| folder.backing.label())
    }

    fn total_size(&self) -> u64 {
        let archive = self
            .archive
            .as_ref()
            .map_or(0, |folder| folder.backing.total_size());
        archive.saturating_add(self.readme.len() as u64)
    }
}

struct Readme(Bytes);

impl FileReader for Readme {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(Bytes::new());
        };
        if offset >= self.0.len() {
            return Ok(Bytes::new());
        }
        let end = offset.saturating_add(len as usize).min(self.0.len());
        Ok(self.0.slice(offset..end))
    }
}

/// The README's text. Plain ASCII with a blank line between paragraphs, so it
/// reads the same in every client's default text viewer.
fn readme_text(archive: Option<&OpenedArchive>, control: Control) -> String {
    let mut text = String::from(
        "smbanything read-only share\n\
         ===========================\n\n",
    );
    match archive {
        Some(archive) => {
            text.push_str(&format!(
                "Archive:  {}\n\
                 Name:     {}\n\
                 Folder:   {}\n\
                 Contents: {} file{}, {} bytes\n\n\
                 The archive's files are under the folder named above. The folder is\n\
                 named with the first eight hex characters of the SHA-256 of the\n\
                 archive's absolute path, so the same archive always appears under\n\
                 the same folder name.\n\n",
                archive.path.display(),
                file_name(&archive.path),
                archive.folder,
                archive.file_count,
                if archive.file_count == 1 { "" } else { "s" },
                archive.total_size,
            ));
        }
        None => text.push_str(
            "No archive is loaded. This README is the only thing in the share.\n\n",
        ),
    }
    text.push_str(
        "About this share\n\
         ----------------\n\
         Everything here is read-only. Creating, changing, renaming and deleting\n\
         files are refused by the server itself, not merely by the mount.\n\n",
    );
    match control {
        Control::Ui => text.push_str(
            "Archives are loaded and unloaded from the smbanything terminal UI on\n\
             the machine running the server: press l to load or replace an archive\n\
             and u to unload it. The share stays mounted throughout; only its\n\
             contents change. Loading replaces the whole share, so files still\n\
             open from a previous archive stop reading, and a client may show a\n\
             stale listing until it is refreshed.\n\n",
        ),
        Control::CommandLine => text.push_str(
            "This archive was named on the smbanything command line and is served\n\
             until that process stops. Nothing else will appear in the share.\n\n",
        ),
    }
    text.push_str("This README.txt is rewritten whenever the share's contents change.\n");
    text
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.display().to_string(), |name| name.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::archive::test_support::{TestBacking, smb_path};

    fn readme(backing: &RootBacking) -> String {
        let file = backing.open(&smb_path("readme.TXT")).unwrap();
        let size = backing.stat(&smb_path(README_NAME)).unwrap().size;
        let bytes = file.read_at(0, size as u32).unwrap();
        assert_eq!(bytes.len() as u64, size, "the reported size is the whole file");
        assert!(file.read_at(size, 16).unwrap().is_empty());
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn opened() -> OpenedArchive {
        OpenedArchive {
            path: PathBuf::from("/tmp/photos.zip"),
            folder: "a1b2c3d4".to_string(),
            file_count: 1,
            total_size: 5,
            backing: Arc::new(TestBacking::new()),
        }
    }

    #[test]
    fn an_empty_root_holds_only_the_readme() {
        let backing = RootBacking::empty(Control::Ui);

        let root = backing.list(&smb_path("")).unwrap();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].name, README_NAME);
        assert!(!root[0].kind.is_dir());
        assert_eq!(root[0].size, backing.total_size());
        assert_eq!(backing.label(), "smbanything");

        let text = readme(&backing);
        assert!(text.contains("No archive is loaded"), "{text}");
        assert!(text.contains("press l to load"), "{text}");
        assert!(text.is_ascii(), "{text}");

        assert_eq!(
            backing.open(&smb_path("")).err(),
            Some(status::FILE_IS_A_DIRECTORY)
        );
        assert_eq!(
            backing.list(&smb_path(README_NAME)).err(),
            Some(status::NOT_A_DIRECTORY)
        );
        assert_eq!(
            backing.stat(&smb_path("a1b2c3d4")).err(),
            Some(status::OBJECT_NAME_NOT_FOUND)
        );
        assert_eq!(
            backing.list(&smb_path(r"README.txt\inside")).err(),
            Some(status::OBJECT_PATH_NOT_FOUND)
        );
    }

    #[test]
    fn a_loaded_root_exposes_the_archive_only_beneath_its_folder() {
        let backing = RootBacking::with_archive(&opened(), Control::Ui);

        let root = backing.list(&smb_path("")).unwrap();
        let names: Vec<&str> = root.iter().map(|info| info.name.as_str()).collect();
        assert_eq!(names, [README_NAME, "a1b2c3d4"]);
        assert!(root[1].kind.is_dir());

        let archive_root = backing.list(&smb_path("A1B2C3D4")).unwrap();
        assert_eq!(archive_root.len(), 1);
        assert_eq!(archive_root[0].name, "docs");
        assert!(backing.list(&smb_path("docs")).is_err());

        let file = backing
            .open(&smb_path(r"a1b2c3d4\docs\readme.txt"))
            .unwrap();
        assert_eq!(&file.read_at(0, 5).unwrap()[..], b"hello");
        // Both directories `stat` and `list` report must open as directories,
        // not as names that do not exist.
        for directory in ["", "a1b2c3d4"] {
            assert!(backing.stat(&smb_path(directory)).unwrap().kind.is_dir());
            assert_eq!(
                backing.open(&smb_path(directory)).err(),
                Some(status::FILE_IS_A_DIRECTORY),
                "opening {directory:?}"
            );
        }
        assert_eq!(backing.label(), "fixture");
        assert_eq!(
            backing.total_size(),
            5 + backing.stat(&smb_path(README_NAME)).unwrap().size
        );
    }

    #[test]
    fn the_readme_names_the_archive_and_how_it_is_served() {
        let ui = readme(&RootBacking::with_archive(&opened(), Control::Ui));
        assert!(ui.contains("Archive:  /tmp/photos.zip"), "{ui}");
        assert!(ui.contains("Name:     photos.zip"), "{ui}");
        assert!(ui.contains("Folder:   a1b2c3d4"), "{ui}");
        assert!(ui.contains("Contents: 1 file, 5 bytes"), "{ui}");
        assert!(ui.contains("press l to load"), "{ui}");
        assert!(!ui.contains("No archive is loaded"), "{ui}");

        let one_shot = readme(&RootBacking::with_archive(&opened(), Control::CommandLine));
        assert!(one_shot.contains("served\nuntil that process stops"), "{one_shot}");
        assert!(!one_shot.contains("press l"), "{one_shot}");
    }
}
