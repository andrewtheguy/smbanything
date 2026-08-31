// SMB path parsing.
//
// This is the trust boundary. Everything a client sends as a filename arrives
// here, and the only thing standing between `..\..\..\etc\shadow` and a walk
// over the archive index is this module. Paths are validated into a
// component list rather than string-manipulated, so there is no normalisation
// step whose ordering could be got wrong.

use super::proto::status;

/// A validated path relative to the share root. An empty component list is the
/// root itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SmbPath {
    components: Vec<String>,
}

impl SmbPath {
    /// Parse a client-supplied path. SMB separates components with backslash
    /// and expresses the share root as the empty string.
    ///
    /// Rejects, with the status a Windows server would return:
    /// - `.` and `..` in any position, so a path can never escape the share
    /// - empty components, which would let `a\\\\b` mean different things to
    ///   this parser and to a later consumer
    /// - `/`, which cannot occur in a Unix filename and so can only be an
    ///   attempt to smuggle a separator past a backslash-only parser
    /// - NUL and the other characters Windows forbids in a filename
    pub(crate) fn parse(raw: &str) -> Result<Self, u32> {
        // Leading and trailing separators are tolerated: clients differ on
        // whether they send them, and neither changes the meaning.
        let trimmed = raw.trim_matches('\\');
        if trimmed.is_empty() {
            return Ok(Self::default());
        }

        let mut components = Vec::new();
        for part in trimmed.split('\\') {
            if part.is_empty() || part == "." || part == ".." {
                return Err(status::OBJECT_PATH_SYNTAX_BAD);
            }
            if part.contains(['/', '\0', ':', '*', '?', '"', '<', '>', '|']) {
                return Err(status::OBJECT_NAME_INVALID);
            }
            components.push(part.to_string());
        }
        Ok(Self { components })
    }

    #[cfg(test)]
    pub(crate) fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// The components, in order, as the client spelled them.
    ///
    /// The ZIP backing uses these components as an index key and never resolves
    /// them through the host filesystem.
    pub(crate) fn components(&self) -> impl Iterator<Item = &str> {
        self.components.iter().map(String::as_str)
    }

    /// Render back to SMB form, for keying and comparison. Only the in-memory
    /// test backing keys on paths this way — the real one walks `components`
    /// — so it is not compiled into the server.
    #[cfg(test)]
    pub(crate) fn to_smb_string(&self) -> String {
        self.components.join("\\")
    }

    /// Render for FileNameInformation, which per MS-FSCC 2.4.27 is the path
    /// relative to the share root *including* a leading backslash.
    ///
    /// The backslash is not cosmetic. Without it the root's name is empty,
    /// making FileAllInformation exactly 100 bytes — and cifs.ko rejects that
    /// with "buffer length 100 smaller than minimum size 101", because its
    /// struct reserves a byte for the name. The root renders as `\`.
    pub(crate) fn to_smb_absolute(&self) -> String {
        format!("\\{}", self.components.join("\\"))
    }

    /// Append one already-validated component. Used to build the path of a
    /// directory entry from its parent, where the name came from the archive
    /// rather than from a client.
    pub(crate) fn join(&self, name: &str) -> Self {
        let mut components = self.components.clone();
        components.push(name.to_string());
        Self { components }
    }

    /// Split off the first component: `(first, rest)`, `None` for the root.
    /// Lets a backing that nests another one route a client path into the
    /// inner tree without re-parsing anything.
    #[cfg(test)]
    pub(crate) fn split_first(&self) -> Option<(&str, Self)> {
        let (first, rest) = self.components.split_first()?;
        Some((
            first.as_str(),
            Self {
                components: rest.to_vec(),
            },
        ))
    }

    /// A stable 64-bit id for this path, used as both the SMB FileId and the
    /// inode number reported in directory listings.
    ///
    /// Derived from the path because ZIP stores no portable inode, and SMB
    /// requires a file id that identifies a single directory entry. The
    /// archive is immutable, so a path-derived id is stable for the
    /// life of the share, which is what clients cache against.
    pub(crate) fn file_id(&self) -> u64 {
        // FNV-1a. Not for security — only for spreading paths across the id
        // space — so a non-cryptographic hash is the right tool.
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01B3;
        let mut hash = OFFSET;
        for c in &self.components {
            for b in c.as_bytes() {
                hash ^= u64::from(*b);
                hash = hash.wrapping_mul(PRIME);
            }
            hash ^= u64::from(b'\\');
            hash = hash.wrapping_mul(PRIME);
        }
        // Zero and u64::MAX are both reserved by SMB2 (the latter is the
        // "related operation" placeholder in a compound), so never return them.
        if hash == 0 || hash == u64::MAX {
            1
        } else {
            hash
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_expressed_several_ways() {
        for raw in ["", "\\", "\\\\"] {
            let p = SmbPath::parse(raw).unwrap_or_else(|_| panic!("{raw:?} parses"));
            assert!(p.is_root(), "{raw:?} should be the root");
            assert_eq!(p.components().count(), 0);
        }
    }

    #[test]
    fn nested_paths_split_into_components() {
        let p = SmbPath::parse(r"dir\sub\file.txt").unwrap();
        assert!(!p.is_root());
        assert_eq!(
            p.components().collect::<Vec<_>>(),
            vec!["dir", "sub", "file.txt"]
        );
        assert_eq!(p.to_smb_string(), r"dir\sub\file.txt");
    }

    /// A backslash from a client is a separator and nothing else, so the
    /// quoted spelling of a name arrives as two components rather than as the
    /// name. This is why a client cannot address a quoted name directly, and
    /// why a client cannot address a ZIP name containing a backslash.
    #[test]
    fn a_client_backslash_is_always_a_separator() {
        let quoted = format!("a{}b.txt", "\\u2002");
        let p = SmbPath::parse(&quoted).unwrap();
        assert_eq!(
            p.components().collect::<Vec<_>>(),
            vec!["a", "u2002b.txt"],
            "a client cannot send a backslash except as a separator"
        );
    }

    #[test]
    fn leading_and_trailing_separators_are_tolerated() {
        let want = SmbPath::parse("dir\\file").unwrap();
        for raw in [r"\dir\file", r"dir\file\", r"\dir\file\"] {
            assert_eq!(SmbPath::parse(raw).unwrap(), want, "input {raw:?}");
        }
    }

    #[test]
    fn dot_dot_is_rejected_in_every_position() {
        for raw in [
            "..",
            r"..\etc",
            r"dir\..",
            r"dir\..\..\etc\shadow",
            r"a\..\b",
        ] {
            assert_eq!(
                SmbPath::parse(raw).unwrap_err(),
                status::OBJECT_PATH_SYNTAX_BAD,
                "traversal must be refused: {raw:?}"
            );
        }
    }

    #[test]
    fn single_dot_and_empty_components_are_rejected() {
        for raw in [".", r"dir\.", r"a\\b", r"a\\\b"] {
            assert!(
                SmbPath::parse(raw).is_err(),
                "ambiguous path must be refused: {raw:?}"
            );
        }
    }

    #[test]
    fn a_forward_slash_cannot_smuggle_a_separator() {
        // No Unix filename can contain '/', so its presence is always an attempt
        // to be interpreted differently by two parsers.
        for raw in ["../etc/shadow", "dir/file", "a/../b"] {
            assert_eq!(
                SmbPath::parse(raw).unwrap_err(),
                status::OBJECT_NAME_INVALID,
                "input {raw:?}"
            );
        }
    }

    #[test]
    fn characters_windows_forbids_are_rejected() {
        for bad in ["a\0b", "a:b", "a*b", "a?b", "a\"b", "a<b", "a>b", "a|b"] {
            assert_eq!(
                SmbPath::parse(bad).unwrap_err(),
                status::OBJECT_NAME_INVALID,
                "input {bad:?}"
            );
        }
    }

    #[test]
    fn ordinary_names_with_unusual_characters_are_accepted() {
        // None of these are traversal; refusing them would make real archives
        // unbrowsable.
        for raw in ["file name.txt", "naïve", "日本語", "a.b.c", "-", "..."] {
            assert!(SmbPath::parse(raw).is_ok(), "input {raw:?} should parse");
        }
    }

    #[test]
    fn absolute_form_always_leads_with_a_backslash() {
        assert_eq!(SmbPath::parse("").unwrap().to_smb_absolute(), "\\");
        assert_eq!(SmbPath::parse("a").unwrap().to_smb_absolute(), "\\a");
        assert_eq!(SmbPath::parse(r"a\b").unwrap().to_smb_absolute(), r"\a\b");
    }

    #[test]
    fn join_extends_a_path() {
        let dir = SmbPath::parse("a\\b").unwrap();
        let child = dir.join("c");
        assert_eq!(child.components().collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(
            dir.components().collect::<Vec<_>>(),
            vec!["a", "b"],
            "parent unchanged"
        );
    }

    #[test]
    fn split_first_peels_one_component() {
        assert!(
            SmbPath::parse("").unwrap().split_first().is_none(),
            "root has no head"
        );

        let single = SmbPath::parse("a").unwrap();
        let (first, rest) = single.split_first().unwrap();
        assert_eq!(first, "a");
        assert!(rest.is_root());

        let nested = SmbPath::parse(r"a\b\c").unwrap();
        let (first, rest) = nested.split_first().unwrap();
        assert_eq!(first, "a");
        assert_eq!(rest.to_smb_string(), r"b\c");
    }

    #[test]
    fn file_ids_are_stable_and_distinct() {
        let a = SmbPath::parse(r"dir\file").unwrap();
        let b = SmbPath::parse(r"dir\file").unwrap();
        let c = SmbPath::parse(r"dir\other").unwrap();
        assert_eq!(a.file_id(), b.file_id(), "same path, same id");
        assert_ne!(a.file_id(), c.file_id());
        // A prefix must not collide with the path it prefixes.
        assert_ne!(
            SmbPath::parse("a").unwrap().file_id(),
            SmbPath::parse(r"a\b").unwrap().file_id()
        );
    }

    #[test]
    fn file_ids_avoid_the_reserved_values() {
        for raw in ["", "a", r"a\b", "zzz"] {
            let id = SmbPath::parse(raw).unwrap().file_id();
            assert_ne!(id, 0, "0 is reserved");
            assert_ne!(id, u64::MAX, "u64::MAX is the compound placeholder");
        }
    }

    #[test]
    fn component_boundaries_are_part_of_the_id() {
        // "ab" and "a\b" must not hash alike, or two different files could
        // share a FileId and confuse a client's cache.
        assert_ne!(
            SmbPath::parse("ab").unwrap().file_id(),
            SmbPath::parse(r"a\b").unwrap().file_id()
        );
    }
}
