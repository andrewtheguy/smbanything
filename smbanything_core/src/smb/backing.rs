use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;

use super::path::SmbPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
}

impl NodeKind {
    pub fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub name: String,
    pub kind: NodeKind,
    pub size: u64,
    pub mtime: SystemTime,
    pub atime: SystemTime,
    pub ctime: SystemTime,
}

impl NodeInfo {
    pub fn synthetic_dir(name: &str, now: SystemTime) -> Self {
        Self {
            name: name.to_string(),
            kind: NodeKind::Dir,
            size: 0,
            mtime: now,
            atime: now,
            ctime: now,
        }
    }
}

pub trait FileReader: Send + Sync {
    fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32>;
}

pub trait Backing: Send + Sync {
    fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32>;
    fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32>;
    fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32>;
    fn label(&self) -> &str;
    fn total_size(&self) -> u64;
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::BTreeMap;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::smb::status;

    #[derive(Default)]
    pub(crate) struct MemBacking {
        entries: BTreeMap<String, (NodeInfo, Vec<u8>)>,
    }

    impl MemBacking {
        pub(crate) fn new() -> Self {
            let mut backing = Self::default();
            backing.entries.insert(
                String::new(),
                (NodeInfo::synthetic_dir("", UNIX_EPOCH), Vec::new()),
            );
            backing
        }

        pub(crate) fn with_dir(mut self, path: &str) -> Self {
            let name = path.rsplit('\\').next().unwrap_or(path).to_string();
            self.entries.insert(
                path.to_string(),
                (
                    NodeInfo {
                        name,
                        kind: NodeKind::Dir,
                        size: 0,
                        mtime: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                        atime: UNIX_EPOCH + Duration::from_secs(1_600_000_001),
                        ctime: UNIX_EPOCH + Duration::from_secs(1_600_000_002),
                    },
                    Vec::new(),
                ),
            );
            self
        }

        pub(crate) fn with_file(mut self, path: &str, content: &[u8]) -> Self {
            let name = path.rsplit('\\').next().unwrap_or(path).to_string();
            self.entries.insert(
                path.to_string(),
                (
                    NodeInfo {
                        name,
                        kind: NodeKind::File,
                        size: content.len() as u64,
                        mtime: UNIX_EPOCH + Duration::from_secs(1_600_000_000),
                        atime: UNIX_EPOCH + Duration::from_secs(1_600_000_001),
                        ctime: UNIX_EPOCH + Duration::from_secs(1_600_000_002),
                    },
                    content.to_vec(),
                ),
            );
            self
        }
    }

    impl Backing for MemBacking {
        fn stat(&self, path: &SmbPath) -> Result<NodeInfo, u32> {
            self.entries
                .get(&path.to_smb_string())
                .map(|(info, _)| info.clone())
                .ok_or(status::OBJECT_NAME_NOT_FOUND)
        }

        fn list(&self, path: &SmbPath) -> Result<Vec<NodeInfo>, u32> {
            let prefix = path.to_smb_string();
            let (info, _) = self
                .entries
                .get(&prefix)
                .ok_or(status::OBJECT_PATH_NOT_FOUND)?;
            if !info.kind.is_dir() {
                return Err(status::NOT_A_DIRECTORY);
            }
            let scope = if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}\\")
            };
            Ok(self
                .entries
                .iter()
                .filter(|(key, _)| {
                    !key.is_empty() && key.starts_with(&scope) && !key[scope.len()..].contains('\\')
                })
                .map(|(_, (info, _))| info.clone())
                .collect())
        }

        fn open(&self, path: &SmbPath) -> Result<Arc<dyn FileReader>, u32> {
            let (info, content) = self
                .entries
                .get(&path.to_smb_string())
                .ok_or(status::OBJECT_NAME_NOT_FOUND)?;
            if info.kind.is_dir() {
                return Err(status::FILE_IS_A_DIRECTORY);
            }
            Ok(Arc::new(MemFile {
                content: content.clone(),
            }))
        }

        fn label(&self) -> &str {
            "test"
        }

        fn total_size(&self) -> u64 {
            self.entries.values().map(|(info, _)| info.size).sum()
        }
    }

    struct MemFile {
        content: Vec<u8>,
    }

    impl FileReader for MemFile {
        fn read_at(&self, offset: u64, len: u32) -> Result<Bytes, u32> {
            let Ok(offset) = usize::try_from(offset) else {
                return Ok(Bytes::new());
            };
            if offset >= self.content.len() {
                return Ok(Bytes::new());
            }
            let end = offset.saturating_add(len as usize).min(self.content.len());
            Ok(Bytes::copy_from_slice(&self.content[offset..end]))
        }
    }
}
