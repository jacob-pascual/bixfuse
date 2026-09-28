//! The FUSE adapter. It gives each tree path an inode number and answers
//! kernel requests from the tree.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, LockOwner, OpenFlags,
    ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
};

use crate::tree::{self, Kind, Tree};

/// The contents never change, so the kernel can keep entries and attributes.
const TTL: Duration = Duration::from_secs(3600);

/// Inode `n` has the path `paths[n - 1]`, so inode 1 is the root.
/// Inodes are never removed: the table grows only with the paths in use.
#[derive(Default)]
struct Inodes {
    paths: Vec<Vec<String>>,
    numbers: HashMap<Vec<String>, u64>,
}

pub struct Bixfuse {
    tree: Tree,
    uid: u32,
    gid: u32,
    inodes: Mutex<Inodes>,
}

fn strs(path: &[String]) -> Vec<&str> {
    path.iter().map(String::as_str).collect()
}

fn errno(error: tree::Error) -> Errno {
    match error {
        tree::Error::NotFound => Errno::ENOENT,
        tree::Error::InvalidKey => Errno::EIO,
    }
}

impl Bixfuse {
    /// Files and directories belong to `uid` and `gid`.
    pub fn new(tree: Tree, uid: u32, gid: u32) -> Self {
        let fs = Self {
            tree,
            uid,
            gid,
            inodes: Mutex::default(),
        };
        fs.ino(Vec::new());
        fs
    }

    fn ino(&self, path: Vec<String>) -> INodeNo {
        let mut inodes = self.inodes.lock().unwrap();
        if let Some(n) = inodes.numbers.get(&path) {
            return INodeNo(*n);
        }
        inodes.paths.push(path.clone());
        let n = inodes.paths.len() as u64;
        inodes.numbers.insert(path, n);
        INodeNo(n)
    }

    fn path(&self, ino: INodeNo) -> Result<Vec<String>, Errno> {
        let inodes = self.inodes.lock().unwrap();
        let i = ino.0.checked_sub(1).ok_or(Errno::ENOENT)?;
        inodes.paths.get(i as usize).cloned().ok_or(Errno::ENOENT)
    }

    fn attr(&self, ino: INodeNo, path: &[String]) -> Result<FileAttr, Errno> {
        let path = strs(path);
        let (kind, perm, nlink, size) = match self.tree.kind(&path).ok_or(Errno::ENOENT)? {
            Kind::Dir => (FileType::Directory, 0o500, 2, 0),
            Kind::File => {
                let size = self.tree.read(&path).map_err(errno)?.len() as u64;
                (FileType::RegularFile, 0o400, 1, size)
            }
        };
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            flags: 0,
            blksize: 512,
        })
    }

    fn lookup_attr(&self, parent: INodeNo, name: &OsStr) -> Result<FileAttr, Errno> {
        let mut path = self.path(parent)?;
        path.push(name.to_str().ok_or(Errno::ENOENT)?.to_string());
        // Check the path first, so that a failed lookup does not add an inode.
        self.tree.kind(&strs(&path)).ok_or(Errno::ENOENT)?;
        let ino = self.ino(path.clone());
        self.attr(ino, &path)
    }

    fn entries(&self, ino: INodeNo) -> Result<Vec<(INodeNo, FileType, String)>, Errno> {
        let path = self.path(ino)?;
        if self.tree.kind(&strs(&path)) != Some(Kind::Dir) {
            return Err(Errno::ENOTDIR);
        }
        let parent = match path.split_last() {
            Some((_, parent)) => self.ino(parent.to_vec()),
            None => ino,
        };
        let mut entries = vec![
            (ino, FileType::Directory, ".".to_string()),
            (parent, FileType::Directory, "..".to_string()),
        ];
        for (name, kind) in self.tree.list(&strs(&path)) {
            let mut child = path.clone();
            child.push(name.clone());
            let kind = match kind {
                Kind::Dir => FileType::Directory,
                Kind::File => FileType::RegularFile,
            };
            entries.push((self.ino(child), kind, name));
        }
        Ok(entries)
    }
}

impl Filesystem for Bixfuse {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.lookup_attr(parent, name) {
            Ok(attr) => reply.entry(&TTL, &attr, Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.path(ino).and_then(|path| self.attr(ino, &path)) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let contents = self
            .path(ino)
            .and_then(|path| self.tree.read(&strs(&path)).map_err(errno));
        match contents {
            Ok(contents) => {
                let start = (offset as usize).min(contents.len());
                let end = start.saturating_add(size as usize).min(contents.len());
                reply.data(&contents[start..end]);
            }
            Err(e) => reply.error(e),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        match self.entries(ino) {
            Ok(entries) => {
                for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize)
                {
                    // The offset of an entry is the offset of the entry after it.
                    if reply.add(ino, i as u64 + 1, kind, name) {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => reply.error(e),
        }
    }
}
