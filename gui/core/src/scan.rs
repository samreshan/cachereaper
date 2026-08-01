//! Parallel directory walker producing an arena tree.
//!
//! Only *directories* become nodes. The bytes held in files sitting directly in
//! a directory are aggregated into that directory's `own_size`, and the actual
//! file list is read on demand when the user drills in. That keeps the tree at
//! ~150k nodes for a home directory instead of ~1.6M, which is what makes the
//! whole thing fit comfortably in memory and serialize cheaply to the frontend.
//!
//! Invariants mirrored from the Python walker (`discover_projects`, `dir_stats`):
//!   * symlinks are never followed
//!   * filesystem boundaries are never crossed
//!   * sizes come from `st_blocks * 512` (APFS-accurate), falling back to length

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

pub const NONE: u32 = u32::MAX;

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub parent: u32,
    pub children: Vec<u32>,
    /// bytes of files directly inside this directory
    pub own_size: u64,
    /// bytes of every file in this subtree (filled in by `propagate`)
    pub total_size: u64,
    pub own_files: u32,
    pub total_files: u64,
    pub newest_mtime: i64,
    pub depth: u16,
    /// true when the directory could not be read (permissions)
    pub unreadable: bool,
    /// Names of *marker* files directly in this directory (Cargo.toml,
    /// package.json, ...). Only names the rules actually ask about are kept, so
    /// this stays a handful of strings per project instead of 1M filenames.
    pub markers: Vec<String>,
}

impl Node {
    fn new(name: String, parent: u32, depth: u16) -> Self {
        Node {
            name,
            parent,
            children: Vec::new(),
            own_size: 0,
            total_size: 0,
            own_files: 0,
            total_files: 0,
            newest_mtime: 0,
            depth,
            unreadable: false,
            markers: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub dirs: u64,
    pub files: u64,
    pub bytes: u64,
    /// directories we could not read — surfaced in the UI rather than swallowed,
    /// because a disk tool that silently under-reports is worse than one that admits it
    pub unreadable: u64,
    pub elapsed_ms: u128,
}

pub struct Tree {
    pub nodes: Vec<Node>,
    pub root_path: PathBuf,
    pub stats: ScanStats,
}

impl Tree {
    pub fn root(&self) -> &Node {
        &self.nodes[0]
    }

    /// Reconstruct a node's absolute path by walking up the parent chain.
    pub fn path_of(&self, mut idx: u32) -> PathBuf {
        let mut parts: Vec<&str> = Vec::new();
        while idx != NONE && idx != 0 {
            let node = &self.nodes[idx as usize];
            parts.push(&node.name);
            idx = node.parent;
        }
        let mut path = self.root_path.clone();
        for part in parts.iter().rev() {
            path.push(part);
        }
        path
    }
}

/// Work queue and the count of directories currently being processed, under one
/// lock so the "are we finished?" test cannot race.
struct Work {
    queue: Vec<(u32, PathBuf)>,
    active: usize,
}

struct Shared {
    work: Mutex<Work>,
    cv: Condvar,
    arena: Mutex<Vec<Node>>,
    files: AtomicU64,
    bytes: AtomicU64,
    dirs: AtomicU64,
    unreadable: AtomicU64,
    root_dev: u64,
    /// file names worth remembering, supplied by the rule table
    markers: std::collections::HashSet<String>,
}

/// Bytes this entry actually occupies on disk.
///
/// `st_blocks` is authoritative on macOS and Linux and must NOT fall back to the
/// logical length when it reads zero. Dataless placeholders (iCloud Drive, Google
/// Drive and OneDrive mounts under `~/Library/CloudStorage`) and sparse files
/// legitimately occupy no local blocks while reporting a large `len()`. Counting
/// that length invents reclaimable space that deleting cannot recover — on this
/// machine it inflated `~/Library` from 29.9G to 704G.
fn entry_size(md: &std::fs::Metadata) -> u64 {
    md.blocks() * 512
}

/// Worker count that measured fastest on an APFS SSD: the walk is syscall-bound,
/// so oversubscribing helps up to a point and then loses to contention.
/// Measured on a 1.05M-file home directory: 1t 144s, 4t 28.6s, 8t 13.2s,
/// 12t 16.8s, 16t 19.9s.
pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().clamp(2, 8))
        .unwrap_or(4)
}

pub fn scan(root: &Path, threads: usize) -> std::io::Result<Tree> {
    scan_with_progress(root, threads, |_, _| {})
}

/// Scan while remembering which marker files (Cargo.toml, package.json, ...)
/// each directory holds, so rule matching afterwards needs no second pass.
pub fn scan_with_markers<F>(
    root: &Path,
    threads: usize,
    markers: std::collections::HashSet<String>,
    progress: F,
) -> std::io::Result<Tree>
where
    F: Fn(u64, u64) + Send + Sync,
{
    scan_inner(root, threads, markers, progress)
}

/// `progress(files_seen, bytes_seen)` is called from worker threads; keep it cheap.
pub fn scan_with_progress<F>(root: &Path, threads: usize, progress: F) -> std::io::Result<Tree>
where
    F: Fn(u64, u64) + Send + Sync,
{
    scan_inner(root, threads, Default::default(), progress)
}

fn scan_inner<F>(
    root: &Path,
    threads: usize,
    markers: std::collections::HashSet<String>,
    progress: F,
) -> std::io::Result<Tree>
where
    F: Fn(u64, u64) + Send + Sync,
{
    let started = Instant::now();
    let root = root.to_path_buf();
    let root_md = std::fs::symlink_metadata(&root)?;
    if !root_md.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "scan root is not a directory",
        ));
    }

    let root_name = root
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.to_string_lossy().into_owned());

    let shared = Arc::new(Shared {
        work: Mutex::new(Work {
            queue: vec![(0, root.clone())],
            active: 0,
        }),
        cv: Condvar::new(),
        arena: Mutex::new(vec![Node::new(root_name, NONE, 0)]),
        files: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        dirs: AtomicU64::new(1),
        unreadable: AtomicU64::new(0),
        root_dev: root_md.dev(),
        markers,
    });

    let progress = Arc::new(progress);
    let threads = threads.max(1);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let shared = Arc::clone(&shared);
            let progress = Arc::clone(&progress);
            scope.spawn(move || worker(&shared, &*progress));
        }
    });

    let mut nodes = Arc::try_unwrap(shared)
        .map_err(|_| std::io::Error::other("scanner threads outlived the scan"))?
        .arena
        .into_inner()
        .unwrap();

    propagate(&mut nodes);

    let stats = ScanStats {
        dirs: nodes.len() as u64,
        files: nodes[0].total_files,
        bytes: nodes[0].total_size,
        unreadable: nodes.iter().filter(|n| n.unreadable).count() as u64,
        elapsed_ms: started.elapsed().as_millis(),
    };

    Ok(Tree {
        nodes,
        root_path: root,
        stats,
    })
}

fn worker<F: Fn(u64, u64)>(shared: &Shared, progress: &F) {
    loop {
        // --- claim a directory, or discover that the walk is finished ---------
        let claimed = {
            let mut work = shared.work.lock().unwrap();
            loop {
                if let Some(item) = work.queue.pop() {
                    work.active += 1;
                    break Some(item);
                }
                if work.active == 0 {
                    // queue empty and nobody can add to it: everyone is done
                    shared.cv.notify_all();
                    break None;
                }
                work = shared.cv.wait(work).unwrap();
            }
        };
        let Some((idx, path)) = claimed else { return };

        // --- read it -----------------------------------------------------------
        let mut own_size = 0u64;
        let mut own_files = 0u32;
        let mut newest = 0i64;
        let mut subdirs: Vec<(String, PathBuf)> = Vec::new();
        let mut markers: Vec<String> = Vec::new();
        let mut unreadable = false;

        match std::fs::read_dir(&path) {
            Err(_) => {
                unreadable = true;
                shared.unreadable.fetch_add(1, Ordering::Relaxed);
            }
            Ok(entries) => {
                for entry in entries.flatten() {
                    let Ok(md) = entry.metadata() else { continue };
                    if md.mtime() > newest {
                        newest = md.mtime();
                    }
                    // never follow symlinks: count the link itself, do not descend
                    if md.is_dir() && !md.file_type().is_symlink() {
                        if md.dev() != shared.root_dev {
                            continue; // never cross a filesystem boundary
                        }
                        subdirs.push((
                            entry.file_name().to_string_lossy().into_owned(),
                            entry.path(),
                        ));
                    } else {
                        own_size += entry_size(&md);
                        own_files += 1;
                        if !shared.markers.is_empty() {
                            let name = entry.file_name();
                            let name = name.to_string_lossy();
                            if shared.markers.contains(name.as_ref()) {
                                markers.push(name.into_owned());
                            }
                        }
                    }
                }
            }
        }

        // --- publish results and enqueue children -------------------------------
        let depth = {
            let mut arena = shared.arena.lock().unwrap();
            let node = &mut arena[idx as usize];
            node.own_size = own_size;
            node.own_files = own_files;
            node.newest_mtime = newest;
            node.unreadable = unreadable;
            node.markers = std::mem::take(&mut markers);
            let depth = node.depth;

            let mut new_tasks = Vec::with_capacity(subdirs.len());
            for (name, child_path) in subdirs {
                let child_idx = arena.len() as u32;
                arena.push(Node::new(name, idx, depth.saturating_add(1)));
                arena[idx as usize].children.push(child_idx);
                new_tasks.push((child_idx, child_path));
            }
            drop(arena);

            let added = new_tasks.len();
            {
                let mut work = shared.work.lock().unwrap();
                work.queue.extend(new_tasks);
                work.active -= 1;
                if added > 0 || (work.queue.is_empty() && work.active == 0) {
                    shared.cv.notify_all();
                }
            }
            depth
        };
        let _ = depth;

        shared.dirs.fetch_add(1, Ordering::Relaxed);
        let files = shared.files.fetch_add(own_files as u64, Ordering::Relaxed) + own_files as u64;
        let bytes = shared.bytes.fetch_add(own_size, Ordering::Relaxed) + own_size;
        progress(files, bytes);
    }
}

/// Roll subtree totals up to the root.
///
/// A child is always allocated while its parent is being scanned, so a node's
/// index is always greater than its parent's. Index order is therefore a valid
/// topological order and a single reverse pass suffices — no recursion, no
/// second traversal.
fn propagate(nodes: &mut [Node]) {
    for idx in (0..nodes.len()).rev() {
        let (total_size, total_files, parent, newest) = {
            let node = &mut nodes[idx];
            node.total_size += node.own_size;
            node.total_files += node.own_files as u64;
            (node.total_size, node.total_files, node.parent, node.newest_mtime)
        };
        if parent != NONE {
            let p = &mut nodes[parent as usize];
            p.total_size += total_size;
            p.total_files += total_files;
            if newest > p.newest_mtime {
                p.newest_mtime = newest;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> (tempdir::TempDir, PathBuf) {
        let dir = tempdir::TempDir::new();
        let root = dir.path().join("proj");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir_all(root.join("c")).unwrap();
        fs::write(root.join("top.bin"), vec![0u8; 8192]).unwrap();
        fs::write(root.join("a/one.bin"), vec![0u8; 4096]).unwrap();
        fs::write(root.join("a/b/two.bin"), vec![0u8; 4096]).unwrap();
        (dir, root)
    }

    #[test]
    fn totals_roll_up_to_the_root() {
        let (_guard, root) = fixture();
        let tree = scan(&root, 4).unwrap();
        assert_eq!(tree.root().total_files, 3);
        // 16 KiB of payload. Bound this on BOTH sides: a lower bound alone let a
        // 24x over-count through once already.
        assert!(
            (16384..=65536).contains(&tree.root().total_size),
            "expected ~16K on disk, got {}",
            tree.root().total_size
        );
        assert_eq!(tree.root().own_files, 1, "only top.bin sits at the root");
    }

    /// Regression: a sparse file reports a huge `len()` but occupies no blocks,
    /// exactly like an iCloud/Drive dataless placeholder. Counting its logical
    /// length inflated a real ~/Library scan from 29.9G to 704G.
    #[test]
    fn sparse_and_dataless_files_count_as_the_space_they_occupy() {
        let dir = tempdir::TempDir::new();
        let root = dir.path().join("cloud");
        fs::create_dir_all(&root).unwrap();

        let placeholder = fs::File::create(root.join("placeholder.bin")).unwrap();
        placeholder.set_len(4 * 1024 * 1024 * 1024).unwrap(); // 4 GiB logical
        drop(placeholder);
        fs::write(root.join("real.bin"), vec![0u8; 4096]).unwrap();

        let tree = scan(&root, 2).unwrap();
        assert_eq!(tree.root().total_files, 2);
        assert!(
            tree.root().total_size < 1024 * 1024,
            "sparse file counted at logical size: got {}",
            tree.root().total_size
        );
    }

    #[test]
    fn subtree_totals_are_correct() {
        let (_guard, root) = fixture();
        let tree = scan(&root, 4).unwrap();
        let a = tree
            .nodes
            .iter()
            .find(|n| n.name == "a")
            .expect("directory a");
        assert_eq!(a.total_files, 2, "a/one.bin and a/b/two.bin");
        assert_eq!(a.own_files, 1, "only one.bin is directly in a");
    }

    #[test]
    fn thread_count_does_not_change_the_answer() {
        let (_guard, root) = fixture();
        let one = scan(&root, 1).unwrap();
        let many = scan(&root, 8).unwrap();
        assert_eq!(one.root().total_size, many.root().total_size);
        assert_eq!(one.root().total_files, many.root().total_files);
        assert_eq!(one.nodes.len(), many.nodes.len());
    }

    #[test]
    fn symlinks_are_not_followed() {
        let (_guard, root) = fixture();
        let outside = root.parent().unwrap().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("huge.bin"), vec![0u8; 65536]).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        let tree = scan(&root, 4).unwrap();
        assert!(
            !tree.nodes.iter().any(|n| n.name == "outside"),
            "walker followed a symlink out of the tree"
        );
        assert!(tree.root().total_size < 65536, "symlinked bytes were counted");
    }

    #[test]
    fn path_reconstruction_round_trips() {
        let (_guard, root) = fixture();
        let tree = scan(&root, 4).unwrap();
        let b = tree.nodes.iter().position(|n| n.name == "b").unwrap() as u32;
        assert_eq!(tree.path_of(b), root.join("a/b"));
        assert_eq!(tree.path_of(0), root);
    }

    #[test]
    fn unreadable_directories_are_recorded_not_swallowed() {
        let (_guard, root) = fixture();
        let locked = root.join("locked");
        fs::create_dir_all(&locked).unwrap();
        fs::write(locked.join("x.bin"), vec![0u8; 4096]).unwrap();
        let mut perms = fs::metadata(&locked).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o000);
        fs::set_permissions(&locked, perms).unwrap();

        let tree = scan(&root, 4).unwrap();
        let readable_again = fs::set_permissions(
            &locked,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );
        assert!(readable_again.is_ok());

        // running as root defeats the permission bits, so only assert when it took
        if tree.stats.unreadable > 0 {
            assert!(tree.nodes.iter().any(|n| n.unreadable && n.name == "locked"));
        }
    }

    /// Minimal scoped temp directory so the crate keeps zero runtime dependencies.
    mod tempdir {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        pub struct TempDir(PathBuf);

        impl TempDir {
            #[allow(clippy::new_without_default)]
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::SeqCst);
                let path = std::env::temp_dir().join(format!(
                    "cachereaper-test-{}-{}-{}",
                    std::process::id(),
                    n,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&path).unwrap();
                TempDir(path)
            }
            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
