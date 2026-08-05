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
//!
//! The three places those invariants touch the operating system directly — how
//! many bytes an entry occupies, when it was last written, and which volume it
//! lives on — are the only per-platform code here, gathered at the top of the
//! file so the walk itself reads the same on either.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
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
    root_volume: VolumeId,
    /// file names worth remembering, supplied by the rule table
    markers: std::collections::HashSet<String>,
    /// Directories to record without opening. Reading one of these would raise a
    /// macOS consent dialog on a worker thread, which is the one thing a scan
    /// must never do — see `access::never_walk`.
    skip: std::collections::HashSet<PathBuf>,
}

/// Bytes this entry actually occupies on disk.
///
/// `st_blocks` is authoritative on macOS and Linux and must NOT fall back to the
/// logical length when it reads zero. Dataless placeholders (iCloud Drive, Google
/// Drive and OneDrive mounts under `~/Library/CloudStorage`) and sparse files
/// legitimately occupy no local blocks while reporting a large `len()`. Counting
/// that length invents reclaimable space that deleting cannot recover — on this
/// machine it inflated `~/Library` from 29.9G to 704G.
#[cfg(unix)]
fn entry_size(md: &std::fs::Metadata) -> u64 {
    md.blocks() * 512
}

/// The same rule where there is no `st_blocks` to ask.
///
/// Windows reports only the logical length, so the placeholders have to be
/// recognised rather than measured: OneDrive's files-on-demand carry `OFFLINE`
/// or one of the `RECALL_ON_*` attributes, and a sparse file says so outright.
/// Each of those occupies nothing locally while reporting its full size, which
/// is the same lie `st_blocks` protects against everywhere else — so they count
/// as zero, and everything else counts as its length.
#[cfg(windows)]
fn entry_size(md: &std::fs::Metadata) -> u64 {
    const SPARSE_FILE: u32 = 0x0000_0200;
    const OFFLINE: u32 = 0x0000_1000;
    const RECALL_ON_OPEN: u32 = 0x0004_0000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    const DATALESS: u32 = SPARSE_FILE | OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS;

    if md.file_attributes() & DATALESS != 0 {
        return 0;
    }
    md.file_size()
}

/// Last write time as unix seconds.
#[cfg(unix)]
fn entry_mtime(md: &std::fs::Metadata) -> i64 {
    md.mtime()
}

/// Windows counts 100-nanosecond ticks from 1601 instead, so the value has to be
/// rebased before the frontend — which only ever speaks unix seconds — sees it.
#[cfg(windows)]
fn entry_mtime(md: &std::fs::Metadata) -> i64 {
    const TICKS_PER_SECOND: u64 = 10_000_000;
    const SECONDS_1601_TO_1970: u64 = 11_644_473_600;
    (md.last_write_time() / TICKS_PER_SECOND).saturating_sub(SECONDS_1601_TO_1970) as i64
}

/// How a volume is identified, which is only possible on one of the two.
#[cfg(unix)]
type VolumeId = u64;
#[cfg(windows)]
type VolumeId = ();

#[cfg(unix)]
fn volume_of(md: &std::fs::Metadata) -> VolumeId {
    md.dev()
}

#[cfg(windows)]
fn volume_of(_md: &std::fs::Metadata) -> VolumeId {}

/// Whether descending into this directory would leave the volume we started on.
#[cfg(unix)]
fn leaves_volume(md: &std::fs::Metadata, root: VolumeId) -> bool {
    md.dev() != root
}

/// Windows exposes no device id through `std`, but it does not need one: another
/// volume is grafted into a directory tree through a reparse point — a junction
/// or a mount point — which is the same thing the symlink rule already refuses to
/// follow. Testing the reparse bit therefore covers both, and covers it for
/// junctions, which `is_symlink` does not report.
#[cfg(windows)]
fn leaves_volume(md: &std::fs::Metadata, _root: VolumeId) -> bool {
    const REPARSE_POINT: u32 = 0x0000_0400;
    md.file_attributes() & REPARSE_POINT != 0
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
///
/// `skip` names directories to record but not open, on top of the ones
/// `access::never_walk` refuses unconditionally. The caller passes the gated
/// folders it does not hold a grant for, which is what makes "the scan never
/// raises a dialog" true rather than hopeful: a folder the user has not allowed
/// is never read, so there is nothing for macOS to ask about.
pub fn scan_with_markers<F>(
    root: &Path,
    threads: usize,
    markers: std::collections::HashSet<String>,
    skip: Vec<PathBuf>,
    progress: F,
) -> std::io::Result<Tree>
where
    F: Fn(u64, u64) + Send + Sync,
{
    scan_inner(root, threads, markers, skip, progress)
}

/// `progress(files_seen, bytes_seen)` is called from worker threads; keep it cheap.
pub fn scan_with_progress<F>(root: &Path, threads: usize, progress: F) -> std::io::Result<Tree>
where
    F: Fn(u64, u64) + Send + Sync,
{
    scan_inner(root, threads, Default::default(), Vec::new(), progress)
}

fn scan_inner<F>(
    root: &Path,
    threads: usize,
    markers: std::collections::HashSet<String>,
    skip: Vec<PathBuf>,
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
        root_volume: volume_of(&root_md),
        markers,
        // The unconditional refusals are the scanner's own business, so every
        // caller gets them — the GUI, `snapshot`, and `bench` alike.
        skip: crate::access::never_walk().into_iter().chain(skip).collect(),
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

        // Decided before the read, not after: for a skipped directory the read
        // itself is the harm, because it is what puts a consent dialog on
        // screen. Refusing here lands it in the same branch as a directory the
        // filesystem would not open, which is what it is from here on.
        let opened = if shared.skip.contains(&path) {
            Err(std::io::ErrorKind::PermissionDenied.into())
        } else {
            std::fs::read_dir(&path)
        };

        match opened {
            Err(_) => {
                unreadable = true;
                shared.unreadable.fetch_add(1, Ordering::Relaxed);
            }
            Ok(entries) => {
                for entry in entries.flatten() {
                    let Ok(md) = entry.metadata() else { continue };
                    let mtime = entry_mtime(&md);
                    if mtime > newest {
                        newest = mtime;
                    }
                    // never follow symlinks: count the link itself, do not descend
                    if md.is_dir() && !md.file_type().is_symlink() {
                        if leaves_volume(&md, shared.root_volume) {
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
    ///
    /// Unix only because `set_len` is what makes a file sparse here; on NTFS it
    /// allocates the blocks, so the fixture would not be the thing under test.
    #[cfg(unix)]
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

    /// Unix only: creating a symlink on Windows needs Developer Mode or an
    /// elevated process, so the fixture cannot be built unconditionally.
    #[cfg(unix)]
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

    /// Unix only: mode bits are how the fixture makes a directory unreadable.
    #[cfg(unix)]
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

    /// The load-bearing property of the skip set: a skipped directory is
    /// recorded, counted as unreadable, and never opened — which on macOS is the
    /// difference between a silent scan and a consent dialog raised from a
    /// worker thread.
    #[test]
    fn skipped_directories_are_recorded_without_being_opened() {
        let (_guard, root) = fixture();
        let secret = root.join("secret");
        fs::create_dir_all(secret.join("inside")).unwrap();
        fs::write(secret.join("inside/blob.bin"), vec![0u8; 65536]).unwrap();

        let tree = scan_with_markers(&root, 4, Default::default(), vec![secret.clone()], |_, _| {});
        let tree = tree.unwrap();

        let node = tree
            .nodes
            .iter()
            .find(|n| n.name == "secret")
            .expect("a skipped directory is still part of the tree");
        assert!(node.unreadable, "a skipped directory must be marked unreadable");
        assert!(
            !tree.nodes.iter().any(|n| n.name == "inside"),
            "the walk descended into a directory it was told not to open"
        );
        assert_eq!(node.total_size, 0, "nothing under a skipped directory is counted");
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
