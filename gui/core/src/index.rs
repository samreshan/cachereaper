//! Versioned, rebuildable scan and content-hash persistence.
//!
//! Nothing in this module is action authority. Corrupt or unknown data is
//! ignored, reported, and rebuilt from a fresh scan. Writes are fsynced and
//! atomically published so an interrupted process leaves the last good index.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::analysis::AnalysisSummary;
use crate::history::{audit_dir, now_millis};
use crate::{FileRecord, ScanMode, Tree};

pub const INDEX_SCHEMA: u32 = 1;
pub const MAX_SNAPSHOTS_PER_ROOT: usize = 20;
pub const MAX_HASH_ENTRIES: usize = 250_000;
const MAX_SNAPSHOT_DIRECTORIES: usize = 2_000;
const HASH_MAX_AGE_MS: u128 = 180 * 86_400_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashEntry {
    pub partial_hash: String,
    #[serde(default)]
    pub full_hash: Option<String>,
    pub last_seen_at: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HashCacheFile {
    schema: u32,
    entries: BTreeMap<String, HashEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct HashCache {
    entries: BTreeMap<String, HashEntry>,
    hits: u64,
    misses: u64,
    warning: Option<String>,
}

impl HashCache {
    pub fn load() -> Self {
        Self::load_from(&index_dir())
    }

    pub fn load_from(dir: &Path) -> Self {
        let path = dir.join("hash-cache.json");
        let Ok(bytes) = std::fs::read(&path) else {
            return Self::default();
        };
        match serde_json::from_slice::<HashCacheFile>(&bytes) {
            Ok(mut file) if file.schema == INDEX_SCHEMA => {
                let before = file.entries.len();
                file.entries.retain(|_, entry| {
                    valid_hash(&entry.partial_hash)
                        && entry.full_hash.as_ref().is_none_or(|hash| valid_hash(hash))
                });
                let discarded = before - file.entries.len();
                Self {
                    entries: file.entries,
                    warning: (discarded > 0)
                        .then(|| format!("discarded {discarded} invalid hash-index entries")),
                    ..Self::default()
                }
            }
            Ok(file) => Self {
                warning: Some(format!(
                    "ignored hash index schema {}; rebuilding schema {INDEX_SCHEMA}",
                    file.schema
                )),
                ..Self::default()
            },
            Err(error) => Self {
                warning: Some(format!("ignored corrupt hash index; rebuilding: {error}")),
                ..Self::default()
            },
        }
    }

    pub fn warning(&self) -> Option<&str> {
        self.warning.as_deref()
    }

    pub fn hits(&self) -> u64 {
        self.hits
    }

    pub fn misses(&self) -> u64 {
        self.misses
    }

    pub fn partial(&mut self, file: &FileRecord) -> Option<String> {
        let key = hash_key(file);
        if let Some(entry) = self.entries.get_mut(&key) {
            self.hits = self.hits.saturating_add(1);
            entry.last_seen_at = now_millis();
            Some(entry.partial_hash.clone())
        } else {
            self.misses = self.misses.saturating_add(1);
            None
        }
    }

    pub fn full(&mut self, file: &FileRecord) -> Option<String> {
        let key = hash_key(file);
        let hash = self.entries.get_mut(&key).and_then(|entry| {
            entry.last_seen_at = now_millis();
            entry.full_hash.clone()
        });
        if hash.is_some() {
            self.hits = self.hits.saturating_add(1);
        } else {
            self.misses = self.misses.saturating_add(1);
        }
        hash
    }

    pub fn store_partial(&mut self, file: &FileRecord, hash: String) {
        self.entries.insert(
            hash_key(file),
            HashEntry {
                partial_hash: hash,
                full_hash: None,
                last_seen_at: now_millis(),
            },
        );
    }

    pub fn store_full(&mut self, file: &FileRecord, partial: String, full: String) {
        self.entries.insert(
            hash_key(file),
            HashEntry {
                partial_hash: partial,
                full_hash: Some(full),
                last_seen_at: now_millis(),
            },
        );
    }

    pub fn save(&mut self) -> Result<(), String> {
        self.save_to(&index_dir())
    }

    pub fn save_to(&mut self, dir: &Path) -> Result<(), String> {
        self.prune(now_millis());
        let bytes = serde_json::to_vec(&HashCacheFile {
            schema: INDEX_SCHEMA,
            entries: self.entries.clone(),
        })
        .map_err(|error| error.to_string())?;
        atomic_write(dir, &dir.join("hash-cache.json"), &bytes)
    }

    fn prune(&mut self, now: u128) {
        let cutoff = now.saturating_sub(HASH_MAX_AGE_MS);
        self.entries.retain(|_, entry| entry.last_seen_at >= cutoff);
        if self.entries.len() <= MAX_HASH_ENTRIES {
            return;
        }
        let mut oldest: Vec<(String, u128)> = self
            .entries
            .iter()
            .map(|(key, value)| (key.clone(), value.last_seen_at))
            .collect();
        oldest.sort_by_key(|(_, seen)| *seen);
        for (key, _) in oldest
            .into_iter()
            .take(self.entries.len() - MAX_HASH_ENTRIES)
        {
            self.entries.remove(&key);
        }
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

fn hash_key(file: &FileRecord) -> String {
    format!(
        "{}:{}:{}:{}",
        file.volume_id, file.file_id, file.logical_size, file.modified_ns
    )
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotCategory {
    pub category: String,
    pub files: u64,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotDirectory {
    pub path: String,
    pub files: u64,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanSnapshot {
    pub schema: u32,
    pub snapshot_id: String,
    pub mode: ScanMode,
    pub root: String,
    pub root_identity: String,
    pub finished_at: u128,
    pub files: u64,
    pub directories: u64,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub reclaimable_bytes: u64,
    pub categories: Vec<SnapshotCategory>,
    pub directory_summaries: Vec<SnapshotDirectory>,
}

impl ScanSnapshot {
    pub fn from_scan(scan_id: &str, tree: &Tree, analysis: &AnalysisSummary) -> Self {
        let mut directory_summaries: Vec<SnapshotDirectory> = tree
            .nodes
            .iter()
            .enumerate()
            .skip(1)
            .map(|(index, node)| SnapshotDirectory {
                path: tree.path_of(index as u32).to_string_lossy().into_owned(),
                files: node.total_files,
                allocated_bytes: node.total_size,
                logical_bytes: node.total_logical_size,
            })
            .collect();
        directory_summaries.sort_by(|left, right| {
            right
                .allocated_bytes
                .cmp(&left.allocated_bytes)
                .then_with(|| left.path.cmp(&right.path))
        });
        directory_summaries.truncate(MAX_SNAPSHOT_DIRECTORIES);
        Self {
            schema: INDEX_SCHEMA,
            snapshot_id: scan_id.to_string(),
            mode: analysis.mode,
            root: tree.root_path.to_string_lossy().into_owned(),
            root_identity: root_identity(&tree.root_path),
            finished_at: now_millis(),
            files: tree.stats.files,
            directories: tree.stats.dirs,
            allocated_bytes: tree.stats.bytes,
            logical_bytes: tree.stats.logical_bytes,
            reclaimable_bytes: tree.stats.reclaimable_bytes,
            categories: analysis
                .categories
                .iter()
                .map(|category| SnapshotCategory {
                    category: category.category.clone(),
                    files: category.files,
                    allocated_bytes: category.reclaimable_size,
                    logical_bytes: category.logical_size,
                })
                .collect(),
            directory_summaries,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrowthDelta {
    pub label: String,
    pub allocated_delta: i128,
    pub logical_delta: i128,
    pub file_delta: i128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrowthReport {
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub elapsed_ms: u128,
    pub allocated_delta: i128,
    pub logical_delta: i128,
    pub file_delta: i128,
    pub categories: Vec<GrowthDelta>,
    pub directories: Vec<GrowthDelta>,
}

pub fn persist_snapshot(snapshot: &ScanSnapshot) -> Result<Option<GrowthReport>, String> {
    persist_snapshot_to(&index_dir(), snapshot)
}

pub fn persist_snapshot_to(
    dir: &Path,
    snapshot: &ScanSnapshot,
) -> Result<Option<GrowthReport>, String> {
    if !valid_snapshot_id(&snapshot.snapshot_id) {
        return Err("invalid snapshot id".to_string());
    }
    let prior = list_snapshots_from(dir)?
        .into_iter()
        .filter(|value| {
            value.root_identity == snapshot.root_identity && value.mode == snapshot.mode
        })
        .max_by_key(|value| value.finished_at);
    let snapshots = dir.join("snapshots");
    std::fs::create_dir_all(&snapshots).map_err(|error| error.to_string())?;
    let destination = snapshots.join(format!("snapshot-{}.json", snapshot.snapshot_id));
    if destination.exists() {
        return Err("snapshot id already exists".to_string());
    }
    let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
    atomic_create(&snapshots, &destination, &bytes)?;
    prune_snapshots(dir, &snapshot.root_identity, snapshot.mode)?;
    Ok(prior
        .as_ref()
        .map(|previous| compare_snapshots(previous, snapshot)))
}

pub fn list_snapshots() -> Result<Vec<ScanSnapshot>, String> {
    list_snapshots_from(&index_dir())
}

pub fn list_snapshots_from(dir: &Path) -> Result<Vec<ScanSnapshot>, String> {
    let snapshots = dir.join("snapshots");
    if !snapshots.exists() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for entry in std::fs::read_dir(&snapshots).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !valid_snapshot_name(name) {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let Ok(snapshot) = serde_json::from_slice::<ScanSnapshot>(&bytes) else {
            continue;
        };
        if snapshot.schema == INDEX_SCHEMA {
            values.push(snapshot);
        }
    }
    values.sort_by_key(|value| std::cmp::Reverse(value.finished_at));
    Ok(values)
}

pub fn compare_snapshots(from: &ScanSnapshot, to: &ScanSnapshot) -> GrowthReport {
    GrowthReport {
        from_snapshot_id: from.snapshot_id.clone(),
        to_snapshot_id: to.snapshot_id.clone(),
        elapsed_ms: to.finished_at.saturating_sub(from.finished_at),
        allocated_delta: delta(to.allocated_bytes, from.allocated_bytes),
        logical_delta: delta(to.logical_bytes, from.logical_bytes),
        file_delta: delta(to.files, from.files),
        categories: compare_named(
            from.categories.iter().map(|value| {
                (
                    &value.category,
                    value.allocated_bytes,
                    value.logical_bytes,
                    value.files,
                )
            }),
            to.categories.iter().map(|value| {
                (
                    &value.category,
                    value.allocated_bytes,
                    value.logical_bytes,
                    value.files,
                )
            }),
        ),
        directories: compare_named(
            from.directory_summaries.iter().map(|value| {
                (
                    &value.path,
                    value.allocated_bytes,
                    value.logical_bytes,
                    value.files,
                )
            }),
            to.directory_summaries.iter().map(|value| {
                (
                    &value.path,
                    value.allocated_bytes,
                    value.logical_bytes,
                    value.files,
                )
            }),
        ),
    }
}

fn compare_named<'a>(
    from: impl Iterator<Item = (&'a String, u64, u64, u64)>,
    to: impl Iterator<Item = (&'a String, u64, u64, u64)>,
) -> Vec<GrowthDelta> {
    let before: BTreeMap<&str, (u64, u64, u64)> = from
        .map(|(name, allocated, logical, files)| (name.as_str(), (allocated, logical, files)))
        .collect();
    let after: BTreeMap<&str, (u64, u64, u64)> = to
        .map(|(name, allocated, logical, files)| (name.as_str(), (allocated, logical, files)))
        .collect();
    let names: BTreeSet<&str> = before.keys().chain(after.keys()).copied().collect();
    let mut changes: Vec<GrowthDelta> = names
        .into_iter()
        .filter_map(|name| {
            let old = before.get(name).copied().unwrap_or_default();
            let new = after.get(name).copied().unwrap_or_default();
            let change = GrowthDelta {
                label: name.to_string(),
                allocated_delta: delta(new.0, old.0),
                logical_delta: delta(new.1, old.1),
                file_delta: delta(new.2, old.2),
            };
            (change.allocated_delta != 0 || change.logical_delta != 0 || change.file_delta != 0)
                .then_some(change)
        })
        .collect();
    changes.sort_by(|left, right| {
        right
            .allocated_delta
            .unsigned_abs()
            .cmp(&left.allocated_delta.unsigned_abs())
            .then_with(|| left.label.cmp(&right.label))
    });
    changes
}

fn delta(new: u64, old: u64) -> i128 {
    i128::from(new) - i128::from(old)
}

fn prune_snapshots(dir: &Path, root_identity: &str, mode: ScanMode) -> Result<(), String> {
    let snapshots = list_snapshots_from(dir)?;
    for old in snapshots
        .into_iter()
        .filter(|value| value.root_identity == root_identity && value.mode == mode)
        .skip(MAX_SNAPSHOTS_PER_ROOT)
    {
        let path = dir
            .join("snapshots")
            .join(format!("snapshot-{}.json", old.snapshot_id));
        if path.exists() {
            std::fs::remove_file(path).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn valid_snapshot_name(name: &str) -> bool {
    name.starts_with("snapshot-")
        && name.ends_with(".json")
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

fn valid_snapshot_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
}

pub fn index_dir() -> PathBuf {
    audit_dir().join("index")
}

fn atomic_write(dir: &Path, destination: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    let temp = dir.join(format!(".tmp-{}-{}", std::process::id(), now_millis()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        replace_file(&temp, destination)?;
        sync_directory(dir).map_err(|error| error.to_string())
    })();
    if temp.exists() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

fn atomic_create(dir: &Path, destination: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    let temp = dir.join(format!(
        ".tmp-create-{}-{}",
        std::process::id(),
        now_millis()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        std::fs::hard_link(&temp, destination).map_err(|error| error.to_string())?;
        sync_directory(dir).map_err(|error| error.to_string())
    })();
    if temp.exists() {
        let _ = std::fs::remove_file(temp);
    }
    result
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    std::fs::rename(source, destination).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }
    const REPLACE_EXISTING: u32 = 0x1;
    const WRITE_THROUGH: u32 = 0x8;
    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: both inputs are valid NUL-terminated UTF-16 buffers for the call.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            REPLACE_EXISTING | WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn root_identity(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .map(|metadata| format!("{}:{}", metadata.dev(), metadata.ino()))
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

#[cfg(windows)]
fn root_identity(path: &Path) -> String {
    crate::windows_identity::query(path)
        .map(|identity| format!("{}:{}", identity.volume, identity.file))
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fixture(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "cachereaper-index-{label}-{}-{}-{}",
            std::process::id(),
            now_millis(),
            FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn snapshot(id: &str, at: u128, bytes: u64, images: u64) -> ScanSnapshot {
        ScanSnapshot {
            schema: INDEX_SCHEMA,
            snapshot_id: id.to_string(),
            mode: ScanMode::Whole,
            root: "/fixture".to_string(),
            root_identity: "1:2".to_string(),
            finished_at: at,
            files: images / 10,
            directories: 2,
            allocated_bytes: bytes,
            logical_bytes: bytes,
            reclaimable_bytes: bytes,
            categories: vec![SnapshotCategory {
                category: "Images".to_string(),
                files: images / 10,
                allocated_bytes: images,
                logical_bytes: images,
            }],
            directory_summaries: vec![SnapshotDirectory {
                path: "/fixture/photos".to_string(),
                files: images / 10,
                allocated_bytes: images,
                logical_bytes: images,
            }],
        }
    }

    #[test]
    fn snapshots_are_immutable_and_growth_is_attributed() {
        let dir = fixture("growth");
        assert!(persist_snapshot_to(&dir, &snapshot("one", 1, 100, 40))
            .unwrap()
            .is_none());
        let growth = persist_snapshot_to(&dir, &snapshot("two", 2, 175, 90))
            .unwrap()
            .unwrap();
        assert_eq!(growth.allocated_delta, 75);
        assert_eq!(growth.categories[0].allocated_delta, 50);
        assert_eq!(growth.directories[0].label, "/fixture/photos");
        assert!(persist_snapshot_to(&dir, &snapshot("two", 3, 200, 100)).is_err());
        assert_eq!(list_snapshots_from(&dir).unwrap().len(), 2);
        assert!(persist_snapshot_to(&dir, &snapshot("../escape", 4, 200, 100)).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn snapshot_and_hash_indexes_are_bounded() {
        let dir = fixture("pruning");
        for index in 0..(MAX_SNAPSHOTS_PER_ROOT + 3) {
            persist_snapshot_to(
                &dir,
                &snapshot(&format!("snapshot-{index}"), index as u128, index as u64, 0),
            )
            .unwrap();
        }
        assert_eq!(
            list_snapshots_from(&dir).unwrap().len(),
            MAX_SNAPSHOTS_PER_ROOT
        );

        let now = now_millis();
        let mut cache = HashCache::default();
        cache.entries.insert(
            "old".to_string(),
            HashEntry {
                partial_hash: "a".repeat(64),
                full_hash: None,
                last_seen_at: now.saturating_sub(HASH_MAX_AGE_MS + 1),
            },
        );
        cache.entries.insert(
            "current".to_string(),
            HashEntry {
                partial_hash: "b".repeat(64),
                full_hash: None,
                last_seen_at: now,
            },
        );
        cache.prune(now);
        assert!(!cache.entries.contains_key("old"));
        assert!(cache.entries.contains_key("current"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_and_unknown_indexes_rebuild_without_blocking() {
        let dir = fixture("corrupt");
        std::fs::write(dir.join("hash-cache.json"), b"not-json").unwrap();
        let mut cache = HashCache::load_from(&dir);
        assert!(cache.warning().unwrap().contains("corrupt"));
        assert_eq!(cache.entry_count(), 0);
        cache.save_to(&dir).unwrap();
        assert!(HashCache::load_from(&dir).warning().is_none());
        std::fs::write(
            dir.join("hash-cache.json"),
            b"{\"schema\":999,\"entries\":{}}",
        )
        .unwrap();
        assert!(HashCache::load_from(&dir)
            .warning()
            .unwrap()
            .contains("schema 999"));
        std::fs::create_dir_all(dir.join("snapshots")).unwrap();
        std::fs::write(dir.join("snapshots/snapshot-bad.json"), b"{").unwrap();
        assert!(list_snapshots_from(&dir).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
