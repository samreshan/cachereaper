//! Deterministic, bounded analysis over an optional file inventory.
//!
//! Whole Disk analysis reads metadata only. All Files additionally streams the
//! contents of size-collision candidates to establish exact duplicate groups.
//! These results are evidence, never deletion targets.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{CancellationToken, FileRecord, HashCache, ScanMode, Tree};

pub const MAX_FILE_INSIGHTS: usize = 100;
pub const MAX_DUPLICATE_GROUPS: usize = 100;
pub const OLD_FILE_DAYS: i64 = 90;
pub const OLD_FILE_MIN_BYTES: u64 = 10 * 1024 * 1024;
pub const DUPLICATE_MIN_BYTES: u64 = 1024 * 1024;
const PREHASH_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FileInsight {
    pub path: String,
    pub name: String,
    pub reclaimable_size: u64,
    pub logical_size: u64,
    pub mtime: i64,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CategorySummary {
    pub category: String,
    pub files: u64,
    pub reclaimable_size: u64,
    pub logical_size: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DuplicateGroup {
    /// SHA-256 of every byte in each member. This is evidence, not an action id.
    pub hash: String,
    pub logical_size: u64,
    pub reclaimable_size: u64,
    pub files: Vec<FileInsight>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnalysisSummary {
    pub mode: ScanMode,
    pub inventory_files: usize,
    pub categories: Vec<CategorySummary>,
    pub largest_files: Vec<FileInsight>,
    pub old_large_files: Vec<FileInsight>,
    pub duplicate_groups: Vec<DuplicateGroup>,
    pub duplicate_reclaimable_bytes: u64,
    pub content_analysis_complete: bool,
    pub hash_cache_hits: u64,
    pub hash_cache_misses: u64,
    pub warnings: Vec<String>,
}

impl AnalysisSummary {
    pub fn cache() -> Self {
        Self {
            mode: ScanMode::Cache,
            inventory_files: 0,
            categories: Vec::new(),
            largest_files: Vec::new(),
            old_large_files: Vec::new(),
            duplicate_groups: Vec::new(),
            duplicate_reclaimable_bytes: 0,
            content_analysis_complete: false,
            hash_cache_hits: 0,
            hash_cache_misses: 0,
            warnings: Vec::new(),
        }
    }
}

pub fn analyze(tree: &Tree, mode: ScanMode, cancellation: &CancellationToken) -> AnalysisSummary {
    analyze_with_cache(tree, mode, cancellation, &mut HashCache::default())
}

pub fn analyze_with_cache(
    tree: &Tree,
    mode: ScanMode,
    cancellation: &CancellationToken,
    hash_cache: &mut HashCache,
) -> AnalysisSummary {
    if mode == ScanMode::Cache {
        debug_assert!(tree.files.is_empty());
        return AnalysisSummary::cache();
    }

    let mut categories: BTreeMap<String, CategorySummary> = BTreeMap::new();
    let mut files: Vec<FileInsight> = tree
        .files
        .iter()
        .map(|record| insight(tree, record))
        .collect();

    for file in &files {
        let entry = categories
            .entry(file.category.clone())
            .or_insert_with(|| CategorySummary {
                category: file.category.clone(),
                files: 0,
                reclaimable_size: 0,
                logical_size: 0,
            });
        entry.files += 1;
        entry.reclaimable_size = entry.reclaimable_size.saturating_add(file.reclaimable_size);
        entry.logical_size = entry.logical_size.saturating_add(file.logical_size);
    }

    files.sort_by(|a, b| {
        b.reclaimable_size
            .cmp(&a.reclaimable_size)
            .then_with(|| a.path.cmp(&b.path))
    });
    let largest_files = files.iter().take(MAX_FILE_INSIGHTS).cloned().collect();

    let cutoff = now_seconds().saturating_sub(OLD_FILE_DAYS * 86_400);
    let old_large_files = files
        .iter()
        .filter(|file| file.reclaimable_size >= OLD_FILE_MIN_BYTES && file.mtime <= cutoff)
        .take(MAX_FILE_INSIGHTS)
        .cloned()
        .collect();

    let mut summary = AnalysisSummary {
        mode,
        inventory_files: tree.files.len(),
        categories: categories.into_values().collect(),
        largest_files,
        old_large_files,
        duplicate_groups: Vec::new(),
        duplicate_reclaimable_bytes: 0,
        content_analysis_complete: false,
        hash_cache_hits: 0,
        hash_cache_misses: 0,
        warnings: Vec::new(),
    };

    summary.categories.sort_by(|a, b| {
        b.reclaimable_size
            .cmp(&a.reclaimable_size)
            .then_with(|| a.category.cmp(&b.category))
    });

    if mode == ScanMode::All {
        let (groups, complete, skipped) = duplicate_groups(tree, cancellation, hash_cache);
        summary.duplicate_reclaimable_bytes =
            groups.iter().map(|group| group.reclaimable_size).sum();
        summary.duplicate_groups = groups;
        summary.content_analysis_complete = complete;
        if skipped > 0 {
            summary.warnings.push(format!(
                "{skipped} duplicate candidates changed or became unreadable during analysis"
            ));
        }
        summary.hash_cache_hits = hash_cache.hits();
        summary.hash_cache_misses = hash_cache.misses();
    }

    summary
}

fn insight(tree: &Tree, record: &FileRecord) -> FileInsight {
    let path = tree.file_path(record);
    FileInsight {
        path: path.to_string_lossy().into_owned(),
        name: record.name.clone(),
        reclaimable_size: record.reclaimable_size,
        logical_size: record.logical_size,
        mtime: record.mtime,
        category: category(&record.name).to_string(),
    }
}

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

fn category(name: &str) -> &'static str {
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "heif" | "avif" | "tif" | "tiff"
        | "bmp" | "raw" | "dng" => "Images",
        "mp4" | "mov" | "mkv" | "avi" | "webm" | "m4v" | "mpeg" | "mpg" => "Video",
        "mp3" | "wav" | "flac" | "aac" | "m4a" | "ogg" | "opus" | "aiff" => "Audio",
        "pdf" | "doc" | "docx" | "odt" | "rtf" | "pages" | "xls" | "xlsx" | "ods" | "numbers"
        | "ppt" | "pptx" | "key" => "Documents",
        "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" | "dmg" | "iso" => "Archives",
        "app" | "exe" | "msi" | "pkg" | "deb" | "rpm" => "Applications",
        "js" | "jsx" | "ts" | "tsx" | "py" | "rs" | "go" | "java" | "c" | "cc" | "cpp" | "h"
        | "hpp" | "swift" | "kt" | "rb" | "php" | "cs" | "sh" | "html" | "css" | "scss" | "vue"
        | "svelte" => "Code",
        "txt" | "md" | "json" | "yaml" | "yml" | "toml" | "xml" | "csv" | "log" => "Text & Data",
        "" => "Other",
        _ => "Other",
    }
}

fn duplicate_groups(
    tree: &Tree,
    cancellation: &CancellationToken,
    hash_cache: &mut HashCache,
) -> (Vec<DuplicateGroup>, bool, usize) {
    let mut sizes: HashMap<u64, Vec<&FileRecord>> = HashMap::new();
    for file in &tree.files {
        // A zero-allocation file may be sparse or a cloud placeholder. Opening
        // it could materialize remote content and cannot reclaim local bytes,
        // so Deep Scan deliberately leaves it out of content analysis.
        if file.logical_size >= DUPLICATE_MIN_BYTES && file.reclaimable_size > 0 {
            sizes.entry(file.logical_size).or_default().push(file);
        }
    }

    // A cheap first/last-window hash prevents two unrelated videos of the same
    // size from both being read in full. It is only a filter: every reported
    // group still requires a complete SHA-256 hash below.
    let mut prehashed: BTreeMap<(u64, String), Vec<&FileRecord>> = BTreeMap::new();
    let mut skipped = 0usize;
    for (size, records) in sizes {
        if records.len() < 2 {
            continue;
        }
        for record in records {
            if cancellation.is_cancelled() {
                return (Vec::new(), false, skipped);
            }
            let path = tree.file_path(record);
            if let Some(hash) = hash_cache.partial(record) {
                prehashed.entry((size, hash)).or_default().push(record);
                continue;
            }
            match prehash_stable_file(&path, size, cancellation) {
                Ok(hash) => {
                    hash_cache.store_partial(record, hash.clone());
                    prehashed.entry((size, hash)).or_default().push(record)
                }
                Err(_) if cancellation.is_cancelled() => return (Vec::new(), false, skipped),
                Err(_) => skipped += 1,
            }
        }
    }

    let mut hashed: BTreeMap<(u64, String), Vec<FileInsight>> = BTreeMap::new();
    for ((size, partial), records) in prehashed {
        if records.len() < 2 {
            continue;
        }
        for record in records {
            let path = tree.file_path(record);
            let result = hash_cache
                .full(record)
                .map(Ok)
                .unwrap_or_else(|| hash_stable_file(&path, size, cancellation));
            match result {
                Ok(hash) => {
                    hash_cache.store_full(record, partial.clone(), hash.clone());
                    hashed
                        .entry((size, hash))
                        .or_default()
                        .push(insight(tree, record))
                }
                Err(_) if cancellation.is_cancelled() => return (Vec::new(), false, skipped),
                Err(_) => skipped += 1,
            }
        }
    }

    let mut groups: Vec<DuplicateGroup> = hashed
        .into_iter()
        .filter_map(|((logical_size, hash), mut files)| {
            if files.len() < 2 {
                return None;
            }
            files.sort_by(|a, b| a.path.cmp(&b.path));
            // Keeping one member means only the remaining allocated bytes are
            // potential savings. No action is implied by this estimate.
            let keep = files
                .iter()
                .map(|file| file.reclaimable_size)
                .min()
                .unwrap_or(0);
            let reclaimable_size = files
                .iter()
                .map(|file| file.reclaimable_size)
                .sum::<u64>()
                .saturating_sub(keep);
            Some(DuplicateGroup {
                hash,
                logical_size,
                reclaimable_size,
                files,
            })
        })
        .collect();

    groups.sort_by(|a, b| {
        b.reclaimable_size
            .cmp(&a.reclaimable_size)
            .then_with(|| a.hash.cmp(&b.hash))
    });
    groups.truncate(MAX_DUPLICATE_GROUPS);
    (groups, true, skipped)
}

fn stable_file(
    path: &Path,
    expected_size: u64,
) -> std::io::Result<(File, Option<std::time::SystemTime>)> {
    let file = File::open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() != expected_size {
        return Err(std::io::Error::other("file changed before hashing"));
    }

    Ok((file, before.modified().ok()))
}

fn still_stable(
    file: &File,
    expected_size: u64,
    before_modified: Option<std::time::SystemTime>,
) -> std::io::Result<()> {
    let after = file.metadata()?;
    if after.len() != expected_size || after.modified().ok() != before_modified {
        return Err(std::io::Error::other("file changed while hashing"));
    }
    Ok(())
}

fn prehash_stable_file(
    path: &Path,
    expected_size: u64,
    cancellation: &CancellationToken,
) -> std::io::Result<String> {
    let (mut file, before_modified) = stable_file(path, expected_size)?;
    let window = expected_size.min(PREHASH_BYTES) as usize;
    let mut buffer = vec![0u8; window];
    file.read_exact(&mut buffer)?;
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    if expected_size > PREHASH_BYTES {
        file.seek(SeekFrom::End(-(window as i64)))?;
        file.read_exact(&mut buffer)?;
        hasher.update(&buffer);
    }
    if cancellation.is_cancelled() {
        return Err(std::io::ErrorKind::Interrupted.into());
    }
    still_stable(&file, expected_size, before_modified)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_stable_file(
    path: &Path,
    expected_size: u64,
    cancellation: &CancellationToken,
) -> std::io::Result<String> {
    let (file, before_modified) = stable_file(path, expected_size)?;
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 256 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if cancellation.is_cancelled() {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
    }

    still_stable(reader.get_ref(), expected_size, before_modified)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan_with_options, ScanOptions};

    fn fixture() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "cachereaper-analysis-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::create_dir_all(root.join("b")).unwrap();
        std::fs::write(
            root.join("a/photo.jpg"),
            vec![7u8; DUPLICATE_MIN_BYTES as usize],
        )
        .unwrap();
        std::fs::write(
            root.join("b/copy.jpg"),
            vec![7u8; DUPLICATE_MIN_BYTES as usize],
        )
        .unwrap();
        std::fs::write(
            root.join("b/different.jpg"),
            vec![8u8; DUPLICATE_MIN_BYTES as usize],
        )
        .unwrap();
        std::fs::write(root.join("notes.txt"), b"small").unwrap();
        root
    }

    #[test]
    fn cache_mode_retains_no_files() {
        let root = fixture();
        let tree = scan_with_options(&root, ScanOptions::default()).unwrap();
        assert!(tree.files.is_empty());
        assert_eq!(
            analyze(&tree, ScanMode::Cache, &CancellationToken::new()),
            AnalysisSummary::cache()
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn whole_mode_is_metadata_only_and_categorized() {
        let root = fixture();
        let tree = scan_with_options(
            &root,
            ScanOptions {
                mode: ScanMode::Whole,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        let summary = analyze(&tree, ScanMode::Whole, &CancellationToken::new());
        assert_eq!(summary.inventory_files, 4);
        assert!(summary.duplicate_groups.is_empty());
        assert!(!summary.content_analysis_complete);
        assert_eq!(summary.categories[0].category, "Images");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn all_mode_requires_full_content_hashes() {
        let root = fixture();
        let tree = scan_with_options(
            &root,
            ScanOptions {
                mode: ScanMode::All,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        let summary = analyze(&tree, ScanMode::All, &CancellationToken::new());
        assert!(summary.content_analysis_complete);
        assert_eq!(summary.duplicate_groups.len(), 1);
        assert_eq!(summary.duplicate_groups[0].files.len(), 2);
        assert_eq!(summary.duplicate_groups[0].hash.len(), 64);
        assert!(summary.duplicate_groups[0]
            .files
            .iter()
            .all(|file| file.name != "different.jpg"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn unchanged_deep_scan_reuses_hashes_and_mutation_invalidates_one_key() {
        let root = fixture();
        let options = || ScanOptions {
            mode: ScanMode::All,
            ..ScanOptions::default()
        };
        let tree = scan_with_options(&root, options()).unwrap();
        let mut cache = HashCache::default();
        let first = analyze_with_cache(&tree, ScanMode::All, &CancellationToken::new(), &mut cache);
        assert_eq!(first.hash_cache_hits, 0);
        assert!(first.hash_cache_misses >= 5);

        let index = root.join("index");
        cache.save_to(&index).unwrap();
        let mut cache = HashCache::load_from(&index);

        let tree = scan_with_options(&root, options()).unwrap();
        let second =
            analyze_with_cache(&tree, ScanMode::All, &CancellationToken::new(), &mut cache);
        assert_eq!(second.hash_cache_misses, 0);
        assert!(second.hash_cache_hits >= 5);

        std::fs::write(
            root.join("b/different.jpg"),
            vec![6u8; DUPLICATE_MIN_BYTES as usize],
        )
        .unwrap();
        let before_misses = cache.misses();
        let tree = scan_with_options(&root, options()).unwrap();
        let _ = analyze_with_cache(&tree, ScanMode::All, &CancellationToken::new(), &mut cache);
        assert!(cache.misses() > before_misses);
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_are_not_reported_as_reclaimable_duplicates() {
        let root = fixture();
        std::fs::hard_link(root.join("a/photo.jpg"), root.join("a/photo-hardlink.jpg")).unwrap();
        let tree = scan_with_options(
            &root,
            ScanOptions {
                mode: ScanMode::All,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        let summary = analyze(&tree, ScanMode::All, &CancellationToken::new());
        assert_eq!(summary.duplicate_groups.len(), 1);
        assert_eq!(summary.duplicate_groups[0].files.len(), 2);
        assert!(summary.duplicate_groups[0]
            .files
            .iter()
            .all(|file| file.name != "photo-hardlink.jpg"));
        std::fs::remove_dir_all(root).ok();
    }

    #[cfg(unix)]
    #[test]
    fn zero_allocation_placeholders_are_never_opened_for_hashing() {
        let root = fixture();
        let first = File::create(root.join("a/placeholder.bin")).unwrap();
        first.set_len(DUPLICATE_MIN_BYTES * 4).unwrap();
        let second = File::create(root.join("b/placeholder-copy.bin")).unwrap();
        second.set_len(DUPLICATE_MIN_BYTES * 4).unwrap();
        let tree = scan_with_options(
            &root,
            ScanOptions {
                mode: ScanMode::All,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        let placeholder_records: Vec<&FileRecord> = tree
            .files
            .iter()
            .filter(|record| record.name.starts_with("placeholder"))
            .collect();
        assert_eq!(placeholder_records.len(), 2);
        assert!(placeholder_records
            .iter()
            .all(|record| record.reclaimable_size == 0));
        let summary = analyze(&tree, ScanMode::All, &CancellationToken::new());
        assert!(summary.duplicate_groups.iter().all(|group| group
            .files
            .iter()
            .all(|file| !file.name.starts_with("placeholder"))));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn cancellation_never_publishes_partial_duplicate_groups() {
        let root = fixture();
        let tree = scan_with_options(
            &root,
            ScanOptions {
                mode: ScanMode::All,
                ..ScanOptions::default()
            },
        )
        .unwrap();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let summary = analyze(&tree, ScanMode::All, &cancellation);
        assert!(!summary.content_analysis_complete);
        assert!(summary.duplicate_groups.is_empty());
        assert_eq!(summary.duplicate_reclaimable_bytes, 0);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn category_mapping_is_deliberately_broad() {
        assert_eq!(category("movie.MOV"), "Video");
        assert_eq!(category("archive.tar"), "Archives");
        assert_eq!(category("main.rs"), "Code");
        assert_eq!(category("unknown.blob"), "Other");
    }
}
