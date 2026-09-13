//! Bounded, local-only similar-media analysis.
//!
//! Image groups use a 64-bit difference hash over decoded pixels. Video and
//! audio groups use a deterministic SimHash over evenly sampled byte windows;
//! that is useful review evidence across container copies, but deliberately is
//! not called a duplicate proof and never authorizes deletion.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{CancellationToken, FileRecord, ScanMode, Tree};

pub const MEDIA_SCHEMA: u16 = 1;
const MAX_CANDIDATES_PER_KIND: usize = 256;
const MAX_GROUPS_PER_KIND: usize = 64;
const MAX_MEDIA_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(feature = "media-intelligence")]
const MAX_IMAGE_PIXELS: u64 = 40_000_000;
#[cfg(feature = "media-intelligence")]
const MAX_IMAGE_DIMENSION: u32 = 20_000;
#[cfg(feature = "media-intelligence")]
const MAX_IMAGE_ALLOCATION: u64 = 192 * 1024 * 1024;
const SAMPLE_WINDOWS: u64 = 8;
const SAMPLE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MediaKind {
    Image,
    Video,
    Audio,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaFile {
    pub path: String,
    pub allocated_bytes: u64,
    pub logical_bytes: u64,
    pub modified_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimilarMediaGroup {
    pub id: String,
    pub kind: MediaKind,
    pub algorithm: String,
    /// Minimum similarity to the group's representative, from 0–1000.
    pub similarity_millis: u16,
    pub files: Vec<MediaFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaAnalysis {
    pub schema: u16,
    pub complete: bool,
    pub image_candidates: usize,
    pub video_candidates: usize,
    pub audio_candidates: usize,
    pub skipped: usize,
    pub groups: Vec<SimilarMediaGroup>,
    pub warnings: Vec<String>,
}

impl MediaAnalysis {
    pub fn unavailable() -> Self {
        Self {
            schema: MEDIA_SCHEMA,
            complete: false,
            image_candidates: 0,
            video_candidates: 0,
            audio_candidates: 0,
            skipped: 0,
            groups: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

pub fn analyze_similar_media(
    tree: &Tree,
    mode: ScanMode,
    cancellation: &CancellationToken,
) -> MediaAnalysis {
    if mode != ScanMode::All {
        return MediaAnalysis::unavailable();
    }

    let images = candidates(tree, MediaKind::Image, 32 * 1024);
    let videos = candidates(tree, MediaKind::Video, 1024 * 1024);
    let audio = candidates(tree, MediaKind::Audio, 256 * 1024);
    let mut output = MediaAnalysis {
        schema: MEDIA_SCHEMA,
        complete: true,
        image_candidates: images.len(),
        video_candidates: videos.len(),
        audio_candidates: audio.len(),
        skipped: 0,
        groups: Vec::new(),
        warnings: Vec::new(),
    };

    if cancellation.is_cancelled() {
        output.complete = false;
        return output;
    }

    #[cfg(feature = "media-intelligence")]
    {
        let (fingerprints, skipped) = fingerprint_images(tree, &images, cancellation);
        output.skipped += skipped;
        output.groups.extend(cluster(
            MediaKind::Image,
            "dhash-9x8-v1",
            fingerprints,
            10,
            false,
        ));
    }
    #[cfg(not(feature = "media-intelligence"))]
    output
        .warnings
        .push("perceptual image support is not enabled in this build".to_string());

    for (kind, records) in [(MediaKind::Video, videos), (MediaKind::Audio, audio)] {
        let mut fingerprints = Vec::new();
        for record in records {
            if cancellation.is_cancelled() {
                output.complete = false;
                break;
            }
            match sampled_simhash(&tree.file_path(record), record.logical_size) {
                Ok(hash) => fingerprints.push((
                    record,
                    tree.file_path(record).to_string_lossy().into_owned(),
                    hash,
                )),
                Err(_) => output.skipped += 1,
            }
        }
        output.groups.extend(cluster(
            kind,
            "sampled-simhash-8x16k-v1",
            fingerprints,
            6,
            true,
        ));
    }
    if cancellation.is_cancelled() {
        output.complete = false;
        output.groups.clear();
        output
            .warnings
            .push("similar-media analysis was cancelled; partial groups were discarded".into());
    }
    output.groups.sort_by(|a, b| {
        a.kind
            .to_string()
            .cmp(&b.kind.to_string())
            .then_with(|| a.id.cmp(&b.id))
    });
    output
}

impl std::fmt::Display for MediaKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Image => "image",
            Self::Video => "video",
            Self::Audio => "audio",
        })
    }
}

fn candidates(tree: &Tree, kind: MediaKind, minimum_bytes: u64) -> Vec<&FileRecord> {
    let mut values: Vec<&FileRecord> = tree
        .files
        .iter()
        .filter(|file| {
            file.reclaimable_size > 0
                && file.logical_size >= minimum_bytes
                && file.logical_size <= MAX_MEDIA_BYTES
                && media_kind(&file.name) == Some(kind)
        })
        .collect();
    values.sort_by(|a, b| {
        b.reclaimable_size
            .cmp(&a.reclaimable_size)
            .then_with(|| tree.file_path(a).cmp(&tree.file_path(b)))
    });
    values.truncate(MAX_CANDIDATES_PER_KIND);
    values
}

fn media_kind(name: &str) -> Option<MediaKind> {
    let extension = Path::new(name)
        .extension()
        .and_then(|value| value.to_str())?
        .to_ascii_lowercase();
    match extension.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "bmp" | "tif" | "tiff" => Some(MediaKind::Image),
        "mp4" | "mov" | "mkv" | "avi" | "webm" | "m4v" | "mpeg" | "mpg" => Some(MediaKind::Video),
        "mp3" | "wav" | "flac" | "aac" | "m4a" | "ogg" | "opus" | "aiff" => Some(MediaKind::Audio),
        _ => None,
    }
}

#[cfg(feature = "media-intelligence")]
fn fingerprint_images<'a>(
    tree: &Tree,
    records: &[&'a FileRecord],
    cancellation: &CancellationToken,
) -> (Vec<(&'a FileRecord, String, u64)>, usize) {
    let mut values = Vec::new();
    let mut skipped = 0;
    for record in records {
        if cancellation.is_cancelled() {
            break;
        }
        match difference_hash(&tree.file_path(record)) {
            Ok(hash) => values.push((
                *record,
                tree.file_path(record).to_string_lossy().into_owned(),
                hash,
            )),
            Err(_) => skipped += 1,
        }
    }
    (values, skipped)
}

#[cfg(feature = "media-intelligence")]
fn difference_hash(path: &Path) -> Result<u64, String> {
    let (width, height) = image::image_dimensions(path).map_err(|error| error.to_string())?;
    if width == 0
        || height == 0
        || width > MAX_IMAGE_DIMENSION
        || height > MAX_IMAGE_DIMENSION
        || u64::from(width).saturating_mul(u64::from(height)) > MAX_IMAGE_PIXELS
    {
        return Err("image dimensions exceed the decoder budget".into());
    }
    let mut reader = image::ImageReader::open(path)
        .map_err(|error| error.to_string())?
        .with_guessed_format()
        .map_err(|error| error.to_string())?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_IMAGE_ALLOCATION);
    reader.limits(limits);
    let image = reader
        .decode()
        .map_err(|error| error.to_string())?
        .to_luma8();
    let small = image::imageops::resize(&image, 9, 8, image::imageops::FilterType::Triangle);
    let mut hash = 0_u64;
    for y in 0..8 {
        for x in 0..8 {
            hash <<= 1;
            if small.get_pixel(x, y).0[0] > small.get_pixel(x + 1, y).0[0] {
                hash |= 1;
            }
        }
    }
    Ok(hash)
}

fn sampled_simhash(path: &Path, length: u64) -> Result<u64, String> {
    let mut file = File::open(path).map_err(|error| error.to_string())?;
    let mut weights = [0_i32; 64];
    let mut buffer = vec![0_u8; SAMPLE_BYTES];
    for window in 0..SAMPLE_WINDOWS {
        let max_offset = length.saturating_sub(SAMPLE_BYTES as u64);
        let offset = if SAMPLE_WINDOWS <= 1 {
            0
        } else {
            max_offset.saturating_mul(window) / (SAMPLE_WINDOWS - 1)
        };
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| error.to_string())?;
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        for chunk in buffer[..read].chunks(8) {
            let token = fnv1a(chunk);
            for (bit, weight) in weights.iter_mut().enumerate() {
                *weight += if token & (1_u64 << bit) == 0 { -1 } else { 1 };
            }
        }
    }
    Ok(weights
        .iter()
        .enumerate()
        .fold(0_u64, |hash, (bit, weight)| {
            if *weight >= 0 {
                hash | (1_u64 << bit)
            } else {
                hash
            }
        }))
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn cluster(
    kind: MediaKind,
    algorithm: &str,
    fingerprints: Vec<(&FileRecord, String, u64)>,
    max_distance: u32,
    constrain_size: bool,
) -> Vec<SimilarMediaGroup> {
    // Use representative-bounded groups instead of transitive unioning: if A
    // resembles B and B resembles C, that alone must not label A and C alike.
    let mut assigned = vec![false; fingerprints.len()];
    let mut buckets = Vec::new();
    for left in 0..fingerprints.len() {
        if assigned[left] {
            continue;
        }
        let mut members = vec![left];
        for right in left + 1..fingerprints.len() {
            if assigned[right] {
                continue;
            }
            let a = &fingerprints[left];
            let b = &fingerprints[right];
            if constrain_size {
                let small = a.0.logical_size.min(b.0.logical_size);
                let large = a.0.logical_size.max(b.0.logical_size);
                if small.saturating_mul(5) < large.saturating_mul(4) {
                    continue;
                }
            }
            if (a.2 ^ b.2).count_ones() <= max_distance {
                members.push(right);
            }
        }
        if members.len() > 1 {
            for index in &members {
                assigned[*index] = true;
            }
            buckets.push(members);
        }
    }
    let mut groups = Vec::new();
    for members in buckets {
        let representative = fingerprints[members[0]].2;
        let worst_distance = members
            .iter()
            .map(|index| (representative ^ fingerprints[*index].2).count_ones())
            .max()
            .unwrap_or(64);
        let mut files: Vec<MediaFile> = members
            .iter()
            .map(|index| media_file(fingerprints[*index].0, &fingerprints[*index].1))
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let id = group_id(kind, &files);
        groups.push(SimilarMediaGroup {
            id,
            kind,
            algorithm: algorithm.to_string(),
            similarity_millis: (((64 - worst_distance.min(64)) * 1000) / 64) as u16,
            files,
        });
    }
    groups.sort_by(|a, b| {
        b.similarity_millis
            .cmp(&a.similarity_millis)
            .then_with(|| a.id.cmp(&b.id))
    });
    groups.truncate(MAX_GROUPS_PER_KIND);
    groups
}

fn media_file(record: &FileRecord, path: &str) -> MediaFile {
    MediaFile {
        path: path.to_string(),
        allocated_bytes: record.reclaimable_size,
        logical_bytes: record.logical_size,
        modified_at: record.mtime,
    }
}

fn group_id(kind: MediaKind, files: &[MediaFile]) -> String {
    let mut digest = Sha256::new();
    digest.update(kind.to_string());
    for file in files {
        digest.update([0]);
        digest.update(file.path.as_bytes());
    }
    format!("similar-{kind}-{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn record(name: &str, bytes: u64) -> FileRecord {
        FileRecord {
            parent: 0,
            name: name.into(),
            reclaimable_size: bytes,
            logical_size: bytes,
            mtime: 1,
            volume_id: 1,
            file_id: bytes,
            modified_ns: 1,
        }
    }

    fn temp_path(extension: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "cachereaper-media-{}-{}.{}",
            std::process::id(),
            crate::history::now_millis(),
            extension
        ))
    }

    #[test]
    fn sampled_fingerprint_is_deterministic_and_changes() {
        let path = temp_path("bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(&vec![0x55; SAMPLE_BYTES * 2]).unwrap();
        file.sync_all().unwrap();
        let first = sampled_simhash(&path, (SAMPLE_BYTES * 2) as u64).unwrap();
        let second = sampled_simhash(&path, (SAMPLE_BYTES * 2) as u64).unwrap();
        assert_eq!(first, second);
        std::fs::write(&path, vec![0xaa; SAMPLE_BYTES * 2]).unwrap();
        let changed = sampled_simhash(&path, (SAMPLE_BYTES * 2) as u64).unwrap();
        assert_ne!(first, changed);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn clustering_is_bounded_and_size_aware() {
        let a = record("a.mov", 100);
        let b = record("b.mov", 105);
        let far_size = record("c.mov", 1_000);
        let groups = cluster(
            MediaKind::Video,
            "test",
            vec![
                (&a, "/a".into(), 1),
                (&b, "/b".into(), 1),
                (&far_size, "/c".into(), 1),
            ],
            0,
            true,
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].files.len(), 2);
        assert!(groups[0]
            .files
            .iter()
            .all(|file| file.path.starts_with('/')));
    }

    #[test]
    fn clustering_does_not_turn_similarity_into_a_transitive_claim() {
        let a = record("a.jpg", 100);
        let b = record("b.jpg", 100);
        let c = record("c.jpg", 100);
        let groups = cluster(
            MediaKind::Image,
            "test",
            vec![
                (&a, "/a".into(), 0),
                (&b, "/b".into(), 0b1111),
                (&c, "/c".into(), 0b1111_1111),
            ],
            4,
            false,
        );
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].files.len(), 2);
        assert!(groups[0].files.iter().all(|file| file.path != "/c"));
    }

    #[cfg(feature = "media-intelligence")]
    #[test]
    fn perceptual_hash_survives_a_resize() {
        let large = temp_path("png");
        let small = temp_path("png-small.png");
        let source = image::GrayImage::from_fn(90, 80, |x, y| image::Luma([((x + y) % 255) as u8]));
        source.save(&large).unwrap();
        image::imageops::resize(&source, 45, 40, image::imageops::FilterType::Triangle)
            .save(&small)
            .unwrap();
        let distance =
            (difference_hash(&large).unwrap() ^ difference_hash(&small).unwrap()).count_ones();
        assert!(distance <= 10, "distance was {distance}");
        let _ = std::fs::remove_file(large);
        let _ = std::fs::remove_file(small);
    }
}
