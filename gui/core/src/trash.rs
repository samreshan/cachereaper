//! Durable transaction wrapper around the platform Trash operation.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::history::{audit_dir, now_millis};
use crate::quarantine::{verify_duplicate_file, QuarantineEvidence};

pub const TRASH_SCHEMA: u32 = 1;
static TRASH_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrashRecord {
    pub schema: u32,
    pub kind: String,
    pub id: String,
    pub at: u128,
    pub state: String,
    pub original_path: String,
    #[serde(default)]
    pub trashed_path: String,
    pub scan_root: String,
    pub sha256: String,
    pub logical_size: u64,
    #[serde(default)]
    pub peer_paths: Vec<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub parse_warning: Option<String>,
}

pub fn trash_duplicate_with<F>(
    original: &Path,
    evidence: QuarantineEvidence<'_>,
    mover: F,
) -> Result<TrashRecord, String>
where
    F: FnOnce(&Path) -> Result<PathBuf, String>,
{
    trash_duplicate_to(original, evidence, &audit_dir(), mover)
}

fn trash_duplicate_to<F>(
    original: &Path,
    evidence: QuarantineEvidence<'_>,
    manifests: &Path,
    mover: F,
) -> Result<TrashRecord, String>
where
    F: FnOnce(&Path) -> Result<PathBuf, String>,
{
    let verified = verify_duplicate_file(original, evidence)?;
    std::fs::create_dir_all(manifests).map_err(|error| error.to_string())?;
    let id = format!(
        "{}-{}-{}",
        now_millis(),
        std::process::id(),
        TRASH_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let manifest_path = manifests.join(format!("trash-{id}.jsonl"));
    let mut manifest = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&manifest_path)
        .map_err(|error| format!("could not create Trash manifest: {error}"))?;
    let mut record = TrashRecord {
        schema: TRASH_SCHEMA,
        kind: "trash".to_string(),
        id,
        at: now_millis(),
        state: "planned".to_string(),
        original_path: original.to_string_lossy().into_owned(),
        trashed_path: String::new(),
        scan_root: verified.scan_root.to_string_lossy().into_owned(),
        sha256: verified.expected_hash,
        logical_size: verified.expected_size,
        peer_paths: verified
            .peer_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        reason: String::new(),
        parse_warning: None,
    };
    write_event(&mut manifest, &record)
        .map_err(|error| format!("could not persist Trash intent: {error}"))?;
    sync_directory(manifests)
        .map_err(|error| format!("could not make Trash intent durable: {error}"))?;

    match mover(original) {
        Ok(destination) => {
            record.at = now_millis();
            record.state = "trashed".to_string();
            record.trashed_path = destination.to_string_lossy().into_owned();
            if let Err(error) = write_event(&mut manifest, &record) {
                let rollback = if !record.trashed_path.is_empty() && !original.exists() {
                    std::fs::rename(&record.trashed_path, original)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "Trash destination unavailable",
                    ))
                };
                record.at = now_millis();
                record.state = if rollback.is_ok() {
                    "rolled-back".to_string()
                } else {
                    "recovery-required".to_string()
                };
                record.reason = error.to_string();
                let _ = write_event(&mut manifest, &record);
                return Err(format!(
                    "could not finish Trash manifest; rollback {}: {error}",
                    if rollback.is_ok() {
                        "succeeded"
                    } else {
                        "failed"
                    }
                ));
            }
            Ok(record)
        }
        Err(error) => {
            record.at = now_millis();
            record.state = "failed".to_string();
            record.reason = error.clone();
            let _ = write_event(&mut manifest, &record);
            Err(format!("could not move file to Trash: {error}"))
        }
    }
}

pub fn list_trash() -> Result<Vec<TrashRecord>, String> {
    list_trash_from(&audit_dir())
}

pub(crate) fn list_trash_from(dir: &Path) -> Result<Vec<TrashRecord>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !valid_manifest_filename(name) {
            continue;
        }
        if let Some(mut record) = read_last_event(&path)? {
            if record.state == "planned" && !Path::new(&record.original_path).exists() {
                record.state = "recovery-required".to_string();
                record.reason = "Trash move may have completed before its final event was written; use the platform Trash to recover it".to_string();
            }
            records.push(record);
        }
    }
    records.sort_by(|left, right| right.at.cmp(&left.at).then_with(|| right.id.cmp(&left.id)));
    Ok(records)
}

fn write_event(file: &mut std::fs::File, record: &TrashRecord) -> std::io::Result<()> {
    serde_json::to_writer(&mut *file, record)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn read_last_event(path: &Path) -> Result<Option<TrashRecord>, String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut last = None;
    let mut malformed = 0usize;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<TrashRecord>(&line) {
            Ok(record) if record.schema == TRASH_SCHEMA && record.kind == "trash" => {
                last = Some(record)
            }
            _ => malformed += 1,
        }
    }
    if let Some(record) = &mut last {
        record.parse_warning =
            (malformed > 0).then(|| format!("ignored {malformed} malformed lines"));
    }
    Ok(last)
}

fn valid_manifest_filename(name: &str) -> bool {
    name.starts_with("trash-")
        && name.ends_with(".jsonl")
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn temp_root(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cachereaper-trash-test-{label}-{}-{}",
            std::process::id(),
            TRASH_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn evidence<'a>(
        root: &'a Path,
        allowed_roots: &'a [PathBuf],
        hash: &'a str,
        peers: &'a [PathBuf],
    ) -> QuarantineEvidence<'a> {
        QuarantineEvidence {
            scan_root: root,
            allowed_roots,
            reference_roots: &[],
            expected_hash: hash,
            expected_size: 7,
            peers,
        }
    }

    #[test]
    fn trash_intent_precedes_move_and_records_destination() {
        let root = temp_root("success");
        let manifests = root.join("audit");
        let first = root.join("first.bin");
        let second = root.join("second.bin");
        std::fs::write(&first, b"content").unwrap();
        std::fs::write(&second, b"content").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"content"));
        let peers = vec![second];
        let allowed = vec![root.clone()];
        let destination = root.join("trash").join("first.bin");
        let record = trash_duplicate_to(
            &first,
            evidence(&root, &allowed, &hash, &peers),
            &manifests,
            |path| {
                assert!(manifests.read_dir().unwrap().next().is_some());
                std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
                std::fs::rename(path, &destination).map_err(|error| error.to_string())?;
                Ok(destination.clone())
            },
        )
        .unwrap();
        assert_eq!(record.state, "trashed");
        assert_eq!(list_trash_from(&manifests).unwrap()[0], record);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn manifest_open_failure_never_calls_mover() {
        let root = temp_root("audit-failure");
        let first = root.join("first.bin");
        let second = root.join("second.bin");
        std::fs::write(&first, b"content").unwrap();
        std::fs::write(&second, b"content").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"content"));
        let peers = vec![second];
        let allowed = vec![root.clone()];
        let blocker = root.join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let mut called = false;
        let result = trash_duplicate_to(
            &first,
            evidence(&root, &allowed, &hash, &peers),
            &blocker,
            |_| {
                called = true;
                unreachable!()
            },
        );
        assert!(result.is_err());
        assert!(!called);
        assert!(first.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn mover_failure_is_a_visible_terminal_event() {
        let root = temp_root("move-failure");
        let manifests = root.join("audit");
        let first = root.join("first.bin");
        let second = root.join("second.bin");
        std::fs::write(&first, b"content").unwrap();
        std::fs::write(&second, b"content").unwrap();
        let hash = format!("{:x}", Sha256::digest(b"content"));
        let peers = vec![second];
        let allowed = vec![root.clone()];
        let result = trash_duplicate_to(
            &first,
            evidence(&root, &allowed, &hash, &peers),
            &manifests,
            |_| Err("volume unavailable".to_string()),
        );
        assert!(result.unwrap_err().contains("volume unavailable"));
        assert_eq!(list_trash_from(&manifests).unwrap()[0].state, "failed");
        assert!(first.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_move_is_projected_as_recovery_required() {
        let root = temp_root("interrupted");
        let manifests = root.join("audit");
        std::fs::create_dir_all(&manifests).unwrap();
        let missing_original = root.join("moved.bin");
        std::fs::write(
            manifests.join("trash-interrupted.jsonl"),
            serde_json::to_string(&TrashRecord {
                schema: TRASH_SCHEMA,
                kind: "trash".to_string(),
                id: "interrupted".to_string(),
                at: 1,
                state: "planned".to_string(),
                original_path: missing_original.to_string_lossy().into_owned(),
                trashed_path: String::new(),
                scan_root: root.to_string_lossy().into_owned(),
                sha256: "a".repeat(64),
                logical_size: 7,
                peer_paths: Vec::new(),
                reason: String::new(),
                parse_warning: None,
            })
            .unwrap()
                + "\n",
        )
        .unwrap();
        let record = list_trash_from(&manifests).unwrap().remove(0);
        assert_eq!(record.state, "recovery-required");
        assert!(record.reason.contains("platform Trash"));
        let _ = std::fs::remove_dir_all(root);
    }
}
