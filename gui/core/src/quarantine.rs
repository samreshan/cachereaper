//! Recoverable, evidence-bound moves for personal files.
//!
//! A quarantine is intentionally not deletion and does not claim to free disk
//! space. The selected file is atomically renamed into a hidden vault at the
//! scan root so it remains on the same filesystem. An append-only manifest is
//! durably created before the rename and records every later state transition.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::guard::{is_within, matching_reference_root, path_is_protected};
use crate::history::{audit_dir, now_millis};

pub const QUARANTINE_SCHEMA: u32 = 1;
pub const VAULT_NAME: &str = ".cachereaper-quarantine";
const MILLIS_PER_DAY: u128 = 86_400_000;
const MAX_EXPIRY_PEERS: usize = 64;

static QUARANTINE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineRecord {
    pub schema: u32,
    pub kind: String,
    pub id: String,
    pub at: u128,
    pub state: String,
    pub original_path: String,
    pub quarantined_path: String,
    pub scan_root: String,
    pub sha256: String,
    pub logical_size: u64,
    #[serde(default)]
    pub quarantined_at: Option<u128>,
    /// Candidate copies captured from the evidence-bound duplicate group.
    /// They are never trusted blindly: expiry rehashes them and requires one
    /// unchanged survivor immediately before permanent deletion.
    #[serde(default)]
    pub peer_paths: Vec<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub parse_warning: Option<String>,
}

/// Scan-time evidence and current policy needed to authorize one move. Keeping
/// these values together makes it difficult for a new call site to omit a
/// safety boundary as the action contract grows.
#[derive(Debug, Clone, Copy)]
pub struct QuarantineEvidence<'a> {
    pub scan_root: &'a Path,
    pub allowed_roots: &'a [PathBuf],
    pub reference_roots: &'a [PathBuf],
    pub expected_hash: &'a str,
    pub expected_size: u64,
    pub peers: &'a [PathBuf],
}

#[derive(Debug, Clone)]
pub struct VerifiedDuplicate {
    pub scan_root: PathBuf,
    pub expected_hash: String,
    pub expected_size: u64,
    pub peer_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub struct ExpiryRequest<'a> {
    pub allowed_roots: &'a [PathBuf],
    pub reference_roots: &'a [PathBuf],
    pub retention_days: Option<u32>,
    pub confirmation: &'a str,
}

pub fn quarantine_file(
    original: &Path,
    evidence: QuarantineEvidence<'_>,
) -> Result<QuarantineRecord, String> {
    quarantine_file_to(original, evidence, &audit_dir())
}

fn quarantine_file_to(
    original: &Path,
    evidence: QuarantineEvidence<'_>,
    manifests: &Path,
) -> Result<QuarantineRecord, String> {
    let verified = verify_duplicate_file(original, evidence)?;
    let scan_root = &verified.scan_root;

    let id = format!(
        "{}-{}-{}",
        now_millis(),
        std::process::id(),
        QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let file_name = original
        .file_name()
        .ok_or_else(|| "file has no name".to_string())?;
    let transaction_dir = scan_root.join(VAULT_NAME).join(&id);
    let destination = transaction_dir.join(file_name);
    std::fs::create_dir_all(&transaction_dir).map_err(|error| error.to_string())?;
    let vault_metadata = std::fs::symlink_metadata(&transaction_dir).map_err(|e| e.to_string())?;
    if vault_metadata.file_type().is_symlink() || !vault_metadata.is_dir() {
        return Err("quarantine vault is not a real directory".to_string());
    }

    std::fs::create_dir_all(manifests).map_err(|error| error.to_string())?;
    let manifest_path = manifests.join(format!("quarantine-{id}.jsonl"));
    let mut manifest = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&manifest_path)
        .map_err(|error| format!("could not create quarantine manifest: {error}"))?;

    let mut record = QuarantineRecord {
        schema: QUARANTINE_SCHEMA,
        kind: "quarantine".to_string(),
        id,
        at: now_millis(),
        state: "planned".to_string(),
        original_path: original.to_string_lossy().into_owned(),
        quarantined_path: destination.to_string_lossy().into_owned(),
        scan_root: scan_root.to_string_lossy().into_owned(),
        sha256: verified.expected_hash,
        logical_size: verified.expected_size,
        quarantined_at: None,
        peer_paths: verified
            .peer_paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
        reason: String::new(),
        parse_warning: None,
    };
    write_event(&mut manifest, &record)
        .map_err(|error| format!("could not persist quarantine intent: {error}"))?;
    sync_directory(manifests)
        .map_err(|error| format!("could not make quarantine manifest durable: {error}"))?;

    if let Err(error) = std::fs::rename(original, &destination) {
        record.at = now_millis();
        record.state = "failed".to_string();
        record.reason = error.to_string();
        let _ = write_event(&mut manifest, &record);
        return Err(format!("could not move file into quarantine: {error}"));
    }

    record.at = now_millis();
    record.state = "quarantined".to_string();
    record.quarantined_at = Some(record.at);
    if let Err(error) = write_event(&mut manifest, &record) {
        let rollback = std::fs::rename(&destination, original);
        record.at = now_millis();
        record.state = if rollback.is_ok() {
            "rolled-back".to_string()
        } else {
            "recovery-required".to_string()
        };
        record.reason = error.to_string();
        let _ = write_event(&mut manifest, &record);
        return Err(format!(
            "could not finish quarantine manifest; rollback {}: {error}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        ));
    }
    Ok(record)
}

pub fn verify_duplicate_file(
    original: &Path,
    evidence: QuarantineEvidence<'_>,
) -> Result<VerifiedDuplicate, String> {
    validate_hash(evidence.expected_hash)?;
    validate_scan_root(evidence.scan_root, evidence.allowed_roots)?;
    validate_personal_file(original, evidence.allowed_roots)?;
    if let Some(root) = matching_reference_root(original, evidence.reference_roots) {
        return Err(format!(
            "reference root is immutable: {}",
            root.to_string_lossy()
        ));
    }
    if !is_within(original, evidence.scan_root) {
        return Err("file is outside the scan root".to_string());
    }
    if hash_stable_file(original, evidence.expected_size)? != evidence.expected_hash {
        return Err("file content changed since the deep scan".to_string());
    }

    let candidates: Vec<PathBuf> = evidence
        .peers
        .iter()
        .filter(|peer| *peer != original)
        .filter(|peer| validate_personal_file(peer, evidence.allowed_roots).is_ok())
        .cloned()
        .collect();
    let survivor = candidates
        .iter()
        .find(|peer| {
            hash_stable_file(peer, evidence.expected_size)
                .is_ok_and(|hash| hash == evidence.expected_hash)
        })
        .cloned()
        .ok_or_else(|| "no unchanged duplicate would remain after this move".to_string())?;
    let mut peer_paths = vec![survivor.clone()];
    peer_paths.extend(
        candidates
            .into_iter()
            .filter(|peer| *peer != survivor)
            .take(MAX_EXPIRY_PEERS - 1),
    );
    Ok(VerifiedDuplicate {
        scan_root: evidence.scan_root.to_path_buf(),
        expected_hash: evidence.expected_hash.to_string(),
        expected_size: evidence.expected_size,
        peer_paths,
    })
}

pub fn list_quarantine() -> Result<Vec<QuarantineRecord>, String> {
    list_quarantine_from(&audit_dir())
}

pub(crate) fn list_quarantine_from(dir: &Path) -> Result<Vec<QuarantineRecord>, String> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !valid_manifest_filename(name) {
            continue;
        }
        if let Some(mut record) = read_last_event(&path)? {
            expose_interrupted_move(&mut record);
            records.push(record);
        }
    }
    records.sort_by(|left, right| right.at.cmp(&left.at).then_with(|| right.id.cmp(&left.id)));
    Ok(records)
}

pub fn restore_quarantine(
    id: &str,
    allowed_roots: &[PathBuf],
    reference_roots: &[PathBuf],
) -> Result<QuarantineRecord, String> {
    restore_quarantine_from(id, allowed_roots, reference_roots, &audit_dir())
}

fn restore_quarantine_from(
    id: &str,
    allowed_roots: &[PathBuf],
    reference_roots: &[PathBuf],
    manifests: &Path,
) -> Result<QuarantineRecord, String> {
    if !valid_id(id) {
        return Err("invalid quarantine id".to_string());
    }
    let manifest_path = manifests.join(format!("quarantine-{id}.jsonl"));
    let mut record = read_last_event(&manifest_path)?
        .ok_or_else(|| "quarantine record not found".to_string())?;
    expose_interrupted_move(&mut record);
    if record.id != id
        || !matches!(
            record.state.as_str(),
            "quarantined" | "planned" | "recovery-required"
        )
    {
        return Err("quarantine item is not restorable".to_string());
    }

    let (original, destination, scan_root) =
        validate_quarantined_file(&record, id, allowed_roots, reference_roots)?;
    if original.exists() {
        return Err("original path is occupied; refusing to overwrite it".to_string());
    }
    if !original.parent().is_some_and(Path::is_dir) {
        return Err("original parent directory no longer exists".to_string());
    }
    let canonical_parent = original
        .parent()
        .unwrap()
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let canonical_root = scan_root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if !is_within(&canonical_parent, &canonical_root) {
        return Err("original parent now resolves outside the scan root".to_string());
    }
    std::fs::rename(&destination, &original)
        .map_err(|error| format!("could not restore quarantined file: {error}"))?;
    record.at = now_millis();
    record.state = "restored".to_string();
    record.reason.clear();
    let mut manifest = std::fs::OpenOptions::new()
        .append(true)
        .open(&manifest_path)
        .map_err(|error| error.to_string())?;
    if let Err(error) = write_event(&mut manifest, &record) {
        let rollback = std::fs::rename(&original, &destination);
        return Err(format!(
            "could not record restore; rollback {}: {error}",
            if rollback.is_ok() {
                "succeeded"
            } else {
                "failed"
            }
        ));
    }
    if let Some(parent) = destination.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    Ok(record)
}

fn validate_quarantined_file(
    record: &QuarantineRecord,
    id: &str,
    allowed_roots: &[PathBuf],
    reference_roots: &[PathBuf],
) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    if record.id != id {
        return Err("quarantine manifest id does not match".to_string());
    }
    let original = PathBuf::from(&record.original_path);
    let destination = PathBuf::from(&record.quarantined_path);
    let scan_root = PathBuf::from(&record.scan_root);
    validate_scan_root(&scan_root, allowed_roots)?;
    validate_hash(&record.sha256)?;
    let protected = path_is_protected(&original);
    if !protected.is_empty() {
        return Err(protected);
    }
    if !allowed_roots.iter().any(|root| is_within(&original, root)) {
        return Err("original path is outside allowed roots".to_string());
    }
    if let Some(root) = matching_reference_root(&original, reference_roots) {
        return Err(format!(
            "reference root is immutable: {}",
            root.to_string_lossy()
        ));
    }
    if !is_within(&original, &scan_root) {
        return Err("original path is outside the recorded scan root".to_string());
    }
    let expected_destination = scan_root.join(VAULT_NAME).join(id).join(
        original
            .file_name()
            .ok_or_else(|| "file has no name".to_string())?,
    );
    if destination != expected_destination {
        return Err("quarantine manifest destination is invalid".to_string());
    }
    for directory in [
        scan_root.join(VAULT_NAME),
        scan_root.join(VAULT_NAME).join(id),
    ] {
        let metadata = std::fs::symlink_metadata(&directory).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("quarantine vault path changed since the move".to_string());
        }
    }
    let metadata = std::fs::symlink_metadata(&destination).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("quarantined item is not a regular file".to_string());
    }
    if hash_stable_file(&destination, record.logical_size)? != record.sha256 {
        return Err("quarantined file content no longer matches its manifest".to_string());
    }
    Ok((original, destination, scan_root))
}

pub fn expire_quarantine(id: &str, request: ExpiryRequest<'_>) -> Result<QuarantineRecord, String> {
    expire_quarantine_from(id, request, now_millis(), &audit_dir())
}

fn expire_quarantine_from(
    id: &str,
    request: ExpiryRequest<'_>,
    now: u128,
    manifests: &Path,
) -> Result<QuarantineRecord, String> {
    if !valid_id(id) {
        return Err("invalid quarantine id".to_string());
    }
    if request.confirmation != format!("expire {id}") {
        return Err("permanent expiry confirmation did not match".to_string());
    }
    let retention_days = request
        .retention_days
        .ok_or_else(|| "permanent expiry is disabled".to_string())?;
    if !(1..=3650).contains(&retention_days) {
        return Err("quarantine retention is invalid".to_string());
    }

    let manifest_path = manifests.join(format!("quarantine-{id}.jsonl"));
    let mut record = read_last_event(&manifest_path)?
        .ok_or_else(|| "quarantine record not found".to_string())?;
    expose_interrupted_move(&mut record);
    if record.state != "quarantined" {
        return Err("only a completed quarantine can be permanently expired".to_string());
    }
    let quarantined_at = record.quarantined_at.ok_or_else(|| {
        "legacy quarantine has no expiry timestamp; restore it instead".to_string()
    })?;
    let eligible_at =
        quarantined_at.saturating_add(u128::from(retention_days).saturating_mul(MILLIS_PER_DAY));
    if now < eligible_at {
        return Err(format!(
            "quarantine retention has not elapsed; eligible at {eligible_at}"
        ));
    }

    let (original, destination, _) =
        validate_quarantined_file(&record, id, request.allowed_roots, request.reference_roots)?;
    let canonical_destination = destination
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let mut surviving_peer = false;
    for peer in &record.peer_paths {
        let peer = PathBuf::from(peer);
        if peer == original || peer == destination {
            continue;
        }
        if validate_personal_file(&peer, request.allowed_roots).is_err() {
            continue;
        }
        if peer
            .canonicalize()
            .ok()
            .is_some_and(|canonical| canonical == canonical_destination)
        {
            continue;
        }
        if hash_stable_file(&peer, record.logical_size).is_ok_and(|hash| hash == record.sha256) {
            surviving_peer = true;
            break;
        }
    }
    if !surviving_peer {
        return Err("no unchanged duplicate remains; restore this file instead".to_string());
    }

    let mut manifest = std::fs::OpenOptions::new()
        .append(true)
        .open(&manifest_path)
        .map_err(|error| error.to_string())?;
    record.at = now;
    record.state = "expiry-planned".to_string();
    record.reason.clear();
    write_event(&mut manifest, &record)
        .map_err(|error| format!("could not persist permanent expiry intent: {error}"))?;

    if let Err(error) = std::fs::remove_file(&destination) {
        record.at = now;
        record.state = "quarantined".to_string();
        record.reason = format!("permanent expiry failed: {error}");
        let _ = write_event(&mut manifest, &record);
        return Err(format!(
            "could not permanently expire quarantined file: {error}"
        ));
    }
    if let Some(parent) = destination.parent() {
        sync_directory(parent)
            .map_err(|error| format!("file was expired but directory sync failed: {error}"))?;
    }

    record.at = now;
    record.state = "expired".to_string();
    record.reason.clear();
    write_event(&mut manifest, &record)
        .map_err(|error| format!("file was expired but final manifest append failed: {error}"))?;
    if let Some(parent) = destination.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    Ok(record)
}

fn validate_scan_root(scan_root: &Path, allowed_roots: &[PathBuf]) -> Result<(), String> {
    if !scan_root.is_absolute() || scan_root == Path::new("/") || scan_root.components().count() < 2
    {
        return Err("scan root is not safe for a quarantine vault".to_string());
    }
    if !allowed_roots
        .iter()
        .any(|root| scan_root == root || is_within(scan_root, root))
    {
        return Err("scan root is outside allowed roots".to_string());
    }
    Ok(())
}

fn validate_personal_file(path: &Path, allowed_roots: &[PathBuf]) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("path is not absolute".to_string());
    }
    let protected = path_is_protected(path);
    if !protected.is_empty() {
        return Err(protected);
    }
    if !allowed_roots.iter().any(|root| is_within(path, root)) {
        return Err("path is outside allowed roots".to_string());
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "file is already gone".to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("file is a symlink".to_string());
    }
    if !metadata.is_file() {
        return Err("path is not a regular file".to_string());
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid SHA-256 evidence".to_string());
    }
    Ok(())
}

fn hash_stable_file(path: &Path, expected_size: u64) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file() || before.len() != expected_size {
        return Err("file size changed since the deep scan".to_string());
    }
    let before_modified = before.modified().ok();
    let mut reader = BufReader::with_capacity(256 * 1024, file);
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 256 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    let after = reader
        .get_ref()
        .metadata()
        .map_err(|error| error.to_string())?;
    if after.len() != expected_size || after.modified().ok() != before_modified {
        return Err("file changed while verifying duplicate evidence".to_string());
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn write_event(file: &mut std::fs::File, record: &QuarantineRecord) -> std::io::Result<()> {
    serde_json::to_writer(&mut *file, record)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_all()
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    // Opening a directory is not portable on Windows. File::sync_all above is
    // still the strongest portable durability boundary available here.
    Ok(())
}

fn read_last_event(path: &Path) -> Result<Option<QuarantineRecord>, String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut last = None;
    let mut malformed = 0usize;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| error.to_string())?;
        match serde_json::from_str::<QuarantineRecord>(&line) {
            Ok(record) if record.schema == QUARANTINE_SCHEMA && record.kind == "quarantine" => {
                last = Some(record)
            }
            _ => malformed += 1,
        }
    }
    if let Some(record) = last.as_mut() {
        record.parse_warning =
            (malformed > 0).then(|| format!("ignored {malformed} malformed events"));
    }
    Ok(last)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_manifest_filename(name: &str) -> bool {
    name.starts_with("quarantine-")
        && name.ends_with(".jsonl")
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

/// A process can stop after the durable intent is written and the atomic move
/// succeeds, but before the final event reaches the manifest. The two paths are
/// enough to expose that item for a normal, fully revalidated restore. This is
/// deliberately a presentation-only reconciliation; history remains append-only
/// until restore records the next real transition.
fn expose_interrupted_move(record: &mut QuarantineRecord) {
    if !matches!(
        record.state.as_str(),
        "planned" | "recovery-required" | "expiry-planned"
    ) {
        return;
    }
    let original = PathBuf::from(&record.original_path);
    let destination = PathBuf::from(&record.quarantined_path);
    let scan_root = PathBuf::from(&record.scan_root);
    let Some(file_name) = original.file_name() else {
        return;
    };
    let expected = scan_root.join(VAULT_NAME).join(&record.id).join(file_name);
    if destination != expected {
        return;
    }
    if record.state == "expiry-planned" && !destination.exists() {
        record.state = "expired".to_string();
        record.reason =
            "permanent expiry completed but its final manifest event was interrupted".to_string();
        return;
    }
    if !original.exists() && destination.is_file() {
        let interrupted_expiry = record.state == "expiry-planned";
        record.state = "recovery-required".to_string();
        if record.quarantined_at.is_none() {
            record.quarantined_at = Some(record.at);
        }
        if record.reason.is_empty() {
            record.reason = if interrupted_expiry {
                "permanent expiry was interrupted before deletion; the file remains recoverable"
                    .to_string()
            } else {
                "the move completed but its final manifest event was interrupted".to_string()
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (PathBuf, PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "cachereaper-quarantine-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let manifests = root.join("manifests");
        std::fs::create_dir_all(root.join("files")).unwrap();
        let first = root.join("files/first.bin");
        let second = root.join("files/second.bin");
        std::fs::write(&first, vec![9u8; 1024 * 1024]).unwrap();
        std::fs::write(&second, vec![9u8; 1024 * 1024]).unwrap();
        (root, manifests, first)
    }

    fn evidence<'a>(
        root: &'a PathBuf,
        reference_roots: &'a [PathBuf],
        hash: &'a str,
        peers: &'a [PathBuf],
    ) -> QuarantineEvidence<'a> {
        QuarantineEvidence {
            scan_root: root.as_path(),
            allowed_roots: std::slice::from_ref(root),
            reference_roots,
            expected_hash: hash,
            expected_size: 1024 * 1024,
            peers,
        }
    }

    #[test]
    fn quarantine_is_recoverable_and_append_only() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record = quarantine_file_to(
            &first,
            evidence(&root, &[], &hash, std::slice::from_ref(&second)),
            &manifests,
        )
        .unwrap();
        assert!(!first.exists());
        assert!(Path::new(&record.quarantined_path).exists());
        assert_eq!(record.state, "quarantined");
        assert!(record.quarantined_at.is_some());
        assert_eq!(record.peer_paths, vec![second.to_string_lossy()]);

        let restored =
            restore_quarantine_from(&record.id, std::slice::from_ref(&root), &[], &manifests)
                .unwrap();
        assert_eq!(restored.state, "restored");
        assert!(first.exists());
        assert!(!Path::new(&record.quarantined_path).exists());
        let listed = list_quarantine_from(&manifests).unwrap();
        assert_eq!(listed[0].state, "restored");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn refuses_without_an_unchanged_surviving_peer() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        std::fs::write(&second, vec![3u8; 1024 * 1024]).unwrap();
        let error = quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests)
            .unwrap_err();
        assert!(error.contains("no unchanged duplicate"));
        assert!(first.exists());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn reference_roots_block_quarantine_and_restore_targets() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let references = vec![root.join("files")];
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let error = quarantine_file_to(
            &first,
            evidence(&root, &references, &hash, std::slice::from_ref(&second)),
            &manifests,
        )
        .unwrap_err();
        assert!(error.contains("reference root is immutable"));
        assert!(first.exists());

        let record =
            quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests).unwrap();
        let error = restore_quarantine_from(
            &record.id,
            std::slice::from_ref(&root),
            &references,
            &manifests,
        )
        .unwrap_err();
        assert!(error.contains("reference root is immutable"));
        assert!(Path::new(&record.quarantined_path).exists());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn permanent_expiry_requires_retention_confirmation_and_a_live_peer() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record = quarantine_file_to(
            &first,
            evidence(&root, &[], &hash, std::slice::from_ref(&second)),
            &manifests,
        )
        .unwrap();
        let request = |confirmation| ExpiryRequest {
            allowed_roots: std::slice::from_ref(&root),
            reference_roots: &[],
            retention_days: Some(30),
            confirmation,
        };
        let quarantined_at = record.quarantined_at.unwrap();

        let error = expire_quarantine_from(
            &record.id,
            request("wrong"),
            quarantined_at + 31 * MILLIS_PER_DAY,
            &manifests,
        )
        .unwrap_err();
        assert!(error.contains("confirmation"));
        let phrase = format!("expire {}", record.id);
        let error = expire_quarantine_from(
            &record.id,
            request(&phrase),
            quarantined_at + 29 * MILLIS_PER_DAY,
            &manifests,
        )
        .unwrap_err();
        assert!(error.contains("retention has not elapsed"));
        assert!(Path::new(&record.quarantined_path).exists());

        let expired = expire_quarantine_from(
            &record.id,
            request(&phrase),
            quarantined_at + 30 * MILLIS_PER_DAY,
            &manifests,
        )
        .unwrap();
        assert_eq!(expired.state, "expired");
        assert!(!Path::new(&record.quarantined_path).exists());
        assert!(second.exists(), "the verified duplicate must remain");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn permanent_expiry_stops_when_every_recorded_peer_changed_or_disappeared() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record = quarantine_file_to(
            &first,
            evidence(&root, &[], &hash, std::slice::from_ref(&second)),
            &manifests,
        )
        .unwrap();
        std::fs::write(&second, b"changed").unwrap();
        let phrase = format!("expire {}", record.id);
        let error = expire_quarantine_from(
            &record.id,
            ExpiryRequest {
                allowed_roots: std::slice::from_ref(&root),
                reference_roots: &[],
                retention_days: Some(1),
                confirmation: &phrase,
            },
            record.quarantined_at.unwrap() + MILLIS_PER_DAY,
            &manifests,
        )
        .unwrap_err();
        assert!(error.contains("no unchanged duplicate remains"));
        assert!(Path::new(&record.quarantined_path).exists());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn interrupted_final_expiry_event_is_reported_as_expired() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record =
            quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests).unwrap();
        let manifest_path = manifests.join(format!("quarantine-{}.jsonl", record.id));
        let mut intent = record.clone();
        intent.state = "expiry-planned".to_string();
        let mut manifest = std::fs::OpenOptions::new()
            .append(true)
            .open(&manifest_path)
            .unwrap();
        write_event(&mut manifest, &intent).unwrap();
        std::fs::remove_file(&record.quarantined_path).unwrap();

        let listed = list_quarantine_from(&manifests).unwrap();
        assert_eq!(listed[0].state, "expired");
        assert!(listed[0].reason.contains("interrupted"));
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn interrupted_expiry_before_deletion_can_still_be_restored() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record =
            quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests).unwrap();
        let manifest_path = manifests.join(format!("quarantine-{}.jsonl", record.id));
        let mut intent = record.clone();
        intent.state = "expiry-planned".to_string();
        let mut manifest = std::fs::OpenOptions::new()
            .append(true)
            .open(&manifest_path)
            .unwrap();
        write_event(&mut manifest, &intent).unwrap();

        let restored =
            restore_quarantine_from(&record.id, std::slice::from_ref(&root), &[], &manifests)
                .unwrap();
        assert_eq!(restored.state, "restored");
        assert!(first.exists());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn restore_never_overwrites_a_recreated_original() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record =
            quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests).unwrap();
        std::fs::write(&first, b"new occupant").unwrap();
        let error =
            restore_quarantine_from(&record.id, std::slice::from_ref(&root), &[], &manifests)
                .unwrap_err();
        assert!(error.contains("refusing to overwrite"));
        assert!(Path::new(&record.quarantined_path).exists());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn invalid_hash_or_manifest_id_never_becomes_a_path() {
        let (root, manifests, first) = fixture();
        let error = quarantine_file_to(
            &first,
            evidence(&root, &[], "../../escape", &[]),
            &manifests,
        )
        .unwrap_err();
        assert_eq!(error, "invalid SHA-256 evidence");
        assert!(restore_quarantine_from(
            "../../escape",
            std::slice::from_ref(&root),
            &[],
            &manifests
        )
        .is_err());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn legacy_manifest_events_default_to_restore_only_evidence() {
        let raw = r#"{
            "schema":1,"kind":"quarantine","id":"legacy-1","at":1,
            "state":"quarantined","original_path":"/tmp/a/file",
            "quarantined_path":"/tmp/a/.cachereaper-quarantine/legacy-1/file",
            "scan_root":"/tmp/a","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "logical_size":12
        }"#;
        let record: QuarantineRecord = serde_json::from_str(raw).unwrap();
        assert_eq!(record.quarantined_at, None);
        assert!(record.peer_paths.is_empty());
    }

    #[test]
    fn manifest_creation_failure_aborts_before_the_move() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        std::fs::write(&manifests, b"this is deliberately not a directory").unwrap();

        let error = quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests)
            .unwrap_err();

        assert!(!error.is_empty());
        assert!(
            first.exists(),
            "audit failure must leave the source in place"
        );
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn restore_rejects_a_tampered_protected_original_path() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record =
            quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests).unwrap();
        let manifest_path = manifests.join(format!("quarantine-{}.jsonl", record.id));
        let mut forged = record.clone();
        forged.original_path = root
            .join(".ssh/authorized_keys")
            .to_string_lossy()
            .into_owned();
        let mut manifest = std::fs::OpenOptions::new()
            .append(true)
            .open(manifest_path)
            .unwrap();
        write_event(&mut manifest, &forged).unwrap();

        let error =
            restore_quarantine_from(&record.id, std::slice::from_ref(&root), &[], &manifests)
                .unwrap_err();

        assert!(error.contains("protected"));
        assert!(Path::new(&record.quarantined_path).exists());
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn an_interrupted_post_move_manifest_remains_restorable() {
        let (root, manifests, first) = fixture();
        let second = root.join("files/second.bin");
        let hash = hash_stable_file(&first, 1024 * 1024).unwrap();
        let record =
            quarantine_file_to(&first, evidence(&root, &[], &hash, &[second]), &manifests).unwrap();
        let manifest_path = manifests.join(format!("quarantine-{}.jsonl", record.id));
        let first_event = BufReader::new(std::fs::File::open(&manifest_path).unwrap())
            .lines()
            .next()
            .unwrap()
            .unwrap();
        std::fs::write(&manifest_path, format!("{first_event}\n")).unwrap();

        let listed = list_quarantine_from(&manifests).unwrap();
        assert_eq!(listed[0].state, "recovery-required");
        assert!(listed[0].reason.contains("interrupted"));

        let restored =
            restore_quarantine_from(&record.id, std::slice::from_ref(&root), &[], &manifests)
                .unwrap();
        assert_eq!(restored.state, "restored");
        assert!(first.exists());
        std::fs::remove_dir_all(root).ok();
    }
}
