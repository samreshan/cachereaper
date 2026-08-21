//! Deletion, behind the same guards the CLI uses.
//!
//! Every target is re-validated immediately before removal, so a selection that
//! went stale between the scan and the click is skipped rather than deleted.
//! Each attempt is appended to a uniquely named durable receipt under
//! `~/.cachereaper`, using the same v1.6 schema as the CLI.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::guard::{home, validate_for_delete, Target};
use crate::history::{
    free_space, now_millis, signed_free_space_change, ReceiptHeader, ReceiptItem, ReceiptSummary,
    RECEIPT_SCHEMA,
};

#[derive(Debug, Default, serde::Serialize)]
pub struct PurgeResult {
    pub freed: u64,
    pub removed: usize,
    /// human-readable "path: why" lines for anything refused or failed
    pub skipped: Vec<String>,
    pub receipt_id: Option<String>,
    pub audit_error: Option<String>,
}

/// Deletion is confined to $HOME plus any roots explicitly scanned.
pub fn allowed_roots(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = vec![home()];
    for root in extra {
        if root != Path::new("/") && root.components().count() >= 2 {
            roots.push(root.clone());
        }
    }
    roots
}

static RECEIPT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn log_path(dir: &Path) -> std::io::Result<(String, PathBuf)> {
    std::fs::create_dir_all(dir)?;
    let stamp = now_millis();
    let counter = RECEIPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let id = format!("{stamp}-{}-{counter}", std::process::id());
    Ok((id.clone(), dir.join(format!("receipt-{id}.jsonl"))))
}

fn write_line<T: serde::Serialize>(file: &mut std::fs::File, value: &T) -> std::io::Result<()> {
    serde_json::to_writer(&mut *file, value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    file.write_all(b"\n")?;
    file.flush()
}

pub fn purge(targets: &[Target], allowed: &[PathBuf], dry_run: bool) -> PurgeResult {
    purge_to(targets, allowed, dry_run, &home().join(".cachereaper"))
}

fn purge_to(
    targets: &[Target],
    allowed: &[PathBuf],
    dry_run: bool,
    audit_dir: &Path,
) -> PurgeResult {
    let mut result = PurgeResult::default();
    let mut receipt_skipped = 0usize;

    let root = targets
        .first()
        .and_then(|target| {
            allowed
                .iter()
                .filter(|root| target.path.starts_with(root))
                .max_by_key(|root| root.components().count())
        })
        .cloned()
        .unwrap_or_else(home);
    let free_before = free_space(&root);

    let mut log = if dry_run {
        None
    } else {
        match log_path(audit_dir).and_then(|(id, path)| {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)?;
            let header = ReceiptHeader {
                schema: RECEIPT_SCHEMA,
                kind: "header".to_string(),
                receipt_id: id.clone(),
                started_at: now_millis(),
                root: root.to_string_lossy().into_owned(),
                estimated_bytes: targets.iter().map(|target| target.size).sum(),
                free_before,
            };
            write_line(&mut file, &header)?;
            file.sync_all()?;
            Ok((id, file))
        }) {
            Ok((id, file)) => {
                result.receipt_id = Some(id);
                Some(file)
            }
            Err(err) => {
                // The audit trail is part of the deletion contract. Quietly
                // continuing here makes the GUI less accountable than the CLI
                // and leaves no record of what disappeared.
                result.skipped.push(format!(
                    "deletion aborted: could not open the audit log: {err}"
                ));
                result.audit_error = Some(err.to_string());
                return result;
            }
        }
    };

    for target in targets {
        let why = validate_for_delete(target, allowed);
        if !why.is_empty() {
            receipt_skipped += 1;
            if why != "already gone" {
                result
                    .skipped
                    .push(format!("{}: {}", target.path.display(), why));
            }
            if let Some(file) = log.as_mut() {
                let item = receipt_item(target, "skipped", &why);
                if let Err(error) = write_line(file, &item) {
                    result.audit_error = Some(error.to_string());
                    result.skipped.push(format!("audit append failed: {error}"));
                    break;
                }
            }
            continue;
        }
        if dry_run {
            result.freed += target.size;
            result.removed += 1;
            continue;
        }

        let outcome = if target.path.is_dir() {
            std::fs::remove_dir_all(&target.path)
        } else {
            std::fs::remove_file(&target.path)
        };
        match outcome {
            Err(err) => {
                receipt_skipped += 1;
                result
                    .skipped
                    .push(format!("{}: {err}", target.path.display()));
                if let Some(file) = log.as_mut() {
                    let item = receipt_item(target, "skipped", &err.to_string());
                    if let Err(error) = write_line(file, &item) {
                        result.audit_error = Some(error.to_string());
                        result.skipped.push(format!("audit append failed: {error}"));
                        break;
                    }
                }
                continue;
            }
            Ok(()) => {
                result.freed += target.size;
                result.removed += 1;
            }
        }

        if let Some(file) = log.as_mut() {
            if let Err(error) = write_line(file, &receipt_item(target, "removed", "")) {
                result.audit_error = Some(error.to_string());
                result.skipped.push(format!(
                    "audit append failed after deletion; stopped: {error}"
                ));
                break;
            }
        }
    }

    if let Some(file) = log.as_mut() {
        let free_after = free_space(&root);
        let summary = ReceiptSummary {
            schema: RECEIPT_SCHEMA,
            kind: "summary".to_string(),
            finished_at: now_millis(),
            removed_count: result.removed,
            skipped_count: receipt_skipped,
            estimated_removed_bytes: result.freed,
            free_after,
            signed_free_space_change: signed_free_space_change(free_before, free_after),
            complete: result.audit_error.is_none(),
        };
        if let Err(error) = write_line(file, &summary).and_then(|_| file.sync_all()) {
            result.audit_error = Some(error.to_string());
            result
                .skipped
                .push(format!("could not finish receipt: {error}"));
        }
    }

    result
}

fn receipt_item(target: &Target, status: &str, reason: &str) -> ReceiptItem {
    ReceiptItem {
        schema: RECEIPT_SCHEMA,
        kind: "item".to_string(),
        path: target.path.to_string_lossy().into_owned(),
        rule: target.rule_id.clone(),
        tier: target.tier.clone(),
        label: target.label.clone(),
        regen: target.regen.clone(),
        estimated_bytes: target.size,
        status: status.to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cachereaper-purge-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(dir.join("proj/node_modules/pkg")).unwrap();
        std::fs::create_dir_all(dir.join("proj/src")).unwrap();
        std::fs::write(dir.join("proj/node_modules/pkg/blob"), vec![0u8; 4096]).unwrap();
        std::fs::write(dir.join("proj/src/main.rs"), b"fn main() {}").unwrap();
        dir
    }

    fn target(path: PathBuf, name: &str) -> Target {
        Target {
            path,
            rule_id: "node-modules".into(),
            tier: "medium".into(),
            expect_name: name.into(),
            size: 4096,
            label: "Installed packages".into(),
            regen: "npm install".into(),
        }
    }

    #[test]
    fn removes_the_target_and_leaves_source_alone() {
        let root = fixture();
        let t = target(root.join("proj/node_modules"), "node_modules");
        let result = purge_to(&[t], &[root.clone()], false, &root.join(".audit"));

        assert_eq!(result.removed, 1);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert!(!root.join("proj/node_modules").exists());
        assert!(
            root.join("proj/src/main.rs").exists(),
            "source must survive"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dry_run_removes_nothing() {
        let root = fixture();
        let t = target(root.join("proj/node_modules"), "node_modules");
        let result = purge_to(&[t], &[root.clone()], true, &root.join(".audit"));

        assert_eq!(result.removed, 1);
        assert!(
            root.join("proj/node_modules").exists(),
            "dry run deleted a path"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn receipt_failure_aborts_before_deletion() {
        let root = fixture();
        let victim = root.join("proj/node_modules");
        let t = target(victim.clone(), "node_modules");
        let impossible = root.join("audit-is-a-file");
        std::fs::write(&impossible, b"not a directory").unwrap();
        let result = purge_to(&[t], std::slice::from_ref(&root), false, &impossible);

        assert_eq!(result.removed, 0);
        assert!(result.audit_error.is_some());
        assert!(victim.exists(), "deletion began without a durable header");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_a_target_outside_the_allowed_roots() {
        let root = fixture();
        let t = target(root.join("proj/node_modules"), "node_modules");
        let result = purge_to(&[t], &[home()], false, &root.join(".audit"));

        assert_eq!(result.removed, 0);
        assert_eq!(result.skipped.len(), 1);
        assert!(result.skipped[0].contains("outside allowed roots"));
        assert!(root.join("proj/node_modules").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_when_the_name_changed_since_the_scan() {
        let root = fixture();
        // the selection said node_modules; the path now points at source
        let t = target(root.join("proj/src"), "node_modules");
        let result = purge_to(&[t], &[root.clone()], false, &root.join(".audit"));

        assert_eq!(result.removed, 0);
        assert!(result.skipped[0].contains("name changed since scan"));
        assert!(root.join("proj/src/main.rs").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_protected_paths_even_when_asked_directly() {
        let root = fixture();
        std::fs::create_dir_all(root.join("proj/.git/objects")).unwrap();
        let t = Target {
            path: root.join("proj/.git"),
            rule_id: "none".into(),
            tier: "high".into(),
            expect_name: ".git".into(),
            size: 0,
            label: String::new(),
            regen: String::new(),
        };
        let result = purge_to(&[t], &[root.clone()], false, &root.join(".audit"));

        assert_eq!(result.removed, 0);
        assert!(result.skipped[0].contains("protected component"));
        assert!(root.join("proj/.git/objects").exists());
        std::fs::remove_dir_all(&root).ok();
    }
}
