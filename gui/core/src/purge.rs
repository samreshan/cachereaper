//! Deletion, behind the same guards the CLI uses.
//!
//! Every target is re-validated immediately before removal, so a selection that
//! went stale between the scan and the click is skipped rather than deleted.
//! Each removal is appended to the same `~/.cachereaper/reap-<ts>.jsonl` audit log
//! the CLI writes, so both halves share one history.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::guard::{home, validate_for_delete, Target};

#[derive(Debug, Default, serde::Serialize)]
pub struct PurgeResult {
    pub freed: u64,
    pub removed: usize,
    /// human-readable "path: why" lines for anything refused or failed
    pub skipped: Vec<String>,
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

fn log_path() -> std::io::Result<PathBuf> {
    let dir = home().join(".cachereaper");
    std::fs::create_dir_all(&dir)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(dir.join(format!("reap-{stamp}.jsonl")))
}

pub fn purge(targets: &[Target], allowed: &[PathBuf], dry_run: bool) -> PurgeResult {
    let mut result = PurgeResult::default();

    // append: two runs inside the same second must not clobber each other's log
    let mut log = if dry_run {
        None
    } else {
        match log_path().and_then(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
        }) {
            Ok(file) => Some(file),
            Err(err) => {
                // The audit trail is part of the deletion contract. Quietly
                // continuing here makes the GUI less accountable than the CLI
                // and leaves no record of what disappeared.
                result
                    .skipped
                    .push(format!("deletion aborted: could not open the audit log: {err}"));
                return result;
            }
        }
    };

    for target in targets {
        let why = validate_for_delete(target, allowed);
        if !why.is_empty() {
            if why != "already gone" {
                result.skipped.push(format!("{}: {}", target.path.display(), why));
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
                result.skipped.push(format!("{}: {err}", target.path.display()));
                continue;
            }
            Ok(()) => {
                result.freed += target.size;
                result.removed += 1;
            }
        }

        if let Some(file) = log.as_mut() {
            let entry = serde_json::json!({
                "ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0),
                "path": target.path.to_string_lossy(),
                "rule": target.rule_id,
                "tier": target.tier,
                "bytes": target.size,
                "source": "gui",
            });
            let _ = writeln!(file, "{entry}");
        }
    }

    result
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
        }
    }

    #[test]
    fn removes_the_target_and_leaves_source_alone() {
        let root = fixture();
        let t = target(root.join("proj/node_modules"), "node_modules");
        let result = purge(&[t], &[root.clone()], false);

        assert_eq!(result.removed, 1);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert!(!root.join("proj/node_modules").exists());
        assert!(root.join("proj/src/main.rs").exists(), "source must survive");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn dry_run_removes_nothing() {
        let root = fixture();
        let t = target(root.join("proj/node_modules"), "node_modules");
        let result = purge(&[t], &[root.clone()], true);

        assert_eq!(result.removed, 1);
        assert!(root.join("proj/node_modules").exists(), "dry run deleted a path");
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_a_target_outside_the_allowed_roots() {
        let root = fixture();
        let t = target(root.join("proj/node_modules"), "node_modules");
        let result = purge(&[t], &[home()], false);

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
        let result = purge(&[t], &[root.clone()], false);

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
        };
        let result = purge(&[t], &[root.clone()], false);

        assert_eq!(result.removed, 0);
        assert!(result.skipped[0].contains("protected component"));
        assert!(root.join("proj/.git/objects").exists());
        std::fs::remove_dir_all(&root).ok();
    }
}
