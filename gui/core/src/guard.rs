//! Port of the Python safety guards (`path_is_protected`, `validate_for_delete`).
//!
//! This is the one place where the GUI duplicates logic rather than reading
//! generated data, because these are decisions, not tables. The duplication is
//! held honest by `tests/guard_vectors.json` at the repo root: the Python suite
//! and the test at the bottom of this file assert against the same cases, so a
//! guard changed in one language and not the other fails CI.
//!
//! Keep the returned reason strings byte-identical to the Python ones.

use std::path::{Component, Path, PathBuf};

/// Path components that are never candidates and never deletable.
pub const FORBIDDEN_PARTS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".ssh",
    ".gnupg",
    "Keychains",
    "CloudStorage",
    "Photos Library.photoslibrary",
    "Mobile Documents",
];

pub const CLOUD_DIR_HINTS: &[&str] = &[
    "onedrive",
    "google drive",
    "dropbox",
    "icloud",
    "creative cloud",
    "pcloud",
    "mega",
    "megasync",
    "sync.com",
    "box sync",
    "nextcloud",
];

/// True for "OneDrive - Acme" and "Google Drive", false for "megaproject".
///
/// A bare prefix test would swallow any directory that merely starts with one of
/// these words, so a hint only matches at a name boundary.
pub fn looks_like_cloud_dir(name: &str) -> bool {
    let low = name.to_lowercase();
    CLOUD_DIR_HINTS.iter().any(|hint| {
        low == *hint
            || low.starts_with(&format!("{hint} "))
            || low.starts_with(&format!("{hint}-"))
    })
}

fn components(path: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for comp in path.components() {
        match comp {
            Component::RootDir => out.push("/".to_string()),
            Component::Normal(s) => out.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => out.push("..".to_string()),
            Component::Prefix(p) => out.push(p.as_os_str().to_string_lossy().into_owned()),
        }
    }
    out
}

#[cfg(not(windows))]
pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Windows has no `$HOME`. `USERPROFILE` is the equivalent, with the drive and
/// path pair as the fallback for the shells that set those instead.
#[cfg(windows)]
pub fn home() -> PathBuf {
    fn set(name: &str) -> Option<std::ffi::OsString> {
        std::env::var_os(name).filter(|value| !value.is_empty())
    }

    if let Some(profile) = set("USERPROFILE") {
        return PathBuf::from(profile);
    }
    if let (Some(drive), Some(path)) = (set("HOMEDRIVE"), set("HOMEPATH")) {
        let mut joined = PathBuf::from(drive);
        joined.push(PathBuf::from(path));
        return joined;
    }
    PathBuf::from("C:\\")
}

/// Returns a reason string when the path must never be touched, `""` when allowed.
pub fn path_is_protected(path: &Path) -> String {
    let parts = components(path);
    for part in &parts {
        if FORBIDDEN_PARTS.contains(&part.as_str()) {
            return format!("protected component: {part}");
        }
        if looks_like_cloud_dir(part) {
            return format!("cloud-sync folder: {part}");
        }
    }
    // "at least two named components below the root". A Windows path carries a
    // drive prefix on top of that root, so it spends one more part reaching the
    // same depth — count it out, or `C:\Users` reads as deep enough to delete.
    let floor = match path.components().next() {
        Some(Component::Prefix(_)) => 4,
        _ => 3,
    };
    if parts.len() < floor {
        return "path too shallow".to_string();
    }
    if path == home() || path == Path::new("/") {
        return "refusing home/root".to_string();
    }
    String::new()
}

pub fn is_within(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

/// A path selected for deletion, carried from scan time to delete time.
#[derive(Debug, Clone)]
pub struct Target {
    pub path: PathBuf,
    pub rule_id: String,
    pub tier: String,
    /// the basename recorded at scan time; a mismatch means the tree moved under us
    pub expect_name: String,
    pub size: u64,
}

/// Re-validates immediately before deletion. Mirrors `validate_for_delete`.
pub fn validate_for_delete(target: &Target, allowed_roots: &[PathBuf]) -> String {
    let p = &target.path;
    if !p.is_absolute() {
        return "not absolute".to_string();
    }
    let reason = path_is_protected(p);
    if !reason.is_empty() {
        return reason;
    }
    let name = p
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name != target.expect_name {
        return "name changed since scan".to_string();
    }
    if !allowed_roots.iter().any(|r| is_within(p, r)) {
        return "outside allowed roots".to_string();
    }
    match std::fs::symlink_metadata(p) {
        Err(_) => "already gone".to_string(),
        Ok(md) if md.file_type().is_symlink() => "symlink".to_string(),
        Ok(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Case {
        path: String,
        reason: String,
        why: String,
    }

    #[derive(Deserialize)]
    struct Vectors {
        cases: Vec<Case>,
    }

    fn vectors() -> Vectors {
        // gui/core/src/guard.rs -> repo root is three levels up
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/guard_vectors.json")
            .canonicalize()
            .expect("guard_vectors.json must be reachable from the core crate");
        let raw = std::fs::read_to_string(path).expect("read guard_vectors.json");
        serde_json::from_str(&raw).expect("parse guard_vectors.json")
    }

    /// The parity test. If this fails, the Rust guard and the Python guard have
    /// diverged and the GUI can no longer be trusted to refuse what the CLI refuses.
    #[test]
    fn matches_shared_vectors() {
        let home = home();
        let vectors = vectors();
        assert!(vectors.cases.len() >= 35, "vector file looks truncated");

        let mut failures = Vec::new();
        for case in &vectors.cases {
            let path = PathBuf::from(case.path.replace("$HOME", &home.to_string_lossy()));
            let got = path_is_protected(&path);
            if got != case.reason {
                failures.push(format!(
                    "  {}\n    expected: {:?}\n    got:      {:?}\n    ({})",
                    case.path, case.reason, got, case.why
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "guard diverged from tests/guard_vectors.json:\n{}",
            failures.join("\n")
        );
    }

    #[test]
    fn cloud_hint_matches_only_at_a_name_boundary() {
        assert!(looks_like_cloud_dir("OneDrive"));
        assert!(looks_like_cloud_dir("OneDrive - Acme Corp"));
        assert!(looks_like_cloud_dir("Google Drive"));
        assert!(!looks_like_cloud_dir("megaproject"));
        assert!(!looks_like_cloud_dir("boxes"));
        assert!(!looks_like_cloud_dir("dropboxer"));
    }

    #[test]
    fn rejects_targets_outside_allowed_roots() {
        let home = home();
        let target = Target {
            path: PathBuf::from("/private/tmp/x/node_modules"),
            rule_id: "node-modules".into(),
            tier: "medium".into(),
            expect_name: "node_modules".into(),
            size: 0,
        };
        assert_eq!(
            validate_for_delete(&target, &[home]),
            "outside allowed roots"
        );
    }

    #[test]
    fn rejects_when_the_name_changed_since_scan() {
        let root = std::env::temp_dir();
        let target = Target {
            path: root.join("definitely-not-node-modules"),
            rule_id: "node-modules".into(),
            tier: "medium".into(),
            expect_name: "node_modules".into(),
            size: 0,
        };
        assert_eq!(
            validate_for_delete(&target, &[root]),
            "name changed since scan"
        );
    }
}
