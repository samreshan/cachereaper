// cachereaper desktop shell.
//
// Thin by design: the scanner, the rule engine and the guards all live in
// cachereaper-core, which is testable without the desktop toolchain. This file
// only maps them onto IPC commands and turns the arena tree into the compact
// payload the frontend draws.
//
// Deletion goes over Tauri IPC rather than a localhost HTTP endpoint, so there is
// no listening socket for another local process to POST to.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Mutex;

use cachereaper_core::guard::{home, Target};
use cachereaper_core::rules::{all_findings, marker_vocabulary};
use cachereaper_core::{allowed_roots, default_threads, purge, scan_with_markers, PurgeResult, NONE};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};

/// Roots the user has actually scanned this session. Deletion is confined to
/// $HOME plus these, so a scan of an external volume can be cleaned but nothing
/// else can.
#[derive(Default)]
struct Session {
    scanned_roots: Mutex<Vec<PathBuf>>,
}

#[derive(Serialize)]
struct NodePayload {
    n: String,
    p: i64,
    c: Vec<u32>,
    s: u64,
    o: u64,
    f: u64,
    m: i64,
    u: bool,
    t: Option<String>,
    r: Option<String>,
    g: Option<String>,
}

#[derive(Serialize)]
struct Stats {
    dirs: u64,
    files: u64,
    bytes: u64,
    unreadable: u64,
    elapsed_ms: u64,
}

#[derive(Serialize)]
struct ScanPayload {
    root_path: String,
    stats: Stats,
    findings: usize,
    nodes: Vec<NodePayload>,
}

#[derive(Serialize, Clone)]
struct Progress {
    files: u64,
    bytes: u64,
}

#[derive(Deserialize)]
struct TargetInput {
    path: String,
    rule_id: Option<String>,
    tier: Option<String>,
    expect_name: String,
    size: u64,
}

#[tauri::command]
async fn scan_home(app: tauri::AppHandle, path: Option<String>) -> Result<ScanPayload, String> {
    let root = path.map(PathBuf::from).unwrap_or_else(home);
    let handle = app.clone();

    // Throttle progress events: the walk visits ~150k directories and emitting
    // on each one would spend more time in IPC than in the filesystem.
    let last = std::sync::atomic::AtomicU64::new(0);
    let tree = scan_with_markers(&root, default_threads(), marker_vocabulary(), move |files, bytes| {
        let bucket = files / 20_000;
        if bucket > last.swap(bucket, std::sync::atomic::Ordering::Relaxed) {
            let _ = handle.emit("scan-progress", Progress { files, bytes });
        }
    })
    .map_err(|e| format!("scan failed: {e}"))?;

    if let Some(session) = app.try_state::<Session>() {
        let mut roots = session.scanned_roots.lock().unwrap();
        if !roots.contains(&tree.root_path) {
            roots.push(tree.root_path.clone());
        }
    }

    let findings = all_findings(&tree, false);
    let by_node: std::collections::HashMap<u32, &cachereaper_core::Finding> =
        findings.iter().map(|f| (f.node, f)).collect();

    let nodes = tree
        .nodes
        .iter()
        .enumerate()
        .map(|(idx, n)| {
            let hit = by_node.get(&(idx as u32));
            NodePayload {
                n: n.name.clone(),
                p: if n.parent == NONE { -1 } else { n.parent as i64 },
                c: n.children.clone(),
                s: n.total_size,
                o: n.own_size,
                f: n.total_files,
                m: n.newest_mtime,
                u: n.unreadable,
                t: hit.map(|h| h.tier.clone()),
                r: hit.map(|h| h.rule_id.clone()),
                g: hit.map(|h| h.regen.clone()),
            }
        })
        .collect();

    Ok(ScanPayload {
        root_path: tree.root_path.to_string_lossy().into_owned(),
        stats: Stats {
            dirs: tree.stats.dirs,
            files: tree.stats.files,
            bytes: tree.stats.bytes,
            unreadable: tree.stats.unreadable,
            elapsed_ms: tree.stats.elapsed_ms as u64,
        },
        findings: findings.len(),
        nodes,
    })
}

#[tauri::command]
fn delete_targets(
    app: tauri::AppHandle,
    targets: Vec<TargetInput>,
    dry_run: Option<bool>,
) -> Result<PurgeResult, String> {
    let extra = app
        .try_state::<Session>()
        .map(|s| s.scanned_roots.lock().unwrap().clone())
        .unwrap_or_default();
    let allowed = allowed_roots(&extra);

    let targets: Vec<Target> = targets
        .into_iter()
        .map(|t| Target {
            path: PathBuf::from(t.path),
            rule_id: t.rule_id.unwrap_or_default(),
            tier: t.tier.unwrap_or_default(),
            expect_name: t.expect_name,
            size: t.size,
        })
        .collect();

    // Every target is re-validated inside purge(); nothing here can bypass it.
    Ok(purge(&targets, &allowed, dry_run.unwrap_or(false)))
}

#[tauri::command]
fn reveal(path: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg("-R").arg(&path).status();
    #[cfg(not(target_os = "macos"))]
    let status = std::process::Command::new("xdg-open").arg(&path).status();

    status.map(|_| ()).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .manage(Session::default())
        .invoke_handler(tauri::generate_handler![scan_home, delete_targets, reveal])
        .run(tauri::generate_context!())
        .expect("failed to start cachereaper");
}
