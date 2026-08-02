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
use tauri_plugin_dialog::DialogExt;

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

/// Open the native folder chooser and return what the user picked.
///
/// The dialog is driven from Rust rather than from the webview on purpose: the
/// frontend never gets the `dialog:allow-open` permission, so the only file
/// dialog that can ever appear is this one, asking for exactly one directory.
/// `None` means the user cancelled, which is not an error.
///
/// Callback form, not `blocking_pick_folder`. The blocking variant parks the
/// calling thread until the panel closes, and on macOS the panel itself has to
/// be driven from the main thread — so calling it from inside the async runtime
/// hangs with no dialog and no error. The callback hands the result back over a
/// channel instead, leaving both the event loop and this task free.
/// The callback form, and deliberately *not* wrapped in `run_on_main_thread`:
/// the plugin already hands the panel to the main thread itself, and asking for
/// it again from a closure that is already running there deadlocks — the panel
/// never draws and this command never resolves. `blocking_pick_folder` is wrong
/// for the same underlying reason. Test any change to this inside the built
/// `.app`; a loose binary has no `NSBundle`, and AppKit answers panels
/// differently without one.
#[tauri::command]
async fn pick_folder(app: tauri::AppHandle) -> Option<String> {
    let (tx, mut rx) = tauri::async_runtime::channel(1);

    app.dialog()
        .file()
        .set_title("Choose a folder to scan")
        .pick_folder(move |picked| {
            // Capacity 1 and exactly one send, so this never blocks the thread
            // the panel closed on.
            let _ = tx.blocking_send(picked);
        });

    rx.recv()
        .await
        .flatten()
        .and_then(|p| p.into_path().ok())
        .map(|p| p.to_string_lossy().into_owned())
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
        .plugin(tauri_plugin_dialog::init())
        .manage(Session::default())
        .invoke_handler(tauri::generate_handler![
            scan_home,
            pick_folder,
            delete_targets,
            reveal
        ])
        .run(tauri::generate_context!())
        .expect("failed to start cachereaper");
}
