// cachereaper desktop shell.
//
// Thin by design: the scanner, the rule engine and the guards all live in
// cachereaper-core, which is testable without the desktop toolchain. This file
// only maps them onto IPC commands and turns the arena tree into the compact
// payload the frontend draws.
//
// Deletion goes over Tauri IPC rather than a localhost HTTP endpoint, so there is
// no listening socket for another local process to POST to.
//
// The access commands are the other half of that care. Reading a gated folder is
// what raises a macOS consent dialog, so exactly one command here can do it, and
// only when the user just asked — see `cachereaper_core::access`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Mutex;

use cachereaper_core::access::{self, AccessState, SettingsPane};
use cachereaper_core::config::{self, Config};
use cachereaper_core::guard::{home, is_within, Target};
use cachereaper_core::rules::{all_findings, marker_vocabulary};
use cachereaper_core::{allowed_roots, default_threads, purge, scan_with_markers, PurgeResult, NONE};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;

/// Roots the user has actually scanned this session. Deletion is confined to
/// $HOME plus these, so a scan of an external volume can be cleaned but nothing
/// else can.
///
/// `config` is the same file on disk, held in memory so a launch can draw the
/// permission rows without touching a gated folder to find out.
struct Session {
    scanned_roots: Mutex<Vec<PathBuf>>,
    config: Mutex<Config>,
}

impl Session {
    fn load() -> Self {
        Session {
            scanned_roots: Mutex::new(Vec::new()),
            config: Mutex::new(config::load()),
        }
    }
}

/// What we last heard about a gate, without asking the operating system.
fn remembered(app: &tauri::AppHandle, id: &str) -> AccessState {
    app.try_state::<Session>()
        .map(|session| session.config.lock().unwrap().state_of(id))
        .unwrap_or_default()
}

/// Remember an answer and put it on disk.
///
/// A failed write costs the user one extra pass through the access step, which
/// is not worth failing the command the user actually asked for.
fn remember(app: &tauri::AppHandle, id: &str, state: AccessState) {
    if let Some(session) = app.try_state::<Session>() {
        let mut config = session.config.lock().unwrap();
        config.record(id, state);
        let _ = config::save(&config);
    }
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

/// One row of the access step.
#[derive(Serialize)]
struct GateStatus {
    id: String,
    label: String,
    path: String,
    state: AccessState,
}

impl GateStatus {
    fn new(gate: &access::Gate, state: AccessState) -> Self {
        GateStatus {
            id: gate.id.clone(),
            label: gate.label.clone(),
            path: gate.path.to_string_lossy().into_owned(),
            state,
        }
    }
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

/// The permission rows for a scope, asking macOS nothing the user has not
/// already answered.
///
/// A gate we hold a record for is re-probed: that read is silent once it has
/// been answered, and it catches a switch the user flipped in System Settings
/// behind our back. A gate we have never asked about is reported `Unknown` and
/// left untouched, because probing it is what raises the dialog.
///
/// Blocking pool rather than the event loop for the same reason as
/// `request_access`: our record can be stale in the one direction that costs
/// something — a gate reset outside the app is `Unknown` again, and the probe we
/// thought was silent would raise a dialog and park the caller until it is
/// answered.
#[tauri::command]
async fn access_status(app: tauri::AppHandle, root: Option<String>) -> Vec<GateStatus> {
    let root = root.map(PathBuf::from).unwrap_or_else(home);
    let gates: Vec<(access::Gate, AccessState)> = access::gates_under(&root)
        .into_iter()
        .map(|gate| {
            let was = remembered(&app, &gate.id);
            (gate, was)
        })
        .collect();

    let probed = tauri::async_runtime::spawn_blocking(move || {
        gates
            .into_iter()
            .map(|(gate, was)| {
                let now = if was == AccessState::Unknown {
                    was
                } else {
                    access::probe(&gate.path)
                };
                (gate, was, now)
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_default();

    probed
        .into_iter()
        .map(|(gate, was, now)| {
            if now != was {
                remember(&app, &gate.id, now);
            }
            GateStatus::new(&gate, now)
        })
        .collect()
}

/// The one command in the app that may put a macOS consent dialog on screen.
///
/// Only ever called from a control the user just operated. It runs on the
/// blocking pool because the read parks its thread until the dialog is answered,
/// which can be as long as the user takes to read it — on the event loop that
/// would freeze the window standing behind the dialog.
#[tauri::command]
async fn request_access(app: tauri::AppHandle, id: String) -> Result<GateStatus, String> {
    let gate = access::gate(&id).ok_or_else(|| format!("no such folder: {id}"))?;

    let path = gate.path.clone();
    let state = tauri::async_runtime::spawn_blocking(move || access::probe(&path))
        .await
        .map_err(|e| format!("permission request failed: {e}"))?;

    remember(&app, &gate.id, state);
    Ok(GateStatus::new(&gate, state))
}

/// Hand a folder back.
///
/// macOS offers no in-app route to this other than `tccutil`, and without it the
/// toggle in the access step would only move one way. The service name is looked
/// up from the gate table, so nothing the webview says reaches the command line.
#[tauri::command]
fn revoke_access(app: tauri::AppHandle, id: String) -> Result<GateStatus, String> {
    let gate = access::gate(&id).ok_or_else(|| format!("no such folder: {id}"))?;
    access::revoke(&gate, &app.config().identifier)?;

    // Back to never-asked, which is what tccutil leaves behind: the next request
    // prompts again rather than being refused.
    remember(&app, &gate.id, AccessState::Unknown);
    Ok(GateStatus::new(&gate, AccessState::Unknown))
}

/// Whether this process can read the folders that have no dialog at all.
/// Probing them never prompts, so this is safe to call on any launch.
#[tauri::command]
async fn full_disk_status() -> AccessState {
    tauri::async_runtime::spawn_blocking(access::full_disk_access)
        .await
        .unwrap_or(AccessState::Denied)
}

/// Open the System Settings pane holding a switch we cannot flip ourselves —
/// a folder the user denied, or Full Disk Access. The URL comes from the pane
/// enum, never from the caller.
#[tauri::command]
fn open_privacy_settings(pane: String) -> Result<(), String> {
    let pane =
        SettingsPane::from_id(&pane).ok_or_else(|| format!("unknown settings pane: {pane}"))?;
    access::open_pane(pane)
}

#[tauri::command]
fn config_get(app: tauri::AppHandle) -> Config {
    app.try_state::<Session>()
        .map(|session| session.config.lock().unwrap().clone())
        .unwrap_or_default()
}

/// Marks the onboarding journey finished, so later launches open straight into
/// the map.
#[tauri::command]
fn set_seen_onboarding(app: tauri::AppHandle, seen: bool) -> Result<(), String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    config.seen_onboarding = seen;
    config::save(&config).map_err(|e| e.to_string())
}

#[tauri::command]
fn reveal(app: tauri::AppHandle, path: String) -> Result<(), String> {
    // The same confinement the delete path uses: $HOME plus the roots actually
    // scanned this session. The frontend only ever hands back paths out of the
    // tree it was given, so this costs nothing in practice — it just stops this
    // command from being a wider door into the filesystem than `delete_targets`.
    let path = PathBuf::from(path);
    let extra = app
        .try_state::<Session>()
        .map(|s| s.scanned_roots.lock().unwrap().clone())
        .unwrap_or_default();
    if !allowed_roots(&extra).iter().any(|root| is_within(&path, root)) {
        return Err("outside allowed roots".to_string());
    }

    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg("-R").arg(&path).status();
    #[cfg(not(target_os = "macos"))]
    let status = std::process::Command::new("xdg-open").arg(&path).status();

    status.map(|_| ()).map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(Session::load())
        .invoke_handler(tauri::generate_handler![
            scan_home,
            pick_folder,
            delete_targets,
            reveal,
            access_status,
            request_access,
            revoke_access,
            full_disk_status,
            open_privacy_settings,
            config_get,
            set_seen_onboarding
        ])
        .run(tauri::generate_context!())
        .expect("failed to start cachereaper");
}
