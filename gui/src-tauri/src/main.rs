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
//
// Updating is held to the same rule. The webview is never given the updater's
// own permissions — `capabilities/default.json` grants `core:default` and
// nothing else — so it cannot reach an endpoint, hand back a manifest or start a
// download. It can only ask the commands below, and none of them takes a URL, a
// version or a path: where to look is compiled in from tauri.conf.json, and what
// arrives is refused unless it is signed by the key whose public half is
// compiled in beside it.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod trash;
mod watcher;

use std::path::PathBuf;
use std::sync::Mutex;

use cachereaper_core::access::{self, AccessState, SettingsPane};
use cachereaper_core::config::{self, Config, ScanProfile};
use cachereaper_core::guard::{home, is_within, Target};
use cachereaper_core::rules::{all_findings_excluding, marker_vocabulary};
use cachereaper_core::{
    action_history, allowed_roots, analyze_ownership, analyze_projects, analyze_similar_media,
    analyze_with_cache, append_advanced_insights, build_insights, clear_history, compile_filter,
    delete_receipt, expire_quarantine, filter_insights, forecast_snapshots, generate_cleanup_plan,
    list_quarantine, list_snapshots, persist_snapshot, purge, quarantine_file, read_history,
    restore_quarantine, scan_with_options_progress, trash_duplicate_with, ActionHistoryEntry,
    AnalysisSummary, ApplicationCatalog, CancellationToken, CleanupPlan, DuplicateGroup,
    ExpiryRequest, FilterAst, GrowthReport, HashCache, Insight, IntelligenceSummary, LocalAiStatus,
    MediaAnalysis, OffloadStatus, PlanPolicy, PurgeResult, QuarantineEvidence, QuarantineRecord,
    Receipt, ScanError, ScanMode, ScanOptions, ScanSnapshot, TrashRecord, NONE, PROJECT_MARKERS,
    SCAN_SCHEMA, VAULT_NAME,
};
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_updater::{Update, UpdaterExt};

/// Roots the user has actually scanned this session. Deletion is confined to
/// $HOME plus these, so a scan of an external volume can be cleaned but nothing
/// else can.
///
/// `config` is the same file on disk, held in memory so a launch can draw the
/// permission rows without touching a gated folder to find out.
///
/// `pending_update` holds whatever the last check turned up. Installing works
/// from that value rather than fetching the manifest a second time, so what gets
/// written over the app is the exact build whose version the user was shown and
/// agreed to — not whatever the feed happens to say a moment later.
struct Session {
    scanned_roots: Mutex<Vec<PathBuf>>,
    config: Mutex<Config>,
    pending_update: Mutex<Option<Update>>,
    active_scan: Mutex<Option<ActiveScan>>,
    duplicate_evidence: Mutex<Option<DuplicateEvidenceSnapshot>>,
    insight_snapshot: Mutex<Option<InsightSnapshot>>,
    change_watcher: Mutex<Option<watcher::ChangeWatcher>>,
}

struct ActiveScan {
    id: String,
    cancellation: CancellationToken,
}

#[derive(Clone)]
struct DuplicateEvidenceSnapshot {
    scan_id: String,
    root: PathBuf,
    groups: Vec<DuplicateGroup>,
}

#[derive(Clone)]
struct InsightSnapshot {
    scan_id: String,
    insights: Vec<Insight>,
}

impl Session {
    fn load() -> Self {
        Session {
            scanned_roots: Mutex::new(Vec::new()),
            config: Mutex::new(config::load()),
            pending_update: Mutex::new(None),
            active_scan: Mutex::new(None),
            duplicate_evidence: Mutex::new(None),
            insight_snapshot: Mutex::new(None),
            change_watcher: Mutex::new(None),
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
    x: String,
}

#[derive(Serialize)]
struct Stats {
    dirs: u64,
    files: u64,
    bytes: u64,
    unreadable: u64,
    elapsed_ms: u64,
    reclaimable_bytes: u64,
    allocated_reference_bytes: u64,
    logical_bytes: u64,
    shared_or_snapshot_bytes: u64,
    excluded: u64,
    unreadable_paths: Vec<String>,
    excluded_paths: Vec<String>,
    volume_capacity: Option<u64>,
    volume_free: Option<u64>,
}

#[derive(Serialize)]
struct ScanPayload {
    schema: u16,
    scan_id: String,
    mode: ScanMode,
    root_path: String,
    home_path: String,
    stats: Stats,
    findings: Vec<FindingPayload>,
    analysis: AnalysisSummary,
    media: MediaAnalysis,
    intelligence: IntelligenceSummary,
    offload: OffloadStatus,
    insights: Vec<Insight>,
    growth: Option<GrowthReport>,
    snapshot_saved: bool,
    change_monitoring: bool,
    nodes: Vec<NodePayload>,
}

#[derive(Serialize)]
struct FindingPayload {
    node_id: u32,
    rule_id: String,
    tier: String,
    label: String,
    regen: String,
    warning: String,
    source: String,
    reclaimable_size: u64,
    path: String,
}

#[derive(Serialize, Clone)]
struct Progress {
    scan_id: String,
    phase: String,
    files: u64,
    reclaimable_bytes: u64,
    elapsed_ms: u64,
}

#[derive(Clone, Serialize)]
struct ChangeNotice {
    root: String,
    reason: String,
}

#[derive(Deserialize)]
struct ScanRequest {
    #[serde(default)]
    schema: Option<u16>,
    scan_id: String,
    #[serde(default)]
    mode: ScanMode,
    root: Option<String>,
    profile_id: Option<String>,
    #[serde(default)]
    excluded_paths: Vec<String>,
    #[serde(default)]
    excluded_rules: Vec<String>,
}

#[derive(Deserialize)]
struct TargetInput {
    path: String,
    rule_id: Option<String>,
    tier: Option<String>,
    expect_name: String,
    size: u64,
    #[serde(default)]
    label: String,
    #[serde(default)]
    regen: String,
}

#[derive(Deserialize)]
struct QuarantineInput {
    scan_id: String,
    hash: String,
    path: String,
}

#[derive(Deserialize)]
struct InsightQueryInput {
    scan_id: String,
    query: String,
}

#[derive(Serialize)]
struct InsightQueryResult {
    ast: FilterAst,
    matches: Vec<Insight>,
}

#[derive(Deserialize)]
struct CleanupPlanInput {
    scan_id: String,
    target_bytes: u64,
    policy: PlanPolicy,
    query: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
enum TrashActionResult {
    Trash {
        record: TrashRecord,
    },
    Quarantine {
        record: QuarantineRecord,
        trash_error: String,
    },
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
async fn scan_request(app: tauri::AppHandle, request: ScanRequest) -> Result<ScanPayload, String> {
    if request.scan_id.trim().is_empty() {
        return Err("scan_id is required".to_string());
    }
    if request.root.is_some() && request.profile_id.is_some() {
        return Err("provide either root or profile_id, never both".to_string());
    }
    if request.schema.is_some_and(|schema| schema != SCAN_SCHEMA) {
        return Err(format!(
            "unsupported scan schema {}; this build supports {SCAN_SCHEMA}",
            request.schema.unwrap()
        ));
    }
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let config = session.config.lock().unwrap().clone();
    let (root, mut excluded_paths, mut excluded_rules) =
        if let Some(profile_id) = &request.profile_id {
            let profile = config
                .profile(profile_id)
                .ok_or_else(|| "profile not found".to_string())?;
            (
                profile.root.clone(),
                profile.excluded_paths.clone(),
                profile.excluded_rules.clone(),
            )
        } else {
            (
                request
                    .root
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(home),
                Vec::new(),
                Vec::new(),
            )
        };
    if !root.is_absolute() {
        return Err("scan root must be absolute".to_string());
    }
    let root = config::normalize_absolute(&root)?;
    if root
        .components()
        .any(|component| component.as_os_str() == VAULT_NAME)
    {
        return Err("the quarantine vault cannot be used as a scan root".to_string());
    }
    excluded_paths.extend(config.global_excluded_paths);
    excluded_rules.extend(config.global_excluded_rules);
    for path in request.excluded_paths {
        excluded_paths.push(config::normalize_absolute(std::path::Path::new(&path))?);
    }
    excluded_paths = excluded_paths
        .into_iter()
        .map(|path| config::normalize_absolute(&path))
        .collect::<Result<Vec<_>, _>>()?;
    // The vault is an explicit protected boundary. It is visible in scan health
    // but is never opened or allowed to become another cleanup candidate.
    excluded_paths.push(root.join(VAULT_NAME));
    excluded_rules.extend(request.excluded_rules);

    let cancellation = CancellationToken::new();
    if let Some(profile_id) = &request.profile_id {
        let mut saved = session.config.lock().unwrap();
        saved.last_profile_id = Some(profile_id.clone());
        config::save(&saved).map_err(|error| error.to_string())?;
    }
    {
        let mut active = session.active_scan.lock().unwrap();
        if active.is_some() {
            return Err("a scan is already active".to_string());
        }
        *active = Some(ActiveScan {
            id: request.scan_id.clone(),
            cancellation: cancellation.clone(),
        });
    }
    let security_skips: Vec<PathBuf> = access::gates()
        .into_iter()
        .filter(|gate| remembered(&app, &gate.id) != AccessState::Granted)
        .map(|gate| gate.path)
        .collect();
    let scan_id = request.scan_id.clone();
    let scan_mode = request.mode;
    let progress_id = scan_id.clone();
    let snapshot_scan_id = scan_id.clone();
    let handle = app.clone();
    let scan_root = root.clone();
    let analysis_cancellation = cancellation.clone();
    let joined = tauri::async_runtime::spawn_blocking(move || {
        let last = std::sync::atomic::AtomicU64::new(0);
        let walking_handle = handle.clone();
        let walking_id = progress_id.clone();
        let mut markers = marker_vocabulary();
        markers.extend(PROJECT_MARKERS.iter().map(|marker| marker.to_string()));
        let options = ScanOptions {
            markers,
            security_skips,
            excluded_paths,
            mode: scan_mode,
            cancellation,
            ..ScanOptions::default()
        };
        let tree =
            scan_with_options_progress(&scan_root, options, move |files, bytes, elapsed| {
                let bucket = files / 20_000;
                if bucket > last.swap(bucket, std::sync::atomic::Ordering::Relaxed) {
                    let _ = walking_handle.emit(
                        "scan-progress",
                        Progress {
                            scan_id: walking_id.clone(),
                            phase: "walking".to_string(),
                            files,
                            reclaimable_bytes: bytes,
                            elapsed_ms: elapsed as u64,
                        },
                    );
                }
            })?;
        let _ = handle.emit(
            "scan-progress",
            Progress {
                scan_id: progress_id,
                phase: if scan_mode.reads_file_contents() {
                    "hashing".to_string()
                } else {
                    "summarizing".to_string()
                },
                files: tree.stats.files,
                reclaimable_bytes: tree.stats.reclaimable_bytes,
                elapsed_ms: tree.stats.elapsed_ms as u64,
            },
        );
        let mut hash_cache = HashCache::load();
        let index_warning = hash_cache.warning().map(str::to_string);
        let mut analysis =
            analyze_with_cache(&tree, scan_mode, &analysis_cancellation, &mut hash_cache);
        if scan_mode == ScanMode::All {
            let _ = handle.emit(
                "scan-progress",
                Progress {
                    scan_id: snapshot_scan_id.clone(),
                    phase: "similar-media".to_string(),
                    files: tree.stats.files,
                    reclaimable_bytes: tree.stats.reclaimable_bytes,
                    elapsed_ms: tree.stats.elapsed_ms as u64,
                },
            );
        }
        let media = analyze_similar_media(&tree, scan_mode, &analysis_cancellation);
        if analysis_cancellation.is_cancelled() {
            Err(ScanError::Cancelled)
        } else {
            if let Some(warning) = index_warning {
                analysis.warnings.push(warning);
            }
            if scan_mode == ScanMode::All {
                if let Err(error) = hash_cache.save() {
                    analysis
                        .warnings
                        .push(format!("hash index could not be saved: {error}"));
                }
            }
            let snapshot = ScanSnapshot::from_scan(&snapshot_scan_id, &tree, &analysis);
            let (growth, snapshot_saved) = match persist_snapshot(&snapshot) {
                Ok(growth) => (growth, true),
                Err(error) => {
                    analysis
                        .warnings
                        .push(format!("scan snapshot could not be saved: {error}"));
                    (None, false)
                }
            };
            Ok((tree, analysis, media, growth, snapshot_saved))
        }
    })
    .await;
    let result = match joined {
        Ok(result) => result,
        Err(error) => {
            let mut active = session.active_scan.lock().unwrap();
            if active.as_ref().is_some_and(|active| active.id == scan_id) {
                *active = None;
            }
            return Err(format!("scan worker failed: {error}"));
        }
    };

    let cancelled_after_join = {
        let mut active = session.active_scan.lock().unwrap();
        let cancelled = active
            .as_ref()
            .is_some_and(|active| active.id == scan_id && active.cancellation.is_cancelled());
        if active.as_ref().is_some_and(|active| active.id == scan_id) {
            *active = None;
        }
        cancelled
    };
    if cancelled_after_join {
        return Err("cancelled".to_string());
    }
    let (tree, mut analysis, media, growth, snapshot_saved) = match result {
        Ok(result) => result,
        Err(ScanError::Cancelled) => return Err("cancelled".to_string()),
        Err(error) => return Err(format!("scan failed: {error}")),
    };

    {
        let mut roots = session.scanned_roots.lock().unwrap();
        if !roots.contains(&tree.root_path) {
            roots.push(tree.root_path.clone());
        }
    }

    let watched_root = tree.root_path.clone();
    let notice_root = watched_root.to_string_lossy().into_owned();
    let watcher_app = app.clone();
    let watcher_result = watcher::ChangeWatcher::start(&watched_root, move || {
        if let Some(session) = watcher_app.try_state::<Session>() {
            *session.duplicate_evidence.lock().unwrap() = None;
            *session.insight_snapshot.lock().unwrap() = None;
        }
        let _ = watcher_app.emit(
            "scan-root-changed",
            ChangeNotice {
                root: notice_root.clone(),
                reason: "filesystem-change".to_string(),
            },
        );
    });
    let change_monitoring = watcher_result.is_ok();
    match watcher_result {
        Ok(watcher) => *session.change_watcher.lock().unwrap() = Some(watcher),
        Err(error) => {
            *session.change_watcher.lock().unwrap() = None;
            analysis
                .warnings
                .push(format!("live refresh unavailable: {error}"));
        }
    }
    // Publish action evidence only after replacing the previous watcher. That
    // prevents a late event from the old snapshot invalidating the new one.
    *session.duplicate_evidence.lock().unwrap() = Some(DuplicateEvidenceSnapshot {
        scan_id: scan_id.clone(),
        root: tree.root_path.clone(),
        groups: analysis.duplicate_groups.clone(),
    });
    let excluded_rules: std::collections::HashSet<String> = excluded_rules.into_iter().collect();
    let findings = all_findings_excluding(&tree, false, &excluded_rules);
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
                p: if n.parent == NONE {
                    -1
                } else {
                    n.parent as i64
                },
                c: n.children.clone(),
                s: n.total_size,
                o: n.own_size,
                f: n.total_files,
                m: n.newest_mtime,
                u: n.unreadable,
                t: hit.map(|h| h.tier.clone()),
                r: hit.map(|h| h.rule_id.clone()),
                g: hit.map(|h| h.regen.clone()),
                x: match n.state {
                    cachereaper_core::NodeState::Readable => "readable",
                    cachereaper_core::NodeState::Unreadable => "unreadable",
                    cachereaper_core::NodeState::Excluded => "excluded",
                }
                .to_string(),
            }
        })
        .collect();

    let finding_payload = findings
        .iter()
        .map(|finding| FindingPayload {
            node_id: finding.node,
            rule_id: finding.rule_id.clone(),
            tier: finding.tier.clone(),
            label: finding.label.clone(),
            regen: finding.regen.clone(),
            warning: finding.warn.clone(),
            source: finding.source.to_string(),
            reclaimable_size: finding.size,
            path: finding.path.to_string_lossy().into_owned(),
        })
        .collect();
    let (volume_capacity, volume_free) = volume_stats(&tree.root_path)
        .map(|(capacity, free)| (Some(capacity), Some(free)))
        .unwrap_or((None, None));
    let catalog = installed_application_catalog();
    let ownership = if scan_mode == ScanMode::Cache {
        Vec::new()
    } else {
        analyze_ownership(&tree, &catalog)
    };
    let projects = analyze_projects(&tree, &findings);
    let forecast = match list_snapshots() {
        Ok(snapshots) => forecast_snapshots(
            &snapshots,
            &tree.root_path.to_string_lossy(),
            scan_mode,
            volume_capacity,
            volume_free,
        ),
        Err(error) => {
            analysis
                .warnings
                .push(format!("forecast history could not be read: {error}"));
            None
        }
    };
    let intelligence = IntelligenceSummary {
        schema: cachereaper_core::INTELLIGENCE_SCHEMA,
        ownership,
        projects,
        forecast,
    };
    let mut insights = build_insights(&findings, &analysis);
    append_advanced_insights(&mut insights, &media, &intelligence);
    *session.insight_snapshot.lock().unwrap() = Some(InsightSnapshot {
        scan_id: scan_id.clone(),
        insights: insights.clone(),
    });
    if let Some(watcher) = session.change_watcher.lock().unwrap().as_ref() {
        watcher.arm();
    }

    Ok(ScanPayload {
        schema: SCAN_SCHEMA,
        scan_id,
        mode: scan_mode,
        root_path: tree.root_path.to_string_lossy().into_owned(),
        home_path: home().to_string_lossy().into_owned(),
        stats: Stats {
            dirs: tree.stats.dirs,
            files: tree.stats.files,
            bytes: tree.stats.bytes,
            unreadable: tree.stats.unreadable,
            elapsed_ms: tree.stats.elapsed_ms as u64,
            reclaimable_bytes: tree.stats.reclaimable_bytes,
            allocated_reference_bytes: tree.stats.allocated_reference_bytes,
            logical_bytes: tree.stats.logical_bytes,
            shared_or_snapshot_bytes: tree.stats.shared_or_snapshot_bytes,
            excluded: tree.stats.excluded,
            unreadable_paths: tree
                .stats
                .unreadable_paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            excluded_paths: tree
                .stats
                .excluded_paths
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            volume_capacity,
            volume_free,
        },
        findings: finding_payload,
        analysis,
        media,
        intelligence,
        offload: OffloadStatus::current(),
        insights,
        growth,
        snapshot_saved,
        change_monitoring,
        nodes,
    })
}

#[tauri::command]
fn cancel_scan(app: tauri::AppHandle, scan_id: String) -> bool {
    app.try_state::<Session>()
        .and_then(|session| {
            let active = session.active_scan.lock().unwrap();
            active
                .as_ref()
                .filter(|active| active.id == scan_id)
                .map(|active| {
                    active.cancellation.cancel();
                    true
                })
        })
        .unwrap_or(false)
}

/// Compile a query into the closed filter AST and apply it to the current
/// immutable evidence snapshot. Query text is never executed or opened.
#[tauri::command]
fn insight_query(
    app: tauri::AppHandle,
    input: InsightQueryInput,
) -> Result<InsightQueryResult, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let snapshot = session
        .insight_snapshot
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "insight evidence is no longer current; scan again".to_string())?;
    if snapshot.scan_id != input.scan_id {
        return Err("insight evidence is stale; scan again".to_string());
    }
    let ast = compile_filter(&input.query).map_err(|error| error.to_string())?;
    let matches = filter_insights(
        &snapshot.insights,
        &ast,
        cachereaper_core::insights::unix_seconds(),
    )
    .into_iter()
    .cloned()
    .collect();
    Ok(InsightQueryResult { ast, matches })
}

/// Generate a deterministic review plan from the current typed evidence. The
/// optional query is recompiled here, so the webview cannot submit its own AST
/// or add paths/actions.
#[tauri::command]
fn cleanup_plan(app: tauri::AppHandle, input: CleanupPlanInput) -> Result<CleanupPlan, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let snapshot = session
        .insight_snapshot
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "insight evidence is no longer current; scan again".to_string())?;
    if snapshot.scan_id != input.scan_id {
        return Err("insight evidence is stale; scan again".to_string());
    }
    let selected: Vec<Insight> =
        if let Some(query) = input.query.filter(|query| !query.trim().is_empty()) {
            let ast = compile_filter(&query).map_err(|error| error.to_string())?;
            filter_insights(
                &snapshot.insights,
                &ast,
                cachereaper_core::insights::unix_seconds(),
            )
            .into_iter()
            .cloned()
            .collect()
        } else {
            snapshot.insights.clone()
        };
    let protected_roots = session.config.lock().unwrap().reference_roots.clone();
    Ok(generate_cleanup_plan(
        &snapshot.scan_id,
        input.target_bytes,
        input.policy,
        &selected,
        &protected_roots,
    ))
}

#[tauri::command]
fn local_ai_status() -> LocalAiStatus {
    LocalAiStatus::current()
}

#[tauri::command]
fn offload_status() -> OffloadStatus {
    OffloadStatus::current()
}

fn installed_application_catalog() -> ApplicationCatalog {
    let mut identifiers = Vec::new();
    #[cfg(target_os = "macos")]
    {
        for root in [
            PathBuf::from("/Applications"),
            PathBuf::from("/System/Applications"),
            home().join("Applications"),
        ] {
            collect_application_names(&root, Some("app"), &mut identifiers);
        }
    }
    #[cfg(target_os = "windows")]
    {
        for variable in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Some(root) = std::env::var_os(variable) {
                collect_application_names(std::path::Path::new(&root), None, &mut identifiers);
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        for root in [
            PathBuf::from("/usr/share/applications"),
            PathBuf::from("/usr/local/share/applications"),
            home().join(".local/share/applications"),
        ] {
            collect_application_names(&root, Some("desktop"), &mut identifiers);
        }
    }
    // Application directories, portable apps, and package-manager installs
    // can always live elsewhere, so absence remains "possible leftover".
    ApplicationCatalog::from_identifiers(identifiers, false)
}

fn collect_application_names(
    root: &std::path::Path,
    suffix: Option<&str>,
    output: &mut Vec<String>,
) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten().take(10_000) {
        let path = entry.path();
        if suffix.is_some_and(|suffix| {
            !path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case(suffix))
        }) {
            continue;
        }
        if let Some(name) = path.file_stem().and_then(|name| name.to_str()) {
            output.push(name.to_string());
        }
    }
}

fn volume_stats(path: &std::path::Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        let output = std::process::Command::new("df")
            .args(["-Pk"])
            .arg(path)
            .output()
            .ok()?;
        let text = String::from_utf8(output.stdout).ok()?;
        let fields: Vec<_> = text.lines().last()?.split_whitespace().collect();
        Some((
            fields.get(1)?.parse::<u64>().ok()?.saturating_mul(1024),
            fields.get(3)?.parse::<u64>().ok()?.saturating_mul(1024),
        ))
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        unsafe extern "system" {
            fn GetDiskFreeSpaceExW(
                directory_name: *const u16,
                free_bytes_available: *mut u64,
                total_bytes: *mut u64,
                total_free_bytes: *mut u64,
            ) -> i32;
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut available = 0;
        let mut capacity = 0;
        let mut total_free = 0;
        // SAFETY: the input is NUL terminated and all output pointers are valid.
        if unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut available,
                &mut capacity,
                &mut total_free,
            )
        } == 0
        {
            None
        } else {
            Some((capacity, available))
        }
    }
}

#[tauri::command]
fn delete_targets(
    app: tauri::AppHandle,
    targets: Vec<TargetInput>,
    dry_run: Option<bool>,
) -> Result<PurgeResult, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session; refusing deletion".to_string())?;
    let extra = session.scanned_roots.lock().unwrap().clone();
    let allowed = allowed_roots(&extra);
    let reference_roots = session.config.lock().unwrap().reference_roots.clone();

    let targets: Vec<Target> = targets
        .into_iter()
        .map(|t| Target {
            path: PathBuf::from(t.path),
            rule_id: t.rule_id.unwrap_or_default(),
            tier: t.tier.unwrap_or_default(),
            expect_name: t.expect_name,
            size: t.size,
            label: t.label,
            regen: t.regen,
        })
        .collect();

    // Every target is re-validated inside purge(); nothing here can bypass it.
    let result = purge(
        &targets,
        &allowed,
        &reference_roots,
        dry_run.unwrap_or(false),
    );
    if result.removed > 0 && !dry_run.unwrap_or(false) {
        *session.duplicate_evidence.lock().unwrap() = None;
        *session.insight_snapshot.lock().unwrap() = None;
    }
    Ok(result)
}

/// Move one exact-duplicate member into a recoverable same-volume vault.
/// Authorization comes exclusively from the newest completed All Files scan;
/// the webview cannot supply peers, sizes, or a scan root of its own choosing.
#[tauri::command]
fn quarantine_duplicate(
    app: tauri::AppHandle,
    input: QuarantineInput,
) -> Result<QuarantineRecord, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let evidence = session
        .duplicate_evidence
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "deep-scan evidence is no longer current; scan again".to_string())?;
    if evidence.scan_id != input.scan_id {
        return Err("deep-scan evidence is stale; scan again".to_string());
    }
    let group = evidence
        .groups
        .iter()
        .find(|group| group.hash == input.hash)
        .ok_or_else(|| "duplicate group is not part of the current scan".to_string())?;
    let target = group
        .files
        .iter()
        .find(|file| file.path == input.path)
        .ok_or_else(|| "file is not part of the current duplicate group".to_string())?;
    let peers: Vec<PathBuf> = group
        .files
        .iter()
        .filter(|file| file.path != input.path)
        .map(|file| PathBuf::from(&file.path))
        .collect();
    let extra = session.scanned_roots.lock().unwrap().clone();
    let allowed = allowed_roots(&extra);
    let reference_roots = session.config.lock().unwrap().reference_roots.clone();
    let result = quarantine_file(
        std::path::Path::new(&target.path),
        QuarantineEvidence {
            scan_root: &evidence.root,
            allowed_roots: &allowed,
            reference_roots: &reference_roots,
            expected_hash: &group.hash,
            expected_size: target.logical_size,
            peers: &peers,
        },
    )?;
    // Any filesystem mutation invalidates every path/hash assertion in the
    // snapshot. The UI rescans before another quarantine can be requested.
    *session.duplicate_evidence.lock().unwrap() = None;
    *session.insight_snapshot.lock().unwrap() = None;
    Ok(result)
}

/// Move one evidence-bound exact duplicate through the operating system's
/// native Trash API. If that API is unavailable, the caller may explicitly
/// request the same-volume CacheReaper quarantine as a recoverable fallback.
#[tauri::command]
fn trash_duplicate(
    app: tauri::AppHandle,
    input: QuarantineInput,
    fallback_to_quarantine: Option<bool>,
) -> Result<TrashActionResult, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let snapshot = session
        .duplicate_evidence
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "deep-scan evidence is no longer current; scan again".to_string())?;
    if snapshot.scan_id != input.scan_id {
        return Err("deep-scan evidence is stale; scan again".to_string());
    }
    let group = snapshot
        .groups
        .iter()
        .find(|group| group.hash == input.hash)
        .ok_or_else(|| "duplicate group is not part of the current scan".to_string())?;
    let target = group
        .files
        .iter()
        .find(|file| file.path == input.path)
        .ok_or_else(|| "file is not part of the current duplicate group".to_string())?;
    let peers: Vec<PathBuf> = group
        .files
        .iter()
        .filter(|file| file.path != input.path)
        .map(|file| PathBuf::from(&file.path))
        .collect();
    let extra = session.scanned_roots.lock().unwrap().clone();
    let allowed = allowed_roots(&extra);
    let reference_roots = session.config.lock().unwrap().reference_roots.clone();
    let evidence = QuarantineEvidence {
        scan_root: &snapshot.root,
        allowed_roots: &allowed,
        reference_roots: &reference_roots,
        expected_hash: &group.hash,
        expected_size: target.logical_size,
        peers: &peers,
    };
    let result = match trash_duplicate_with(
        std::path::Path::new(&target.path),
        evidence,
        trash::move_to_trash,
    ) {
        Ok(record) => TrashActionResult::Trash { record },
        Err(trash_error) if fallback_to_quarantine.unwrap_or(false) => {
            let record = quarantine_file(std::path::Path::new(&target.path), evidence)
                .map_err(|fallback_error| {
                    format!("Trash failed ({trash_error}); quarantine fallback also failed: {fallback_error}")
                })?;
            TrashActionResult::Quarantine {
                record,
                trash_error,
            }
        }
        Err(error) => return Err(error),
    };
    *session.duplicate_evidence.lock().unwrap() = None;
    *session.insight_snapshot.lock().unwrap() = None;
    Ok(result)
}

#[tauri::command]
fn quarantine_history() -> Result<Vec<QuarantineRecord>, String> {
    list_quarantine()
}

#[tauri::command]
fn quarantine_restore(app: tauri::AppHandle, id: String) -> Result<QuarantineRecord, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let extra = session.scanned_roots.lock().unwrap().clone();
    let allowed = allowed_roots(&extra);
    let reference_roots = session.config.lock().unwrap().reference_roots.clone();
    restore_quarantine(&id, &allowed, &reference_roots)
}

#[tauri::command]
fn quarantine_expire(
    app: tauri::AppHandle,
    id: String,
    confirmation: String,
) -> Result<QuarantineRecord, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let extra = session.scanned_roots.lock().unwrap().clone();
    let allowed = allowed_roots(&extra);
    let config = session.config.lock().unwrap().clone();
    let result = expire_quarantine(
        &id,
        ExpiryRequest {
            allowed_roots: &allowed,
            reference_roots: &config.reference_roots,
            retention_days: config.quarantine_retention_days,
            confirmation: &confirmation,
        },
    )?;
    *session.duplicate_evidence.lock().unwrap() = None;
    *session.insight_snapshot.lock().unwrap() = None;
    Ok(result)
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

/// The permission rows for a scope, without putting a dialog on screen.
///
/// Only a gate we recorded as `Denied` is re-probed. That read cannot prompt —
/// macOS refuses a denied folder outright and never asks twice — so it is free,
/// and it is the one case worth checking, because it catches the user turning
/// the folder back on in System Settings, which they have to do outside the app.
///
/// `Granted` is deliberately taken on trust rather than confirmed. TCC ties a
/// grant to the code signature, and this app is signed ad-hoc, so a grant does
/// not survive being rebuilt: probing to confirm one would raise the very dialog
/// this command exists to avoid, at a moment nobody asked for it. If the record
/// is wrong the scan finds out harmlessly — it skips anything not granted — and
/// the switch is there to ask again.
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
                let now = if was == AccessState::Denied {
                    access::probe(&gate.path)
                } else {
                    was
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

#[tauri::command]
fn quarantine_retention_set(app: tauri::AppHandle, days: Option<u32>) -> Result<Config, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut saved = session.config.lock().unwrap();
    let mut candidate = saved.clone();
    candidate.set_quarantine_retention(days)?;
    config::save(&candidate).map_err(|error| error.to_string())?;
    *saved = candidate.clone();
    Ok(candidate)
}

#[tauri::command]
fn profile_list(app: tauri::AppHandle) -> Vec<ScanProfile> {
    app.try_state::<Session>()
        .map(|session| session.config.lock().unwrap().profiles.clone())
        .unwrap_or_default()
}

#[tauri::command]
fn rule_ids() -> Vec<String> {
    let rules = cachereaper_core::rules::rules();
    rules
        .statics
        .iter()
        .map(|rule| rule.id.clone())
        .chain(rules.artifacts.iter().map(|rule| rule.id.clone()))
        .collect()
}

#[tauri::command]
fn profile_create(
    app: tauri::AppHandle,
    name: String,
    root: String,
) -> Result<ScanProfile, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    let profile = config.create_profile(name, PathBuf::from(root))?;
    config::save(&config).map_err(|error| error.to_string())?;
    Ok(profile)
}

#[tauri::command]
fn profile_update(
    app: tauri::AppHandle,
    id: String,
    name: String,
    root: String,
) -> Result<ScanProfile, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    let profile = config.update_profile(&id, name, PathBuf::from(root))?;
    config::save(&config).map_err(|error| error.to_string())?;
    Ok(profile)
}

#[tauri::command]
fn profile_delete(app: tauri::AppHandle, id: String) -> Result<bool, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    let deleted = config.delete_profile(&id);
    if deleted {
        config::save(&config).map_err(|error| error.to_string())?;
    }
    Ok(deleted)
}

#[tauri::command]
fn exclusion_add_path(
    app: tauri::AppHandle,
    path: String,
    profile_id: Option<String>,
) -> Result<Config, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    if let Some(id) = profile_id {
        config.add_profile_path(&id, PathBuf::from(path))?;
    } else {
        config.add_global_path(PathBuf::from(path))?;
    }
    config::save(&config).map_err(|error| error.to_string())?;
    Ok(config.clone())
}

#[tauri::command]
fn exclusion_remove_path(
    app: tauri::AppHandle,
    path: String,
    profile_id: Option<String>,
) -> Result<Config, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    let path = cachereaper_core::config::normalize_absolute(std::path::Path::new(&path))?;
    if let Some(id) = profile_id {
        let profile = config
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "profile not found".to_string())?;
        profile
            .excluded_paths
            .retain(|value| !cachereaper_core::config::paths_equal(value, &path));
    } else {
        config
            .global_excluded_paths
            .retain(|value| !cachereaper_core::config::paths_equal(value, &path));
    }
    config::save(&config).map_err(|error| error.to_string())?;
    Ok(config.clone())
}

#[tauri::command]
fn reference_add(app: tauri::AppHandle, path: String) -> Result<Config, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let path = config::normalize_absolute(std::path::Path::new(&path))?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("reference root is not available: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("reference root must be a real directory".to_string());
    }
    let result = {
        let mut saved = session.config.lock().unwrap();
        let mut candidate = saved.clone();
        candidate.add_reference_root(path)?;
        config::save(&candidate).map_err(|error| error.to_string())?;
        *saved = candidate.clone();
        candidate
    };
    *session.duplicate_evidence.lock().unwrap() = None;
    *session.insight_snapshot.lock().unwrap() = None;
    Ok(result)
}

#[tauri::command]
fn reference_remove(app: tauri::AppHandle, path: String) -> Result<Config, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let result = {
        let mut saved = session.config.lock().unwrap();
        let mut candidate = saved.clone();
        candidate.remove_reference_root(std::path::Path::new(&path))?;
        config::save(&candidate).map_err(|error| error.to_string())?;
        *saved = candidate.clone();
        candidate
    };
    *session.duplicate_evidence.lock().unwrap() = None;
    *session.insight_snapshot.lock().unwrap() = None;
    Ok(result)
}

#[tauri::command]
fn exclusion_add_rule(
    app: tauri::AppHandle,
    rule_id: String,
    profile_id: Option<String>,
) -> Result<Config, String> {
    if rule_id.trim().is_empty() {
        return Err("rule id cannot be empty".to_string());
    }
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    let rules = if let Some(id) = profile_id {
        &mut config
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "profile not found".to_string())?
            .excluded_rules
    } else {
        &mut config.global_excluded_rules
    };
    if !rules.contains(&rule_id) {
        rules.push(rule_id);
    }
    config::save(&config).map_err(|error| error.to_string())?;
    Ok(config.clone())
}

#[tauri::command]
fn exclusion_remove_rule(
    app: tauri::AppHandle,
    rule_id: String,
    profile_id: Option<String>,
) -> Result<Config, String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    let rules = if let Some(id) = profile_id {
        &mut config
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "profile not found".to_string())?
            .excluded_rules
    } else {
        &mut config.global_excluded_rules
    };
    rules.retain(|value| value != &rule_id);
    config::save(&config).map_err(|error| error.to_string())?;
    Ok(config.clone())
}

#[tauri::command]
fn history_list() -> Result<Vec<Receipt>, String> {
    read_history().map_err(|error| error.to_string())
}

#[tauri::command]
fn action_history_list() -> Result<Vec<ActionHistoryEntry>, String> {
    action_history()
}

#[tauri::command]
fn snapshot_history() -> Result<Vec<ScanSnapshot>, String> {
    list_snapshots()
}

#[tauri::command]
fn history_detail(receipt_id: String) -> Result<Receipt, String> {
    read_history()
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|receipt| receipt.receipt_id == receipt_id)
        .ok_or_else(|| "receipt not found".to_string())
}

#[tauri::command]
fn history_delete(receipt_id: String) -> Result<bool, String> {
    delete_receipt(&receipt_id)
}

#[tauri::command]
fn history_clear() -> Result<usize, String> {
    clear_history()
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
    if !allowed_roots(&extra)
        .iter()
        .any(|root| is_within(&path, root))
    {
        return Err("outside allowed roots".to_string());
    }

    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open")
        .arg("-R")
        .arg(&path)
        .status();
    // Explorer takes the path glued to the switch — a separate argument selects
    // nothing — and returns a non-zero exit code even when it worked, which is
    // why only the spawn failure is reported.
    #[cfg(target_os = "windows")]
    let status = std::process::Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .status();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let status = std::process::Command::new("xdg-open").arg(&path).status();

    status.map(|_| ()).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// updates
// ---------------------------------------------------------------------------

/// A build that is newer than this one, as the panel describes it.
#[derive(Serialize, Clone)]
struct UpdateInfo {
    version: String,
    current: String,
    notes: Option<String>,
}

#[derive(Serialize, Clone)]
struct UpdateProgress {
    downloaded: u64,
    total: Option<u64>,
}

/// Ask the release feed, and keep whatever it offers.
///
/// `Ok(None)` is "you already have the newest one" and is a normal answer, not a
/// failure — the distinction matters because a manual check has to say something
/// either way, and being offline should not read as being up to date.
async fn look_for_update(app: &tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    let found = updater.check().await.map_err(|e| e.to_string())?;

    let Some(update) = found else {
        if let Some(session) = app.try_state::<Session>() {
            *session.pending_update.lock().unwrap() = None;
        }
        return Ok(None);
    };

    let info = UpdateInfo {
        version: update.version.clone(),
        current: update.current_version.clone(),
        notes: update.body.clone(),
    };
    if let Some(session) = app.try_state::<Session>() {
        *session.pending_update.lock().unwrap() = Some(update);
    }
    Ok(Some(info))
}

/// Look now. Called on launch when the setting allows it, and by the button in
/// the panel whenever the user asks — the same code either way, because a manual
/// check that took a different path is a manual check that can rot separately.
#[tauri::command]
async fn update_check(app: tauri::AppHandle) -> Result<Option<UpdateInfo>, String> {
    look_for_update(&app).await
}

/// Download the waiting build, replace this one with it, and start it again.
///
/// The bytes are verified against the compiled-in public key before anything is
/// written; an unsigned or tampered payload fails here rather than being
/// installed. Nothing about the machine is uploaded — this is a GET and a
/// replace.
///
/// On Windows the installer takes over and ends this process itself, so the
/// restart below is only ever reached on macOS.
#[tauri::command]
async fn update_install(app: tauri::AppHandle) -> Result<(), String> {
    let waiting = app
        .try_state::<Session>()
        .and_then(|session| session.pending_update.lock().unwrap().clone());
    let update = waiting.ok_or_else(|| "no update is waiting — check again".to_string())?;

    // An atomic keeps the running total independent of callback capture rules
    // and makes a future concurrent downloader safe as well.
    let handle = app.clone();
    let downloaded = std::sync::atomic::AtomicU64::new(0);
    update
        .download_and_install(
            move |chunk, total| {
                let so_far = downloaded
                    .fetch_add(chunk as u64, std::sync::atomic::Ordering::Relaxed)
                    + chunk as u64;
                let _ = handle.emit(
                    "update-progress",
                    UpdateProgress {
                        downloaded: so_far,
                        total,
                    },
                );
            },
            || {},
        )
        .await
        .map_err(|e| e.to_string())?;

    app.restart()
}

/// Turn the launch check on or off. The manual button is unaffected by it.
#[tauri::command]
fn set_auto_update(app: tauri::AppHandle, on: bool) -> Result<(), String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    config.auto_update = on;
    config::save(&config).map_err(|e| e.to_string())
}

/// What this build calls itself, so the panel can show it without a second copy
/// of the version number living in the frontend.
#[tauri::command]
fn app_version(app: tauri::AppHandle) -> String {
    app.package_info().version.to_string()
}

// ---------------------------------------------------------------------------
// support
// ---------------------------------------------------------------------------

const DAY_SECONDS: u64 = 24 * 60 * 60;
const GITHUB_URL: &str = "https://github.com/samreshan/cachereaper";
const COFFEE_URL: &str = "https://buymeacoffee.com/samreshan";

#[derive(Serialize)]
struct SupportPromptState {
    show: bool,
    next_at: Option<u64>,
}

fn unix_seconds() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("system clock is before 1970: {e}"))
}

/// Pick a point from 24 through 48 hours from now. This is presentation
/// jitter, not security-sensitive randomness: mixing the sub-second clock with
/// the process id is enough to keep every install from prompting in lockstep.
fn next_support_prompt(now: u64) -> u64 {
    let entropy = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos() as u64)
        .unwrap_or(0)
        ^ std::process::id() as u64;
    now.saturating_add(DAY_SECONDS + entropy % (DAY_SECONDS + 1))
}

/// Schedule the first prompt, or report that the saved time has arrived.
#[tauri::command]
fn support_prompt_status(app: tauri::AppHandle) -> Result<SupportPromptState, String> {
    let now = unix_seconds()?;
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();

    if config.support_prompt_disabled {
        return Ok(SupportPromptState {
            show: false,
            next_at: None,
        });
    }

    if config.support_prompt_at.is_none() {
        config.support_prompt_at = Some(next_support_prompt(now));
        config::save(&config).map_err(|e| e.to_string())?;
    }

    Ok(SupportPromptState {
        show: config.support_prompt_at.is_some_and(|at| now >= at),
        next_at: config.support_prompt_at,
    })
}

/// "Later" starts a fresh random 24–48 hour interval.
#[tauri::command]
fn support_prompt_later(app: tauri::AppHandle) -> Result<SupportPromptState, String> {
    let now = unix_seconds()?;
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    config.support_prompt_at = Some(next_support_prompt(now));
    config::save(&config).map_err(|e| e.to_string())?;
    Ok(SupportPromptState {
        show: false,
        next_at: config.support_prompt_at,
    })
}

/// Permanent opt-out for the card. The footer link is deliberately unaffected.
#[tauri::command]
fn support_prompt_never(app: tauri::AppHandle) -> Result<(), String> {
    let session = app
        .try_state::<Session>()
        .ok_or_else(|| "no session".to_string())?;
    let mut config = session.config.lock().unwrap();
    config.support_prompt_disabled = true;
    config.support_prompt_at = None;
    config::save(&config).map_err(|e| e.to_string())
}

/// Open one of two fixed support pages without accepting a URL from the webview.
#[tauri::command]
fn open_support_page(destination: String) -> Result<(), String> {
    let url = match destination.as_str() {
        "coffee" => COFFEE_URL,
        "github" => GITHUB_URL,
        _ => return Err(format!("unknown support destination: {destination}")),
    };

    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg(url).status();
    #[cfg(target_os = "windows")]
    let status = std::process::Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", url])
        .status();
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let status = std::process::Command::new("xdg-open").arg(url).status();

    match status {
        Ok(exit) if exit.success() => Ok(()),
        Ok(exit) => Err(format!("could not open the support page: {exit}")),
        Err(err) => Err(format!("could not open the support page: {err}")),
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(Session::load())
        .invoke_handler(tauri::generate_handler![
            scan_request,
            cancel_scan,
            insight_query,
            cleanup_plan,
            local_ai_status,
            offload_status,
            pick_folder,
            delete_targets,
            quarantine_duplicate,
            trash_duplicate,
            quarantine_history,
            quarantine_restore,
            quarantine_expire,
            reveal,
            access_status,
            request_access,
            revoke_access,
            full_disk_status,
            open_privacy_settings,
            config_get,
            quarantine_retention_set,
            profile_list,
            rule_ids,
            profile_create,
            profile_update,
            profile_delete,
            exclusion_add_path,
            exclusion_remove_path,
            reference_add,
            reference_remove,
            exclusion_add_rule,
            exclusion_remove_rule,
            history_list,
            action_history_list,
            snapshot_history,
            history_detail,
            history_delete,
            history_clear,
            set_seen_onboarding,
            update_check,
            update_install,
            set_auto_update,
            app_version,
            support_prompt_status,
            support_prompt_later,
            support_prompt_never,
            open_support_page
        ])
        .run(tauri::generate_context!())
        .expect("failed to start cachereaper");
}
