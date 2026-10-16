//! Port of the proven rules in cachereaper.py (`PROVEN_RULES`).
//!
//! A static rule is true of everything its glob matches. These are not: an old
//! VS Code extension looks exactly like the current one until `.obsolete` names
//! it, and a Codex worktree is disposable only while git says nothing in it
//! would be lost. Each rule here carries a proof that answers for one path —
//! `""` when it holds, otherwise why not — and it runs when the path is found
//! and again in `validate_for_delete`, because any of these can stop being true
//! between the scan and the click.
//!
//! What each rule is called, its tier and its OS come from the `proven` list in
//! the generated table, like every other rule; only the proofs are duplicated,
//! as with the guards. A rule the table lists and this file cannot prove is
//! never claimed and never deleted: the GUI finds less, never more.
//!
//! Keep the returned reason strings byte-identical to the Python ones.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

use crate::guard::path_is_protected;
use crate::rules::{git_command, rules, ProvenRule};

/// The fixed places the proofs look at. Tests point these into a temporary
/// tree, the way the Python suite swaps `HOME`, `CLAUDE_TMP_BASE`,
/// `APPLICATIONS` and `ADOBE_SUPPORT`; everything else uses `system()`.
#[derive(Debug, Clone)]
pub struct Locations {
    pub home: PathBuf,
    /// where this user's `claude-<uid>` folder lives
    pub claude_tmp_base: PathBuf,
    pub applications: PathBuf,
    pub adobe_support: PathBuf,
}

impl Locations {
    pub fn system() -> Self {
        Locations {
            home: crate::guard::home(),
            claude_tmp_base: PathBuf::from("/private/tmp"),
            applications: PathBuf::from("/Applications"),
            adobe_support: PathBuf::from("/Library/Application Support/Adobe"),
        }
    }
}

type Proof = fn(&Path, &Locations) -> String;
type Finder = fn(&Locations) -> Vec<PathBuf>;

/// The proof for a rule id, when this build has one.
fn proof_for(rule_id: &str) -> Option<Proof> {
    let proof: Proof = match rule_id {
        "vscode-obsolete-ext" => prove_obsolete_extension,
        "claude-code-tmp" => prove_stale_claude_session,
        "brag-work" => |path, _| prove_brag_work(path),
        "adobe-orphaned" => prove_orphaned_adobe_folder,
        "codex-worktree" => prove_finished_codex_worktree,
        _ => return None,
    };
    Some(proof)
}

/// Where a rule looks. A rule without one is found by the project walk instead.
fn finder_for(rule_id: &str) -> Option<Finder> {
    let find: Finder = match rule_id {
        "vscode-obsolete-ext" => find_obsolete_extensions,
        "claude-code-tmp" => find_claude_sessions,
        "adobe-orphaned" => find_adobe_folders,
        "codex-worktree" => find_codex_worktrees,
        _ => return None,
    };
    Some(find)
}

/// The table's proven rule with this id, whether or not this build can prove it.
pub fn rule(rule_id: &str) -> Option<&'static ProvenRule> {
    rules().proven.iter().find(|rule| rule.id == rule_id)
}

/// `""` when the rule's proof holds for `path`, otherwise why not.
pub fn prove(rule_id: &str, path: &Path, at: &Locations) -> String {
    match proof_for(rule_id) {
        Some(proof) => proof(path, at),
        None => "the desktop app has no proof for this rule".to_string(),
    }
}

/// The one delete root a proven rule adds to the scanned roots: the user's own
/// Claude Code temp dir, for that rule and nothing else. Mirrors the line in
/// `allowed_roots_for`, scoped to the rule whose proof checks that every level
/// under it is a real directory the user owns.
pub fn extra_allowed_root(rule: &ProvenRule, at: &Locations) -> Option<PathBuf> {
    if rule.id == "claude-code-tmp" && rule.applies_here() {
        claude_tmp_root(at)
    } else {
        None
    }
}

/// Paths the proven rules' finders turn up whose proof holds. Mirrors
/// `discover_proven`; `skip` is checked before the proof, which may run git.
pub fn discover(
    include_system: bool,
    at: &Locations,
    skip: impl Fn(&Path) -> bool,
) -> Vec<(&'static ProvenRule, PathBuf)> {
    let mut out = Vec::new();
    for rule in &rules().proven {
        let (Some(find), Some(proof)) = (finder_for(&rule.id), proof_for(&rule.id)) else {
            continue;
        };
        if !rule.applies_here() || (rule.system && !include_system) {
            continue;
        }
        for path in find(at) {
            if skip(&path) || !path_is_protected(&path).is_empty() {
                continue;
            }
            if proof(&path, at).is_empty() {
                out.push((rule, path));
            }
        }
    }
    out
}

/// A proven rule found by directory name that claims `path`. Mirrors
/// `match_proven_dir`. The walk asks this of every directory, so the name is
/// compared before anything is allocated or read.
pub fn match_dir(name: &str, path: &Path) -> Option<&'static ProvenRule> {
    let mut named = rules()
        .proven
        .iter()
        .filter(|rule| rule.dir_name == name && rule.applies_here())
        .peekable();
    named.peek()?;
    if !path_is_protected(path).is_empty() {
        return None;
    }
    let at = Locations::system();
    named.find(|rule| proof_for(&rule.id).is_some_and(|proof| proof(path, &at).is_empty()))
}

/// How a rule's paths are removed when it is not a plain recursive delete.
pub fn remove(rule_id: &str, path: &Path) -> Option<Result<(), String>> {
    match rule_id {
        "codex-worktree" => Some(remove_codex_worktree(path)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|md| md.is_dir())
}

fn child_dirs(path: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|child| is_real_dir(child))
        .collect();
    dirs.sort();
    dirs
}

fn name_of(path: &Path) -> &str {
    path.file_name().and_then(OsStr::to_str).unwrap_or("")
}

fn grandparent(path: &Path) -> Option<&Path> {
    path.parent()?.parent()
}

// ---------------------------------------------------------------------------
// superseded editor extensions
// ---------------------------------------------------------------------------
//
// When VS Code updates an extension it installs the new version beside the old
// one and records the old directory's name in extensions/.obsolete, deleting it
// itself on some later launch. That file is the proof. Nothing is inferred from
// version numbers: pre-release builds and platform suffixes make "older"
// unreliable, and an editor rolled back to a pinned version would be wrong.

const EDITOR_EXTENSION_DIRS: &[[&str; 2]] = &[
    [".vscode", "extensions"],
    [".vscode-insiders", "extensions"],
    [".cursor", "extensions"],
];

fn editor_extension_dirs(at: &Locations) -> impl Iterator<Item = PathBuf> + '_ {
    EDITOR_EXTENSION_DIRS
        .iter()
        .map(|[editor, folder]| at.home.join(editor).join(folder))
}

pub fn prove_obsolete_extension(path: &Path, at: &Locations) -> String {
    let Some(ext_dir) = path
        .parent()
        .filter(|parent| editor_extension_dirs(at).any(|dir| dir == *parent))
    else {
        return "not in an editor extensions folder".to_string();
    };
    if !is_real_dir(path) {
        return "not a directory".to_string();
    }
    let name = name_of(path);
    let obsolete = read_json(&ext_dir.join(".obsolete"));
    if obsolete.as_ref().and_then(|map| map.as_object()?.get(name)) != Some(&Value::Bool(true)) {
        return "not listed in .obsolete".to_string();
    }
    // The editor's own list of what is installed. Without it there is no way to
    // rule out an entry the editor has since reinstalled, so its absence is a no.
    let Some(Value::Array(installed)) = read_json(&ext_dir.join("extensions.json")) else {
        return "extensions.json unreadable".to_string();
    };
    let listed = installed
        .iter()
        .any(|entry| entry.get("relativeLocation").and_then(Value::as_str) == Some(name));
    if listed {
        return "still listed as installed in extensions.json".to_string();
    }
    String::new()
}

fn find_obsolete_extensions(at: &Locations) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for ext_dir in editor_extension_dirs(at) {
        let Some(Value::Object(obsolete)) = read_json(&ext_dir.join(".obsolete")) else {
            continue;
        };
        let mut names: Vec<&String> = obsolete.keys().collect();
        names.sort();
        for name in names {
            // a key is a directory name, never a path out of the folder
            if Path::new(name).file_name() != Some(OsStr::new(name)) || name.starts_with('.') {
                continue;
            }
            if ext_dir.join(name).exists() {
                out.push(ext_dir.join(name));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Claude Code session temp folders
// ---------------------------------------------------------------------------
//
// Claude Code keeps each session's scratchpad and background-task output under
// /tmp/claude-<uid>/<project>/<session-id>/. A running session writes there, but
// nothing records which sessions are still running, so the proof is time: a
// session folder nothing has written to for a week is not in use.

pub const CLAUDE_TMP_STALE_DAYS: u64 = 7;

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    // SAFETY: getuid takes no arguments, touches no memory and cannot fail.
    Some(unsafe { getuid() })
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

fn claude_tmp_root(at: &Locations) -> Option<PathBuf> {
    current_uid().map(|uid| at.claude_tmp_base.join(format!("claude-{uid}")))
}

#[cfg(unix)]
fn own_real_dir(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::symlink_metadata(path), current_uid()) {
        (Ok(md), Some(uid)) => md.is_dir() && md.uid() == uid,
        _ => false,
    }
}

#[cfg(not(unix))]
fn own_real_dir(_path: &Path) -> bool {
    false
}

fn is_session_id(name: &str) -> bool {
    name.len() == 36
        && name.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// True as soon as anything at or under `path` has an mtime after `cutoff`.
/// Anything it cannot read counts as touched: what cannot be seen cannot be
/// called idle.
fn touched_since(path: &Path, cutoff: SystemTime) -> bool {
    let newer = |md: &std::fs::Metadata| !md.modified().is_ok_and(|mtime| mtime <= cutoff);
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(md) = std::fs::symlink_metadata(&dir) else {
            return true;
        };
        if newer(&md) {
            return true;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return true;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                return true;
            };
            // DirEntry::metadata does not follow symlinks
            let Ok(md) = entry.metadata() else {
                return true;
            };
            if newer(&md) {
                return true;
            }
            if md.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    false
}

pub fn prove_stale_claude_session(path: &Path, at: &Locations) -> String {
    let Some(root) = claude_tmp_root(at).filter(|root| grandparent(path) == Some(root.as_path()))
    else {
        return "not a session folder in this user's claude temp dir".to_string();
    };
    if !is_session_id(name_of(path)) {
        return "not named for a session".to_string();
    }
    // /tmp is shared: anyone can create a claude-<uid> there first, or a symlink
    // by that name pointing into your home. Every level has to be a real
    // directory that you own before anything under it is offered.
    let project = path.parent().unwrap_or(path);
    if ![root.as_path(), project, path]
        .into_iter()
        .all(own_real_dir)
    {
        return "not a directory you own".to_string();
    }
    let window = Duration::from_secs(CLAUDE_TMP_STALE_DAYS * 86_400);
    let cutoff = SystemTime::now()
        .checked_sub(window)
        .unwrap_or(SystemTime::UNIX_EPOCH);
    if touched_since(path, cutoff) {
        return format!(
            "written to within {CLAUDE_TMP_STALE_DAYS} days; the session may be running"
        );
    }
    String::new()
}

fn find_claude_sessions(at: &Locations) -> Vec<PathBuf> {
    let Some(root) = claude_tmp_root(at).filter(|root| own_real_dir(root)) else {
        return Vec::new();
    };
    child_dirs(&root)
        .iter()
        .flat_map(|project| child_dirs(project))
        .filter(|session| is_session_id(name_of(session)))
        .collect()
}

// ---------------------------------------------------------------------------
// finished Codex worktrees
// ---------------------------------------------------------------------------
//
// Codex runs each task in a linked git worktree under
// ~/.codex/worktrees/<slug>/<repo>. One is disposable when git itself says it
// holds nothing: a clean `git status` and no commit that is not on a remote.
// A repo with no remote has nowhere to have pushed to, so it never qualifies.
// Removal goes through `git worktree remove`, which also drops the main repo's
// record of it and refuses on its own if the worktree got dirty after the scan.

const GIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Read a child's pipe to the end on its own thread, so a full pipe cannot
/// stall the child while it is being waited on.
fn drain<R: std::io::Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    })
}

/// `git --no-optional-locks -C <dir> <args>`, or `None` if it could not run or
/// took longer than the CLI's 30 seconds.
fn git<S: AsRef<OsStr>>(dir: &Path, args: &[S]) -> Option<Output> {
    let mut child = git_command()
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + GIT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    Some(Output {
        status,
        stdout: stdout.join().ok()?,
        stderr: stderr.join().ok()?,
    })
}

fn trimmed(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

/// The main checkout a linked worktree belongs to, read from its .git file.
fn worktree_main(path: &Path) -> Option<PathBuf> {
    let marker = path.join(".git");
    // a .git directory is a whole repository, not a worktree
    if !std::fs::symlink_metadata(&marker).ok()?.is_file() {
        return None;
    }
    let text = std::fs::read_to_string(&marker).ok()?;
    let gitdir = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
    let gitdir = if gitdir.is_absolute() {
        gitdir
    } else {
        path.join(gitdir)
    };
    let worktrees = gitdir.parent()?;
    let dot_git = worktrees.parent()?;
    if worktrees.file_name()? != "worktrees" || dot_git.file_name()? != ".git" {
        return None;
    }
    let main = dot_git.parent()?;
    is_real_dir(&main.join(".git")).then(|| main.to_path_buf())
}

pub fn prove_finished_codex_worktree(path: &Path, at: &Locations) -> String {
    if grandparent(path) != Some(at.home.join(".codex").join("worktrees").as_path()) {
        return "not in ~/.codex/worktrees".to_string();
    }
    if !is_real_dir(path) {
        return "not a directory".to_string();
    }
    if worktree_main(path).is_none() {
        return "not a linked git worktree".to_string();
    }
    // Spelled out so a user's status.showUntrackedFiles or diff.ignoreSubmodules
    // cannot hide anything from the check.
    let status = git(
        path,
        &[
            "status",
            "--porcelain",
            "--untracked-files=normal",
            "--ignore-submodules=none",
        ],
    );
    match status {
        Some(out) if out.status.success() => {
            if !trimmed(&out.stdout).is_empty() {
                return "has uncommitted or untracked changes".to_string();
            }
        }
        _ => return "git status failed".to_string(),
    }
    match git(path, &["rev-list", "--count", "HEAD", "--not", "--remotes"]) {
        Some(out) if out.status.success() => {
            if trimmed(&out.stdout) != "0" {
                return "has commits that are on no remote".to_string();
            }
        }
        _ => return "cannot tell what is pushed".to_string(),
    }
    String::new()
}

fn find_codex_worktrees(at: &Locations) -> Vec<PathBuf> {
    child_dirs(&at.home.join(".codex").join("worktrees"))
        .iter()
        .flat_map(|slug| child_dirs(slug))
        .collect()
}

fn remove_codex_worktree(path: &Path) -> Result<(), String> {
    let main = worktree_main(path).ok_or("no longer a linked git worktree")?;
    let args = [
        OsStr::new("worktree"),
        OsStr::new("remove"),
        path.as_os_str(),
    ];
    match git(&main, &args) {
        Some(out) if out.status.success() => Ok(()),
        out => {
            let stderr = out.map(|out| trimmed(&out.stderr)).unwrap_or_default();
            Err(if stderr.is_empty() {
                "git worktree remove failed".to_string()
            } else {
                stderr
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Adobe support folders for versions no longer installed
// ---------------------------------------------------------------------------
//
// /Library/Application Support/Adobe keeps a folder per installed version, and
// an uninstall or upgrade leaves the old one. Adobe is not consistent about the
// name: Illustrator uses the major version ("Adobe Illustrator 29" belongs to
// Illustrator 2025, which is 29.x) while Photoshop uses the year. So neither is
// assumed. A folder is orphaned only when a sibling folder of the same product
// matches an app that is installed — proving which scheme that product uses on
// this machine — and nothing installed matches this one under that scheme.
//
// The desktop app never scans system scope and cannot delete as root, so this
// rule is found only when asked for and is refused at delete time regardless.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Scheme {
    Year,
    Major,
}

/// `"Adobe Photoshop 2024"` -> `("Adobe Photoshop", "2024")`, the way
/// `^(Adobe .+) (\d+)$` splits it.
fn adobe_versioned(name: &str) -> Option<(&str, &str)> {
    let (product, number) = name.rsplit_once(' ')?;
    let named =
        product.len() > "Adobe ".len() && product.starts_with("Adobe ") && !product.contains('\n');
    let numbered = !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit());
    (named && numbered).then_some((product, number))
}

fn version_key(number: &str) -> Option<(Scheme, u64)> {
    let scheme = if number.len() == 4 {
        Scheme::Year
    } else {
        Scheme::Major
    };
    Some((scheme, number.parse().ok()?))
}

/// `CFBundleShortVersionString`'s major number. The bundles this reads are
/// XML plists; anything else proves nothing, the same as a plist the CLI
/// cannot parse.
fn bundle_major(bundle: &Path) -> Option<u64> {
    let text = std::fs::read_to_string(bundle.join("Contents").join("Info.plist")).ok()?;
    let key = "<key>CFBundleShortVersionString</key>";
    let rest = text[text.find(key)? + key.len()..].trim_start();
    let rest = rest.strip_prefix("<string>")?;
    let version = &rest[..rest.find("</string>")?];
    version.split('.').next()?.trim().parse().ok()
}

/// Product name -> {(Year, 2025), (Major, 29), ...} for the applications folder.
fn installed_adobe(at: &Locations) -> HashMap<String, HashSet<(Scheme, u64)>> {
    let mut found: HashMap<String, HashSet<(Scheme, u64)>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir(&at.applications) else {
        return found;
    };
    let mut entries: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    entries.sort();
    for entry in entries {
        let name = name_of(&entry);
        if !name.starts_with("Adobe ") || !is_real_dir(&entry) {
            continue;
        }
        let (folder, bundles) = match name.strip_suffix(".app") {
            Some(stem) => (stem, vec![entry.clone()]),
            None => (
                name,
                child_dirs(&entry)
                    .into_iter()
                    .filter(|bundle| bundle.extension() == Some(OsStr::new("app")))
                    .collect(),
            ),
        };
        let matched = adobe_versioned(folder);
        let product = matched.map_or(folder, |(product, _)| product);
        let versions = found.entry(product.to_string()).or_default();
        if let Some((_, number)) = matched.filter(|(_, number)| number.len() == 4) {
            versions.extend(version_key(number));
        }
        for bundle in bundles {
            if name_of(&bundle).starts_with(product) {
                versions.extend(bundle_major(&bundle).map(|major| (Scheme::Major, major)));
            }
        }
    }
    found
}

pub fn prove_orphaned_adobe_folder(path: &Path, at: &Locations) -> String {
    if path.parent() != Some(at.adobe_support.as_path()) {
        return "not in the Adobe support folder".to_string();
    }
    let Some((product, key)) = adobe_versioned(name_of(path))
        .and_then(|(product, number)| Some((product, version_key(number)?)))
    else {
        return "not named for a product version".to_string();
    };
    if !is_real_dir(path) {
        return "not a directory".to_string();
    }
    let installed = installed_adobe(at);
    let Some(installed) = installed
        .get(product)
        .filter(|versions| !versions.is_empty())
    else {
        return format!(
            "no {product} in {} to show how its folders are named",
            at.applications.display()
        );
    };
    if installed.contains(&key) {
        return "that version is installed".to_string();
    }
    for sibling in child_dirs(&at.adobe_support) {
        let Some((other, number)) = adobe_versioned(name_of(&sibling)) else {
            continue;
        };
        if other != product || sibling == path {
            continue;
        }
        if version_key(number)
            .is_some_and(|other_key| other_key.0 == key.0 && installed.contains(&other_key))
        {
            return String::new();
        }
    }
    format!("no folder of an installed {product} shows how it names versions")
}

fn find_adobe_folders(at: &Locations) -> Vec<PathBuf> {
    child_dirs(&at.adobe_support)
        .into_iter()
        .filter(|folder| adobe_versioned(name_of(folder)).is_some())
        .collect()
}

// ---------------------------------------------------------------------------
// brag video intermediates
// ---------------------------------------------------------------------------
//
// /brag renders into brag-output[-<timestamp>]/ beside brag-plan.md, leaving
// the finished video and poster next to a work/ folder of frames, stills,
// capture scripts and a high-quality master. Only work/ is claimed, and only
// once a finished .mp4 sits beside it — before that the render may be running.

/// `^brag-output(-.+)?$`
fn is_brag_output(name: &str) -> bool {
    name == "brag-output"
        || name
            .strip_prefix("brag-output-")
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('\n'))
}

pub fn prove_brag_work(path: &Path) -> String {
    let Some(parent) = path
        .parent()
        .filter(|parent| name_of(path) == "work" && is_brag_output(name_of(parent)))
    else {
        return "not the work folder of a brag-output folder".to_string();
    };
    if !is_real_dir(path) {
        return "not a directory".to_string();
    }
    if !std::fs::symlink_metadata(parent.join("brag-plan.md")).is_ok_and(|md| md.is_file()) {
        return "no brag-plan.md beside it".to_string();
    }
    let Ok(siblings) = std::fs::read_dir(parent) else {
        return "no brag-plan.md beside it".to_string();
    };
    for sibling in siblings.flatten() {
        let is_mp4 = sibling
            .path()
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("mp4"));
        if is_mp4 && sibling.file_type().is_ok_and(|kind| kind.is_file()) {
            return String::new();
        }
    }
    "no finished .mp4 beside it; the render may still be running".to_string()
}

/// Mirrors the proven-rule classes in tests/test_cachereaper.py, case for case,
/// plus the parts only the desktop app has: painting a finding on the scanned
/// tree and refusing system locations.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::{validate_for_delete_in, Target};
    use crate::purge::{purge_in, PurgeResult};
    use crate::rules::{artifact_findings, marker_vocabulary, proven_findings, Finding};
    use std::collections::BTreeSet;

    fn write(path: &Path) {
        write_text(path, &"\0".repeat(1024));
    }

    fn write_text(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A temporary home, applications folder and temp base, so nothing here
    /// sees the real machine. Mirrors `ProvenRuleCase`.
    struct Case {
        tmp: PathBuf,
        home: PathBuf,
        at: Locations,
    }

    impl Case {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let tmp = std::env::temp_dir().join(format!(
                "cachereaper-proven-{tag}-{}-{nanos}",
                std::process::id()
            ));
            let home = tmp.join("home");
            std::fs::create_dir_all(&home).unwrap();
            // every finder runs on each discover call; none may see the real machine
            let at = Locations {
                home: home.clone(),
                claude_tmp_base: tmp.join("private-tmp"),
                applications: tmp.join("Applications"),
                adobe_support: tmp
                    .join("Library")
                    .join("Application Support")
                    .join("Adobe"),
            };
            Case { tmp, home, at }
        }

        fn found(&self, rule_id: &str, include_system: bool) -> BTreeSet<PathBuf> {
            discover(include_system, &self.at, |_| false)
                .into_iter()
                .filter(|(rule, _)| rule.id == rule_id)
                .map(|(_, path)| path)
                .collect()
        }

        fn target(&self, path: &Path, rule_id: &str) -> Target {
            let rule = rule(rule_id).expect("rule is in the table");
            Target {
                path: path.to_path_buf(),
                rule_id: rule.id.clone(),
                tier: rule.tier.clone(),
                expect_name: name_of(path).to_string(),
                size: 0,
                label: rule.label.clone(),
                regen: rule.regen.clone(),
            }
        }

        fn discovered(&self, rule_id: &str) -> Vec<Target> {
            self.found(rule_id, false)
                .iter()
                .map(|path| self.target(path, rule_id))
                .collect()
        }

        fn validate(&self, path: &Path, rule_id: &str) -> String {
            let target = self.target(path, rule_id);
            validate_for_delete_in(&target, std::slice::from_ref(&self.tmp), &self.at)
        }

        /// Deletes with the whole temporary tree allowed, as the Python suite
        /// passes `allowed=[self.tmp]`.
        fn delete(&self, targets: &[Target]) -> PurgeResult {
            self.delete_within(targets, std::slice::from_ref(&self.tmp))
        }

        fn delete_within(&self, targets: &[Target], allowed: &[PathBuf]) -> PurgeResult {
            let audit = self.tmp.join(".cachereaper");
            purge_in(targets, allowed, &[], false, &audit, &self.at)
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.tmp);
        }
    }

    fn set(paths: &[PathBuf]) -> BTreeSet<PathBuf> {
        paths.iter().cloned().collect()
    }

    // --- the table -----------------------------------------------------------

    #[test]
    fn every_proven_rule_in_the_table_has_a_rust_proof() {
        let ids: BTreeSet<&str> = rules().proven.iter().map(|rule| rule.id.as_str()).collect();
        let expected = [
            "adobe-orphaned",
            "brag-work",
            "claude-code-tmp",
            "codex-worktree",
            "vscode-obsolete-ext",
        ];
        assert_eq!(ids, expected.into_iter().collect());
        for rule in &rules().proven {
            assert!(proof_for(&rule.id).is_some(), "{} has no proof", rule.id);
            assert!(
                finder_for(&rule.id).is_some() || !rule.dir_name.is_empty(),
                "{} can never be found",
                rule.id
            );
            assert!(["low", "medium", "high"].contains(&rule.tier.as_str()));
            assert!(["any", "macos", "windows", "linux"].contains(&rule.os.as_str()));
            assert!(!rule.label.is_empty() && !rule.regen.is_empty() && !rule.proof.is_empty());
        }
    }

    #[test]
    fn proven_rules_stay_out_of_the_glob_and_marker_lists() {
        // those lists are applied with nothing but a glob or a marker
        for rule in &rules().proven {
            assert!(
                rules().statics.iter().all(|other| other.id != rule.id),
                "{}",
                rule.id
            );
            assert!(
                rules().artifacts.iter().all(|other| other.id != rule.id),
                "{}",
                rule.id
            );
        }
    }

    #[test]
    fn a_rule_without_a_proof_never_holds() {
        let case = Case::new("unknown");
        assert!(!prove("no-such-rule", &case.home, &case.at).is_empty());
    }

    // --- superseded editor extensions ----------------------------------------

    struct Extensions {
        case: Case,
        ext: PathBuf,
    }

    impl Extensions {
        fn new() -> Self {
            let case = Case::new("ext");
            let ext = case.home.join(".vscode").join("extensions");
            for name in [
                "pub.a-1.0.0",
                "pub.a-1.1.0",
                "pub.b-2.0.0-darwin-arm64",
                "pub.c-0.9.0",
            ] {
                write(&ext.join(name).join("package.json"));
            }
            let obsolete = serde_json::json!({
                "pub.a-1.0.0": true,
                "pub.b-2.0.0-darwin-arm64": true,   // reinstalled since: extensions.json has it
                "pub.gone-0.1.0": true,             // already deleted by VS Code
                "../escape": true,
            });
            write_text(&ext.join(".obsolete"), &obsolete.to_string());
            let fixture = Extensions { case, ext };
            fixture.write_installed(&["pub.a-1.1.0", "pub.b-2.0.0-darwin-arm64", "pub.c-0.9.0"]);
            fixture
        }

        fn write_installed(&self, names: &[&str]) {
            let entries: Vec<Value> = names
                .iter()
                .map(|name| {
                    let id = name.rsplit_once('-').map_or(*name, |(id, _)| id);
                    serde_json::json!({"identifier": {"id": id}, "relativeLocation": name})
                })
                .collect();
            write_text(
                &self.ext.join("extensions.json"),
                &Value::Array(entries).to_string(),
            );
        }

        fn found(&self) -> BTreeSet<PathBuf> {
            self.case.found("vscode-obsolete-ext", false)
        }
    }

    #[test]
    fn claims_only_entries_named_in_obsolete_and_not_installed() {
        let f = Extensions::new();
        assert_eq!(f.found(), set(&[f.ext.join("pub.a-1.0.0")]));
    }

    #[test]
    fn older_looking_versions_are_not_inferred() {
        // pub.c-0.9.0 is older than everything here and still is not claimed
        let f = Extensions::new();
        assert!(!f.found().contains(&f.ext.join("pub.c-0.9.0")));
    }

    #[test]
    fn without_extensions_json_nothing_is_claimed() {
        let f = Extensions::new();
        std::fs::remove_file(f.ext.join("extensions.json")).unwrap();
        assert!(f.found().is_empty());
    }

    #[test]
    fn malformed_obsolete_claims_nothing() {
        let f = Extensions::new();
        write_text(&f.ext.join(".obsolete"), "{not json");
        assert!(f.found().is_empty());
    }

    #[test]
    fn reinstall_after_scan_blocks_delete() {
        let f = Extensions::new();
        let target = f.ext.join("pub.a-1.0.0");
        assert_eq!(f.case.validate(&target, "vscode-obsolete-ext"), "");
        f.write_installed(&["pub.a-1.0.0", "pub.a-1.1.0"]);
        let why = f.case.validate(&target, "vscode-obsolete-ext");
        assert!(why.contains("no longer proven"), "{why}");
        f.case
            .delete(&[f.case.target(&target, "vscode-obsolete-ext")]);
        assert!(target.exists());
    }

    #[test]
    fn delete_keeps_the_current_version() {
        let f = Extensions::new();
        let result = f.case.delete(&f.case.discovered("vscode-obsolete-ext"));
        assert_eq!((result.removed, result.skipped), (1, Vec::<String>::new()));
        assert!(!f.ext.join("pub.a-1.0.0").exists());
        assert!(f.ext.join("pub.a-1.1.0").join("package.json").exists());
    }

    #[test]
    fn a_proven_path_is_painted_only_when_the_scan_holds_it() {
        let f = Extensions::new();
        let scan = |root: &Path| {
            crate::scan::scan_with_markers(root, 2, marker_vocabulary(), Vec::new(), |_, _| {})
                .unwrap()
        };
        let tree = scan(&f.case.home);
        let findings: Vec<Finding> = proven_findings(&tree, false, &f.case.at);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let finding = &findings[0];
        assert_eq!(finding.path, f.ext.join("pub.a-1.0.0"));
        assert_eq!(finding.rule_id, "vscode-obsolete-ext");
        assert_eq!(finding.source, "proven");
        assert_eq!(tree.path_of(finding.node), finding.path);
        assert!(finding.size > 0);

        // the same machine scanned from somewhere that does not hold it
        let elsewhere = scan(&f.ext.join("pub.a-1.1.0"));
        assert!(proven_findings(&elsewhere, false, &f.case.at).is_empty());
    }

    // --- Claude Code session temp folders ------------------------------------

    /// Backdates `path` and everything under it, children first: creating a
    /// child is what moved its directory's mtime.
    #[cfg(target_os = "macos")]
    fn age(path: &Path, days: u64) {
        if std::fs::symlink_metadata(path).unwrap().is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                age(&entry.unwrap().path(), days);
            }
        }
        let old = SystemTime::now() - Duration::from_secs(days * 86_400);
        std::fs::File::open(path)
            .unwrap()
            .set_modified(old)
            .unwrap();
    }

    #[cfg(target_os = "macos")]
    struct Sessions {
        case: Case,
        root: PathBuf,
        stale: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl Sessions {
        const SESSION: &'static str = "6b217802-85e8-4bac-9408-2790915c0050";

        fn new() -> Self {
            let case = Case::new("claude");
            let root = claude_tmp_root(&case.at).unwrap();
            let project = root.join("-Users-someone-Programming-demo");
            let stale = project.join(Self::SESSION);
            let live = project.join("26cdb326-4424-4cf3-ba0d-cd41bc0bc564");
            let other = root.join("bash-edit-diff").join("1234-5678-abcd");
            let state = root.join(format!("cache-break-state-{}.json", Self::SESSION));
            write(&stale.join("tasks").join("b1.output"));
            write(&stale.join("scratchpad").join("notes.txt"));
            write(&live.join("tasks").join("b2.output"));
            write(&other.join("blob"));
            write(&state);
            for path in [&stale, &other, &state] {
                age(path, CLAUDE_TMP_STALE_DAYS + 1);
            }
            Sessions { case, root, stale }
        }

        fn found(&self) -> BTreeSet<PathBuf> {
            self.case.found("claude-code-tmp", false)
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claims_only_stale_session_folders() {
        let f = Sessions::new();
        assert_eq!(f.found(), set(std::slice::from_ref(&f.stale)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_recent_write_anywhere_inside_protects_the_session() {
        let f = Sessions::new();
        write_text(&f.stale.join("tasks").join("b1.output"), "still running");
        assert!(f.found().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_symlinked_root_is_not_followed() {
        // /tmp is shared: a claude-<uid> planted by someone else, pointing into
        // your files, must not turn them into candidates
        let f = Sessions::new();
        std::fs::remove_dir_all(&f.root).unwrap();
        std::os::unix::fs::symlink(&f.case.home, &f.root).unwrap();
        let victim = f.case.home.join("proj").join(Sessions::SESSION);
        write(&victim.join("thesis.tex"));
        age(&victim, 30);
        assert!(f.found().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn temp_root_is_an_allowed_delete_root() {
        let f = Sessions::new();
        let rule = rule("claude-code-tmp").unwrap();
        assert_eq!(extra_allowed_root(rule, &f.case.at), Some(f.root.clone()));
        // only the scanned home is allowed, and the temp dir is outside it
        let home = std::slice::from_ref(&f.case.home);
        let target = f.case.target(&f.stale, "claude-code-tmp");
        assert_eq!(validate_for_delete_in(&target, home, &f.case.at), "");
        // the root is added for this rule alone, not for anything under it
        let stray = f.stale.join("scratchpad");
        let mut other = f.case.target(&stray, "claude-code-tmp");
        other.rule_id = "node-modules".to_string();
        assert_eq!(
            validate_for_delete_in(&other, home, &f.case.at),
            "outside allowed roots"
        );
        let result = f.case.delete_within(&[target], home);
        assert_eq!((result.removed, result.skipped), (1, Vec::<String>::new()));
        assert!(!f.stale.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn session_woken_after_scan_is_skipped_at_delete() {
        let f = Sessions::new();
        let targets = f.case.discovered("claude-code-tmp");
        write_text(&f.stale.join("tasks").join("b3.output"), "resumed");
        let result = f.case.delete(&targets);
        assert_eq!(result.removed, 0);
        assert!(
            result.skipped[0].contains("no longer proven"),
            "{:?}",
            result.skipped
        );
        assert!(f.stale.exists());
    }

    // --- finished Codex worktrees --------------------------------------------

    fn run_git(cwd: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .args(["-c", "init.defaultBranch=main", "-C"])
            .arg(cwd)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn text(path: &Path) -> &str {
        path.to_str().unwrap()
    }

    struct Worktrees {
        case: Case,
        main: PathBuf,
        wt: PathBuf,
    }

    impl Worktrees {
        /// `None`, and the test passes vacuously, where git is not installed.
        fn new() -> Option<Self> {
            let git = std::process::Command::new("git").arg("--version").output();
            if !git.is_ok_and(|out| out.status.success()) {
                eprintln!("git not installed; skipping");
                return None;
            }
            let case = Case::new("codex");
            let origin = case.tmp.join("origin.git");
            let main = case.tmp.join("repo");
            run_git(&case.tmp, &["init", "-q", "--bare", text(&origin)]);
            run_git(&case.tmp, &["init", "-q", text(&main)]);
            write_text(&main.join("app.py"), "print('hi')\n");
            write_text(&main.join(".gitignore"), "node_modules/\n");
            run_git(&main, &["add", "."]);
            run_git(&main, &["commit", "-q", "-m", "init"]);
            run_git(&main, &["remote", "add", "origin", text(&origin)]);
            run_git(&main, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
            run_git(&main, &["fetch", "-q", "origin"]);
            let wt = case
                .home
                .join(".codex")
                .join("worktrees")
                .join("02fc")
                .join("repo");
            run_git(&main, &["worktree", "add", "-q", "--detach", text(&wt)]);
            write(&wt.join("node_modules").join("pkg").join("blob"));
            Some(Worktrees { case, main, wt })
        }

        fn found(&self) -> BTreeSet<PathBuf> {
            self.case.found("codex-worktree", false)
        }
    }

    #[test]
    fn clean_pushed_worktree_is_claimed() {
        let Some(f) = Worktrees::new() else { return };
        assert_eq!(f.found(), set(std::slice::from_ref(&f.wt)));
        assert_eq!(rule("codex-worktree").unwrap().tier, "high");
    }

    #[test]
    fn untracked_file_blocks_the_claim() {
        let Some(f) = Worktrees::new() else { return };
        write_text(&f.wt.join("draft.md"), "not committed");
        assert!(f.found().is_empty());
    }

    #[test]
    fn modified_tracked_file_blocks_the_claim() {
        let Some(f) = Worktrees::new() else { return };
        write_text(&f.wt.join("app.py"), "print('changed')\n");
        assert!(f.found().is_empty());
    }

    #[test]
    fn unpushed_commit_blocks_the_claim() {
        let Some(f) = Worktrees::new() else { return };
        write_text(&f.wt.join("new.py"), "x = 1\n");
        run_git(&f.wt, &["add", "new.py"]);
        run_git(&f.wt, &["commit", "-q", "-m", "local only"]);
        assert!(f.found().is_empty());
    }

    #[test]
    fn repo_without_a_remote_never_qualifies() {
        let Some(f) = Worktrees::new() else { return };
        run_git(&f.main, &["remote", "remove", "origin"]);
        assert!(f.found().is_empty());
    }

    #[test]
    fn a_full_clone_is_not_a_worktree() {
        let Some(f) = Worktrees::new() else { return };
        let clone = f
            .case
            .home
            .join(".codex")
            .join("worktrees")
            .join("9308")
            .join("clone");
        std::fs::create_dir_all(clone.parent().unwrap()).unwrap();
        let origin = f.case.tmp.join("origin.git");
        run_git(&f.case.tmp, &["clone", "-q", text(&origin), text(&clone)]);
        assert!(!f.found().contains(&clone));
    }

    #[test]
    fn removal_goes_through_git_worktree_remove() {
        let Some(f) = Worktrees::new() else { return };
        let result = f.case.delete(&f.case.discovered("codex-worktree"));
        assert_eq!((result.removed, result.skipped), (1, Vec::<String>::new()));
        assert!(!f.wt.exists());
        let listed = std::process::Command::new("git")
            .arg("-C")
            .arg(&f.main)
            .args(["worktree", "list", "--porcelain"])
            .output()
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&listed.stdout).contains("02fc"),
            "rm would leave the main repo listing a missing worktree"
        );
        assert!(f.main.join("app.py").exists());
    }

    #[test]
    fn edit_after_scan_is_refused_at_delete() {
        let Some(f) = Worktrees::new() else { return };
        let targets = f.case.discovered("codex-worktree");
        write_text(&f.wt.join("app.py"), "print('late edit')\n");
        let result = f.case.delete(&targets);
        assert_eq!(result.removed, 0);
        assert!(
            result.skipped[0].contains("no longer proven"),
            "{:?}",
            result.skipped
        );
        assert_eq!(
            std::fs::read_to_string(f.wt.join("app.py")).unwrap(),
            "print('late edit')\n"
        );
    }

    // --- Adobe support folders for versions no longer installed --------------

    #[cfg(target_os = "macos")]
    fn install_app(case: &Case, folder: &str, bundle: &str, version: &str) {
        let plist = case
            .at
            .applications
            .join(folder)
            .join(bundle)
            .join("Contents")
            .join("Info.plist");
        write_text(
            &plist,
            &format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
                 \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
                 <plist version=\"1.0\">\n<dict>\n\
                 \t<key>CFBundleShortVersionString</key>\n\t<string>{version}</string>\n\
                 </dict>\n</plist>\n"
            ),
        );
    }

    #[cfg(target_os = "macos")]
    fn adobe() -> Case {
        let case = Case::new("adobe");
        install_app(
            &case,
            "Adobe Illustrator 2025",
            "Adobe Illustrator.app",
            "29.0.1",
        );
        install_app(
            &case,
            "Adobe Photoshop 2023",
            "Adobe Photoshop 2023.app",
            "24.0.0",
        );
        for name in [
            "Adobe Illustrator 28",
            "Adobe Illustrator 29",
            "Adobe Photoshop 2023",
            "Adobe Photoshop 2024",
            "Adobe InDesign 2020",
            "CEP",
            "SLStore",
            "backup20240808T183841",
            "Adobe Desktop Common",
        ] {
            write(&case.at.adobe_support.join(name).join("blob"));
        }
        case
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn claims_versions_whose_app_is_gone_under_either_naming() {
        let case = adobe();
        let support = &case.at.adobe_support;
        assert_eq!(
            case.found("adobe-orphaned", true),
            set(&[
                support.join("Adobe Illustrator 28"), // by major version: 29 is installed
                support.join("Adobe Photoshop 2024"), // by year: 2023 is installed
            ])
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_with_system_scope() {
        assert!(adobe().found("adobe-orphaned", false).is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn naming_is_not_assumed_without_a_matching_sibling() {
        // With no folder for the installed Illustrator 29, nothing proves that
        // Illustrator names its folders by major version.
        let case = adobe();
        std::fs::remove_dir_all(case.at.adobe_support.join("Adobe Illustrator 29")).unwrap();
        let orphan = case.at.adobe_support.join("Adobe Illustrator 28");
        assert!(!case.found("adobe-orphaned", true).contains(&orphan));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn product_not_installed_at_all_is_left_alone() {
        let case = adobe();
        let indesign = case.at.adobe_support.join("Adobe InDesign 2020");
        assert!(!case.found("adobe-orphaned", true).contains(&indesign));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reinstalling_the_version_blocks_delete() {
        let case = adobe();
        let target = case.at.adobe_support.join("Adobe Illustrator 28");
        assert_eq!(prove("adobe-orphaned", &target, &case.at), "");
        install_app(
            &case,
            "Adobe Illustrator 2024",
            "Adobe Illustrator.app",
            "28.7.1",
        );
        assert_eq!(
            prove("adobe-orphaned", &target, &case.at),
            "that version is installed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_desktop_app_never_deletes_a_system_rule() {
        // it has no way to run as root, so a proof that holds is not enough
        let case = adobe();
        let orphan = case.at.adobe_support.join("Adobe Illustrator 28");
        assert_eq!(
            case.validate(&orphan, "adobe-orphaned"),
            crate::guard::SYSTEM_RULE_REFUSAL
        );
        let result = case.delete(&[case.target(&orphan, "adobe-orphaned")]);
        assert_eq!(result.removed, 0);
        assert!(orphan.join("blob").exists());
        let home = std::slice::from_ref(&case.home);
        let target = case.target(&orphan, "adobe-orphaned");
        assert_eq!(
            validate_for_delete_in(&target, home, &case.at),
            "outside allowed roots"
        );
    }

    // --- brag video intermediates --------------------------------------------

    struct Brag {
        case: Case,
        out: PathBuf,
    }

    impl Brag {
        fn new() -> Self {
            let case = Case::new("brag");
            let out = case.home.join("proj").join("brag-output-2026-09-26-221544");
            write(&out.join("brag-plan.md"));
            write(&out.join("share-copy.txt"));
            write(&out.join("launch.mp4"));
            write(&out.join("work").join("frames").join("0001.png"));
            write(&out.join("work").join("master_crf17.mp4"));
            Brag { case, out }
        }

        /// The project walk over the scanned home, as `discover_projects` runs it.
        fn scan(&self) -> Vec<Finding> {
            let tree = crate::scan::scan_with_markers(
                &self.case.home,
                2,
                marker_vocabulary(),
                Vec::new(),
                |_, _| {},
            )
            .unwrap();
            artifact_findings(&tree)
                .into_iter()
                .filter(|finding| finding.rule_id == "brag-work")
                .collect()
        }
    }

    #[test]
    fn claims_work_and_never_the_finished_video() {
        let f = Brag::new();
        let findings = f.scan();
        let paths: Vec<PathBuf> = findings
            .iter()
            .map(|finding| finding.path.clone())
            .collect();
        assert_eq!(paths, vec![f.out.join("work")]);
        assert_eq!(findings[0].source, "proven");
        let result = f.case.delete(&[f.case.target(&paths[0], "brag-work")]);
        assert_eq!((result.removed, result.skipped), (1, Vec::<String>::new()));
        assert!(!f.out.join("work").exists());
        for kept in ["launch.mp4", "brag-plan.md", "share-copy.txt"] {
            assert!(f.out.join(kept).exists(), "{kept}");
        }
    }

    #[test]
    fn unfinished_render_is_not_claimed() {
        let f = Brag::new();
        std::fs::remove_file(f.out.join("launch.mp4")).unwrap();
        assert!(f.scan().is_empty());
    }

    #[test]
    fn work_needs_a_brag_output_parent_and_plan() {
        let f = Brag::new();
        let other = f.case.home.join("proj").join("notes");
        write(&other.join("brag-plan.md"));
        write(&other.join("talk.mp4"));
        write(&other.join("work").join("draft.txt"));
        std::fs::remove_file(f.out.join("brag-plan.md")).unwrap();
        assert!(f.scan().is_empty());
    }
}
