//! Rule matching against the table generated from `cachereaper.py`.
//!
//! The rules themselves are never written here — `gui/rules.generated.json` is
//! produced by `cachereaper.py dump-rules` and embedded at compile time, so the
//! Python CLI stays the single definition of what counts as a cache. CI fails if
//! the committed copy drifts from the source.
//!
//! Unlike the CLI, a matched directory is *marked* rather than pruned: the
//! treemap still wants to show what is inside a node_modules when you drill in.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::scan::{Tree, NONE};

const EMBEDDED: &str = include_str!("../../rules.generated.json");

/// Top-level directories the CLI does not search for project artifacts.
/// Mirrors `SKIP_TOP_LEVEL` in cachereaper.py.
pub const SKIP_TOP_LEVEL: &[&str] = &[
    "Library",
    "Applications",
    "Movies",
    "Music",
    "Pictures",
    "Public",
    ".Trash",
    "Virtual Machines.localized",
    "AppData",
];

/// Which rule table this build belongs to, matching `PLATFORM` in cachereaper.py.
///
/// A rule says which operating system its path is true on, and the ones that
/// cannot apply here are never resolved — `Library/Application Support/*/Cache`
/// is four wasted directory reads on Windows and nothing else.
pub const PLATFORM: &str = if cfg!(target_os = "macos") {
    "macos"
} else if cfg!(target_os = "windows") {
    "windows"
} else {
    "linux"
};

#[derive(Debug, Deserialize, Clone)]
pub struct StaticRule {
    pub id: String,
    pub tier: String,
    pub glob: String,
    pub label: String,
    pub regen: String,
    pub children: bool,
    pub warn: String,
    pub system: bool,
    /// `any`, or the one operating system this path exists on.
    pub os: String,
}

impl StaticRule {
    pub fn applies_here(&self) -> bool {
        self.os == "any" || self.os == PLATFORM
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ArtifactRule {
    pub dir_name: String,
    pub id: String,
    pub tier: String,
    pub label: String,
    pub regen: String,
    pub markers: Vec<String>,
    pub contains: Vec<String>,
    pub need_gitignored: bool,
}

#[derive(Debug, Deserialize)]
pub struct Rules {
    pub schema: u32,
    pub version: String,
    #[serde(rename = "static")]
    pub statics: Vec<StaticRule>,
    pub artifacts: Vec<ArtifactRule>,
}

impl Rules {
    /// Artifact rules bucketed by the directory name they apply to.
    pub fn by_dir_name(&self) -> HashMap<&str, Vec<&ArtifactRule>> {
        let mut map: HashMap<&str, Vec<&ArtifactRule>> = HashMap::new();
        for rule in &self.artifacts {
            map.entry(rule.dir_name.as_str()).or_default().push(rule);
        }
        map
    }
}

/// Every marker filename any artifact rule asks about. Handed to the scanner so
/// it records just these names per directory rather than all 1M filenames.
pub fn marker_vocabulary() -> HashSet<String> {
    rules()
        .artifacts
        .iter()
        .flat_map(|r| r.markers.iter().cloned())
        .collect()
}

pub fn rules() -> &'static Rules {
    static PARSED: OnceLock<Rules> = OnceLock::new();
    PARSED.get_or_init(|| {
        serde_json::from_str(EMBEDDED).expect("gui/rules.generated.json is malformed")
    })
}

/// A directory the rules claim, ready to be painted on the treemap.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub node: u32,
    pub path: PathBuf,
    pub rule_id: String,
    pub tier: String,
    pub label: String,
    pub regen: String,
    pub warn: String,
    pub size: u64,
    pub source: &'static str,
}

/// Decides whether a directory encountered during the walk is a build artifact.
///
/// Mirrors `match_artifact` in cachereaper.py: a rule only claims a directory when
/// its markers sit alongside it and its required contents are present. Rules
/// gated on `need_gitignored` are deferred to a batched git pass afterwards.
pub struct ArtifactMatcher {
    by_name: HashMap<String, Vec<ArtifactRule>>,
}

impl Default for ArtifactMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl ArtifactMatcher {
    pub fn new() -> Self {
        let mut by_name: HashMap<String, Vec<ArtifactRule>> = HashMap::new();
        for rule in &rules().artifacts {
            by_name
                .entry(rule.dir_name.clone())
                .or_default()
                .push(rule.clone());
        }
        ArtifactMatcher { by_name }
    }

    /// `siblings` are the entry names in the *parent* directory, which is where
    /// markers like Cargo.toml live.
    pub fn match_dir(
        &self,
        name: &str,
        siblings: &HashSet<String>,
        path: &Path,
    ) -> Option<&ArtifactRule> {
        for rule in self.by_name.get(name)? {
            if !rule.markers.is_empty() && !rule.markers.iter().any(|m| siblings.contains(m)) {
                continue;
            }
            if !rule.contains.is_empty() && !rule.contains.iter().all(|c| path.join(c).exists()) {
                continue;
            }
            return Some(rule);
        }
        None
    }
}

/// Walk down from the tree root to the node for `path`, if it was scanned.
pub fn find_node(tree: &Tree, path: &Path) -> Option<u32> {
    let rel = path.strip_prefix(&tree.root_path).ok()?;
    let mut idx = 0u32;
    for part in rel.components() {
        let want = part.as_os_str().to_string_lossy();
        let node = &tree.nodes[idx as usize];
        let next = node
            .children
            .iter()
            .find(|&&c| tree.nodes[c as usize].name == want)?;
        idx = *next;
    }
    Some(idx)
}

/// Expand a rule glob (only `*` is used, always as a whole component).
fn is_user_excluded(tree: &Tree, path: &Path) -> bool {
    tree.stats
        .excluded_paths
        .iter()
        .any(|excluded| path == excluded || path.starts_with(excluded))
}

fn expand_glob(tree: &Tree, base: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut current = vec![base.to_path_buf()];
    for part in pattern.split('/').filter(|p| !p.is_empty()) {
        let mut next = Vec::new();
        if part == "*" {
            for dir in &current {
                if is_user_excluded(tree, dir) {
                    continue;
                }
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        next.push(entry.path());
                    }
                }
            }
        } else {
            for dir in &current {
                let candidate = dir.join(part);
                if candidate.symlink_metadata().is_ok() {
                    next.push(candidate);
                }
            }
        }
        current = next;
        if current.is_empty() {
            break;
        }
    }
    current
}

/// Resolve every static rule against the filesystem and map hits onto tree nodes.
///
/// Order matters: the generated table lists specific rules before generic ones,
/// and the first rule to claim a path wins — same as `discover_static`.
pub fn static_findings(tree: &Tree, include_system: bool) -> Vec<Finding> {
    let home = crate::guard::home();
    let mut claimed: HashSet<PathBuf> = HashSet::new();
    let mut out = Vec::new();

    for rule in &rules().statics {
        if !rule.applies_here() {
            continue;
        }
        if rule.system && !include_system {
            continue;
        }
        let (base, pattern) = if rule.glob.starts_with('/') {
            (PathBuf::from("/"), rule.glob.trim_start_matches('/'))
        } else {
            (home.clone(), rule.glob.as_str())
        };

        for matched in expand_glob(tree, &base, pattern) {
            if is_user_excluded(tree, &matched) {
                continue;
            }
            let targets: Vec<PathBuf> = if rule.children {
                match std::fs::read_dir(&matched) {
                    Ok(entries) => entries.flatten().map(|e| e.path()).collect(),
                    Err(_) => continue,
                }
            } else {
                vec![matched]
            };
            for target in targets {
                if is_user_excluded(tree, &target) {
                    continue;
                }
                if claimed.contains(&target) {
                    continue;
                }
                if !crate::guard::path_is_protected(&target).is_empty() {
                    continue;
                }
                let Some(node) = find_node(tree, &target) else {
                    continue;
                };
                claimed.insert(target.clone());
                out.push(Finding {
                    node,
                    path: target,
                    rule_id: rule.id.clone(),
                    tier: rule.tier.clone(),
                    label: rule.label.clone(),
                    regen: rule.regen.clone(),
                    warn: rule.warn.clone(),
                    size: tree.nodes[node as usize].total_size,
                    source: "static",
                });
            }
        }
    }
    out
}

/// Keep only the paths git already ignores, batched one call per repository.
/// Mirrors `filter_gitignored`: a path outside any repo is dropped, because
/// nothing proves it is build output rather than source.
pub fn filter_gitignored(
    paths: Vec<(u32, PathBuf, ArtifactRule)>,
) -> Vec<(u32, PathBuf, ArtifactRule)> {
    use std::io::Write;
    use std::process::Stdio;

    let mut by_repo: HashMap<PathBuf, Vec<(u32, PathBuf, ArtifactRule)>> = HashMap::new();
    for (node, path, rule) in paths {
        if let Some(repo) = git_repo_root(path.parent().unwrap_or(&path)) {
            by_repo.entry(repo).or_default().push((node, path, rule));
        }
    }

    let mut kept = Vec::new();
    for (repo, items) in by_repo {
        let payload: String = items
            .iter()
            .map(|(_, p, _)| git_path(p))
            .collect::<Vec<_>>()
            .join("\n");

        let Ok(mut child) = git_check_ignore_command(&repo)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        if let Some(stdin) = child.stdin.as_mut() {
            let _ = stdin.write_all(payload.as_bytes());
        }
        let Ok(output) = child.wait_with_output() else {
            continue;
        };
        let ignored: HashSet<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        for (node, path, rule) in items {
            if ignored.contains(&git_path(&path)) {
                kept.push((node, path, rule));
            }
        }
    }
    kept
}

/// Build the Git probe used by the rule pass.
///
/// The desktop executable uses Windows' GUI subsystem, so it has no console for
/// console children such as `git.exe` to inherit. Without `CREATE_NO_WINDOW`,
/// Windows briefly creates a terminal for every repository checked during a
/// scan. Redirecting stdio does not suppress that window; it must be disabled at
/// process creation time.
fn git_check_ignore_command(repo: &Path) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command.args(["-C", &repo.to_string_lossy(), "check-ignore", "--stdin"]);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        // WinBase.h: CREATE_NO_WINDOW. Keep the literal local so the core crate
        // does not need a Windows bindings dependency for one stable flag.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    command
}

/// A path in the spelling git uses.
///
/// `check-ignore --stdin` echoes back the paths it was handed, and git speaks
/// forward slashes on every platform. Sending a Windows path verbatim gets
/// either nothing back or something that no longer matches the key we look it up
/// by — and a miss here silently drops a finding, so both ends go through this.
fn git_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.into_owned()
    }
}

fn git_repo_root(start: &Path) -> Option<PathBuf> {
    let mut cur = start;
    loop {
        if cur.join(".git").exists() {
            return Some(cur.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

/// Drop findings that sit inside another finding, keeping the outermost.
/// Mirrors `dedupe_nested`; sorting by components makes a child always follow
/// its parent, which a plain string sort does not guarantee.
pub fn dedupe_nested(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        let ap: Vec<_> = a.path.components().collect();
        let bp: Vec<_> = b.path.components().collect();
        ap.cmp(&bp)
    });
    let mut kept: Vec<Finding> = Vec::new();
    for finding in findings {
        if let Some(last) = kept.last() {
            if finding.path != last.path && finding.path.starts_with(&last.path) {
                continue;
            }
            if finding.path == last.path {
                continue;
            }
        }
        kept.push(finding);
    }
    kept
}

/// Every finding in the tree: artifacts marked during the walk, plus static
/// rule hits, deduped so nested matches do not double-count.
pub fn all_findings(tree: &Tree, include_system: bool) -> Vec<Finding> {
    all_findings_excluding(tree, include_system, &HashSet::new())
}

/// Rule exclusions affect classification only. The arena and its reclaimable
/// totals stay intact, so excluded matches remain ordinary map content.
pub fn all_findings_excluding(
    tree: &Tree,
    include_system: bool,
    excluded_rules: &HashSet<String>,
) -> Vec<Finding> {
    let mut findings = artifact_findings(tree);
    findings.extend(static_findings(tree, include_system));
    dedupe_nested(findings)
        .into_iter()
        .filter(|finding| !excluded_rules.contains(&finding.rule_id))
        .collect()
}

/// Artifact hits recorded on the nodes during the walk, with the deferred
/// gitignore-gated candidates resolved.
pub fn artifact_findings(tree: &Tree) -> Vec<Finding> {
    let matcher = ArtifactMatcher::new();
    let mut direct = Vec::new();
    let mut deferred: Vec<(u32, PathBuf, ArtifactRule)> = Vec::new();

    // Replicate the CLI's traversal decisions so both halves claim the same set:
    // top-level directories like Library/Applications are not searched for
    // project artifacts, hidden directories are skipped unless they are
    // themselves an artifact name, and nothing inside a claimed artifact is
    // claimed again. Index order is topological, so one forward pass suffices.
    let skip_top: HashSet<&str> = SKIP_TOP_LEVEL.iter().copied().collect();
    let hidden_artifacts: HashSet<&str> = rules()
        .artifacts
        .iter()
        .map(|r| r.dir_name.as_str())
        .filter(|n| n.starts_with('.'))
        .collect();

    let mut eligible = vec![false; tree.nodes.len()];
    let mut claimed = vec![false; tree.nodes.len()];
    eligible[0] = true;

    for idx in 1..tree.nodes.len() {
        let node = &tree.nodes[idx];
        let parent = node.parent as usize;
        let hidden_ok =
            !node.name.starts_with('.') || hidden_artifacts.contains(node.name.as_str());
        let top_ok = node.depth != 1 || !skip_top.contains(node.name.as_str());
        eligible[idx] = eligible[parent] && !claimed[parent] && hidden_ok && top_ok;
    }

    for idx in 0..tree.nodes.len() {
        let node = &tree.nodes[idx];
        if node.parent == NONE || !eligible[idx] {
            continue;
        }
        let parent = &tree.nodes[node.parent as usize];
        // markers (Cargo.toml, package.json, ...) are files recorded during the
        // walk; sibling directories come from the parent's child list
        let siblings: HashSet<String> = parent
            .children
            .iter()
            .map(|&c| tree.nodes[c as usize].name.clone())
            .chain(parent.markers.iter().cloned())
            .collect();

        let path = tree.path_of(idx as u32);
        if is_user_excluded(tree, &path) {
            continue;
        }
        let Some(rule) = matcher.match_dir(&node.name, &siblings, &path) else {
            continue;
        };
        claimed[idx] = true;
        if rule.need_gitignored {
            deferred.push((idx as u32, path, rule.clone()));
        } else {
            direct.push((idx as u32, path, rule.clone()));
        }
    }

    direct.extend(filter_gitignored(deferred));
    direct
        .into_iter()
        .map(|(node, path, rule)| Finding {
            node,
            size: tree.nodes[node as usize].total_size,
            path,
            rule_id: rule.id,
            tier: rule.tier,
            label: rule.label,
            regen: rule.regen,
            warn: String::new(),
            source: "project",
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_parse_and_look_sane() {
        let r = rules();
        assert_eq!(r.schema, 2);
        assert!(r.statics.len() >= 50, "got {}", r.statics.len());
        assert!(r.artifacts.len() >= 30, "got {}", r.artifacts.len());
        for rule in &r.statics {
            assert!(["low", "medium", "high"].contains(&rule.tier.as_str()));
            assert!(!rule.label.is_empty());
            assert!(!rule.regen.is_empty());
            assert!(
                ["any", "macos", "windows", "linux"].contains(&rule.os.as_str()),
                "{} claims os {:?}",
                rule.id,
                rule.os
            );
        }
    }

    /// Every platform must have rules of its own to run. A table that filtered
    /// down to nothing on Windows would still parse, still pass every other
    /// check here, and find nothing at all on the machine it shipped to.
    #[test]
    fn each_platform_keeps_a_table_worth_running() {
        for platform in ["macos", "windows", "linux"] {
            let live = rules()
                .statics
                .iter()
                .filter(|rule| rule.os == "any" || rule.os == platform)
                .count();
            assert!(live >= 25, "{platform} is down to {live} static rules");
        }
    }

    #[test]
    fn ambiguous_directory_names_stay_gitignore_gated() {
        let by_name = rules().by_dir_name();
        for name in ["build", "dist", "out", "obj"] {
            for rule in by_name
                .get(name)
                .unwrap_or_else(|| panic!("{name} missing"))
            {
                assert!(rule.need_gitignored, "{name} must stay gated");
            }
        }
    }

    #[test]
    fn markers_are_required_where_the_cli_requires_them() {
        let matcher = ArtifactMatcher::new();
        let siblings: HashSet<String> = ["Cargo.toml".to_string()].into_iter().collect();
        let empty: HashSet<String> = HashSet::new();
        let path = Path::new("/nonexistent/target");

        assert!(matcher.match_dir("target", &siblings, path).is_some());
        assert!(
            matcher.match_dir("target", &empty, path).is_none(),
            "target/ without Cargo.toml or pom.xml must not be claimed"
        );
        assert!(
            matcher.match_dir("node_modules", &empty, path).is_some(),
            "node_modules is unambiguous"
        );
    }

    #[test]
    fn excluded_artifact_keeps_tree_boundary_without_becoming_a_finding() {
        let root = std::env::temp_dir().join(format!(
            "cachereaper-rules-excluded-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let excluded = root.join("node_modules");
        std::fs::create_dir_all(excluded.join("package")).unwrap();
        std::fs::write(excluded.join("package/blob"), b"data").unwrap();
        let tree = crate::scan::scan_with_options(
            &root,
            crate::scan::ScanOptions {
                markers: marker_vocabulary(),
                excluded_paths: vec![excluded.clone()],
                ..crate::scan::ScanOptions::default()
            },
        )
        .unwrap();
        assert_eq!(tree.nodes.len(), 2);
        assert!(all_findings(&tree, false).is_empty());
        assert_eq!(tree.stats.excluded_paths, vec![excluded]);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn rule_exclusion_suppresses_finding_without_removing_tree_bytes() {
        let root = std::env::temp_dir().join(format!(
            "cachereaper-rules-suppressed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("node_modules/package")).unwrap();
        std::fs::write(root.join("node_modules/package/blob"), vec![1u8; 8192]).unwrap();
        let tree = crate::scan::scan_with_markers(
            &root,
            2,
            marker_vocabulary(),
            Vec::new(),
            |_, _| {},
        )
        .unwrap();
        assert!(tree.root().total_size > 0);
        let excluded = ["node-modules".to_string()].into_iter().collect();
        assert!(all_findings_excluding(&tree, false, &excluded).is_empty());
        assert!(tree.root().total_size > 0);
        std::fs::remove_dir_all(root).ok();
    }
}
