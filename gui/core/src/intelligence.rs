//! Deterministic ownership, project-cost, forecasting, and anomaly analysis.
//!
//! Every result is bounded and explanatory. Ownership misses are explicitly
//! labelled "possible" because an installed-application catalogue is never a
//! perfect uninstall oracle, and forecasts refuse to extrapolate without time.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{Finding, RebuildCost, ScanMode, ScanSnapshot, Tree};

pub const INTELLIGENCE_SCHEMA: u16 = 1;
pub const PROJECT_MARKERS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "requirements.txt",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "Package.swift",
    "Package.resolved",
    "Podfile",
    "Podfile.lock",
    "go.mod",
    "go.sum",
    "pubspec.yaml",
    "pubspec.lock",
    "mix.exs",
    "mix.lock",
];
const MAX_OWNERSHIP: usize = 100;
const MAX_PROJECTS: usize = 100;
const MIN_OWNERSHIP_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct ApplicationCatalog {
    identifiers: BTreeSet<String>,
    pub complete: bool,
}

impl ApplicationCatalog {
    pub fn from_identifiers(identifiers: impl IntoIterator<Item = String>, complete: bool) -> Self {
        let identifiers = identifiers
            .into_iter()
            .flat_map(|value| identifier_aliases(&value))
            .collect();
        Self {
            identifiers,
            complete,
        }
    }

    fn contains(&self, owner: &str) -> bool {
        identifier_aliases(owner)
            .iter()
            .any(|alias| self.identifiers.contains(alias))
    }

    pub fn len(&self) -> usize {
        self.identifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.identifiers.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OwnershipState {
    InstalledMatch,
    PossibleLeftover,
    Unresolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnershipEvidence {
    pub path: String,
    pub owner_identifier: String,
    pub allocated_bytes: u64,
    pub state: OwnershipState,
    pub confidence_millis: u16,
    pub catalog_complete: bool,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectEstimate {
    pub root: String,
    pub ecosystem: String,
    pub manifest: String,
    pub lockfile_present: bool,
    pub repository_present: bool,
    pub artifact_paths: Vec<String>,
    pub artifact_bytes: u64,
    pub estimated_regeneration_seconds: u64,
    pub estimated_bandwidth_bytes: Option<u64>,
    pub rebuild_cost: RebuildCost,
    pub confidence_millis: u16,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AnomalySeverity {
    Notice,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrowthAnomaly {
    pub scope: String,
    pub label: String,
    pub observed_delta_bytes: i128,
    pub baseline_delta_bytes: i128,
    pub severity: AnomalySeverity,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForecastReport {
    pub schema: u16,
    pub snapshot_count: usize,
    pub span_days_millis: u64,
    pub growth_bytes_per_day: i128,
    pub confidence_millis: u16,
    pub days_until_low_space: Option<u64>,
    pub low_space_threshold_bytes: Option<u64>,
    pub anomalies: Vec<GrowthAnomaly>,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelligenceSummary {
    pub schema: u16,
    pub ownership: Vec<OwnershipEvidence>,
    pub projects: Vec<ProjectEstimate>,
    pub forecast: Option<ForecastReport>,
}

pub fn analyze_ownership(tree: &Tree, catalog: &ApplicationCatalog) -> Vec<OwnershipEvidence> {
    let mut results = Vec::new();
    for (index, node) in tree.nodes.iter().enumerate().skip(1) {
        if node.total_size < MIN_OWNERSHIP_BYTES {
            continue;
        }
        let path = tree.path_of(index as u32).to_string_lossy().into_owned();
        let Some(owner) = owner_from_path(&path) else {
            continue;
        };
        let matched = catalog.contains(&owner);
        let (state, confidence_millis, explanation) = if matched {
            (
                OwnershipState::InstalledMatch,
                900,
                "The cache owner matches an identifier in the local installed-application catalogue."
                    .to_string(),
            )
        } else if catalog.is_empty() {
            (
                OwnershipState::Unresolved,
                250,
                "No installed-application catalogue was available, so ownership could not be checked."
                    .to_string(),
            )
        } else {
            (
                OwnershipState::PossibleLeftover,
                if catalog.complete { 750 } else { 550 },
                "No matching identifier was found in the local application catalogue. This is a review hint, not proof that the application was uninstalled."
                    .to_string(),
            )
        };
        results.push(OwnershipEvidence {
            path,
            owner_identifier: owner,
            allocated_bytes: node.total_size,
            state,
            confidence_millis,
            catalog_complete: catalog.complete,
            explanation,
        });
    }
    results.sort_by(|a, b| {
        b.allocated_bytes
            .cmp(&a.allocated_bytes)
            .then_with(|| a.path.cmp(&b.path))
    });
    results.truncate(MAX_OWNERSHIP);
    results
}

pub fn analyze_projects(tree: &Tree, findings: &[Finding]) -> Vec<ProjectEstimate> {
    let mut projects = Vec::new();
    for (index, node) in tree.nodes.iter().enumerate() {
        let Some((manifest, ecosystem, lockfiles, base_seconds, bytes_per_second)) =
            project_kind(&node.markers)
        else {
            continue;
        };
        let root = tree.path_of(index as u32);
        let mut artifacts: Vec<&Finding> = findings
            .iter()
            .filter(|finding| finding.path.starts_with(&root))
            .collect();
        if artifacts.is_empty() {
            continue;
        }
        artifacts.sort_by(|a, b| a.path.cmp(&b.path));
        let artifact_bytes = artifacts
            .iter()
            .fold(0_u64, |total, finding| total.saturating_add(finding.size));
        let lockfile_present = lockfiles
            .iter()
            .any(|lockfile| node.markers.iter().any(|marker| marker == lockfile));
        let repository_present = node.children.iter().any(|child| {
            tree.nodes
                .get(*child as usize)
                .is_some_and(|child| child.name == ".git")
        });
        let estimated_regeneration_seconds = base_seconds
            + artifact_bytes
                .checked_div(bytes_per_second)
                .unwrap_or_default();
        let rebuild_cost = match (estimated_regeneration_seconds, lockfile_present) {
            (0..=30, true) => RebuildCost::Low,
            (0..=120, _) => RebuildCost::Moderate,
            _ => RebuildCost::High,
        };
        let artifact_paths = artifacts
            .iter()
            .map(|finding| finding.path.to_string_lossy().into_owned())
            .collect();
        let mut evidence = vec![format!("manifest:{manifest}")];
        evidence.push(if lockfile_present {
            "lockfile:present".into()
        } else {
            "lockfile:not-observed".into()
        });
        evidence.push(if repository_present {
            "repository:present; working-tree state was not inspected".into()
        } else {
            "repository:not-observed".into()
        });
        evidence.extend(
            artifacts
                .iter()
                .map(|finding| format!("artifact-rule:{}", finding.rule_id)),
        );
        projects.push(ProjectEstimate {
            root: root.to_string_lossy().into_owned(),
            ecosystem: ecosystem.into(),
            manifest: manifest.into(),
            lockfile_present,
            repository_present,
            artifact_paths,
            artifact_bytes,
            estimated_regeneration_seconds,
            estimated_bandwidth_bytes: Some(artifact_bytes),
            rebuild_cost,
            confidence_millis: if lockfile_present { 800 } else { 650 },
            evidence,
        });
    }
    projects.sort_by(|a, b| {
        b.artifact_bytes
            .cmp(&a.artifact_bytes)
            .then_with(|| a.root.cmp(&b.root))
    });
    projects.truncate(MAX_PROJECTS);
    projects
}

pub fn forecast_snapshots(
    snapshots: &[ScanSnapshot],
    root: &str,
    mode: ScanMode,
    volume_capacity: Option<u64>,
    volume_free: Option<u64>,
) -> Option<ForecastReport> {
    let mut series: Vec<&ScanSnapshot> = snapshots
        .iter()
        .filter(|snapshot| snapshot.root == root && snapshot.mode == mode)
        .collect();
    series.sort_by_key(|snapshot| snapshot.finished_at);
    if series.len() < 2 {
        return None;
    }
    let span_ms = series
        .last()?
        .finished_at
        .saturating_sub(series.first()?.finished_at);
    if span_ms < 60 * 60 * 1000 {
        return None;
    }
    let mut slopes = Vec::new();
    for left in 0..series.len() {
        for right in left + 1..series.len() {
            let elapsed = series[right]
                .finished_at
                .saturating_sub(series[left].finished_at);
            if elapsed < 60 * 60 * 1000 {
                continue;
            }
            let delta = i128::from(series[right].allocated_bytes)
                - i128::from(series[left].allocated_bytes);
            slopes.push(delta.saturating_mul(86_400_000) / elapsed as i128);
        }
    }
    if slopes.is_empty() {
        return None;
    }
    slopes.sort();
    let growth_per_day = median_i128(&slopes);
    let deviations: Vec<i128> = slopes
        .iter()
        .map(|slope| (*slope - growth_per_day).abs())
        .collect();
    let dispersion = median_i128(&sorted(deviations)).unsigned_abs();
    let signal = growth_per_day.unsigned_abs().max(1);
    let stability = 1000_u128.saturating_sub((dispersion.saturating_mul(1000) / signal).min(900));
    let sample_factor = (series.len() as u128 * 125).min(1000);
    let confidence_millis = stability.min(sample_factor) as u16;
    let threshold = volume_capacity.map(|capacity| capacity / 10);
    let days_until_low_space = match (growth_per_day > 0, volume_free, threshold) {
        (true, Some(free), Some(threshold)) => {
            let daily_growth = growth_per_day.unsigned_abs().min(u128::from(u64::MAX)) as u64;
            Some(
                free.saturating_sub(threshold)
                    .checked_div(daily_growth)
                    .unwrap_or(0),
            )
        }
        _ => None,
    };
    let anomalies = detect_anomalies(&series);
    Some(ForecastReport {
        schema: INTELLIGENCE_SCHEMA,
        snapshot_count: series.len(),
        span_days_millis: ((span_ms.saturating_mul(1000)) / 86_400_000).min(u64::MAX as u128)
            as u64,
        growth_bytes_per_day: growth_per_day,
        confidence_millis,
        days_until_low_space,
        low_space_threshold_bytes: threshold,
        anomalies,
        explanation: "Growth uses a median pairwise slope across local snapshots; anomalies compare the newest interval with prior deltas. Forecasts are estimates, never cleanup authority.".into(),
    })
}

fn detect_anomalies(series: &[&ScanSnapshot]) -> Vec<GrowthAnomaly> {
    if series.len() < 3 {
        return Vec::new();
    }
    let latest = series[series.len() - 1];
    let previous = series[series.len() - 2];
    let mut output = Vec::new();
    detect_scope_anomalies(
        "category",
        &previous
            .categories
            .iter()
            .map(|item| (item.category.as_str(), item.allocated_bytes))
            .collect(),
        &latest
            .categories
            .iter()
            .map(|item| (item.category.as_str(), item.allocated_bytes))
            .collect(),
        series,
        &mut output,
    );
    detect_scope_anomalies(
        "directory",
        &previous
            .directory_summaries
            .iter()
            .map(|item| (item.path.as_str(), item.allocated_bytes))
            .collect(),
        &latest
            .directory_summaries
            .iter()
            .map(|item| (item.path.as_str(), item.allocated_bytes))
            .collect(),
        series,
        &mut output,
    );
    output.sort_by(|a, b| {
        b.observed_delta_bytes
            .cmp(&a.observed_delta_bytes)
            .then_with(|| a.label.cmp(&b.label))
    });
    output.truncate(20);
    output
}

fn detect_scope_anomalies(
    scope: &str,
    before: &BTreeMap<&str, u64>,
    after: &BTreeMap<&str, u64>,
    series: &[&ScanSnapshot],
    output: &mut Vec<GrowthAnomaly>,
) {
    for (label, after_bytes) in after {
        let observed = i128::from(*after_bytes) - i128::from(*before.get(label).unwrap_or(&0));
        if observed < 256 * 1024 * 1024 {
            continue;
        }
        let history = historic_deltas(scope, label, &series[..series.len() - 1]);
        let baseline = if history.is_empty() {
            0
        } else {
            median_i128(&sorted(history))
        };
        if baseline > 0 && observed < baseline.saturating_mul(3) {
            continue;
        }
        let severity = if observed >= 5 * 1024 * 1024 * 1024 {
            AnomalySeverity::Critical
        } else if observed >= 1024 * 1024 * 1024 {
            AnomalySeverity::Warning
        } else {
            AnomalySeverity::Notice
        };
        output.push(GrowthAnomaly {
            scope: scope.into(),
            label: (*label).into(),
            observed_delta_bytes: observed,
            baseline_delta_bytes: baseline,
            severity,
            explanation: format!(
                "The newest snapshot added {observed} bytes here versus a prior median change of {baseline} bytes."
            ),
        });
    }
}

fn historic_deltas(scope: &str, label: &str, series: &[&ScanSnapshot]) -> Vec<i128> {
    series
        .windows(2)
        .map(|pair| {
            let value = |snapshot: &ScanSnapshot| -> u64 {
                if scope == "category" {
                    snapshot
                        .categories
                        .iter()
                        .find(|item| item.category == label)
                        .map(|item| item.allocated_bytes)
                        .unwrap_or(0)
                } else {
                    snapshot
                        .directory_summaries
                        .iter()
                        .find(|item| item.path == label)
                        .map(|item| item.allocated_bytes)
                        .unwrap_or(0)
                }
            };
            i128::from(value(pair[1])) - i128::from(value(pair[0]))
        })
        .collect()
}

fn owner_from_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let lowered = normalized.to_ascii_lowercase();
    for marker in [
        "/library/caches/",
        "/library/application support/",
        "/.cache/",
        "/appdata/local/",
        "/appdata/roaming/",
        "/packages/",
    ] {
        let Some(position) = lowered.find(marker) else {
            continue;
        };
        let start = position + marker.len();
        let mut remainder = normalized[start..].split('/');
        let owner = remainder.next()?.trim();
        if remainder.next().is_some() {
            continue;
        }
        if owner.is_empty()
            || matches!(
                owner.to_ascii_lowercase().as_str(),
                "cache" | "caches" | "temp" | "temporaryitems"
            )
        {
            return None;
        }
        return Some(owner.to_string());
    }
    None
}

fn identifier_aliases(value: &str) -> Vec<String> {
    let lowered = value.trim_end_matches(".app").to_ascii_lowercase();
    let mut aliases = vec![normalize_identifier(&lowered)];
    if let Some(last) = lowered
        .split(|character: char| !character.is_ascii_alphanumeric())
        .rfind(|part| part.len() > 2)
    {
        aliases.push(normalize_identifier(last));
    }
    aliases.retain(|alias| alias.len() >= 3);
    aliases.sort();
    aliases.dedup();
    aliases
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[allow(clippy::type_complexity)]
fn project_kind(
    markers: &[String],
) -> Option<(
    &'static str,
    &'static str,
    &'static [&'static str],
    u64,
    u64,
)> {
    let has = |name: &str| markers.iter().any(|marker| marker == name);
    if has("Cargo.toml") {
        Some(("Cargo.toml", "Rust", &["Cargo.lock"], 10, 80 * 1024 * 1024))
    } else if has("package.json") {
        Some((
            "package.json",
            "JavaScript",
            &["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
            5,
            150 * 1024 * 1024,
        ))
    } else if has("pyproject.toml") || has("requirements.txt") {
        Some((
            if has("pyproject.toml") {
                "pyproject.toml"
            } else {
                "requirements.txt"
            },
            "Python",
            &["poetry.lock", "uv.lock"],
            5,
            100 * 1024 * 1024,
        ))
    } else if has("pom.xml") || has("build.gradle") || has("build.gradle.kts") {
        Some((
            if has("pom.xml") {
                "pom.xml"
            } else if has("build.gradle.kts") {
                "build.gradle.kts"
            } else {
                "build.gradle"
            },
            "JVM",
            &["gradle.lockfile"],
            15,
            50 * 1024 * 1024,
        ))
    } else if has("Package.swift") {
        Some((
            "Package.swift",
            "Swift",
            &["Package.resolved"],
            12,
            60 * 1024 * 1024,
        ))
    } else if has("Podfile") {
        Some((
            "Podfile",
            "CocoaPods",
            &["Podfile.lock"],
            20,
            40 * 1024 * 1024,
        ))
    } else if has("go.mod") {
        Some(("go.mod", "Go", &["go.sum"], 5, 120 * 1024 * 1024))
    } else if has("pubspec.yaml") {
        Some((
            "pubspec.yaml",
            "Dart",
            &["pubspec.lock"],
            8,
            80 * 1024 * 1024,
        ))
    } else if has("mix.exs") {
        Some(("mix.exs", "Elixir", &["mix.lock"], 8, 70 * 1024 * 1024))
    } else {
        None
    }
}

fn sorted(mut values: Vec<i128>) -> Vec<i128> {
    values.sort();
    values
}

fn median_i128(values: &[i128]) -> i128 {
    if values.is_empty() {
        0
    } else if values.len() % 2 == 1 {
        values[values.len() / 2]
    } else {
        values[values.len() / 2 - 1].saturating_add(values[values.len() / 2]) / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{SnapshotCategory, SnapshotDirectory};

    fn snapshot(id: &str, day: u128, bytes: u64, video: u64) -> ScanSnapshot {
        ScanSnapshot {
            schema: 1,
            snapshot_id: id.into(),
            mode: ScanMode::Whole,
            root: "/fixture".into(),
            root_identity: "volume:root".into(),
            finished_at: day * 86_400_000,
            files: 10,
            directories: 2,
            allocated_bytes: bytes,
            logical_bytes: bytes,
            reclaimable_bytes: bytes,
            categories: vec![SnapshotCategory {
                category: "Video".into(),
                files: 1,
                allocated_bytes: video,
                logical_bytes: video,
            }],
            directory_summaries: vec![SnapshotDirectory {
                path: "/fixture/Videos".into(),
                files: 1,
                allocated_bytes: video,
                logical_bytes: video,
            }],
        }
    }

    #[test]
    fn application_aliases_match_bundle_style_cache_owners() {
        let catalog = ApplicationCatalog::from_identifiers(
            vec!["Safari.app".into(), "Google Chrome.app".into()],
            false,
        );
        assert!(catalog.contains("com.apple.Safari"));
        assert!(catalog.contains("com.google.Chrome"));
        assert_eq!(
            owner_from_path("/Users/a/Library/Caches/com.google.Chrome"),
            Some("com.google.Chrome".into())
        );
    }

    #[test]
    fn project_markers_produce_bounded_cost_inputs() {
        let markers = vec!["Cargo.toml".into(), "Cargo.lock".into()];
        let (manifest, ecosystem, locks, _, _) = project_kind(&markers).unwrap();
        assert_eq!((manifest, ecosystem), ("Cargo.toml", "Rust"));
        assert_eq!(locks, &["Cargo.lock"]);
    }

    #[test]
    fn forecast_uses_robust_growth_and_predicts_pressure() {
        let gib = 1024_u64.pow(3);
        let values = vec![
            snapshot("a", 1, 10 * gib, gib),
            snapshot("b", 2, 11 * gib, 2 * gib),
            snapshot("c", 3, 12 * gib, 3 * gib),
        ];
        let report = forecast_snapshots(
            &values,
            "/fixture",
            ScanMode::Whole,
            Some(20 * gib),
            Some(8 * gib),
        )
        .unwrap();
        assert_eq!(report.growth_bytes_per_day, i128::from(gib));
        assert_eq!(report.days_until_low_space, Some(6));
        assert!(report.confidence_millis > 0);
    }

    #[test]
    fn sudden_growth_is_an_anomaly_but_not_an_action() {
        let mib = 1024_u64.pow(2);
        let values = vec![
            snapshot("a", 1, 10 * mib, 10 * mib),
            snapshot("b", 2, 20 * mib, 20 * mib),
            snapshot("c", 3, 2_000 * mib, 2_000 * mib),
        ];
        let report = forecast_snapshots(&values, "/fixture", ScanMode::Whole, None, None).unwrap();
        assert!(report.anomalies.iter().any(|value| value.label == "Video"));
    }

    #[test]
    fn refuses_forecast_without_meaningful_elapsed_time() {
        let a = snapshot("a", 1, 1, 1);
        let mut b = a.clone();
        b.snapshot_id = "b".into();
        b.finished_at += 1000;
        assert!(forecast_snapshots(&[a, b], "/fixture", ScanMode::Whole, None, None).is_none());
    }
}
