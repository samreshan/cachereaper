//! Deterministic, snapshot-bound cleanup planning.
//!
//! Plans select only actions already permitted by typed insights. They are
//! review documents, not execution requests; the destructive command layer
//! still revalidates fresh filesystem evidence before changing anything.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::insights::{Insight, InsightKind, PermittedAction, Recoverability, Risk};

pub const PLAN_SCHEMA: u16 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PlanPolicy {
    Safest,
    Balanced,
    Maximum,
    FastestRecovery,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PlanActionKind {
    PurgeCache,
    TrashVerifiedDuplicate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ReclaimTiming {
    Immediate,
    AfterTrashEmptied,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum RebuildCost {
    None,
    Low,
    Moderate,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlanAction {
    pub id: String,
    pub insight_id: String,
    pub kind: PlanActionKind,
    pub paths: Vec<String>,
    pub node_ids: Vec<u32>,
    pub estimated_reclaimable_bytes: u64,
    pub reclaim_timing: ReclaimTiming,
    pub risk: Risk,
    pub recoverability: Recoverability,
    pub estimated_rebuild_cost: RebuildCost,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupPlan {
    pub schema: u16,
    pub snapshot_id: String,
    pub target_bytes: u64,
    pub policy: PlanPolicy,
    pub actions: Vec<PlanAction>,
    pub estimated_reclaimable_bytes: u64,
    pub immediate_reclaimable_bytes: u64,
    pub estimated_time_seconds: u64,
    /// `None` means evidence cannot support a credible download estimate.
    pub estimated_bandwidth_bytes: Option<u64>,
    pub estimated_rebuild_cost: RebuildCost,
    pub target_met: bool,
    pub risks: Vec<String>,
    pub excluded_alternatives: Vec<String>,
}

pub fn generate_cleanup_plan(
    snapshot_id: &str,
    target_bytes: u64,
    policy: PlanPolicy,
    insights: &[Insight],
    protected_roots: &[PathBuf],
) -> CleanupPlan {
    let mut candidates = Vec::new();
    let mut excluded = Vec::new();

    for insight in insights {
        match insight.kind {
            InsightKind::CacheArtifact => {
                let risk_allowed = match policy {
                    PlanPolicy::Safest | PlanPolicy::FastestRecovery => insight.risk == Risk::Low,
                    PlanPolicy::Balanced => insight.risk <= Risk::Medium,
                    PlanPolicy::Maximum => true,
                };
                if risk_allowed
                    && insight
                        .permitted_actions
                        .contains(&PermittedAction::PurgeCache)
                {
                    candidates.push(action_for_cache(insight));
                } else {
                    excluded.push(format!(
                        "{}: cache risk exceeds the {:?} policy",
                        insight.id, policy
                    ));
                }
            }
            InsightKind::ExactDuplicate
                if matches!(policy, PlanPolicy::Maximum | PlanPolicy::FastestRecovery) =>
            {
                if !insight
                    .permitted_actions
                    .contains(&PermittedAction::TrashVerifiedDuplicate)
                {
                    excluded.push(format!("{}: duplicate evidence is incomplete", insight.id));
                    continue;
                }
                let mut paths = insight.paths.clone();
                paths.sort();
                let evidence_removable_count = paths.len().saturating_sub(1) as u64;
                let keep = paths
                    .iter()
                    .find(|path| is_protected(path, protected_roots))
                    .cloned()
                    .or_else(|| paths.first().cloned());
                let removable: Vec<String> = paths
                    .into_iter()
                    .filter(|path| {
                        Some(path) != keep.as_ref() && !is_protected(path, protected_roots)
                    })
                    .collect();
                if removable.is_empty() {
                    excluded.push(format!(
                        "{}: no unprotected duplicate member is eligible",
                        insight.id
                    ));
                } else {
                    let per_file = insight
                        .estimated_reclaimable_bytes
                        .checked_div(evidence_removable_count)
                        .unwrap_or(0);
                    for (index, path) in removable.into_iter().enumerate() {
                        candidates.push(PlanAction {
                            id: format!("{}-trash-{index}", insight.id), insight_id: insight.id.clone(), kind: PlanActionKind::TrashVerifiedDuplicate,
                            paths: vec![path], node_ids: vec![], estimated_reclaimable_bytes: per_file,
                            reclaim_timing: ReclaimTiming::AfterTrashEmptied, risk: Risk::Medium,
                            recoverability: Recoverability::PlatformTrash,
                            estimated_rebuild_cost: RebuildCost::None,
                            explanation: "Move one byte-verified duplicate to system Trash after reviewing which copy to keep. Space returns only after Trash is emptied.".into(),
                        });
                    }
                }
            }
            InsightKind::ExactDuplicate => excluded.push(format!(
                "{}: personal-file actions are outside the {:?} policy",
                insight.id, policy
            )),
            _ => excluded.push(format!(
                "{}: read-only insight has no cleanup action",
                insight.id
            )),
        }
    }

    candidates.sort_by(|a, b| {
        action_priority(a, policy)
            .cmp(&action_priority(b, policy))
            .then_with(|| {
                b.estimated_reclaimable_bytes
                    .cmp(&a.estimated_reclaimable_bytes)
            })
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut actions = Vec::new();
    let mut planned = 0_u64;
    let mut seen_paths: Vec<PathBuf> = Vec::new();
    for action in candidates {
        if target_bytes == 0 || planned >= target_bytes {
            break;
        }
        if action.paths.iter().any(|path| {
            let candidate = Path::new(path);
            seen_paths
                .iter()
                .any(|seen| candidate.starts_with(seen) || seen.starts_with(candidate))
        }) {
            continue;
        }
        seen_paths.extend(action.paths.iter().map(PathBuf::from));
        planned = planned.saturating_add(action.estimated_reclaimable_bytes);
        actions.push(action);
    }

    let immediate = actions
        .iter()
        .filter(|action| action.reclaim_timing == ReclaimTiming::Immediate)
        .map(|action| action.estimated_reclaimable_bytes)
        .sum();
    let estimated_time_seconds = actions.iter().fold(0_u64, |seconds, action| {
        seconds.saturating_add(1_u64.max(action.estimated_reclaimable_bytes / (200 * 1024 * 1024)))
    });
    let estimated_rebuild_cost = actions
        .iter()
        .map(|action| action.estimated_rebuild_cost)
        .max()
        .unwrap_or(RebuildCost::None);
    let mut risks = Vec::new();
    if actions.iter().any(|action| action.risk == Risk::High) {
        risks.push("High-risk cache actions require explicit review and typed confirmation at execution time.".into());
    }
    if actions
        .iter()
        .any(|action| action.reclaim_timing == ReclaimTiming::AfterTrashEmptied)
    {
        risks.push(
            "Duplicate files in system Trash do not release usable space until Trash is emptied."
                .into(),
        );
    }
    if target_bytes > planned {
        risks.push(
            "The permitted evidence in this snapshot cannot meet the requested target.".into(),
        );
    }

    CleanupPlan {
        schema: PLAN_SCHEMA,
        snapshot_id: snapshot_id.to_string(),
        target_bytes,
        policy,
        actions,
        estimated_reclaimable_bytes: planned,
        immediate_reclaimable_bytes: immediate,
        estimated_time_seconds,
        estimated_bandwidth_bytes: None,
        estimated_rebuild_cost,
        target_met: target_bytes == 0 || planned >= target_bytes,
        risks,
        excluded_alternatives: excluded,
    }
}

fn action_for_cache(insight: &Insight) -> PlanAction {
    PlanAction {
        id: format!("{}-purge", insight.id),
        insight_id: insight.id.clone(),
        kind: PlanActionKind::PurgeCache,
        paths: insight.paths.clone(),
        node_ids: insight.node_ids.clone(),
        estimated_reclaimable_bytes: insight.estimated_reclaimable_bytes,
        reclaim_timing: ReclaimTiming::Immediate,
        risk: insight.risk,
        recoverability: Recoverability::Regenerate,
        estimated_rebuild_cost: match insight.risk {
            Risk::Low => RebuildCost::Low,
            Risk::Medium => RebuildCost::Moderate,
            Risk::High => RebuildCost::High,
        },
        explanation: insight.explanation.clone(),
    }
}

fn action_priority(action: &PlanAction, policy: PlanPolicy) -> (u8, u8) {
    let timing = match (policy, action.reclaim_timing) {
        (PlanPolicy::FastestRecovery, ReclaimTiming::AfterTrashEmptied) => 0,
        (_, ReclaimTiming::Immediate) => 0,
        _ => 1,
    };
    let risk = match action.risk {
        Risk::Low => 0,
        Risk::Medium => 1,
        Risk::High => 2,
    };
    (timing, risk)
}

fn is_protected(path: &str, roots: &[PathBuf]) -> bool {
    let path = Path::new(path);
    roots
        .iter()
        .any(|root| path.starts_with(root) || root.starts_with(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Evidence, Provenance};

    fn insight(
        id: &str,
        kind: InsightKind,
        risk: Risk,
        bytes: u64,
        paths: &[&str],
        actions: &[PermittedAction],
    ) -> Insight {
        Insight {
            schema: 1,
            id: id.into(),
            kind,
            title: id.into(),
            explanation: "why".into(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
            node_ids: vec![1],
            estimated_reclaimable_bytes: bytes,
            confidence_millis: 1000,
            risk,
            recoverability: Recoverability::Regenerate,
            category: None,
            modified_at: None,
            evidence: Vec::<Evidence>::new(),
            provenance: Provenance::Rule,
            permitted_actions: actions.to_vec(),
        }
    }

    #[test]
    fn safest_is_deterministic_and_low_risk_only() {
        let input = vec![
            insight(
                "big",
                InsightKind::CacheArtifact,
                Risk::Medium,
                90,
                &["/cache/big"],
                &[PermittedAction::PurgeCache],
            ),
            insight(
                "small",
                InsightKind::CacheArtifact,
                Risk::Low,
                60,
                &["/cache/small"],
                &[PermittedAction::PurgeCache],
            ),
        ];
        let a = generate_cleanup_plan("scan", 50, PlanPolicy::Safest, &input, &[]);
        let b = generate_cleanup_plan("scan", 50, PlanPolicy::Safest, &input, &[]);
        assert_eq!(a, b);
        assert_eq!(a.actions.len(), 1);
        assert_eq!(a.actions[0].insight_id, "small");
    }

    #[test]
    fn never_invents_an_unpermitted_action() {
        let read_only = insight(
            "large",
            InsightKind::LargeFile,
            Risk::High,
            999,
            &["/personal"],
            &[PermittedAction::Reveal],
        );
        let plan = generate_cleanup_plan("scan", 1, PlanPolicy::Maximum, &[read_only], &[]);
        assert!(plan.actions.is_empty());
        assert!(!plan.target_met);
    }

    #[test]
    fn zero_target_is_an_empty_plan() {
        let cache = insight(
            "cache",
            InsightKind::CacheArtifact,
            Risk::Low,
            50,
            &["/cache"],
            &[PermittedAction::PurgeCache],
        );
        let plan = generate_cleanup_plan("scan", 0, PlanPolicy::Safest, &[cache], &[]);
        assert!(plan.actions.is_empty());
        assert!(plan.target_met);
    }

    #[test]
    fn duplicate_plan_keeps_a_protected_reference() {
        let duplicate = insight(
            "dup",
            InsightKind::ExactDuplicate,
            Risk::Medium,
            20,
            &["/archive/master", "/downloads/copy"],
            &[PermittedAction::TrashVerifiedDuplicate],
        );
        let plan = generate_cleanup_plan(
            "scan",
            10,
            PlanPolicy::Maximum,
            &[duplicate],
            &[PathBuf::from("/archive")],
        );
        assert_eq!(plan.actions[0].paths, vec!["/downloads/copy"]);
        assert_eq!(plan.immediate_reclaimable_bytes, 0);
    }
}
