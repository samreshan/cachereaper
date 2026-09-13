//! Optional local-model presentation adapter.
//!
//! A model may rank known insight IDs and offer short explanatory prose. It
//! cannot return paths, actions, commands, or new IDs. `deny_unknown_fields`
//! makes that boundary fail closed even when the JSON is otherwise valid.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{Insight, InsightKind, Recoverability, Risk};

const MODEL_SCHEMA: u16 = 1;
const MAX_MODEL_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_EXPLANATION_CHARS: usize = 500;
const MAX_MODEL_INSIGHTS: usize = 200;
const MAX_MODEL_PROMPT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LocalAiStatus {
    pub enabled: bool,
    pub privacy: &'static str,
    pub authority: &'static str,
}

impl LocalAiStatus {
    pub fn current() -> Self {
        Self {
            enabled: cfg!(feature = "local-ai"),
            privacy: "local-only",
            authority: "presentation-only; deterministic evidence controls every action",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelOutput {
    schema: u16,
    rankings: Vec<ModelRanking>,
    explanations: Vec<ModelExplanation>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelRanking {
    insight_id: String,
    score_millis: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelExplanation {
    insight_id: String,
    text: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidatedModelPresentation {
    pub schema: u16,
    pub rankings: Vec<ValidatedRanking>,
    pub explanations: Vec<ValidatedExplanation>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidatedRanking {
    pub insight_id: String,
    pub score_millis: u16,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ValidatedExplanation {
    pub insight_id: String,
    pub text: String,
}

#[derive(Serialize)]
struct SanitizedModelRequest<'a> {
    schema: u16,
    instruction: &'static str,
    request: &'a str,
    insights: Vec<SanitizedInsight<'a>>,
}

#[derive(Serialize)]
struct SanitizedInsight<'a> {
    id: &'a str,
    kind: InsightKind,
    title: &'a str,
    estimated_reclaimable_bytes: u64,
    risk: Risk,
    recoverability: Recoverability,
    category: Option<&'a str>,
}

/// Create the only prompt shape the built-in adapter will send. Filesystem
/// paths, evidence values, and permitted actions are intentionally absent.
pub fn build_model_prompt(request: &str, insights: &[Insight]) -> Result<String, String> {
    if request.is_empty() || request.len() > 4_096 || request.chars().any(char::is_control) {
        return Err(
            "local model request is empty, too long, or contains control characters".into(),
        );
    }
    let mut candidates: Vec<&Insight> = insights.iter().collect();
    candidates.sort_by(|a, b| {
        b.estimated_reclaimable_bytes
            .cmp(&a.estimated_reclaimable_bytes)
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.truncate(MAX_MODEL_INSIGHTS);
    let insights = candidates
        .into_iter()
        .map(|insight| SanitizedInsight {
            id: &insight.id,
            kind: insight.kind,
            title: &insight.title,
            estimated_reclaimable_bytes: insight.estimated_reclaimable_bytes,
            risk: insight.risk,
            recoverability: insight.recoverability,
            category: insight.category.as_deref(),
        })
        .collect();
    let prompt = serde_json::to_string(&SanitizedModelRequest {
        schema: MODEL_SCHEMA,
        instruction: "Return JSON containing only rankings and explanations for supplied insight IDs. Never propose paths, commands, or actions.",
        request,
        insights,
    })
    .map_err(|error| error.to_string())?;
    if prompt.len() > MAX_MODEL_PROMPT_BYTES {
        return Err("sanitized local model prompt exceeds 256 KiB".into());
    }
    Ok(prompt)
}

pub fn validate_model_output(
    raw: &str,
    insights: &[Insight],
) -> Result<ValidatedModelPresentation, String> {
    if raw.len() > MAX_MODEL_OUTPUT_BYTES {
        return Err("local model output exceeds 64 KiB".into());
    }
    let output: ModelOutput =
        serde_json::from_str(raw).map_err(|error| format!("invalid local model JSON: {error}"))?;
    if output.schema != MODEL_SCHEMA {
        return Err(format!("unsupported local model schema {}", output.schema));
    }
    let known: HashSet<&str> = insights.iter().map(|insight| insight.id.as_str()).collect();
    let mut seen_rankings = HashSet::new();
    let mut rankings = Vec::new();
    for ranking in output.rankings {
        if !known.contains(ranking.insight_id.as_str()) {
            return Err(format!("unknown insight id {}", ranking.insight_id));
        }
        if ranking.score_millis > 1000 {
            return Err("model score must be between 0 and 1000".into());
        }
        if !seen_rankings.insert(ranking.insight_id.clone()) {
            return Err("duplicate model ranking".into());
        }
        rankings.push(ValidatedRanking {
            insight_id: ranking.insight_id,
            score_millis: ranking.score_millis,
        });
    }
    let mut seen_explanations = HashSet::new();
    let mut explanations = Vec::new();
    for explanation in output.explanations {
        if !known.contains(explanation.insight_id.as_str()) {
            return Err(format!("unknown insight id {}", explanation.insight_id));
        }
        if explanation.text.is_empty()
            || explanation.text.chars().count() > MAX_EXPLANATION_CHARS
            || explanation.text.chars().any(char::is_control)
        {
            return Err(
                "model explanation is empty, too long, or contains control characters".into(),
            );
        }
        if !seen_explanations.insert(explanation.insight_id.clone()) {
            return Err("duplicate model explanation".into());
        }
        explanations.push(ValidatedExplanation {
            insight_id: explanation.insight_id,
            text: explanation.text,
        });
    }
    rankings.sort_by(|a, b| {
        b.score_millis
            .cmp(&a.score_millis)
            .then_with(|| a.insight_id.cmp(&b.insight_id))
    });
    explanations.sort_by(|a, b| a.insight_id.cmp(&b.insight_id));
    Ok(ValidatedModelPresentation {
        schema: MODEL_SCHEMA,
        rankings,
        explanations,
    })
}

/// Implemented by an explicitly configured on-device runtime. No shell or
/// network implementation is built into the safety core.
#[cfg(feature = "local-ai")]
pub trait LocalModelRuntime {
    fn infer_json(&self, prompt: &str) -> Result<String, String>;
}

#[cfg(feature = "local-ai")]
pub fn run_local_model<R: LocalModelRuntime>(
    runtime: &R,
    request: &str,
    insights: &[Insight],
) -> Result<ValidatedModelPresentation, String> {
    let prompt = build_model_prompt(request, insights)?;
    validate_model_output(&runtime.infer_json(&prompt)?, insights)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InsightKind, PermittedAction, Provenance, Recoverability, Risk};

    fn known() -> Vec<Insight> {
        vec![Insight {
            schema: 1,
            id: "known".into(),
            kind: InsightKind::CacheArtifact,
            title: "Cache".into(),
            explanation: "Rule evidence".into(),
            paths: vec!["/cache".into()],
            node_ids: vec![1],
            estimated_reclaimable_bytes: 10,
            confidence_millis: 1000,
            risk: Risk::Low,
            recoverability: Recoverability::Regenerate,
            category: Some("Cache".into()),
            modified_at: None,
            evidence: vec![],
            provenance: Provenance::Rule,
            permitted_actions: vec![PermittedAction::PurgeCache],
        }]
    }

    #[test]
    fn validates_presentation_only_output() {
        let value = validate_model_output(r#"{"schema":1,"rankings":[{"insight_id":"known","score_millis":900}],"explanations":[{"insight_id":"known","text":"High value cache."}]}"#, &known()).unwrap();
        assert_eq!(value.rankings[0].insight_id, "known");
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(validate_model_output(&encoded, &known()).unwrap(), value);
    }

    #[test]
    fn rejects_action_or_path_injection() {
        for raw in [
            r#"{"schema":1,"rankings":[],"explanations":[],"permitted_actions":["delete"]}"#,
            r#"{"schema":1,"rankings":[{"insight_id":"known","score_millis":1,"path":"/etc"}],"explanations":[]}"#,
            r#"{"schema":1,"rankings":[{"insight_id":"unknown","score_millis":1}],"explanations":[]}"#,
            "not json",
        ] {
            assert!(
                validate_model_output(raw, &known()).is_err(),
                "accepted {raw}"
            );
        }
    }

    #[test]
    fn model_cannot_mutate_source_evidence() {
        let source = known();
        let before = source.clone();
        let _ = validate_model_output(r#"{"schema":1,"rankings":[],"explanations":[]}"#, &source)
            .unwrap();
        assert_eq!(source, before);
    }

    #[test]
    fn sanitized_prompt_omits_paths_and_actions() {
        let prompt = build_model_prompt("explain the best result", &known()).unwrap();
        assert!(!prompt.contains("/cache"));
        assert!(!prompt.contains("purge-cache"));
        assert!(prompt.contains("known"));
    }

    #[cfg(feature = "local-ai")]
    #[test]
    fn disconnected_or_corrupt_runtime_fails_closed() {
        struct Runtime(Result<&'static str, &'static str>);
        impl LocalModelRuntime for Runtime {
            fn infer_json(&self, _prompt: &str) -> Result<String, String> {
                self.0.map(str::to_string).map_err(str::to_string)
            }
        }
        assert!(run_local_model(&Runtime(Err("offline")), "rank", &known()).is_err());
        assert!(run_local_model(&Runtime(Ok("not json")), "rank", &known()).is_err());
    }
}
