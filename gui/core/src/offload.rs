//! Opt-in offload connector boundary.
//!
//! Core preparation is available without any provider SDK. Actual connectors
//! are feature-gated and receive a transfer only after an exact disclosure and
//! typed confirmation. Connector responses cannot create local file actions.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Insight, PermittedAction};

pub const OFFLOAD_SCHEMA: u16 = 1;
const MAX_OFFLOAD_ITEMS: usize = 100;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OffloadStatus {
    pub compiled: bool,
    pub configured_providers: Vec<String>,
    pub per_request_consent_required: bool,
    pub authority: String,
}

impl OffloadStatus {
    pub fn current() -> Self {
        Self {
            compiled: cfg!(feature = "offload-connectors"),
            configured_providers: Vec::new(),
            per_request_consent_required: true,
            authority: "connector results cannot authorize local deletion".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OffloadItem {
    pub insight_id: String,
    pub local_path: String,
    pub estimated_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OffloadDisclosure {
    pub schema: u16,
    pub id: String,
    pub snapshot_id: String,
    pub provider: String,
    pub destination: String,
    pub item_count: usize,
    pub total_bytes: u64,
    pub data_leaving_device: Vec<String>,
    pub items: Vec<OffloadItem>,
    pub confirmation_phrase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizedOffload {
    pub schema: u16,
    pub disclosure_id: String,
    pub snapshot_id: String,
    pub provider: String,
    pub destination: String,
    pub items: Vec<OffloadItem>,
}

pub fn prepare_offload(
    snapshot_id: &str,
    provider: &str,
    destination: &str,
    insight_ids: &[String],
    insights: &[Insight],
) -> Result<OffloadDisclosure, String> {
    if snapshot_id.is_empty() || snapshot_id.len() > 128 {
        return Err("invalid snapshot id".into());
    }
    validate_label("provider", provider)?;
    validate_label("destination", destination)?;
    if insight_ids.is_empty() || insight_ids.len() > MAX_OFFLOAD_ITEMS {
        return Err(format!(
            "select between 1 and {MAX_OFFLOAD_ITEMS} offload items"
        ));
    }
    let selected: BTreeSet<&str> = insight_ids.iter().map(String::as_str).collect();
    if selected.len() != insight_ids.len() {
        return Err("duplicate offload insight id".into());
    }
    let mut items = Vec::new();
    for id in selected {
        let insight = insights
            .iter()
            .find(|insight| insight.id == id)
            .ok_or_else(|| format!("unknown insight id {id}"))?;
        if !insight
            .permitted_actions
            .contains(&PermittedAction::PrepareOffload)
        {
            return Err(format!(
                "insight {id} is not eligible for offload preparation"
            ));
        }
        if insight.paths.len() != 1 {
            return Err(format!("insight {id} does not identify exactly one file"));
        }
        items.push(OffloadItem {
            insight_id: id.to_string(),
            local_path: insight.paths[0].clone(),
            estimated_bytes: insight.estimated_reclaimable_bytes,
        });
    }
    items.sort_by(|a, b| a.insight_id.cmp(&b.insight_id));
    let total_bytes = items.iter().fold(0_u64, |total, item| {
        total.saturating_add(item.estimated_bytes)
    });
    let id = disclosure_id(snapshot_id, provider, destination, &items);
    Ok(OffloadDisclosure {
        schema: OFFLOAD_SCHEMA,
        id: id.clone(),
        snapshot_id: snapshot_id.to_string(),
        provider: provider.to_string(),
        destination: destination.to_string(),
        item_count: items.len(),
        total_bytes,
        data_leaving_device: vec![
            "selected filenames and relative destination names".into(),
            "selected file contents".into(),
            "byte sizes required for transfer verification".into(),
        ],
        items,
        confirmation_phrase: format!(
            "offload {}",
            id.strip_prefix("offload-")
                .unwrap_or(&id)
                .get(..12)
                .unwrap_or_else(|| id.strip_prefix("offload-").unwrap_or(&id))
        ),
    })
}

pub fn authorize_offload(
    disclosure: &OffloadDisclosure,
    confirmation: &str,
) -> Result<AuthorizedOffload, String> {
    if disclosure.schema != OFFLOAD_SCHEMA
        || disclosure.id
            != disclosure_id(
                &disclosure.snapshot_id,
                &disclosure.provider,
                &disclosure.destination,
                &disclosure.items,
            )
    {
        return Err("offload disclosure was changed or uses an unknown schema".into());
    }
    if confirmation != disclosure.confirmation_phrase {
        return Err("offload confirmation did not match".into());
    }
    Ok(AuthorizedOffload {
        schema: OFFLOAD_SCHEMA,
        disclosure_id: disclosure.id.clone(),
        snapshot_id: disclosure.snapshot_id.clone(),
        provider: disclosure.provider.clone(),
        destination: disclosure.destination.clone(),
        items: disclosure.items.clone(),
    })
}

#[cfg(feature = "offload-connectors")]
pub trait OffloadConnector {
    fn provider_id(&self) -> &str;
    fn transfer(&self, request: &AuthorizedOffload) -> Result<OffloadReceipt, String>;
}

#[cfg(feature = "offload-connectors")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OffloadReceipt {
    pub schema: u16,
    pub disclosure_id: String,
    pub provider: String,
    pub uploaded_insight_ids: Vec<String>,
    pub remote_receipt_id: String,
}

#[cfg(feature = "offload-connectors")]
pub fn validate_offload_receipt(
    request: &AuthorizedOffload,
    receipt: OffloadReceipt,
) -> Result<OffloadReceipt, String> {
    if receipt.schema != OFFLOAD_SCHEMA
        || receipt.disclosure_id != request.disclosure_id
        || receipt.provider != request.provider
        || receipt.remote_receipt_id.is_empty()
        || receipt.remote_receipt_id.len() > 256
    {
        return Err("connector receipt does not match the authorized transfer".into());
    }
    let expected: BTreeSet<&str> = request
        .items
        .iter()
        .map(|item| item.insight_id.as_str())
        .collect();
    let actual: BTreeSet<&str> = receipt
        .uploaded_insight_ids
        .iter()
        .map(String::as_str)
        .collect();
    if expected != actual || actual.len() != receipt.uploaded_insight_ids.len() {
        return Err("connector receipt contains missing, duplicate, or unknown item ids".into());
    }
    Ok(receipt)
}

fn disclosure_id(
    snapshot_id: &str,
    provider: &str,
    destination: &str,
    items: &[OffloadItem],
) -> String {
    let mut digest = Sha256::new();
    digest.update(snapshot_id);
    digest.update([0]);
    digest.update(provider);
    digest.update([0]);
    digest.update(destination);
    for item in items {
        digest.update([0]);
        digest.update(&item.insight_id);
        digest.update([0]);
        digest.update(&item.local_path);
        digest.update(item.estimated_bytes.to_le_bytes());
    }
    format!("offload-{:x}", digest.finalize())
}

fn validate_label(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || value.contains(['`', ';'])
    {
        Err(format!("invalid offload {label}"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InsightKind, Provenance, Recoverability, Risk};

    fn insight(actions: Vec<PermittedAction>) -> Insight {
        Insight {
            schema: 1,
            id: "file-1".into(),
            kind: InsightKind::LargeFile,
            title: "Large file".into(),
            explanation: "review".into(),
            paths: vec!["/Users/test/movie.mov".into()],
            node_ids: vec![],
            estimated_reclaimable_bytes: 42,
            confidence_millis: 1000,
            risk: Risk::High,
            recoverability: Recoverability::None,
            category: Some("Video".into()),
            modified_at: None,
            evidence: vec![],
            provenance: Provenance::Analyzer,
            permitted_actions: actions,
        }
    }

    #[test]
    fn disclosure_requires_typed_eligibility_and_exact_confirmation() {
        let denied = insight(vec![PermittedAction::Reveal]);
        assert!(prepare_offload("scan", "archive", "cold", &["file-1".into()], &[denied]).is_err());

        let allowed = insight(vec![
            PermittedAction::Reveal,
            PermittedAction::PrepareOffload,
        ]);
        let disclosure =
            prepare_offload("scan", "archive", "cold", &["file-1".into()], &[allowed]).unwrap();
        assert!(authorize_offload(&disclosure, "wrong").is_err());
        let request = authorize_offload(&disclosure, &disclosure.confirmation_phrase).unwrap();
        assert_eq!(request.items[0].insight_id, "file-1");
        assert!(disclosure
            .data_leaving_device
            .iter()
            .any(|value| value.contains("contents")));
    }

    #[test]
    fn changed_disclosure_fails_closed() {
        let allowed = insight(vec![PermittedAction::PrepareOffload]);
        let mut disclosure =
            prepare_offload("scan", "archive", "cold", &["file-1".into()], &[allowed]).unwrap();
        disclosure.items[0].local_path = "/etc/passwd".into();
        assert!(authorize_offload(&disclosure, &disclosure.confirmation_phrase).is_err());
    }

    #[cfg(feature = "offload-connectors")]
    #[test]
    fn connector_receipt_cannot_add_items() {
        let allowed = insight(vec![PermittedAction::PrepareOffload]);
        let disclosure =
            prepare_offload("scan", "archive", "cold", &["file-1".into()], &[allowed]).unwrap();
        let request = authorize_offload(&disclosure, &disclosure.confirmation_phrase).unwrap();
        let receipt = OffloadReceipt {
            schema: 1,
            disclosure_id: disclosure.id,
            provider: "archive".into(),
            uploaded_insight_ids: vec!["file-1".into(), "invented".into()],
            remote_receipt_id: "receipt".into(),
        };
        assert!(validate_offload_receipt(&request, receipt).is_err());
    }
}
