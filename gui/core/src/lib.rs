//! Core of the cachereaper GUI: a parallel disk scanner and the safety guards.
//!
//! Deliberately independent of Tauri so it can be tested and benchmarked with a
//! plain `cargo test` / `cargo run --bin bench`, and so CI does not need the
//! full desktop toolchain to check the parts that decide what gets deleted.

pub mod access;
pub mod ai;
pub mod analysis;
pub mod config;
pub mod guard;
pub mod history;
pub mod index;
pub mod insights;
pub mod intelligence;
pub mod media;
pub mod mode;
pub mod offload;
pub mod plan;
pub mod purge;
pub mod quarantine;
pub mod rules;
pub mod scan;
pub mod trash;
#[cfg(windows)]
mod windows_identity;

pub use access::{AccessState, Gate, SettingsPane};
pub use ai::{
    build_model_prompt, validate_model_output, LocalAiStatus, ValidatedModelPresentation,
};
#[cfg(feature = "local-ai")]
pub use ai::{run_local_model, LocalModelRuntime};
pub use analysis::{
    analyze, analyze_with_cache, AnalysisSummary, CategorySummary, DuplicateGroup, FileInsight,
};
pub use config::{Config, ScanProfile};
pub use guard::{path_is_protected, validate_for_delete, Target};
pub use history::{
    action_history, clear_history, delete_receipt, read_history, ActionHistoryEntry,
    ActionHistoryItem, Receipt, ReceiptItem, ReceiptSummary,
};
pub use index::{
    compare_snapshots, list_snapshots, persist_snapshot, GrowthDelta, GrowthReport, HashCache,
    ScanSnapshot,
};
pub use insights::{
    append_advanced_insights, build_insights, compile_filter, filter_insights, Evidence, FilterAst,
    FilterField, FilterOperator, FilterValue, Insight, InsightKind, PermittedAction, Provenance,
    QueryError, Recoverability, Risk, INSIGHT_SCHEMA,
};
pub use intelligence::{
    analyze_ownership, analyze_projects, forecast_snapshots, ApplicationCatalog, ForecastReport,
    GrowthAnomaly, IntelligenceSummary, OwnershipEvidence, OwnershipState, ProjectEstimate,
    INTELLIGENCE_SCHEMA, PROJECT_MARKERS,
};
pub use media::{
    analyze_similar_media, MediaAnalysis, MediaFile, MediaKind, SimilarMediaGroup, MEDIA_SCHEMA,
};
pub use mode::{ScanMode, SCAN_SCHEMA};
pub use offload::{
    authorize_offload, prepare_offload, AuthorizedOffload, OffloadDisclosure, OffloadItem,
    OffloadStatus, OFFLOAD_SCHEMA,
};
#[cfg(feature = "offload-connectors")]
pub use offload::{validate_offload_receipt, OffloadConnector, OffloadReceipt};
pub use plan::{
    generate_cleanup_plan, CleanupPlan, PlanAction, PlanActionKind, PlanPolicy, RebuildCost,
    ReclaimTiming,
};
pub use purge::{allowed_roots, purge, PurgeResult};
pub use quarantine::{
    expire_quarantine, list_quarantine, quarantine_file, restore_quarantine, ExpiryRequest,
    QuarantineEvidence, QuarantineRecord, VAULT_NAME,
};
pub use rules::{all_findings, all_findings_excluding, marker_vocabulary, Finding};
pub use scan::{
    default_threads, scan, scan_with_markers, scan_with_options, scan_with_options_progress,
    scan_with_progress, CancellationToken, FileRecord, Node, NodeState, ScanError, ScanOptions,
    ScanStats, Tree, NONE,
};
pub use trash::{list_trash, trash_duplicate_with, TrashRecord};

/// Human-readable byte sizes, matching the CLI's `human()` formatting.
pub fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut value = bytes as f64;
    for (i, unit) in UNITS.iter().enumerate() {
        if value.abs() < 1024.0 || i == UNITS.len() - 1 {
            return if *unit == "B" {
                format!("{value:.0}B")
            } else {
                format!("{value:.1}{unit}")
            };
        }
        value /= 1024.0;
    }
    format!("{value:.1}T")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_matches_the_cli_format() {
        assert_eq!(human(0), "0B");
        assert_eq!(human(512), "512B");
        assert_eq!(human(1536), "1.5K");
        assert_eq!(human(5 * 1024 * 1024 * 1024), "5.0G");
    }
}
