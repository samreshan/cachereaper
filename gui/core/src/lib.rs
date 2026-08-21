//! Core of the cachereaper GUI: a parallel disk scanner and the safety guards.
//!
//! Deliberately independent of Tauri so it can be tested and benchmarked with a
//! plain `cargo test` / `cargo run --bin bench`, and so CI does not need the
//! full desktop toolchain to check the parts that decide what gets deleted.

pub mod access;
pub mod config;
pub mod guard;
pub mod history;
pub mod purge;
pub mod rules;
pub mod scan;

pub use access::{AccessState, Gate, SettingsPane};
pub use config::{Config, ScanProfile};
pub use guard::{path_is_protected, validate_for_delete, Target};
pub use history::{
    clear_history, delete_receipt, read_history, Receipt, ReceiptItem, ReceiptSummary,
};
pub use purge::{allowed_roots, purge, PurgeResult};
pub use rules::{all_findings, all_findings_excluding, marker_vocabulary, Finding};
pub use scan::{
    default_threads, scan, scan_with_markers, scan_with_options, scan_with_options_progress,
    scan_with_progress, CancellationToken, Node, NodeState, ScanError, ScanOptions, ScanStats,
    Tree, NONE,
};

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
