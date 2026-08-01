//! Core of the cachereap GUI: a parallel disk scanner and the safety guards.
//!
//! Deliberately independent of Tauri so it can be tested and benchmarked with a
//! plain `cargo test` / `cargo run --bin bench`, and so CI does not need the
//! full desktop toolchain to check the parts that decide what gets deleted.

pub mod guard;
pub mod rules;
pub mod scan;

pub use guard::{path_is_protected, validate_for_delete, Target};
pub use rules::{all_findings, marker_vocabulary, Finding};
pub use scan::{default_threads, scan_with_markers, scan, scan_with_progress, Node, ScanStats, Tree, NONE};

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
