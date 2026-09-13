//! Versioned scan-mode contracts shared by the scanner, analyzers, and desktop.

use serde::{Deserialize, Serialize};

pub const SCAN_SCHEMA: u16 = 2;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanMode {
    /// Directory metadata plus the marker vocabulary required by cleanup rules.
    #[default]
    Cache,
    /// Retain compact file metadata, but do not read file contents.
    Whole,
    /// Retain metadata and allow bounded, opt-in content analyzers to run.
    All,
}

impl ScanMode {
    pub fn keeps_file_inventory(self) -> bool {
        !matches!(self, Self::Cache)
    }

    pub fn reads_file_contents(self) -> bool {
        matches!(self, Self::All)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Cache => "Cache Scan",
            Self::Whole => "Whole Disk",
            Self::All => "All Files",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_contract_is_stable() {
        assert_eq!(
            serde_json::to_string(&ScanMode::Cache).unwrap(),
            "\"cache\""
        );
        assert_eq!(
            serde_json::to_string(&ScanMode::Whole).unwrap(),
            "\"whole\""
        );
        assert_eq!(serde_json::to_string(&ScanMode::All).unwrap(), "\"all\"");
        assert_eq!(
            serde_json::from_str::<ScanMode>("\"whole\"").unwrap(),
            ScanMode::Whole
        );
    }

    #[test]
    fn only_all_files_authorizes_content_analysis() {
        assert!(!ScanMode::Cache.keeps_file_inventory());
        assert!(ScanMode::Whole.keeps_file_inventory());
        assert!(!ScanMode::Whole.reads_file_contents());
        assert!(ScanMode::All.reads_file_contents());
    }
}
