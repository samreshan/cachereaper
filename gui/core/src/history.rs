//! Local cleanup receipts. Every deletion session is an append-only JSONL file
//! under `~/.cachereaper`; history never implies undo.

use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub const RECEIPT_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptHeader {
    pub schema: u32,
    pub kind: String,
    pub receipt_id: String,
    pub started_at: u128,
    pub root: String,
    pub estimated_bytes: u64,
    pub free_before: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptItem {
    pub schema: u32,
    pub kind: String,
    pub path: String,
    pub rule: String,
    pub tier: String,
    pub label: String,
    pub regen: String,
    pub estimated_bytes: u64,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSummary {
    pub schema: u32,
    pub kind: String,
    pub finished_at: u128,
    pub removed_count: usize,
    pub skipped_count: usize,
    pub estimated_removed_bytes: u64,
    pub free_after: Option<u64>,
    pub signed_free_space_change: Option<i128>,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub receipt_id: String,
    pub started_at: u128,
    pub root: String,
    pub estimated_bytes: u64,
    pub free_before: Option<u64>,
    pub items: Vec<ReceiptItem>,
    pub summary: Option<ReceiptSummary>,
    pub complete: bool,
    pub legacy: bool,
    pub parse_warning: Option<String>,
    #[serde(skip)]
    pub file_name: String,
}

pub fn audit_dir() -> PathBuf {
    crate::guard::home().join(".cachereaper")
}

pub fn now_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

pub fn signed_free_space_change(before: Option<u64>, after: Option<u64>) -> Option<i128> {
    before
        .zip(after)
        .map(|(before, after)| after as i128 - before as i128)
}

pub fn read_history_from(dir: &Path) -> std::io::Result<Vec<Receipt>> {
    let mut receipts = Vec::new();
    if !dir.exists() {
        return Ok(receipts);
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !valid_receipt_filename(name) {
            continue;
        }
        if let Some(receipt) = parse_receipt(&path, name)? {
            receipts.push(receipt);
        }
    }
    receipts.sort_by(|left, right| {
        right
            .started_at
            .cmp(&left.started_at)
            .then_with(|| right.receipt_id.cmp(&left.receipt_id))
    });
    Ok(receipts)
}

pub fn read_history() -> std::io::Result<Vec<Receipt>> {
    read_history_from(&audit_dir())
}

fn parse_receipt(path: &Path, file_name: &str) -> std::io::Result<Option<Receipt>> {
    let file = std::fs::File::open(path)?;
    let mut header: Option<ReceiptHeader> = None;
    let mut items = Vec::new();
    let mut summary = None;
    let mut malformed = 0usize;
    let mut legacy_started = 0u128;

    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            malformed += 1;
            continue;
        };
        match value.get("kind").and_then(|kind| kind.as_str()) {
            Some("header") => match serde_json::from_value(value) {
                Ok(value) => header = Some(value),
                Err(_) => malformed += 1,
            },
            Some("item") => match serde_json::from_value(value) {
                Ok(value) => items.push(value),
                Err(_) => malformed += 1,
            },
            Some("summary") => match serde_json::from_value(value) {
                Ok(value) => summary = Some(value),
                Err(_) => malformed += 1,
            },
            _ if value.get("path").is_some() => {
                let timestamp = value
                    .get("ts")
                    .and_then(|value| value.as_f64())
                    .map(|value| (value * 1000.0) as u128)
                    .unwrap_or(0);
                legacy_started = legacy_started.max(timestamp);
                items.push(ReceiptItem {
                    schema: 0,
                    kind: "item".to_string(),
                    path: value["path"].as_str().unwrap_or_default().to_string(),
                    rule: value["rule"].as_str().unwrap_or_default().to_string(),
                    tier: value["tier"].as_str().unwrap_or_default().to_string(),
                    label: String::new(),
                    regen: value["regen"].as_str().unwrap_or_default().to_string(),
                    estimated_bytes: value["bytes"].as_u64().unwrap_or(0),
                    status: "removed".to_string(),
                    reason: String::new(),
                });
            }
            _ => malformed += 1,
        }
    }

    if let Some(header) = header {
        let complete = summary
            .as_ref()
            .is_some_and(|value: &ReceiptSummary| value.complete);
        return Ok(Some(Receipt {
            receipt_id: header.receipt_id,
            started_at: header.started_at,
            root: header.root,
            estimated_bytes: header.estimated_bytes,
            free_before: header.free_before,
            items,
            summary,
            complete,
            legacy: false,
            parse_warning: (malformed > 0).then(|| format!("ignored {malformed} malformed lines")),
            file_name: file_name.to_string(),
        }));
    }

    if items.is_empty() && malformed == 0 {
        return Ok(None);
    }
    let id = file_name.trim_end_matches(".jsonl").to_string();
    let estimated_bytes = items.iter().map(|item| item.estimated_bytes).sum();
    Ok(Some(Receipt {
        receipt_id: id,
        started_at: legacy_started,
        root: String::new(),
        estimated_bytes,
        free_before: None,
        items,
        summary: None,
        complete: malformed == 0,
        legacy: true,
        parse_warning: (malformed > 0).then(|| format!("ignored {malformed} malformed lines")),
        file_name: file_name.to_string(),
    }))
}

pub fn valid_receipt_filename(name: &str) -> bool {
    name.ends_with(".jsonl")
        && (name.starts_with("receipt-") || name.starts_with("reap-"))
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".-_".contains(character))
}

pub fn delete_receipt(receipt_id: &str) -> Result<bool, String> {
    let receipt = read_history()
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|receipt| receipt.receipt_id == receipt_id)
        .ok_or_else(|| "receipt not found".to_string())?;
    if !valid_receipt_filename(&receipt.file_name) {
        return Err("invalid receipt filename".to_string());
    }
    std::fs::remove_file(audit_dir().join(receipt.file_name))
        .map(|_| true)
        .map_err(|error| error.to_string())
}

pub fn clear_history() -> Result<usize, String> {
    let receipts = read_history().map_err(|error| error.to_string())?;
    let mut removed = 0;
    for receipt in receipts {
        if valid_receipt_filename(&receipt.file_name) {
            std::fs::remove_file(audit_dir().join(receipt.file_name))
                .map_err(|error| error.to_string())?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(unix)]
pub fn free_space(path: &Path) -> Option<u64> {
    let output = std::process::Command::new("df")
        .args(["-Pk"])
        .arg(path)
        .output()
        .ok()?;
    let last = String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .last()?
        .to_string();
    last.split_whitespace()
        .nth(3)?
        .parse::<u64>()
        .ok()
        .map(|kilobytes| kilobytes.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cachereaper-history-{}-{}",
            std::process::id(),
            now_millis()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn parses_complete_truncated_and_legacy_receipts() {
        let dir = fixture();
        let mut complete = std::fs::File::create(dir.join("receipt-a.jsonl")).unwrap();
        writeln!(complete, "{}", serde_json::json!({"schema":1,"kind":"header","receipt_id":"a","started_at":2,"root":"/tmp","estimated_bytes":4,"free_before":10})).unwrap();
        writeln!(complete, "not-json").unwrap();
        writeln!(complete, "{}", serde_json::json!({"schema":1,"kind":"summary","finished_at":3,"removed_count":0,"skipped_count":0,"estimated_removed_bytes":0,"free_after":10,"signed_free_space_change":0,"complete":true})).unwrap();
        std::fs::write(dir.join("receipt-b.jsonl"), "{\"schema\":1,\"kind\":\"header\",\"receipt_id\":\"b\",\"started_at\":1,\"root\":\"/tmp\",\"estimated_bytes\":0,\"free_before\":null}\n").unwrap();
        std::fs::write(
            dir.join("reap-old.jsonl"),
            "{\"ts\":1.0,\"path\":\"/tmp/cache\",\"rule\":\"r\",\"tier\":\"low\",\"bytes\":7}\n",
        )
        .unwrap();

        let history = read_history_from(&dir).unwrap();
        assert_eq!(history.len(), 3);
        assert!(history
            .iter()
            .find(|receipt| receipt.receipt_id == "a")
            .unwrap()
            .parse_warning
            .is_some());
        assert!(
            !history
                .iter()
                .find(|receipt| receipt.receipt_id == "b")
                .unwrap()
                .complete
        );
        assert!(history.iter().find(|receipt| receipt.legacy).is_some());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn filename_validation_rejects_escape_attempts() {
        assert!(valid_receipt_filename("receipt-1-2-3.jsonl"));
        assert!(!valid_receipt_filename("../receipt-1.jsonl"));
        assert!(!valid_receipt_filename("config.json"));
    }


    #[test]
    fn free_space_deltas_keep_their_sign() {
        assert_eq!(signed_free_space_change(Some(10), Some(15)), Some(5));
        assert_eq!(signed_free_space_change(Some(10), Some(10)), Some(0));
        assert_eq!(signed_free_space_change(Some(15), Some(10)), Some(-5));
        assert_eq!(signed_free_space_change(None, Some(10)), None);
    }
}

#[cfg(windows)]
pub fn free_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            directory_name: *const u16,
            free_bytes_available: *mut u64,
            total_bytes: *mut u64,
            total_free_bytes: *mut u64,
        ) -> i32;
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut free = 0;
    // SAFETY: the path is NUL terminated and the output pointer is valid.
    if unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        None
    } else {
        Some(free)
    }
}
