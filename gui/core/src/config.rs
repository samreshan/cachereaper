//! What the desktop app remembers between launches.
//!
//! Lives in `~/.cachereaper/config.json`, beside the reap logs, so everything
//! the tool keeps about you is in one directory you can read and delete.
//!
//! Small on purpose. The field that earns its place is `access`: it is what lets
//! the app draw truthful permission state at startup without reading a single
//! gated folder, and reading one is how a dialog gets raised. Without a record
//! of what was already answered there is no way to tell "granted" from "never
//! asked" except by asking — which is the behaviour this whole path exists to
//! avoid.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::access::AccessState;
use crate::guard::home;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Whether the onboarding journey has run to the end.
    pub seen_onboarding: bool,
    /// Last known answer per gate id. Absent means never asked, which is
    /// [`AccessState::Unknown`] and not a denial.
    pub access: BTreeMap<String, AccessState>,
}

impl Config {
    /// What we last heard about a gate. Absent reads as `Unknown`.
    pub fn state_of(&self, id: &str) -> AccessState {
        self.access.get(id).copied().unwrap_or_default()
    }

    /// Remember an answer. `Unknown` is stored rather than removed so a gate the
    /// user handed back still shows up as something we have talked about.
    pub fn record(&mut self, id: &str, state: AccessState) {
        self.access.insert(id.to_string(), state);
    }
}

pub fn config_path() -> PathBuf {
    home().join(".cachereaper").join("config.json")
}

/// Read it, or fall back to defaults.
///
/// Never fails. A missing, unreadable or malformed config is not a reason to
/// refuse to start; the cost of defaults is one onboarding run, and pretending
/// a parse error is fatal would strand the user with no window.
pub fn load() -> Config {
    load_from(&config_path())
}

pub fn load_from(path: &Path) -> Config {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

pub fn save(config: &Config) -> std::io::Result<()> {
    save_to(config, &config_path())
}

/// Write beside the target and rename over it, so an interrupted save leaves the
/// previous config intact instead of a truncated one that loads as defaults and
/// silently re-asks for everything.
pub fn save_to(config: &Config, path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cachereaper-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_absent_record_is_unknown_not_denied() {
        let config = Config::default();
        assert_eq!(config.state_of("desktop"), AccessState::Unknown);
        assert!(!config.seen_onboarding);
    }

    #[test]
    fn a_saved_config_round_trips() {
        let dir = fixture();
        let path = dir.join("config.json");

        let mut written = Config::default();
        written.seen_onboarding = true;
        written.record("desktop", AccessState::Granted);
        written.record("documents", AccessState::Denied);
        save_to(&written, &path).unwrap();

        let read = load_from(&path);
        assert!(read.seen_onboarding);
        assert_eq!(read.state_of("desktop"), AccessState::Granted);
        assert_eq!(read.state_of("documents"), AccessState::Denied);
        assert_eq!(read.state_of("downloads"), AccessState::Unknown);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_config_loads_as_defaults() {
        let dir = fixture();
        let read = load_from(&dir.join("not-written-yet.json"));
        assert!(!read.seen_onboarding);
        assert!(read.access.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_config_loads_as_defaults_rather_than_failing_to_start() {
        let dir = fixture();
        let path = dir.join("config.json");
        std::fs::write(&path, "{ not json at all").unwrap();

        let read = load_from(&path);
        assert!(!read.seen_onboarding);
        assert!(read.access.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A config written by a newer build, or edited by hand, must not cost the
    /// user the answers it does still contain.
    #[test]
    fn unknown_and_missing_fields_do_not_discard_the_rest() {
        let dir = fixture();
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{"seen_onboarding": true, "something_we_shipped_later": 7}"#,
        )
        .unwrap();

        let read = load_from(&path);
        assert!(read.seen_onboarding);
        assert!(read.access.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn saving_creates_the_directory_and_leaves_no_temp_file_behind() {
        let dir = fixture();
        let path = dir.join("nested/deeper/config.json");

        save_to(&Config::default(), &path).unwrap();

        assert!(path.exists());
        assert!(!path.with_extension("json.tmp").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_config_sits_beside_the_reap_logs() {
        assert_eq!(config_path().parent().unwrap(), home().join(".cachereaper"));
    }
}
