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
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::access::AccessState;
use crate::guard::home;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Whether the onboarding journey has run to the end.
    pub seen_onboarding: bool,
    /// Last known answer per gate id. Absent means never asked, which is
    /// [`AccessState::Unknown`] and not a denial.
    pub access: BTreeMap<String, AccessState>,
    /// Whether a launch may ask the release feed if there is a newer build.
    ///
    /// The check is one HTTPS GET of a small manifest and sends nothing about
    /// the machine, but it is still a network call the user did not initiate,
    /// so it is a switch rather than a fact of life.
    pub auto_update: bool,
    /// Unix timestamp after which the optional support card may appear.
    /// `None` means a first launch has not scheduled it yet.
    pub support_prompt_at: Option<u64>,
    /// Permanent opt-out for the occasional support card. The support link in
    /// the footer remains available without prompting.
    pub support_prompt_disabled: bool,
    pub global_excluded_paths: Vec<PathBuf>,
    pub global_excluded_rules: Vec<String>,
    pub profiles: Vec<ScanProfile>,
    pub last_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanProfile {
    pub id: String,
    pub name: String,
    pub root: PathBuf,
    #[serde(default)]
    pub excluded_paths: Vec<PathBuf>,
    #[serde(default)]
    pub excluded_rules: Vec<String>,
}

/// Not derived: `auto_update` has to default to `true`, and the container-level
/// `#[serde(default)]` above means this is also what fills the field in for a
/// config written by a build that predates it. A derived `Default` would read
/// every existing config on disk as "checking turned off" — a setting nobody
/// chose, silently applied to everyone already using the app.
impl Default for Config {
    fn default() -> Self {
        Config {
            seen_onboarding: false,
            access: BTreeMap::new(),
            auto_update: true,
            support_prompt_at: None,
            support_prompt_disabled: false,
            global_excluded_paths: Vec::new(),
            global_excluded_rules: Vec::new(),
            profiles: Vec::new(),
            last_profile_id: None,
        }
    }
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

    pub fn profile(&self, id_or_name: &str) -> Option<&ScanProfile> {
        self.profiles.iter().find(|profile| {
            profile.id == id_or_name || profile.name.eq_ignore_ascii_case(id_or_name)
        })
    }

    pub fn create_profile(&mut self, name: String, root: PathBuf) -> Result<ScanProfile, String> {
        validate_profile_name(self, &name, None)?;
        let root = normalize_absolute(&root)?;
        let profile = ScanProfile {
            id: profile_id(),
            name: name.trim().to_string(),
            root,
            excluded_paths: Vec::new(),
            excluded_rules: Vec::new(),
        };
        self.last_profile_id = Some(profile.id.clone());
        self.profiles.push(profile.clone());
        Ok(profile)
    }

    pub fn update_profile(
        &mut self,
        id: &str,
        name: String,
        root: PathBuf,
    ) -> Result<ScanProfile, String> {
        validate_profile_name(self, &name, Some(id))?;
        let root = normalize_absolute(&root)?;
        let index = self
            .profiles
            .iter()
            .position(|profile| profile.id == id)
            .ok_or_else(|| "profile not found".to_string())?;
        if self.profiles[index]
            .excluded_paths
            .iter()
            .any(|path| !is_descendant(path, &root))
        {
            return Err("existing profile exclusions are outside the new root".to_string());
        }
        self.profiles[index].name = name.trim().to_string();
        self.profiles[index].root = root;
        Ok(self.profiles[index].clone())
    }

    pub fn delete_profile(&mut self, id: &str) -> bool {
        let before = self.profiles.len();
        self.profiles.retain(|profile| profile.id != id);
        if self.last_profile_id.as_deref() == Some(id) {
            self.last_profile_id = None;
        }
        before != self.profiles.len()
    }

    pub fn add_global_path(&mut self, path: PathBuf) -> Result<PathBuf, String> {
        let path = normalize_absolute(&path)?;
        push_unique_path(&mut self.global_excluded_paths, path.clone());
        Ok(path)
    }

    pub fn add_profile_path(&mut self, id: &str, path: PathBuf) -> Result<PathBuf, String> {
        let path = normalize_absolute(&path)?;
        let profile = self
            .profiles
            .iter_mut()
            .find(|profile| profile.id == id)
            .ok_or_else(|| "profile not found".to_string())?;
        if !is_descendant(&path, &profile.root) {
            return Err("profile exclusion must be below the profile root".to_string());
        }
        push_unique_path(&mut profile.excluded_paths, path.clone());
        Ok(path)
    }
}

static PROFILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn profile_id() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let counter = PROFILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("profile-{millis}-{}-{counter}", std::process::id())
}

fn validate_profile_name(config: &Config, name: &str, except: Option<&str>) -> Result<(), String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("profile name cannot be empty".to_string());
    }
    if config.profiles.iter().any(|profile| {
        Some(profile.id.as_str()) != except && profile.name.eq_ignore_ascii_case(name)
    }) {
        return Err("profile name already exists".to_string());
    }
    Ok(())
}

/// Normalize `.` and `..` without touching the filesystem or resolving links.
pub fn normalize_absolute(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("path must be absolute".to_string());
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        use std::path::Component;
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn comparable(path: &Path) -> String {
    let value = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        value.to_lowercase()
    } else {
        value
    }
}

pub fn paths_equal(left: &Path, right: &Path) -> bool {
    comparable(left) == comparable(right)
}

pub fn is_descendant(path: &Path, root: &Path) -> bool {
    let path = comparable(path);
    let mut root = comparable(root);
    let separator = std::path::MAIN_SEPARATOR;
    if !root.ends_with(separator) {
        root.push(separator);
    }
    path.starts_with(&root)
}

fn push_unique_path(paths: &mut Vec<PathBuf>, path: PathBuf) {
    let candidate = comparable(&path);
    if !paths
        .iter()
        .any(|existing| comparable(existing) == candidate)
    {
        paths.push(path);
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

/// Write beside the target and replace it, so an interrupted save cannot leave a
/// truncated config that loads as defaults and silently re-asks for everything.
pub fn save_to(config: &Config, path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string_pretty(config)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)?;

    // Unix rename replaces atomically. `std::fs::rename` refuses an existing
    // destination on Windows, so without this branch every setting change after
    // the first save fails there. The standard library has no atomic replace on
    // Windows; removing only after the complete temp file exists keeps the
    // non-atomic interval as small as possible.
    #[cfg(windows)]
    if path.exists() {
        std::fs::remove_file(path)?;
    }
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
    fn update_checking_is_on_until_it_is_turned_off() {
        assert!(Config::default().auto_update);
    }

    /// The upgrade case: a config written before the field existed must not read
    /// as an opt-out.
    #[test]
    fn a_config_without_the_field_still_checks_for_updates() {
        let dir = fixture();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"seen_onboarding": true, "access": {}}"#).unwrap();

        let read = load_from(&path);
        assert!(read.auto_update);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn turning_update_checks_off_survives_a_round_trip() {
        let dir = fixture();
        let path = dir.join("config.json");

        let mut written = Config::default();
        written.auto_update = false;
        save_to(&written, &path).unwrap();

        assert!(!load_from(&path).auto_update);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn support_prompt_starts_unscheduled_and_enabled() {
        let config = Config::default();
        assert_eq!(config.support_prompt_at, None);
        assert!(!config.support_prompt_disabled);
    }

    #[test]
    fn support_prompt_preferences_survive_a_round_trip() {
        let dir = fixture();
        let path = dir.join("config.json");
        let written = Config {
            support_prompt_at: Some(1_700_000_000),
            support_prompt_disabled: true,
            ..Config::default()
        };

        save_to(&written, &path).unwrap();
        let read = load_from(&path);

        assert_eq!(read.support_prompt_at, Some(1_700_000_000));
        assert!(read.support_prompt_disabled);
        std::fs::remove_dir_all(&dir).ok();
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
    fn profiles_validate_and_keep_stable_ids_when_renamed() {
        let dir = fixture();
        let root = dir.join("work");
        let mut config = Config::default();
        let created = config.create_profile("Work".into(), root.clone()).unwrap();
        config
            .add_profile_path(&created.id, root.join("tmp/../cache"))
            .unwrap();
        let updated = config
            .update_profile(&created.id, "Projects".into(), root.clone())
            .unwrap();
        assert_eq!(created.id, updated.id);
        assert_eq!(updated.excluded_paths, vec![root.join("cache")]);
        assert!(config
            .create_profile("projects".into(), root.clone())
            .is_err());
        assert!(config
            .add_profile_path(&created.id, dir.join("outside"))
            .is_err());
        assert!(config.add_profile_path(&created.id, root).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn lexical_normalization_cannot_walk_above_root() {
        assert_eq!(normalize_absolute(Path::new("/../../tmp/./cache")).unwrap(), Path::new("/tmp/cache"));
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
