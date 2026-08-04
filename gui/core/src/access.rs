//! What macOS gates, and what our last answer for each gate was.
//!
//! Three directories inside `$HOME` sit behind TCC: Desktop, Documents and
//! Downloads. Reading one for the first time *is* the request — that read is
//! what raises the consent dialog, and it blocks until the user answers. Left
//! alone that happens inside the scan, which walks with a thread pool, so the
//! dialogs surface from worker threads in an order nobody chose, stacked on top
//! of the scan curtain. Everything here exists to make the only call that can
//! raise a dialog be one the user just clicked.
//!
//! A second class of directory — `~/Library/Safari`, `Mail`, the TCC database —
//! has no dialog at all. It is Full Disk Access or nothing, and probing it is
//! always silent, so [`full_disk_access`] is safe to call whenever.
//!
//! Nothing here can grant anything. macOS has no API for that: a folder the user
//! denied never prompts again, and Full Disk Access never prompts in the first
//! place. Past that point the honest move is [`open_pane`], which puts the user
//! in front of the switch.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::guard::{home, is_within};

/// Where we stand with one gated folder.
///
/// `Unknown` is "we have never asked", which is not `Denied`: macOS prompts on
/// the first read and never again, so an `Unknown` gate still has a dialog
/// waiting behind it and a `Denied` one does not. Collapsing the two into a bool
/// is what makes a permissions toggle lie.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessState {
    #[default]
    Unknown,
    Granted,
    Denied,
}

/// `(id, directory name, TCC service as `tccutil` spells it)`.
///
/// The name doubles as the label; these three are called the same thing in the
/// filesystem and in the Privacy pane.
#[cfg(target_os = "macos")]
const GATED: &[(&str, &str, &str)] = &[
    ("desktop", "Desktop", "SystemPolicyDesktopFolder"),
    ("documents", "Documents", "SystemPolicyDocumentsFolder"),
    ("downloads", "Downloads", "SystemPolicyDownloadsFolder"),
];

/// Nothing outside macOS puts a consent dialog in front of a directory read.
#[cfg(not(target_os = "macos"))]
const GATED: &[(&str, &str, &str)] = &[];

/// One folder the operating system asks about.
#[derive(Debug, Clone, Serialize)]
pub struct Gate {
    pub id: String,
    pub label: String,
    pub path: PathBuf,
    /// Never leaves the process: it is an argument to `tccutil`, and it is
    /// looked up from [`GATED`] rather than accepted from a caller.
    #[serde(skip)]
    pub service: String,
}

/// Every gated folder that exists on this machine.
pub fn gates() -> Vec<Gate> {
    let home = home();
    GATED
        .iter()
        .map(|(id, name, service)| Gate {
            id: (*id).to_string(),
            label: (*name).to_string(),
            path: home.join(name),
            service: (*service).to_string(),
        })
        // A machine with no ~/Documents has nothing to ask about. `exists` stats
        // the path, and TCC gates reading a directory's contents rather than its
        // existence, so this filter cannot itself raise a dialog.
        .filter(|gate| gate.path.exists())
        .collect()
}

/// The gates inside `root` — the only ones a scan of `root` can walk into.
///
/// This is why the access step belongs after the scope step: pointed at
/// `~/Programming`, the app has nothing to ask for and should say so.
pub fn gates_under(root: &Path) -> Vec<Gate> {
    gates()
        .into_iter()
        .filter(|gate| is_within(&gate.path, root))
        .collect()
}

/// Look one up by id. `None` for anything not in the table, which is how an id
/// arriving from the webview is kept out of a `tccutil` argument list.
pub fn gate(id: &str) -> Option<Gate> {
    gates().into_iter().find(|gate| gate.id == id)
}

/// Locations that raise a consent dialog of their own and can never hold a
/// finding.
///
/// Desktop, Documents and Downloads are not the only gated things under `$HOME`.
/// The Photos library, Contacts, Calendars and Reminders each sit behind their
/// own TCC service, and a walk that reads them raises a separate dialog for each
/// — from whichever worker thread arrived first, which is exactly the
/// interruption this module exists to stop. No rule claims anything inside them,
/// so reading them buys a prompt and nothing else. They are never walked.
///
/// The Photos library is named by whoever created it; the extension is the only
/// fixed part, and `~/Pictures` itself is not gated, so listing it to find them
/// is free.
#[cfg(target_os = "macos")]
pub fn never_walk() -> Vec<PathBuf> {
    let home = home();
    let mut out = vec![
        home.join("Library/Application Support/AddressBook"),
        home.join("Library/Calendars"),
        home.join("Library/Reminders"),
    ];
    if let Ok(entries) = std::fs::read_dir(home.join("Pictures")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "photoslibrary") {
                out.push(path);
            }
        }
    }
    out
}

#[cfg(not(target_os = "macos"))]
pub fn never_walk() -> Vec<PathBuf> {
    Vec::new()
}

/// Find out where we stand with `path` — **by reading it**, which is the same
/// thing as asking.
///
/// On a gate we have never asked about, this is the call that raises the dialog,
/// and it blocks until the user answers. Only reach for it off the back of a
/// gesture, and run it somewhere a long block is harmless. A gate that has
/// already been answered returns immediately either way, which is what makes a
/// silent refresh at startup possible.
pub fn probe(path: &Path) -> AccessState {
    match std::fs::read_dir(path) {
        Ok(_) => AccessState::Granted,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => AccessState::Denied,
        // Moved or gone since we listed it, or some other IO failure. Not an
        // answer from the user, so do not record one.
        Err(_) => AccessState::Unknown,
    }
}

/// Whether this process can read the whole disk.
///
/// Probes the TCC database's own directory: it is present on every macOS
/// install, and it is reachable with Full Disk Access and by no other means, so
/// the answer is unambiguous and no dialog exists to be raised by asking.
#[cfg(target_os = "macos")]
pub fn full_disk_access() -> AccessState {
    match probe(&home().join("Library/Application Support/com.apple.TCC")) {
        // The directory is always there; anything other than a clean read is a
        // refusal, including the IO errors `probe` declines to interpret.
        AccessState::Granted => AccessState::Granted,
        _ => AccessState::Denied,
    }
}

#[cfg(not(target_os = "macos"))]
pub fn full_disk_access() -> AccessState {
    AccessState::Granted
}

/// Hand a folder back.
///
/// `tccutil reset` drops our record for one service, so the gate returns to
/// `Unknown` and the next request prompts again. Resetting our own bundle id
/// needs no privileges. Without this a permissions toggle only moves one way,
/// because macOS offers no other route back.
#[cfg(target_os = "macos")]
pub fn revoke(gate: &Gate, bundle_id: &str) -> Result<(), String> {
    let out = std::process::Command::new("tccutil")
        .args(["reset", &gate.service, bundle_id])
        .output()
        .map_err(|e| format!("could not run tccutil: {e}"))?;

    if out.status.success() {
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr).trim().to_string();
    Err(if why.is_empty() {
        format!("tccutil could not reset {}", gate.label)
    } else {
        why
    })
}

#[cfg(not(target_os = "macos"))]
pub fn revoke(_gate: &Gate, _bundle_id: &str) -> Result<(), String> {
    Err("nothing to revoke outside macOS".to_string())
}

/// The System Settings panes holding the switches we cannot flip ourselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsPane {
    /// Where a folder the user denied can be turned back on.
    FilesAndFolders,
    /// Where Full Disk Access lives. It is never granted any other way.
    FullDisk,
}

impl SettingsPane {
    /// `None` for anything unrecognised, so the webview cannot name a URL.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "files" => Some(Self::FilesAndFolders),
            "full-disk" => Some(Self::FullDisk),
            _ => None,
        }
    }

    pub fn url(self) -> &'static str {
        match self {
            Self::FilesAndFolders => {
                "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_FilesAndFolders"
            }
            Self::FullDisk => {
                "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles"
            }
        }
    }
}

/// Open one of those panes. The URL comes from [`SettingsPane`], never from a
/// caller.
#[cfg(target_os = "macos")]
pub fn open_pane(pane: SettingsPane) -> Result<(), String> {
    std::process::Command::new("open")
        .arg(pane.url())
        .status()
        .map(|_| ())
        .map_err(|e| format!("could not open System Settings: {e}"))
}

#[cfg(not(target_os = "macos"))]
pub fn open_pane(_pane: SettingsPane) -> Result<(), String> {
    Err("System Settings is macOS only".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cachereaper-access-{}-{}",
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
    fn unknown_is_the_default_so_an_absent_record_never_reads_as_denied() {
        assert_eq!(AccessState::default(), AccessState::Unknown);
        assert_ne!(AccessState::Unknown, AccessState::Denied);
    }

    #[test]
    fn probing_a_readable_directory_reports_granted() {
        let dir = fixture();
        assert_eq!(probe(&dir), AccessState::Granted);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn probing_an_unreadable_directory_reports_denied() {
        let dir = fixture();
        let locked = dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        let mut perms = std::fs::metadata(&locked).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o000);
        std::fs::set_permissions(&locked, perms).unwrap();

        let state = probe(&locked);

        std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o755)).ok();
        std::fs::remove_dir_all(&dir).ok();

        // running as root defeats the permission bits, so only assert when it took
        if state != AccessState::Granted {
            assert_eq!(state, AccessState::Denied);
        }
    }

    #[test]
    fn a_missing_directory_is_not_recorded_as_an_answer() {
        let dir = fixture();
        let gone = dir.join("never-existed");
        assert_eq!(probe(&gone), AccessState::Unknown);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_gate_lives_inside_home_and_resolves_by_id() {
        let home = home();
        for listed in gates() {
            assert!(is_within(&listed.path, &home), "{:?} escaped $HOME", listed.path);
            assert!(!listed.service.is_empty(), "{} has no TCC service", listed.id);
            let found = gate(&listed.id).expect("a listed gate must resolve by id");
            assert_eq!(found.path, listed.path);
        }
    }

    #[test]
    fn an_id_we_do_not_know_resolves_to_nothing() {
        assert!(gate("").is_none());
        assert!(gate("../../etc").is_none());
        assert!(gate("SystemPolicyAllFiles").is_none());
    }

    /// The reason the access step comes after the scope step: a root with no
    /// gates under it must ask for nothing at all.
    #[test]
    fn a_root_outside_the_gated_folders_asks_for_nothing() {
        let dir = fixture();
        assert!(gates_under(&dir).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scanning_home_asks_for_every_gate() {
        assert_eq!(gates_under(&home()).len(), gates().len());
    }

    #[test]
    fn only_the_two_known_panes_resolve() {
        assert_eq!(
            SettingsPane::from_id("files"),
            Some(SettingsPane::FilesAndFolders)
        );
        assert_eq!(SettingsPane::from_id("full-disk"), Some(SettingsPane::FullDisk));
        assert!(SettingsPane::from_id("anything-else").is_none());
        assert!(SettingsPane::from_id("").is_none());
    }
}
