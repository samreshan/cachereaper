//! Advisory cross-platform filesystem change notifications.
//!
//! Events invalidate stale scan evidence and ask the UI to refresh. They never
//! supply action paths and therefore cannot grant filesystem authority.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};

pub struct ChangeWatcher {
    _watcher: RecommendedWatcher,
    armed: Arc<AtomicBool>,
}

impl ChangeWatcher {
    pub fn start(root: &Path, callback: impl Fn() + Send + Sync + 'static) -> Result<Self, String> {
        let watched_root = root.canonicalize().map_err(|error| error.to_string())?;
        let last_event_ms = Arc::new(AtomicU64::new(0));
        let armed = Arc::new(AtomicBool::new(false));
        let event_armed = armed.clone();
        let callback = Arc::new(callback);
        let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
            if result.is_err() || !event_armed.load(Ordering::Acquire) {
                return;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
                .unwrap_or(0);
            let previous = last_event_ms.swap(now, Ordering::AcqRel);
            if now.saturating_sub(previous) >= 750 {
                callback();
            }
        })
        .map_err(|error| error.to_string())?;
        watcher
            .watch(&watched_root, RecursiveMode::Recursive)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            _watcher: watcher,
            armed,
        })
    }

    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watcher_registers_an_existing_root_and_rejects_a_missing_one() {
        let root = std::env::temp_dir().join(format!(
            "cachereaper-watcher-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let watcher = ChangeWatcher::start(&root, || {}).unwrap();
        watcher.arm();
        drop(watcher);
        assert!(ChangeWatcher::start(&root.join("missing"), || {}).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
