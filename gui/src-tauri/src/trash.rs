use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub fn move_to_trash(path: &Path) -> Result<PathBuf, String> {
    use objc2_foundation::{NSFileManager, NSString, NSURL};

    let text = path
        .to_str()
        .ok_or_else(|| "Trash only accepts a Unicode path".to_string())?;
    let url = NSURL::fileURLWithPath(&NSString::from_str(text));
    let manager = NSFileManager::defaultManager();
    let mut resulting = None;
    manager
        .trashItemAtURL_resultingItemURL_error(&url, Some(&mut resulting))
        .map_err(|error| error.localizedDescription().to_string())?;
    let resulting = resulting.ok_or_else(|| {
        "the platform moved the file but did not report its Trash location".to_string()
    })?;
    resulting
        .path()
        .map(|value| PathBuf::from(value.to_string()))
        .ok_or_else(|| "the platform returned an invalid Trash location".to_string())
}

#[cfg(not(target_os = "macos"))]
pub fn move_to_trash(_path: &Path) -> Result<PathBuf, String> {
    Err("native Trash is not available on this platform build".to_string())
}
