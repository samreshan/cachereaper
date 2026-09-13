//! Stable Windows file identity without nightly-only `MetadataExt` methods.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct FileIdentity {
    pub volume: u64,
    pub file: u64,
    pub links: u32,
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the constructor only stores a valid owned handle, and Drop
        // runs exactly once for that handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Read the volume serial and 64-bit file index for a file or directory.
///
/// `FILE_FLAG_BACKUP_SEMANTICS` is required for directory handles. Sharing all
/// common operations prevents an inventory scan from needlessly blocking an
/// application that is concurrently reading, writing, renaming, or deleting.
pub(crate) fn query(path: &Path) -> io::Result<FileIdentity> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: `wide` is a live NUL-terminated UTF-16 path; the security and
    // template pointers are null by contract. A successful call returns an
    // owned handle closed by `OwnedHandle`.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let handle = OwnedHandle(raw);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` remains open and `info` is a correctly sized writable
    // output buffer for the duration of the call.
    if unsafe { GetFileInformationByHandle(handle.0, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume: u64::from(info.dwVolumeSerialNumber),
        file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        links: info.nNumberOfLinks,
    })
}

/// A conservative fallback for entries whose handles cannot be opened.
///
/// Keeping volume zero separates this namespace from normal filesystem IDs.
/// The path digest prevents unrelated inaccessible files with the same size and
/// timestamp from ever sharing cached content evidence.
pub(crate) fn query_or_path(path: &Path) -> FileIdentity {
    query(path).unwrap_or_else(|_| {
        let mut hasher = Sha256::new();
        for unit in path.as_os_str().encode_wide() {
            hasher.update(unit.to_le_bytes());
        }
        let digest = hasher.finalize();
        FileIdentity {
            volume: 0,
            file: u64::from_le_bytes(digest[..8].try_into().expect("SHA-256 prefix is 8 bytes")),
            links: 1,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_file_has_a_stable_nonzero_identity() {
        let path = std::env::temp_dir().join(format!(
            "cachereaper-windows-identity-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"identity probe").unwrap();
        let first = query(&path).unwrap();
        let second = query(&path).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(first.volume, second.volume);
        assert_eq!(first.file, second.file);
        assert!(first.volume != 0 || first.file != 0);
        assert!(first.links >= 1);
    }
}
