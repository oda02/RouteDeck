//! One controller owns startup recovery for each application data directory.
//!
//! The file name is durable, but only the open kernel handle owns the lease. Never
//! delete a stale marker or infer ownership from a PID. Acquire before recovery and
//! keep the guard alive until the controller has finished restoring its state.

use std::{
    fs::{self, File, OpenOptions},
    io,
    path::Path,
};

use crate::engine_runtime::RuntimeError;

const LOCK_FILE: &str = "controller.lock";

pub(crate) struct AppInstanceGuard {
    _file: File,
}

impl AppInstanceGuard {
    pub(crate) fn acquire(root: &Path) -> Result<Self, RuntimeError> {
        let root = if root.is_absolute() {
            root.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| failure("Cannot locate the application data directory"))?
                .join(root)
        };
        // Reject existing junctions/symlinks before following them to create data.
        // This is coordination between cooperating controllers, not a security
        // boundary against a same-user process replacing ancestor directories.
        validate_directories(&root)?;
        fs::create_dir_all(&root)
            .map_err(|_| failure("Cannot create the application data directory"))?;
        validate_directories(&root)?;
        let path = root.join(LOCK_FILE);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => validate_lock_file(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(failure("Cannot inspect the controller lease")),
        }

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

            // Deny concurrent opens and deletion while the controller is alive.
            // OPEN_REPARSE_POINT lets handle metadata reject a final-component
            // link even if one was substituted after the path check above.
            options
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(&path).map_err(|error| {
            if is_busy(&error) {
                failure("RouteDeck is already running for this application data directory")
            } else {
                failure("Cannot acquire the controller lease")
            }
        })?;
        validate_lock_file(
            &file
                .metadata()
                .map_err(|_| failure("Cannot verify the controller lease"))?,
        )?;
        #[cfg(not(windows))]
        {
            // File::try_lock is stable since Rust 1.89, our minimum Rust version.
            // The portable fallback coordinates cooperating controllers only.
            file.try_lock().map_err(|error| match error {
                std::fs::TryLockError::WouldBlock => {
                    failure("RouteDeck is already running for this application data directory")
                }
                std::fs::TryLockError::Error(_) => failure("Cannot acquire the controller lease"),
            })?;
        }
        Ok(Self { _file: file })
    }
}

fn validate_directories(root: &Path) -> Result<(), RuntimeError> {
    for ancestor in root.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.is_dir() && !is_reparse(&metadata) => {}
            Ok(_) => {
                return Err(failure(
                    "Application data directories must not be reparse points",
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(failure("Cannot inspect the application data directory")),
        }
    }
    Ok(())
}

fn validate_lock_file(metadata: &fs::Metadata) -> Result<(), RuntimeError> {
    if !metadata.is_file() || is_reparse(metadata) {
        return Err(failure("The controller lease must be a regular file"));
    }
    Ok(())
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    metadata.file_type().is_symlink()
}

fn is_busy(error: &io::Error) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};

        matches!(error.raw_os_error(), Some(code) if code == ERROR_SHARING_VIOLATION as i32 || code == ERROR_LOCK_VIOLATION as i32)
    }
    #[cfg(not(windows))]
    {
        error.kind() == io::ErrorKind::WouldBlock
    }
}

fn failure(message: &'static str) -> RuntimeError {
    RuntimeError::new("app_instance", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "routedeck-instance-test-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn second_controller_is_rejected_until_guard_drops() {
        let fixture = Fixture::new();
        let first = AppInstanceGuard::acquire(&fixture.0).unwrap();
        let second = AppInstanceGuard::acquire(&fixture.0);
        assert!(matches!(second, Err(error) if error.stage() == "app_instance"));
        drop(first);
        assert!(fixture.0.join(LOCK_FILE).exists());
        let _next = AppInstanceGuard::acquire(&fixture.0).unwrap();
    }

    #[test]
    fn acquiring_and_contending_never_truncate_existing_marker() {
        let fixture = Fixture::new();
        let path = fixture.0.join(LOCK_FILE);
        fs::write(&path, b"existing evidence").unwrap();
        let first = AppInstanceGuard::acquire(&fixture.0).unwrap();
        assert!(AppInstanceGuard::acquire(&fixture.0).is_err());
        drop(first);
        assert_eq!(fs::read(&path).unwrap(), b"existing evidence");
    }

    #[test]
    fn separate_roots_have_independent_leases() {
        let fixture = Fixture::new();
        let _first = AppInstanceGuard::acquire(&fixture.0.join("first")).unwrap();
        let _second = AppInstanceGuard::acquire(&fixture.0.join("second")).unwrap();
    }

    #[test]
    fn directory_cannot_be_used_as_the_lock_file() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join(LOCK_FILE)).unwrap();
        assert!(AppInstanceGuard::acquire(&fixture.0).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_file_and_parent_are_rejected() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new();
        let target = fixture.0.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join(LOCK_FILE), b"untouched").unwrap();
        let link = fixture.0.join("link");
        symlink(&target, &link).unwrap();
        assert!(AppInstanceGuard::acquire(&link.join("child")).is_err());
        assert!(!target.join("child").exists());
        symlink(target.join(LOCK_FILE), fixture.0.join(LOCK_FILE)).unwrap();
        assert!(AppInstanceGuard::acquire(&fixture.0).is_err());
        assert_eq!(fs::read(target.join(LOCK_FILE)).unwrap(), b"untouched");
    }
}
