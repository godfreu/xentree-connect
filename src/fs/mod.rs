//! Hardened storage for private key material.
//!
//! Files are created with owner-only permissions *at creation time* (no
//! write-then-chmod window), fsynced, verified, and moved into place
//! atomically. If permissions cannot be enforced or verified the write fails;
//! there is no silent fallback.

use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

use ring::rand::{SecureRandom, SystemRandom};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as platform;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as platform;

#[cfg(not(any(unix, windows)))]
compile_error!("xentree-connect supports only unix and windows targets");

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("I/O error on {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{0} already exists; refusing to overwrite")]
    AlreadyExists(PathBuf),
    #[error("insecure permissions on {path}: {reason}")]
    InsecurePermissions { path: PathBuf, reason: String },
}

impl FsError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// What to do when the destination already exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Fail with [`FsError::AlreadyExists`]. The existing file is untouched.
    Fail,
    /// Atomically replace it.
    Replace,
}

/// Atomically writes `contents` to `path`, readable only by the current user.
///
/// Missing parent directories are created (owner-only on Unix).
pub fn write_private_file(path: &Path, contents: &[u8], existing: Existing) -> Result<(), FsError> {
    let name = path.file_name().ok_or_else(|| {
        FsError::io(
            path,
            io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"),
        )
    })?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    platform::create_private_dir_all(parent).map_err(|e| FsError::io(parent, e))?;

    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        random_suffix()
    ));
    let result = write_and_install(&tmp, path, contents, existing);
    if tmp.exists() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    platform::sync_dir(parent);
    Ok(())
}

fn write_and_install(
    tmp: &Path,
    dest: &Path,
    contents: &[u8],
    existing: Existing,
) -> Result<(), FsError> {
    let mut file = platform::create_private_new(tmp).map_err(|e| FsError::io(tmp, e))?;
    file.write_all(contents).map_err(|e| FsError::io(tmp, e))?;
    file.sync_all().map_err(|e| FsError::io(tmp, e))?;
    platform::verify_private(&file, tmp)?;
    drop(file);

    match existing {
        Existing::Replace => std::fs::rename(tmp, dest).map_err(|e| FsError::io(dest, e)),
        // A hard link fails atomically if `dest` exists, unlike rename.
        Existing::Fail => match std::fs::hard_link(tmp, dest) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                Err(FsError::AlreadyExists(dest.to_path_buf()))
            }
            Err(e) => Err(FsError::io(dest, e)),
        },
    }
}

/// Checks that an existing file is private to the current user (for `health`
/// and gateway startup).
pub fn verify_private_file(path: &Path) -> Result<(), FsError> {
    let file = File::open(path).map_err(|e| FsError::io(path, e))?;
    platform::verify_private(&file, path)
}

fn random_suffix() -> String {
    let mut b = [0u8; 8];
    SystemRandom::new().fill(&mut b).expect("system RNG");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn leftovers(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn writes_contents_and_passes_verification() {
        let d = tempdir().unwrap();
        let p = d.path().join("xentree_private.pem");
        write_private_file(&p, b"secret", Existing::Fail).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"secret");
        verify_private_file(&p).unwrap();
        assert!(leftovers(d.path()).is_empty());
    }

    #[test]
    fn fail_mode_never_clobbers_existing_file() {
        let d = tempdir().unwrap();
        let p = d.path().join("k.pem");
        write_private_file(&p, b"original", Existing::Fail).unwrap();
        let err = write_private_file(&p, b"new", Existing::Fail).unwrap_err();
        assert!(matches!(err, FsError::AlreadyExists(_)));
        assert_eq!(std::fs::read(&p).unwrap(), b"original");
        assert!(leftovers(d.path()).is_empty());
    }

    #[test]
    fn replace_mode_swaps_contents() {
        let d = tempdir().unwrap();
        let p = d.path().join("k.pem");
        write_private_file(&p, b"one", Existing::Fail).unwrap();
        write_private_file(&p, b"two", Existing::Replace).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        verify_private_file(&p).unwrap();
        assert!(leftovers(d.path()).is_empty());
    }

    #[test]
    fn creates_missing_parent_directories() {
        let d = tempdir().unwrap();
        let p = d.path().join("a/b/k.pem");
        write_private_file(&p, b"x", Existing::Fail).unwrap();
        assert!(p.exists());
    }

    #[test]
    fn verification_rejects_a_default_permission_file() {
        let d = tempdir().unwrap();
        let p = d.path().join("loose.pem");
        std::fs::write(&p, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        assert!(matches!(
            verify_private_file(&p),
            Err(FsError::InsecurePermissions { .. })
        ));
    }

    #[cfg(unix)]
    mod unix_only {
        use super::*;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        #[test]
        fn file_is_0600_even_with_permissive_umask() {
            let d = tempdir().unwrap();
            let p = d.path().join("k.pem");
            // SAFETY: umask is process-global; this test only loosens it briefly.
            let old = unsafe { libc::umask(0) };
            let r = write_private_file(&p, b"x", Existing::Fail);
            unsafe { libc::umask(old) };
            r.unwrap();
            assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        }

        #[test]
        fn created_directories_are_0700() {
            let d = tempdir().unwrap();
            let p = d.path().join("cfg/xentree/k.pem");
            write_private_file(&p, b"x", Existing::Fail).unwrap();
            for dir in ["cfg", "cfg/xentree"] {
                let m = std::fs::metadata(d.path().join(dir)).unwrap().mode() & 0o777;
                assert_eq!(m, 0o700, "{dir}");
            }
        }

        #[test]
        fn replace_does_not_follow_symlink_at_destination() {
            let d = tempdir().unwrap();
            let victim = d.path().join("victim");
            std::fs::write(&victim, b"keep").unwrap();
            let link = d.path().join("k.pem");
            std::os::unix::fs::symlink(&victim, &link).unwrap();
            write_private_file(&link, b"key", Existing::Replace).unwrap();
            assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
            assert!(!std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
        }

        #[test]
        fn verification_rejects_group_readable_key() {
            let d = tempdir().unwrap();
            let p = d.path().join("k.pem");
            write_private_file(&p, b"x", Existing::Fail).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(verify_private_file(&p).is_err());
        }
    }
}
