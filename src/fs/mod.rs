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
    #[error("invalid ownership policy: {0}")]
    InvalidPolicy(String),
}

impl FsError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Who may read a stored key. Web servers (Moodle's `www-data`, Apache,
/// Nginx) can't read a key that only its creator may open, so Unix
/// deployments can grant a specific group read access.
///
/// Permission bits are only ever *subsets* of the policy's mode: a stricter
/// file (say `0400`) passes verification, anything wider fails.
///
/// Only [`CurrentUserOnly`](Self::CurrentUserOnly) exists on Windows, where
/// the key always gets a single-user protected DACL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum KeyOwnershipPolicy {
    /// Mode `0600` (Unix) or a single-user DACL (Windows), owned by the
    /// executing user.
    #[default]
    CurrentUserOnly,
    /// Mode `0640`, owned by the executing user, group `gid` may read, others
    /// get nothing. The process must be a member of `gid` (or root) to apply it.
    #[cfg(unix)]
    GroupReadable { gid: u32 },
    /// Explicit owner and group, for installers running as root. `mode` may
    /// not exceed `0640`: no group-write, no access for others, no
    /// setuid/setgid/sticky.
    #[cfg(unix)]
    SpecificOwner { uid: u32, gid: u32, mode: u32 },
}

impl KeyOwnershipPolicy {
    /// Rejects policies that would grant more than a private key should allow.
    pub fn validate(&self) -> Result<(), FsError> {
        #[cfg(unix)]
        if let Self::SpecificOwner { mode, .. } = self {
            if mode & !unix::MAX_MODE != 0 {
                return Err(FsError::InvalidPolicy(format!(
                    "mode {mode:04o} grants more than {:04o}",
                    unix::MAX_MODE
                )));
            }
            if mode & 0o400 == 0 {
                return Err(FsError::InvalidPolicy(format!(
                    "mode {mode:04o} is not readable by the owner"
                )));
            }
        }
        Ok(())
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

/// Atomically writes `contents` to `path` with access limited per `policy`.
///
/// With [`KeyOwnershipPolicy::CurrentUserOnly`], missing parent directories
/// are created (owner-only on Unix). Other policies require the parent
/// directory to exist already: its group ownership and traversal bits are the
/// deployer's responsibility, and guessing them here could lock out the web
/// server or expose the key.
pub fn write_private_file(
    path: &Path,
    contents: &[u8],
    existing: Existing,
    policy: &KeyOwnershipPolicy,
) -> Result<(), FsError> {
    policy.validate()?;
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
    platform::create_private_dir_all(parent, policy).map_err(|e| FsError::io(parent, e))?;

    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        random_suffix()
    ));
    let result = write_and_install(&tmp, path, contents, existing, policy);
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
    policy: &KeyOwnershipPolicy,
) -> Result<(), FsError> {
    // Created owner-only. Ownership is handed over before the secret is
    // written, and the mode is widened (if the policy says so) only after.
    let mut file = platform::create_private_new(tmp).map_err(|e| FsError::io(tmp, e))?;
    platform::assign_owner(&file, policy).map_err(|e| FsError::io(tmp, e))?;
    file.write_all(contents).map_err(|e| FsError::io(tmp, e))?;
    file.sync_all().map_err(|e| FsError::io(tmp, e))?;
    platform::apply_mode(&file, policy).map_err(|e| FsError::io(tmp, e))?;
    platform::verify_private(&file, tmp, policy)?;
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

/// Creates the directory a key will live in, appropriately for `policy`.
///
/// `CurrentUserOnly` creates missing ancestors owner-only. Other policies
/// create just the final directory (its parent must exist) and give it the
/// policy's group/owner, so a web server can traverse into it.
pub fn ensure_key_dir(dir: &Path, policy: &KeyOwnershipPolicy) -> Result<(), FsError> {
    policy.validate()?;
    platform::ensure_dir(dir, policy).map_err(|e| FsError::io(dir, e))
}

/// Checks that an existing key file satisfies `policy` (for `health` and
/// gateway startup).
pub fn verify_private_file(path: &Path, policy: &KeyOwnershipPolicy) -> Result<(), FsError> {
    policy.validate()?;
    let file = File::open(path).map_err(|e| FsError::io(path, e))?;
    platform::verify_private(&file, path, policy)
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

    const CUO: KeyOwnershipPolicy = KeyOwnershipPolicy::CurrentUserOnly;

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
        write_private_file(&p, b"secret", Existing::Fail, &CUO).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"secret");
        verify_private_file(&p, &CUO).unwrap();
        assert!(leftovers(d.path()).is_empty());
    }

    #[test]
    fn fail_mode_never_clobbers_existing_file() {
        let d = tempdir().unwrap();
        let p = d.path().join("k.pem");
        write_private_file(&p, b"original", Existing::Fail, &CUO).unwrap();
        let err = write_private_file(&p, b"new", Existing::Fail, &CUO).unwrap_err();
        assert!(matches!(err, FsError::AlreadyExists(_)));
        assert_eq!(std::fs::read(&p).unwrap(), b"original");
        assert!(leftovers(d.path()).is_empty());
    }

    #[test]
    fn replace_mode_swaps_contents() {
        let d = tempdir().unwrap();
        let p = d.path().join("k.pem");
        write_private_file(&p, b"one", Existing::Fail, &CUO).unwrap();
        write_private_file(&p, b"two", Existing::Replace, &CUO).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        verify_private_file(&p, &CUO).unwrap();
        assert!(leftovers(d.path()).is_empty());
    }

    #[test]
    fn creates_missing_parent_directories() {
        let d = tempdir().unwrap();
        let p = d.path().join("a/b/k.pem");
        write_private_file(&p, b"x", Existing::Fail, &CUO).unwrap();
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
            verify_private_file(&p, &CUO),
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
            let r = write_private_file(&p, b"x", Existing::Fail, &CUO);
            unsafe { libc::umask(old) };
            r.unwrap();
            assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        }

        #[test]
        fn created_directories_are_0700() {
            let d = tempdir().unwrap();
            let p = d.path().join("cfg/xentree/k.pem");
            write_private_file(&p, b"x", Existing::Fail, &CUO).unwrap();
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
            write_private_file(&link, b"key", Existing::Replace, &CUO).unwrap();
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
            write_private_file(&p, b"x", Existing::Fail, &CUO).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(verify_private_file(&p, &CUO).is_err());
        }

        mod policy {
            use super::*;
            use std::os::unix::fs::MetadataExt;

            fn euid() -> u32 {
                unsafe { libc::geteuid() }
            }
            fn egid() -> u32 {
                unsafe { libc::getegid() }
            }
            /// A group we belong to other than our primary one, if any.
            fn other_group() -> Option<u32> {
                let mut gs = [0 as libc::gid_t; 64];
                let n = unsafe { libc::getgroups(gs.len() as i32, gs.as_mut_ptr()) };
                gs[..n.max(0) as usize]
                    .iter()
                    .copied()
                    .find(|g| *g != egid())
            }
            fn file_with_mode(d: &Path, mode: u32) -> PathBuf {
                let p = d.join(format!("k{mode:o}.pem"));
                std::fs::write(&p, b"x").unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
                p
            }
            fn group() -> KeyOwnershipPolicy {
                KeyOwnershipPolicy::GroupReadable { gid: egid() }
            }

            #[test]
            fn current_user_only_accepts_owner_only_and_rejects_anything_wider() {
                let d = tempdir().unwrap();
                for mode in [0o600, 0o400] {
                    assert!(
                        verify_private_file(&file_with_mode(d.path(), mode), &CUO).is_ok(),
                        "{mode:o}"
                    );
                }
                for mode in [0o640, 0o644, 0o660, 0o604, 0o700, 0o4600] {
                    assert!(
                        verify_private_file(&file_with_mode(d.path(), mode), &CUO).is_err(),
                        "{mode:o}"
                    );
                }
            }

            #[test]
            fn group_readable_accepts_640_and_600() {
                let d = tempdir().unwrap();
                for mode in [0o640, 0o600, 0o440, 0o400] {
                    assert!(
                        verify_private_file(&file_with_mode(d.path(), mode), &group()).is_ok(),
                        "{mode:o}"
                    );
                }
            }

            #[test]
            fn group_readable_rejects_anything_wider_than_640() {
                let d = tempdir().unwrap();
                // group-write, world bits, owner exec, group exec, setuid/setgid
                for mode in [
                    0o660, 0o644, 0o664, 0o604, 0o641, 0o650, 0o700, 0o666, 0o4640, 0o2640,
                ] {
                    let r = verify_private_file(&file_with_mode(d.path(), mode), &group());
                    assert!(
                        matches!(r, Err(FsError::InsecurePermissions { .. })),
                        "{mode:o}"
                    );
                }
            }

            #[test]
            fn group_readable_rejects_wrong_group() {
                let d = tempdir().unwrap();
                let p = file_with_mode(d.path(), 0o640);
                let other = KeyOwnershipPolicy::GroupReadable {
                    gid: egid().wrapping_add(54321),
                };
                assert!(verify_private_file(&p, &other).is_err());
            }

            #[test]
            fn group_readable_write_sets_640_and_group() {
                let d = tempdir().unwrap();
                let p = d.path().join("k.pem");
                write_private_file(&p, b"key", Existing::Fail, &group()).unwrap();
                let m = std::fs::metadata(&p).unwrap();
                assert_eq!(m.mode() & 0o7777, 0o640);
                assert_eq!((m.uid(), m.gid()), (euid(), egid()));
                verify_private_file(&p, &group()).unwrap();
                // The default policy must flag the same file: group-readable is not "private".
                assert!(verify_private_file(&p, &CUO).is_err());
            }

            #[test]
            fn group_readable_write_assigns_a_different_group() {
                let Some(gid) = other_group() else { return };
                let d = tempdir().unwrap();
                let p = d.path().join("k.pem");
                let policy = KeyOwnershipPolicy::GroupReadable { gid };
                write_private_file(&p, b"key", Existing::Fail, &policy).unwrap();
                assert_eq!(std::fs::metadata(&p).unwrap().gid(), gid);
                verify_private_file(&p, &policy).unwrap();
                assert!(
                    verify_private_file(&p, &group()).is_err(),
                    "wrong gid for the other policy"
                );
            }

            #[test]
            fn unprivileged_chown_to_foreign_group_fails_cleanly() {
                if euid() == 0 {
                    return;
                }
                let d = tempdir().unwrap();
                let p = d.path().join("k.pem");
                // A gid we're not in (and unlikely to exist).
                let policy = KeyOwnershipPolicy::GroupReadable { gid: 3_999_999_999 };
                assert!(matches!(
                    write_private_file(&p, b"key", Existing::Fail, &policy),
                    Err(FsError::Io { .. })
                ));
                assert!(!p.exists());
                assert!(leftovers(d.path()).is_empty());
            }

            #[test]
            fn specific_owner_round_trip() {
                let d = tempdir().unwrap();
                let p = d.path().join("k.pem");
                let policy = KeyOwnershipPolicy::SpecificOwner {
                    uid: euid(),
                    gid: egid(),
                    mode: 0o640,
                };
                write_private_file(&p, b"key", Existing::Fail, &policy).unwrap();
                assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o7777, 0o640);
                verify_private_file(&p, &policy).unwrap();
                let wrong_uid = KeyOwnershipPolicy::SpecificOwner {
                    uid: euid().wrapping_add(1),
                    gid: egid(),
                    mode: 0o640,
                };
                assert!(verify_private_file(&p, &wrong_uid).is_err());
            }

            #[test]
            fn specific_owner_rejects_dangerous_modes() {
                let d = tempdir().unwrap();
                for mode in [0o644, 0o660, 0o666, 0o4640, 0o700, 0o040] {
                    let policy = KeyOwnershipPolicy::SpecificOwner {
                        uid: euid(),
                        gid: egid(),
                        mode,
                    };
                    let p = d.path().join(format!("k{mode:o}"));
                    assert!(
                        matches!(
                            write_private_file(&p, b"x", Existing::Fail, &policy),
                            Err(FsError::InvalidPolicy(_))
                        ),
                        "{mode:o}"
                    );
                    assert!(!p.exists());
                    assert!(matches!(
                        verify_private_file(&p, &policy),
                        Err(FsError::InvalidPolicy(_))
                    ));
                }
            }

            #[test]
            fn specific_owner_for_another_uid_needs_privilege() {
                if euid() == 0 {
                    return;
                }
                let d = tempdir().unwrap();
                let policy = KeyOwnershipPolicy::SpecificOwner {
                    uid: euid().wrapping_add(1),
                    gid: egid(),
                    mode: 0o600,
                };
                let p = d.path().join("k.pem");
                assert!(write_private_file(&p, b"x", Existing::Fail, &policy).is_err());
                assert!(!p.exists());
            }

            #[test]
            fn non_default_policies_do_not_invent_parent_directories() {
                let d = tempdir().unwrap();
                let p = d.path().join("missing/k.pem");
                assert!(write_private_file(&p, b"x", Existing::Fail, &group()).is_err());
                assert!(!d.path().join("missing").exists());
            }

            #[test]
            fn ensure_key_dir_creates_group_traversable_leaf_only() {
                let d = tempdir().unwrap();
                let leaf = d.path().join("moodledata");
                ensure_key_dir(&leaf, &group()).unwrap();
                let m = std::fs::metadata(&leaf).unwrap();
                assert_eq!(m.mode() & 0o7777, 0o750);
                assert_eq!(m.gid(), egid());
                ensure_key_dir(&leaf, &group()).unwrap(); // idempotent
                let deep = d.path().join("a/b");
                assert!(ensure_key_dir(&deep, &group()).is_err());
                assert!(!d.path().join("a").exists());
                // default policy creates ancestors, owner-only
                let own = d.path().join("x/y");
                ensure_key_dir(&own, &CUO).unwrap();
                assert_eq!(std::fs::metadata(&own).unwrap().mode() & 0o777, 0o700);
            }

            #[test]
            fn replace_keeps_policy_applied() {
                let d = tempdir().unwrap();
                let p = d.path().join("k.pem");
                write_private_file(&p, b"one", Existing::Fail, &CUO).unwrap();
                write_private_file(&p, b"two", Existing::Replace, &group()).unwrap();
                assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o7777, 0o640);
                verify_private_file(&p, &group()).unwrap();
            }
        }
    }
}
