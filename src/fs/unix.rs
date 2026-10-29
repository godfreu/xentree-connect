use std::{
    fs::{DirBuilder, File, OpenOptions, Permissions},
    io,
    os::unix::fs::{fchown, DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use super::{FsError, KeyOwnershipPolicy};

/// Widest mode any policy may grant: owner read/write, group read.
pub const MAX_MODE: u32 = 0o640;

/// Mode the file ends up with, and the most it may have when verified.
fn policy_mode(policy: &KeyOwnershipPolicy) -> u32 {
    match policy {
        KeyOwnershipPolicy::CurrentUserOnly => 0o600,
        KeyOwnershipPolicy::GroupReadable { .. } => 0o640,
        KeyOwnershipPolicy::SpecificOwner { mode, .. } => *mode,
    }
}

pub fn create_private_dir_all(dir: &Path, policy: &KeyOwnershipPolicy) -> io::Result<()> {
    match policy {
        // Mode applies only to directories this call creates; existing ones are untouched.
        KeyOwnershipPolicy::CurrentUserOnly => {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)
        }
        _ if dir.is_dir() => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "parent directory must exist when a non-default ownership policy is used",
        )),
    }
}

/// `create_new` implies `O_EXCL`, which also refuses to follow a symlink at the final component.
/// Always owner-only at creation, whatever the policy.
pub fn create_private_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Hands the (still empty, still 0600) file to its intended owner/group.
pub fn assign_owner(file: &File, policy: &KeyOwnershipPolicy) -> io::Result<()> {
    match policy {
        KeyOwnershipPolicy::CurrentUserOnly => Ok(()),
        KeyOwnershipPolicy::GroupReadable { gid } => fchown(file, None, Some(*gid)),
        KeyOwnershipPolicy::SpecificOwner { uid, gid, .. } => fchown(file, Some(*uid), Some(*gid)),
    }
}

/// Widens the mode to the policy's, after contents are written.
pub fn apply_mode(file: &File, policy: &KeyOwnershipPolicy) -> io::Result<()> {
    file.set_permissions(Permissions::from_mode(policy_mode(policy)))
}

pub fn verify_private(
    file: &File,
    path: &Path,
    policy: &KeyOwnershipPolicy,
) -> Result<(), FsError> {
    let meta = file.metadata().map_err(|e| FsError::io(path, e))?;
    let bad = |reason: String| FsError::InsecurePermissions {
        path: path.to_path_buf(),
        reason,
    };
    if !meta.is_file() {
        return Err(bad("not a regular file".into()));
    }

    // Include setuid/setgid/sticky: they are never acceptable on a key.
    let mode = meta.mode() & 0o7777;
    let allowed = policy_mode(policy);
    if mode & !allowed != 0 {
        return Err(bad(format!(
            "mode is {mode:04o}, policy allows at most {allowed:04o}"
        )));
    }

    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let (want_uid, want_gid) = match policy {
        KeyOwnershipPolicy::CurrentUserOnly => (euid, None),
        KeyOwnershipPolicy::GroupReadable { gid } => (euid, Some(*gid)),
        KeyOwnershipPolicy::SpecificOwner { uid, gid, .. } => (*uid, Some(*gid)),
    };
    if meta.uid() != want_uid {
        return Err(bad(format!(
            "owned by uid {}, expected {want_uid}",
            meta.uid()
        )));
    }
    if let Some(gid) = want_gid {
        if meta.gid() != gid {
            return Err(bad(format!("group is gid {}, expected {gid}", meta.gid())));
        }
    }
    Ok(())
}

pub fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}
