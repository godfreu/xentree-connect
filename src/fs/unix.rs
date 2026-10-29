use std::{
    fs::{DirBuilder, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

use super::FsError;

pub fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    // Mode applies only to directories this call creates; existing ones are untouched.
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

/// `create_new` implies `O_EXCL`, which also refuses to follow a symlink at the final component.
pub fn create_private_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

pub fn verify_private(file: &File, path: &Path) -> Result<(), FsError> {
    let meta = file.metadata().map_err(|e| FsError::io(path, e))?;
    let bad = |reason: String| FsError::InsecurePermissions {
        path: path.to_path_buf(),
        reason,
    };
    if !meta.is_file() {
        return Err(bad("not a regular file".into()));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(bad(format!(
            "mode is {mode:04o}, group/other access must be 0"
        )));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(bad(format!("owned by uid {}, expected {euid}", meta.uid())));
    }
    Ok(())
}

pub fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}
