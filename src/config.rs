//! The non-secret record `init` leaves behind so `health` (and later the
//! gateway) know which key, integration and cloud to use.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::fs::{write_private_file, Existing, FsError, KeyOwnershipPolicy};

pub const FILE_NAME: &str = "xentree-connect.json";
pub const KEY_FILE_NAME: &str = "xentree_private.pem";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub base_url: String,
    pub org_id: String,
    /// The `client_record_id` returned at registration.
    pub client_record_id: String,
    pub client_id: String,
    pub issuer: String,
    pub audience: String,
    /// Thumbprint of the registered signing key.
    pub kid: String,
    pub key_path: PathBuf,
    pub ownership: OwnershipConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OwnershipConfig {
    CurrentUserOnly,
    GroupReadable { gid: u32 },
    SpecificOwner { uid: u32, gid: u32, mode: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not a valid config: {source}")]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("ownership policy {0} is not supported on this platform")]
    UnsupportedOwnership(&'static str),
    #[error(transparent)]
    Write(#[from] FsError),
}

impl OwnershipConfig {
    pub fn from_policy(policy: &KeyOwnershipPolicy) -> Self {
        match policy {
            KeyOwnershipPolicy::CurrentUserOnly => Self::CurrentUserOnly,
            #[cfg(unix)]
            KeyOwnershipPolicy::GroupReadable { gid } => Self::GroupReadable { gid: *gid },
            #[cfg(unix)]
            KeyOwnershipPolicy::SpecificOwner { uid, gid, mode } => Self::SpecificOwner {
                uid: *uid,
                gid: *gid,
                mode: *mode,
            },
        }
    }

    pub fn to_policy(&self) -> Result<KeyOwnershipPolicy, ConfigError> {
        match self {
            Self::CurrentUserOnly => Ok(KeyOwnershipPolicy::CurrentUserOnly),
            #[cfg(unix)]
            Self::GroupReadable { gid } => Ok(KeyOwnershipPolicy::GroupReadable { gid: *gid }),
            #[cfg(unix)]
            Self::SpecificOwner { uid, gid, mode } => Ok(KeyOwnershipPolicy::SpecificOwner {
                uid: *uid,
                gid: *gid,
                mode: *mode,
            }),
            #[cfg(not(unix))]
            Self::GroupReadable { .. } => Err(ConfigError::UnsupportedOwnership("group_readable")),
            #[cfg(not(unix))]
            Self::SpecificOwner { .. } => Err(ConfigError::UnsupportedOwnership("specific_owner")),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        serde_json::from_slice(&bytes).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Atomically (re)writes the config with the same access policy as the key
    /// it describes, so a web server that can read the key can read this too.
    pub fn save(&self, path: &Path, policy: &KeyOwnershipPolicy) -> Result<(), ConfigError> {
        let mut json = serde_json::to_vec_pretty(self).expect("config serializes");
        json.push(b'\n');
        write_private_file(path, &json, Existing::Replace, policy)?;
        Ok(())
    }
}

fn project_dirs() -> Option<ProjectDirs> {
    ProjectDirs::from("ai", "Xentree", "xentree-connect")
}

/// Per-user default home for the key and config.
pub fn default_config_dir() -> Option<PathBuf> {
    project_dirs().map(|d| d.config_dir().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample() -> Config {
        Config {
            base_url: "https://my.xentree.ai".into(),
            org_id: "org_1".into(),
            client_record_id: "rec_1".into(),
            client_id: "moodle".into(),
            issuer: "https://lms.example.com".into(),
            audience: "xentree".into(),
            kid: "abc".into(),
            key_path: "/k/xentree_private.pem".into(),
            ownership: OwnershipConfig::CurrentUserOnly,
        }
    }

    #[test]
    fn save_and_load_round_trip() {
        let d = tempdir().unwrap();
        let p = d.path().join(FILE_NAME);
        sample()
            .save(&p, &KeyOwnershipPolicy::CurrentUserOnly)
            .unwrap();
        assert_eq!(Config::load(&p).unwrap(), sample());
        // idempotent overwrite
        sample()
            .save(&p, &KeyOwnershipPolicy::CurrentUserOnly)
            .unwrap();
    }

    #[test]
    fn contains_no_private_material() {
        let d = tempdir().unwrap();
        let p = d.path().join(FILE_NAME);
        sample()
            .save(&p, &KeyOwnershipPolicy::CurrentUserOnly)
            .unwrap();
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            !text.contains("PRIVATE KEY") && !text.contains("secret") && !text.contains("token")
        );
    }

    #[test]
    fn rejects_garbage_and_missing_files() {
        let d = tempdir().unwrap();
        let p = d.path().join(FILE_NAME);
        assert!(matches!(Config::load(&p), Err(ConfigError::Read { .. })));
        std::fs::write(&p, "{not json").unwrap();
        assert!(matches!(Config::load(&p), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn ownership_serializes_with_a_type_tag() {
        let json = serde_json::to_string(&OwnershipConfig::CurrentUserOnly).unwrap();
        assert_eq!(json, r#"{"type":"current_user_only"}"#);
    }

    #[cfg(unix)]
    #[test]
    fn ownership_policy_round_trip() {
        for policy in [
            KeyOwnershipPolicy::CurrentUserOnly,
            KeyOwnershipPolicy::GroupReadable { gid: 33 },
            KeyOwnershipPolicy::SpecificOwner {
                uid: 1,
                gid: 2,
                mode: 0o640,
            },
        ] {
            assert_eq!(
                OwnershipConfig::from_policy(&policy).to_policy().unwrap(),
                policy
            );
        }
    }
}
