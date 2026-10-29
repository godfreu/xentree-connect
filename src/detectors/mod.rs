//! Heuristic detection of the platform a Connect integration is being set up for.
//!
//! Detection only reads a few well-known manifests; it never executes
//! anything from the inspected project.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

pub mod moodle;
mod node;
mod python;
mod rustlang;

/// Manifests are small; never slurp an arbitrarily large file.
const MAX_READ: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedPlatform {
    Moodle {
        root: PathBuf,
        config_php: PathBuf,
    },
    Node {
        package_json: PathBuf,
        is_typescript: bool,
    },
    /// `pyproject.toml` if present, else `requirements.txt`.
    Python {
        manifest: PathBuf,
    },
    Rust {
        cargo_toml: PathBuf,
    },
    Generic,
}

impl DetectedPlatform {
    /// Inspects `dir`. Moodle is checked first (and also in ancestors, so a
    /// plugin directory resolves to its site) because a Moodle checkout also
    /// contains a `package.json`.
    pub fn detect(dir: &Path) -> Self {
        if let Some(site) = moodle::detect(dir) {
            return Self::Moodle {
                root: site.root,
                config_php: site.config_php,
            };
        }
        node::detect(dir)
            .or_else(|| python::detect(dir))
            .or_else(|| rustlang::detect(dir))
            .unwrap_or(Self::Generic)
    }

    /// Stable identifier, used to build localization keys.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Moodle { .. } => "moodle",
            Self::Node {
                is_typescript: true,
                ..
            } => "node_ts",
            Self::Node { .. } => "node",
            Self::Python { .. } => "python",
            Self::Rust { .. } => "rust",
            Self::Generic => "generic",
        }
    }

    /// Where this platform conventionally keeps private keys, if it has an opinion.
    pub fn suggested_key_dir(&self) -> Option<PathBuf> {
        match self {
            Self::Moodle { root, config_php } => Some(moodle::suggested_key_dir(root, config_php)),
            _ => None,
        }
    }

    /// The issuer URL this platform already knows about (Moodle's `wwwroot`).
    pub fn suggested_issuer(&self) -> Option<String> {
        match self {
            Self::Moodle { config_php, .. } => moodle::wwwroot(config_php),
            _ => None,
        }
    }
}

/// Reads at most [`MAX_READ`] bytes, lossily decoded.
pub(crate) fn read_head(path: &Path) -> Option<String> {
    let mut buf = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_READ)
        .read_to_end(&mut buf)
        .ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    pub(super) fn touch(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        p
    }

    #[test]
    fn empty_directory_is_generic() {
        let d = tempdir().unwrap();
        assert_eq!(
            DetectedPlatform::detect(d.path()),
            DetectedPlatform::Generic
        );
    }

    #[test]
    fn detects_node_and_typescript_variants() {
        let d = tempdir().unwrap();
        let pj = touch(
            d.path(),
            "package.json",
            r#"{"name":"app","dependencies":{"express":"4"}}"#,
        );
        assert_eq!(
            DetectedPlatform::detect(d.path()),
            DetectedPlatform::Node {
                package_json: pj.clone(),
                is_typescript: false
            }
        );
        touch(d.path(), "tsconfig.json", "{}");
        assert_eq!(
            DetectedPlatform::detect(d.path()),
            DetectedPlatform::Node {
                package_json: pj,
                is_typescript: true
            }
        );
    }

    #[test]
    fn typescript_dependency_without_tsconfig_counts() {
        let d = tempdir().unwrap();
        touch(
            d.path(),
            "package.json",
            r#"{"devDependencies":{"typescript":"^5"}}"#,
        );
        assert!(matches!(
            DetectedPlatform::detect(d.path()),
            DetectedPlatform::Node {
                is_typescript: true,
                ..
            }
        ));
    }

    #[test]
    fn python_prefers_pyproject_over_requirements() {
        let d = tempdir().unwrap();
        let req = touch(d.path(), "requirements.txt", "flask\n");
        assert_eq!(
            DetectedPlatform::detect(d.path()),
            DetectedPlatform::Python { manifest: req }
        );
        let pp = touch(d.path(), "pyproject.toml", "[project]\n");
        assert_eq!(
            DetectedPlatform::detect(d.path()),
            DetectedPlatform::Python { manifest: pp }
        );
    }

    #[test]
    fn detects_rust() {
        let d = tempdir().unwrap();
        let c = touch(d.path(), "Cargo.toml", "[package]\n");
        assert_eq!(
            DetectedPlatform::detect(d.path()),
            DetectedPlatform::Rust { cargo_toml: c }
        );
    }

    #[test]
    fn precedence_node_then_python_then_rust() {
        let d = tempdir().unwrap();
        touch(d.path(), "Cargo.toml", "");
        touch(d.path(), "requirements.txt", "");
        assert_eq!(DetectedPlatform::detect(d.path()).id(), "python");
        touch(d.path(), "package.json", "{}");
        assert_eq!(DetectedPlatform::detect(d.path()).id(), "node");
    }

    #[test]
    fn moodle_wins_over_its_own_package_json() {
        let d = tempdir().unwrap();
        touch(d.path(), "package.json", "{}");
        touch(
            d.path(),
            "version.php",
            "<?php $version = 2024100700; $release = '4.5';",
        );
        touch(d.path(), "config.php", "<?php $CFG = new stdClass();");
        assert_eq!(DetectedPlatform::detect(d.path()).id(), "moodle");
    }

    #[test]
    fn ids_are_stable() {
        assert_eq!(DetectedPlatform::Generic.id(), "generic");
    }
}
