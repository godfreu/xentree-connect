use std::path::Path;

use super::DetectedPlatform;

pub(super) fn detect(dir: &Path) -> Option<DetectedPlatform> {
    let cargo_toml = dir.join("Cargo.toml");
    cargo_toml
        .is_file()
        .then_some(DetectedPlatform::Rust { cargo_toml })
}
