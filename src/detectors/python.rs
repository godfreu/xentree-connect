use std::path::Path;

use super::DetectedPlatform;

pub(super) fn detect(dir: &Path) -> Option<DetectedPlatform> {
    ["pyproject.toml", "requirements.txt"]
        .iter()
        .map(|name| dir.join(name))
        .find(|p| p.is_file())
        .map(|manifest| DetectedPlatform::Python { manifest })
}
