use std::path::Path;

use super::{read_head, DetectedPlatform};

pub(super) fn detect(dir: &Path) -> Option<DetectedPlatform> {
    let package_json = dir.join("package.json");
    if !package_json.is_file() {
        return None;
    }
    let is_typescript = dir.join("tsconfig.json").is_file()
        || read_head(&package_json).is_some_and(|s| s.contains("\"typescript\""));
    Some(DetectedPlatform::Node {
        package_json,
        is_typescript,
    })
}
