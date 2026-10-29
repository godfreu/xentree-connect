//! Moodle site detection and conventions.

use std::path::{Path, PathBuf};

use super::read_head;

/// How far above the start directory to look for the site root (a plugin
/// lives at `<root>/local/xentreeconnect`, two levels down).
const MAX_ANCESTORS: usize = 6;

/// Group names web servers run under: Debian/Ubuntu, RHEL, nginx, macOS.
pub const WEB_SERVER_GROUPS: [&str; 4] = ["www-data", "apache", "nginx", "_www"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoodleSite {
    pub root: PathBuf,
    pub config_php: PathBuf,
}

/// A Moodle site root has a `config.php` (which defines `$CFG`) next to a
/// `version.php` carrying either Moodle's `$release`/`$version` or our
/// plugin's component name.
pub fn detect(start: &Path) -> Option<MoodleSite> {
    start.ancestors().take(MAX_ANCESTORS).find_map(|dir| {
        let config_php = dir.join("config.php");
        let version_php = dir.join("version.php");
        let config_ok = read_head(&config_php).is_some_and(|s| s.contains("$CFG"));
        let version_ok = read_head(&version_php).is_some_and(|s| {
            s.contains("local_xentreeconnect") || (s.contains("$release") && s.contains("$version"))
        });
        (config_ok && version_ok).then(|| MoodleSite {
            root: dir.to_path_buf(),
            config_php,
        })
    })
}

/// Reads `$CFG->{name} = '...';` from a Moodle `config.php`, ignoring
/// commented-out lines. Does not evaluate PHP.
pub fn config_value(source: &str, name: &str) -> Option<String> {
    let needle = format!("$CFG->{name}");
    source.lines().find_map(|line| {
        let line = line.trim_start();
        // `<?php $CFG->... = ...;` on a single line is legal.
        let line = line.strip_prefix("<?php").map_or(line, str::trim_start);
        if line.starts_with("//") || line.starts_with('#') || line.starts_with('*') {
            return None;
        }
        let rest = line
            .strip_prefix(&needle)?
            .trim_start()
            .strip_prefix('=')?
            .trim_start();
        let quote = rest.chars().next().filter(|c| *c == '\'' || *c == '"')?;
        let inner = &rest[1..];
        inner.find(quote).map(|end| inner[..end].to_string())
    })
}

pub fn data_root(config_php: &Path) -> Option<PathBuf> {
    config_value(&read_head(config_php)?, "dataroot").map(PathBuf::from)
}

pub fn wwwroot(config_php: &Path) -> Option<String> {
    config_value(&read_head(config_php)?, "wwwroot").map(|s| s.trim_end_matches('/').to_string())
}

/// `<dataroot>/keys`, falling back to the conventional sibling `moodledata`.
/// `moodledata` sits outside the web root, so keys there are never served.
pub fn suggested_key_dir(root: &Path, config_php: &Path) -> PathBuf {
    data_root(config_php)
        .unwrap_or_else(|| root.parent().unwrap_or(root).join("moodledata"))
        .join("keys")
}

/// Looks up a group id by name, without touching global libc state.
#[cfg(unix)]
pub fn lookup_gid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: all pointers are valid for the call; `grp` is plain data that
    // getgrnam_r fully initialises when it returns 0 with a non-null result.
    unsafe {
        let mut grp: libc::group = std::mem::zeroed();
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        );
        (rc == 0 && !result.is_null()).then_some(grp.gr_gid)
    }
}

/// The first well-known web-server group that exists on this host.
#[cfg(unix)]
pub fn web_server_group() -> Option<(&'static str, u32)> {
    WEB_SERVER_GROUPS
        .iter()
        .find_map(|n| lookup_gid(n).map(|gid| (*n, gid)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::tests::touch;
    use tempfile::tempdir;

    const CONFIG: &str = r#"<?php
unset($CFG);
global $CFG;
$CFG = new stdClass();
//$CFG->dataroot  = '/old/moodledata';
$CFG->wwwroot   = 'https://lms.example.com/';
$CFG->dataroot  = "/var/www/moodledata";
"#;

    #[test]
    fn parses_config_values_and_skips_comments() {
        assert_eq!(
            config_value(CONFIG, "dataroot").as_deref(),
            Some("/var/www/moodledata")
        );
        assert_eq!(
            config_value(CONFIG, "wwwroot").as_deref(),
            Some("https://lms.example.com/")
        );
        assert_eq!(config_value(CONFIG, "dbtype"), None);
        // unquoted / dynamic values are not guessed at
        assert_eq!(
            config_value("$CFG->dataroot = getenv('X');", "dataroot"),
            None
        );
    }

    fn site(d: &Path) {
        touch(
            d,
            "version.php",
            "<?php $version = 2024100700; $release = '4.5 (Build)';",
        );
        touch(d, "config.php", CONFIG);
    }

    #[test]
    fn detects_site_root_and_suggests_dataroot_keys() {
        let d = tempdir().unwrap();
        site(d.path());
        let found = detect(d.path()).unwrap();
        assert_eq!(found.root, d.path());
        assert_eq!(
            suggested_key_dir(&found.root, &found.config_php),
            PathBuf::from("/var/www/moodledata/keys")
        );
        assert_eq!(
            wwwroot(&found.config_php).as_deref(),
            Some("https://lms.example.com")
        );
    }

    #[test]
    fn plugin_directory_resolves_to_its_site() {
        let d = tempdir().unwrap();
        site(d.path());
        let plugin = d.path().join("local/xentreeconnect");
        touch(
            &plugin,
            "version.php",
            "<?php $plugin->component = 'local_xentreeconnect';",
        );
        assert_eq!(detect(&plugin).unwrap().root, d.path());
    }

    #[test]
    fn falls_back_to_sibling_moodledata() {
        let d = tempdir().unwrap();
        let root = d.path().join("moodle");
        touch(&root, "version.php", "<?php $version = 1; $release = '4';");
        touch(&root, "config.php", "<?php $CFG = new stdClass();");
        let s = detect(&root).unwrap();
        assert_eq!(
            suggested_key_dir(&s.root, &s.config_php),
            d.path().join("moodledata/keys")
        );
    }

    #[test]
    fn needs_both_files_with_the_right_content() {
        let d = tempdir().unwrap();
        touch(d.path(), "config.php", CONFIG);
        assert!(detect(d.path()).is_none(), "no version.php");
        touch(d.path(), "version.php", "<?php echo 'hi';");
        assert!(detect(d.path()).is_none(), "unrelated version.php");
        let e = tempdir().unwrap();
        touch(
            e.path(),
            "version.php",
            "<?php $version = 1; $release = '4';",
        );
        touch(e.path(), "config.php", "<?php echo 1;");
        assert!(detect(e.path()).is_none(), "config.php without $CFG");
    }

    #[test]
    fn plugin_component_marker_is_enough_for_version_php() {
        let d = tempdir().unwrap();
        touch(
            d.path(),
            "version.php",
            "<?php $plugin->component = 'local_xentreeconnect';",
        );
        touch(d.path(), "config.php", CONFIG);
        assert!(detect(d.path()).is_some());
    }

    #[cfg(unix)]
    #[test]
    fn group_lookup() {
        // GID 0's group name differs by OS (root/wheel); look up one that exists via libc.
        assert_eq!(lookup_gid("definitely-not-a-group-xyz"), None);
        assert_eq!(lookup_gid("bad\0name"), None);
        let name = unsafe {
            let g = libc::getgrgid(libc::getegid());
            std::ffi::CStr::from_ptr((*g).gr_name)
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(lookup_gid(&name), Some(unsafe { libc::getegid() }));
    }
}
