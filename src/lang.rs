//! Language selection and message lookup.
//!
//! The language is passed explicitly rather than set globally, so output is
//! deterministic and tests don't race on process-wide state.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum Lang {
    #[default]
    En,
    Id,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Id => "id",
        }
    }

    /// `--lang` wins. Otherwise the first of `LC_ALL`, `LC_MESSAGES`, `LANG`
    /// that is set and non-empty decides (POSIX precedence); unknown locales
    /// and `C`/`POSIX` mean English.
    pub fn detect(flag: Option<Lang>, env: impl Fn(&str) -> Option<String>) -> Lang {
        if let Some(l) = flag {
            return l;
        }
        ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|k| env(k))
            .find(|v| !v.trim().is_empty())
            .map_or(Lang::En, |v| Self::from_locale(&v))
    }

    /// `id`, `id_ID`, `id_ID.UTF-8`, `id-ID@euro` -> Indonesian.
    pub fn from_locale(locale: &str) -> Lang {
        let lang = locale.split(['_', '-', '.', '@']).next().unwrap_or("");
        match lang.to_ascii_lowercase().as_str() {
            "id" | "in" => Lang::Id, // "in" is the legacy ISO 639 code for Indonesian
            _ => Lang::En,
        }
    }
}

/// Looks up `key` and substitutes `%{name}` placeholders from `args`.
pub fn tr(lang: Lang, key: &str, args: &[(&str, &str)]) -> String {
    let mut s = rust_i18n::t!(key, locale = lang.code()).into_owned();
    for (name, value) in args {
        s = s.replace(&format!("%{{{name}}}"), value);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn flag_beats_environment() {
        assert_eq!(
            Lang::detect(Some(Lang::En), env(&[("LANG", "id_ID.UTF-8")])),
            Lang::En
        );
        assert_eq!(Lang::detect(Some(Lang::Id), env(&[])), Lang::Id);
    }

    #[test]
    fn detects_from_posix_variables_in_precedence_order() {
        assert_eq!(
            Lang::detect(None, env(&[("LANG", "id_ID.UTF-8")])),
            Lang::Id
        );
        assert_eq!(
            Lang::detect(
                None,
                env(&[("LANG", "id_ID.UTF-8"), ("LC_ALL", "en_US.UTF-8")])
            ),
            Lang::En
        );
        assert_eq!(
            Lang::detect(None, env(&[("LC_MESSAGES", "id"), ("LANG", "en_US")])),
            Lang::Id
        );
        // empty variables are skipped
        assert_eq!(
            Lang::detect(None, env(&[("LC_ALL", ""), ("LANG", "id_ID")])),
            Lang::Id
        );
    }

    #[test]
    fn unknown_or_missing_locale_is_english() {
        assert_eq!(Lang::detect(None, env(&[])), Lang::En);
        assert_eq!(Lang::detect(None, env(&[("LANG", "C")])), Lang::En);
        assert_eq!(Lang::detect(None, env(&[("LANG", "POSIX")])), Lang::En);
        assert_eq!(
            Lang::detect(None, env(&[("LANG", "fr_FR.UTF-8")])),
            Lang::En
        );
    }

    #[test]
    fn locale_variants_parse() {
        for l in [
            "id",
            "id_ID",
            "id_ID.UTF-8",
            "id-ID",
            "ID_id",
            "id_ID@euro",
            "in_ID",
        ] {
            assert_eq!(Lang::from_locale(l), Lang::Id, "{l}");
        }
        assert_eq!(Lang::from_locale("indonesia"), Lang::En);
    }

    #[test]
    fn lookup_with_dynamic_key_and_placeholders() {
        let args = [("platform", "Moodle"), ("path", "/srv/lms")];
        assert_eq!(
            tr(Lang::En, "init.platform.detected", &args),
            "Detected platform: Moodle (/srv/lms)"
        );
        assert_eq!(
            tr(Lang::Id, "init.platform.detected", &args),
            "Platform terdeteksi: Moodle (/srv/lms)"
        );
    }
}

#[cfg(test)]
mod locale_tests {
    use std::collections::{BTreeMap, BTreeSet};

    use regex::Regex;

    fn load(json: &str) -> BTreeMap<String, String> {
        serde_json::from_str(json).expect("locale file is a flat string map")
    }

    fn en() -> BTreeMap<String, String> {
        load(include_str!("../locales/en.json"))
    }
    fn id() -> BTreeMap<String, String> {
        load(include_str!("../locales/id.json"))
    }

    fn placeholders(s: &str) -> BTreeSet<String> {
        Regex::new(r"%\{(\w+)\}")
            .unwrap()
            .captures_iter(s)
            .map(|c| c[1].to_string())
            .collect()
    }

    #[test]
    fn both_languages_define_the_same_keys() {
        let (en, id) = (en(), id());
        let only_en: Vec<_> = en.keys().filter(|k| !id.contains_key(*k)).collect();
        let only_id: Vec<_> = id.keys().filter(|k| !en.contains_key(*k)).collect();
        assert!(only_en.is_empty(), "missing in id.json: {only_en:?}");
        assert!(only_id.is_empty(), "missing in en.json: {only_id:?}");
    }

    #[test]
    fn translations_use_the_same_placeholders() {
        let (en, id) = (en(), id());
        for (k, v) in &en {
            assert_eq!(
                placeholders(v),
                placeholders(&id[k]),
                "placeholders differ for {k}"
            );
            assert!(!id[k].trim().is_empty(), "empty translation for {k}");
        }
    }

    /// Every locale-looking string literal in the source must exist, and every
    /// key must be used somewhere (`platform.*` is built with `format!`).
    #[test]
    fn source_and_locale_files_agree() {
        let key_re = Regex::new(r#""((?:health|init|platform|gateway|cli)\.[a-z_.]+)""#).unwrap();
        let mut used = BTreeSet::new();
        let mut stack = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let src = std::fs::read_to_string(&path).unwrap();
                    used.extend(key_re.captures_iter(&src).map(|c| c[1].to_string()));
                }
            }
        }
        let en = en();
        let undefined: Vec<_> = used.iter().filter(|k| !en.contains_key(*k)).collect();
        assert!(
            undefined.is_empty(),
            "keys used in source but missing from en.json: {undefined:?}"
        );
        let unused: Vec<_> = en
            .keys()
            .filter(|k| !k.starts_with("platform.") && !used.contains(*k))
            .collect();
        assert!(
            unused.is_empty(),
            "keys in en.json never used in source: {unused:?}"
        );
    }
}
