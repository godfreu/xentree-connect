//! `xentree-connect health`: clock, key file and API diagnostics.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
};

use clap::Args;
use secrecy::SecretString;

use crate::{
    api::{ApiError, XentreeAdminClient, DEFAULT_BASE_URL},
    clock::{self, Severity, Skew, Source},
    config::{self, Config, KEY_FILE_NAME},
    crypto::SigningKey,
    detectors::DetectedPlatform,
    fs::{verify_private_file, KeyOwnershipPolicy},
    lang::{tr, Lang},
};

#[derive(Debug, Clone, Default, Args)]
pub struct HealthArgs {
    /// Xentree base URL (default: from the config file, else https://my.xentree.ai).
    #[arg(long)]
    pub base_url: Option<String>,
    /// Private key file to check (default: from the config file, else the default locations).
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Config file written by `init` (default: searched for).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Expect the key to be group-readable by this gid (Unix; overrides the config file).
    #[arg(long)]
    pub key_group: Option<u32>,
}

pub struct HealthInputs {
    pub args: HealthArgs,
    /// Admin token; without it the API check is skipped.
    pub token: Option<SecretString>,
    pub lang: Lang,
    /// Directories searched for the config file and, failing that, the key file.
    pub search_dirs: Vec<PathBuf>,
    /// Overrides the clock sources (tests, restricted networks).
    pub clock: Option<clock::Options>,
}

impl HealthInputs {
    /// The directories a normal run searches: here, the per-user config
    /// directory, and the Moodle key directory if run inside a Moodle site.
    pub fn default_search_dirs(cwd: &Path) -> Vec<PathBuf> {
        let mut dirs = vec![cwd.to_path_buf()];
        dirs.extend(config::default_config_dir());
        dirs.extend(DetectedPlatform::detect(cwd).suggested_key_dir());
        dirs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Ok,
    Skipped,
    Warning,
    Critical,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Skipped => "SKIPPED",
            Status::Warning => "WARNING",
            Status::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Config,
    Clock,
    Key,
    Api,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub check: Check,
    pub status: Status,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct HealthReport {
    pub lang: Lang,
    pub results: Vec<CheckResult>,
}

impl HealthReport {
    pub fn count(&self, status: Status) -> usize {
        self.results.iter().filter(|r| r.status == status).count()
    }

    /// 0 unless a check is critical. Warnings and skips don't fail the run.
    pub fn exit_code(&self) -> u8 {
        u8::from(self.count(Status::Critical) > 0)
    }

    pub fn render(&self) -> String {
        let mut out = format!("{}\n\n", tr(self.lang, "health.title", &[]));
        for r in &self.results {
            let name = tr(
                self.lang,
                match r.check {
                    Check::Config => "health.check.config",
                    Check::Clock => "health.check.clock",
                    Check::Key => "health.check.key",
                    Check::Api => "health.check.api",
                },
                &[],
            );
            let _ = writeln!(out, "{} {}: {}", paint(r.status), name, r.message);
        }
        let criticals = self.count(Status::Critical);
        let summary = if criticals > 0 {
            tr(
                self.lang,
                "health.summary.fail",
                &[("n", &criticals.to_string())],
            )
        } else if self.count(Status::Warning) > 0 {
            tr(self.lang, "health.summary.warn", &[])
        } else {
            tr(self.lang, "health.summary.pass", &[])
        };
        let _ = write!(out, "\n{summary}\n");
        out
    }
}

fn paint(status: Status) -> String {
    use console::style;
    // Pad the plain text first: escape codes would throw the column width off.
    let label = format!("{:<8}", status.label());
    match status {
        Status::Ok => style(label).green(),
        Status::Skipped => style(label).dim(),
        Status::Warning => style(label).yellow(),
        Status::Critical => style(label).red().bold(),
    }
    .to_string()
}

pub async fn run(inputs: &HealthInputs) -> HealthReport {
    let lang = inputs.lang;
    let mut results = Vec::new();

    let (config, config_result) = load_config(inputs);
    results.extend(config_result);

    let base_url = inputs
        .args
        .base_url
        .clone()
        .or_else(|| config.as_ref().map(|c| c.base_url.clone()))
        .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

    results.push(check_clock(inputs, &base_url).await);
    results.push(check_key(inputs, config.as_ref()));
    results.push(check_api(inputs, &base_url).await);
    HealthReport { lang, results }
}

fn result(check: Check, status: Status, message: String) -> CheckResult {
    CheckResult {
        check,
        status,
        message,
    }
}

// --- config ---------------------------------------------------------------

fn load_config(inputs: &HealthInputs) -> (Option<Config>, Option<CheckResult>) {
    let lang = inputs.lang;
    let explicit = inputs.args.config.is_some();
    let candidates: Vec<PathBuf> = match &inputs.args.config {
        Some(p) => vec![p.clone()],
        None => inputs
            .search_dirs
            .iter()
            .map(|d| d.join(config::FILE_NAME))
            .filter(|p| p.is_file())
            .collect(),
    };
    let Some(path) = candidates.into_iter().next() else {
        return (None, None);
    };
    match Config::load(&path) {
        Ok(c) => {
            let msg = tr(
                lang,
                "health.config.ok",
                &[("path", &path.display().to_string())],
            );
            (Some(c), Some(result(Check::Config, Status::Ok, msg)))
        }
        Err(e) => {
            let msg = tr(
                lang,
                "health.config.invalid",
                &[
                    ("path", &path.display().to_string()),
                    ("error", &e.to_string()),
                ],
            );
            let status = if explicit {
                Status::Critical
            } else {
                Status::Warning
            };
            (None, Some(result(Check::Config, status, msg)))
        }
    }
}

// --- clock ----------------------------------------------------------------

async fn check_clock(inputs: &HealthInputs, base_url: &str) -> CheckResult {
    let lang = inputs.lang;
    let opts = inputs
        .clock
        .clone()
        .unwrap_or_else(|| clock::Options::new(base_url));
    match clock::measure(&opts).await {
        Ok(skew) => clock_result(lang, &skew),
        Err(e) => result(
            Check::Clock,
            Status::Warning,
            tr(
                lang,
                "health.clock.unavailable",
                &[("error", &e.to_string())],
            ),
        ),
    }
}

fn clock_result(lang: Lang, skew: &Skew) -> CheckResult {
    let source = match &skew.source {
        Source::Ntp { server } => format!("NTP {server}"),
        Source::HttpDate { url } => format!("HTTP Date {url}"),
    };
    let args = [
        ("ms", format!("{:+.0}", skew.offset_secs * 1000.0)),
        ("unc", format!("{:.0}", skew.uncertainty_secs * 1000.0)),
        ("source", source),
    ];
    let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (status, key) = match skew.severity() {
        Severity::Ok => (Status::Ok, "health.clock.ok"),
        Severity::Warn => (Status::Warning, "health.clock.warning"),
        Severity::High => (Status::Critical, "health.clock.critical"),
    };
    result(Check::Clock, status, tr(lang, key, &args))
}

// --- key ------------------------------------------------------------------

fn check_key(inputs: &HealthInputs, config: Option<&Config>) -> CheckResult {
    let lang = inputs.lang;
    let explicit = inputs
        .args
        .key
        .clone()
        .or_else(|| config.map(|c| c.key_path.clone()));
    let path = explicit.clone().or_else(|| {
        inputs
            .search_dirs
            .iter()
            .map(|d| d.join(KEY_FILE_NAME))
            .find(|p| p.is_file())
    });
    let Some(path) = path else {
        return result(
            Check::Key,
            Status::Skipped,
            tr(lang, "health.key.none", &[]),
        );
    };
    let shown = path.display().to_string();
    if !path.exists() {
        return result(
            Check::Key,
            Status::Critical,
            tr(lang, "health.key.missing", &[("path", &shown)]),
        );
    }

    let policy = match key_policy(inputs, config) {
        Ok(p) => p,
        Err(e) => return result(Check::Key, Status::Critical, e),
    };
    if let Err(e) = verify_private_file(&path, &policy) {
        return result(
            Check::Key,
            Status::Critical,
            tr(lang, "health.key.insecure", &[("error", &e.to_string())]),
        );
    }
    let key = std::fs::read_to_string(&path)
        .ok()
        .map(zeroize::Zeroizing::new)
        .and_then(|pem| SigningKey::from_pem(&pem).ok());
    let Some(key) = key else {
        return result(
            Check::Key,
            Status::Critical,
            tr(lang, "health.key.invalid", &[("path", &shown)]),
        );
    };
    if let Some(c) = config.filter(|c| c.kid != key.kid()) {
        let msg = tr(
            lang,
            "health.key.kid_mismatch",
            &[("kid", key.kid()), ("expected", &c.kid)],
        );
        return result(Check::Key, Status::Warning, msg);
    }
    let msg = tr(
        lang,
        "health.key.ok",
        &[
            ("path", &shown),
            ("policy", &describe_policy(&policy)),
            ("kid", key.kid()),
        ],
    );
    result(Check::Key, Status::Ok, msg)
}

fn key_policy(
    inputs: &HealthInputs,
    config: Option<&Config>,
) -> Result<KeyOwnershipPolicy, String> {
    #[cfg(unix)]
    if let Some(gid) = inputs.args.key_group {
        return Ok(KeyOwnershipPolicy::GroupReadable { gid });
    }
    #[cfg(not(unix))]
    if inputs.args.key_group.is_some() {
        return Err(tr(inputs.lang, "health.key.group_unsupported", &[]));
    }
    match config {
        Some(c) => c.ownership.to_policy().map_err(|e| e.to_string()),
        None => Ok(KeyOwnershipPolicy::CurrentUserOnly),
    }
}

fn describe_policy(policy: &KeyOwnershipPolicy) -> String {
    match policy {
        KeyOwnershipPolicy::CurrentUserOnly => "current-user-only".into(),
        #[cfg(unix)]
        KeyOwnershipPolicy::GroupReadable { gid } => format!("group-readable gid {gid}"),
        #[cfg(unix)]
        KeyOwnershipPolicy::SpecificOwner { uid, gid, mode } => {
            format!("owner {uid}:{gid} mode {mode:04o}")
        }
    }
}

// --- API ------------------------------------------------------------------

async fn check_api(inputs: &HealthInputs, base_url: &str) -> CheckResult {
    let lang = inputs.lang;
    let Some(token) = inputs.token.clone() else {
        return result(
            Check::Api,
            Status::Skipped,
            tr(lang, "health.api.skipped", &[]),
        );
    };
    let client = match XentreeAdminClient::with_base_url(base_url, token) {
        Ok(c) => c,
        Err(e) => {
            return result(
                Check::Api,
                Status::Critical,
                tr(
                    lang,
                    "health.api.failed",
                    &[("url", base_url), ("error", &e.to_string())],
                ),
            )
        }
    };
    let url = client.base_url().as_str().to_string();
    match client.list_organizations().await {
        Ok(orgs) => {
            let msg = tr(
                lang,
                "health.api.ok",
                &[("url", &url), ("count", &orgs.len().to_string())],
            );
            result(Check::Api, Status::Ok, msg)
        }
        Err(ApiError::Unauthorized) => result(
            Check::Api,
            Status::Critical,
            tr(lang, "health.api.unauthorized", &[("url", &url)]),
        ),
        Err(ApiError::RateLimited { .. }) => result(
            Check::Api,
            Status::Warning,
            tr(lang, "health.api.rate_limited", &[]),
        ),
        Err(e) => result(
            Check::Api,
            Status::Critical,
            tr(
                lang,
                "health.api.failed",
                &[("url", &url), ("error", &e.to_string())],
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use secrecy::SecretString;
    use serde_json::json;
    use tempfile::{tempdir, TempDir};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::{
        config::OwnershipConfig,
        fs::{write_private_file, Existing},
    };

    const CUO: KeyOwnershipPolicy = KeyOwnershipPolicy::CurrentUserOnly;

    fn inputs(dirs: &[&Path]) -> HealthInputs {
        HealthInputs {
            args: HealthArgs::default(),
            token: None,
            lang: Lang::En,
            search_dirs: dirs.iter().map(|d| d.to_path_buf()).collect(),
            // No NTP, no HTTP source: the clock check reports "unavailable".
            clock: Some(clock::Options {
                ntp_servers: vec![],
                http_url: None,
                ..clock::Options::new("")
            }),
        }
    }

    fn get(r: &HealthReport, c: Check) -> &CheckResult {
        r.results
            .iter()
            .find(|x| x.check == c)
            .unwrap_or_else(|| panic!("no {c:?} result"))
    }

    /// Serves one HTTP response whose Date is `offset` seconds from local time.
    async fn date_server(offset: i64) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let when = if offset >= 0 {
            SystemTime::now() + Duration::from_secs(offset as u64)
        } else {
            SystemTime::now() - Duration::from_secs(offset.unsigned_abs())
        };
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nDate: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                httpdate::fmt_http_date(when)
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
        format!("http://{addr}/")
    }

    fn clock_via(url: String) -> Option<clock::Options> {
        Some(clock::Options {
            ntp_servers: vec![],
            ..clock::Options::new(url)
        })
    }

    fn write_key(dir: &Path, policy: &KeyOwnershipPolicy) -> (PathBuf, SigningKey) {
        let key = SigningKey::generate().unwrap();
        let p = dir.join(KEY_FILE_NAME);
        write_private_file(&p, key.to_pem().as_bytes(), Existing::Fail, policy).unwrap();
        (p, key)
    }

    // --- clock ---

    #[tokio::test]
    async fn clock_status_follows_thresholds() {
        for (offset, expected) in [
            (0, Status::Ok),
            (5, Status::Warning),
            (30, Status::Critical),
            (-30, Status::Critical),
        ] {
            let d = tempdir().unwrap();
            let mut i = inputs(&[d.path()]);
            i.clock = clock_via(date_server(offset).await);
            let r = run(&i).await;
            let c = get(&r, Check::Clock);
            assert_eq!(c.status, expected, "offset {offset}s: {}", c.message);
        }
    }

    #[tokio::test]
    async fn clock_message_reports_signed_milliseconds_and_source() {
        let d = tempdir().unwrap();
        let mut i = inputs(&[d.path()]);
        i.clock = clock_via(date_server(30).await);
        let msg = get(&run(&i).await, Check::Clock).message.clone();
        assert!(
            msg.contains(" ms") && msg.contains("+") && msg.contains("HTTP Date"),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn unmeasurable_clock_is_a_warning_not_a_failure() {
        let d = tempdir().unwrap();
        let r = run(&inputs(&[d.path()])).await;
        assert_eq!(get(&r, Check::Clock).status, Status::Warning);
        assert_eq!(r.exit_code(), 0);
    }

    // --- key ---

    #[tokio::test]
    async fn valid_key_passes_and_reports_its_kid() {
        let d = tempdir().unwrap();
        let (p, key) = write_key(d.path(), &CUO);
        let mut i = inputs(&[]);
        i.args.key = Some(p);
        let r = run(&i).await;
        let k = get(&r, Check::Key);
        assert_eq!(k.status, Status::Ok);
        assert!(k.message.contains(key.kid()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn loose_permissions_are_critical_and_fail_the_run() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let (p, _) = write_key(d.path(), &CUO);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut i = inputs(&[]);
        i.args.key = Some(p);
        let r = run(&i).await;
        assert_eq!(get(&r, Check::Key).status, Status::Critical);
        assert_eq!(r.exit_code(), 1);
    }

    #[tokio::test]
    async fn explicit_missing_key_is_critical_but_no_key_anywhere_is_skipped() {
        let d = tempdir().unwrap();
        let mut i = inputs(&[d.path()]);
        assert_eq!(get(&run(&i).await, Check::Key).status, Status::Skipped);
        i.args.key = Some(d.path().join("nope.pem"));
        assert_eq!(get(&run(&i).await, Check::Key).status, Status::Critical);
    }

    #[tokio::test]
    async fn garbage_key_file_is_critical() {
        let d = tempdir().unwrap();
        let p = d.path().join(KEY_FILE_NAME);
        write_private_file(&p, b"not a key", Existing::Fail, &CUO).unwrap();
        let mut i = inputs(&[]);
        i.args.key = Some(p);
        assert_eq!(get(&run(&i).await, Check::Key).status, Status::Critical);
    }

    #[tokio::test]
    async fn key_is_discovered_in_search_dirs() {
        let d = tempdir().unwrap();
        let (_, key) = write_key(d.path(), &CUO);
        let r = run(&inputs(&[d.path()])).await;
        assert!(get(&r, Check::Key).message.contains(key.kid()));
    }

    // --- config ---

    fn config_for(key_path: &Path, kid: &str, ownership: OwnershipConfig) -> Config {
        Config {
            base_url: "https://my.xentree.ai".into(),
            org_id: "o".into(),
            client_record_id: "r".into(),
            client_id: "c".into(),
            issuer: "https://i.example".into(),
            audience: "a".into(),
            kid: kid.into(),
            key_path: key_path.to_path_buf(),
            ownership,
        }
    }

    #[tokio::test]
    async fn config_supplies_the_key_path() {
        let d = tempdir().unwrap();
        let (kp, key) = write_key(d.path(), &CUO);
        config_for(&kp, key.kid(), OwnershipConfig::CurrentUserOnly)
            .save(&d.path().join(config::FILE_NAME), &CUO)
            .unwrap();
        let r = run(&inputs(&[d.path()])).await;
        assert_eq!(get(&r, Check::Config).status, Status::Ok);
        assert_eq!(get(&r, Check::Key).status, Status::Ok);
    }

    #[tokio::test]
    async fn stale_kid_in_config_is_a_warning() {
        let d = tempdir().unwrap();
        let (kp, _) = write_key(d.path(), &CUO);
        config_for(&kp, "old-kid", OwnershipConfig::CurrentUserOnly)
            .save(&d.path().join(config::FILE_NAME), &CUO)
            .unwrap();
        let k = run(&inputs(&[d.path()]))
            .await
            .results
            .into_iter()
            .find(|r| r.check == Check::Key)
            .unwrap();
        assert_eq!(k.status, Status::Warning);
        assert!(k.message.contains("old-kid"));
    }

    #[tokio::test]
    async fn invalid_config_is_critical_only_when_explicit() {
        let d = tempdir().unwrap();
        let p = d.path().join(config::FILE_NAME);
        std::fs::write(&p, "{broken").unwrap();
        let found = run(&inputs(&[d.path()])).await;
        assert_eq!(get(&found, Check::Config).status, Status::Warning);
        let mut i = inputs(&[]);
        i.args.config = Some(p);
        assert_eq!(get(&run(&i).await, Check::Config).status, Status::Critical);
    }

    /// The Moodle case: a group-readable key must not be flagged when the
    /// config (or --key-group) says so, and must be flagged when it doesn't.
    #[cfg(unix)]
    #[tokio::test]
    async fn group_readable_key_honors_the_declared_policy() {
        let gid = unsafe { libc::getegid() };
        let policy = KeyOwnershipPolicy::GroupReadable { gid };
        let d = tempdir().unwrap();
        let (kp, key) = write_key(d.path(), &policy);

        // Declared via config.
        config_for(&kp, key.kid(), OwnershipConfig::GroupReadable { gid })
            .save(&d.path().join(config::FILE_NAME), &policy)
            .unwrap();
        assert_eq!(
            get(&run(&inputs(&[d.path()])).await, Check::Key).status,
            Status::Ok
        );

        // Declared via the flag.
        let mut i = inputs(&[]);
        i.args.key = Some(kp.clone());
        i.args.key_group = Some(gid);
        assert_eq!(get(&run(&i).await, Check::Key).status, Status::Ok);

        // Undeclared: the same file is too open for the default policy.
        let mut i = inputs(&[]);
        i.args.key = Some(kp);
        assert_eq!(get(&run(&i).await, Check::Key).status, Status::Critical);
    }

    // --- API ---

    fn with_token(mut i: HealthInputs, server: &MockServer) -> HealthInputs {
        i.args.base_url = Some(server.uri());
        i.token = Some(SecretString::from("tok"));
        i
    }

    #[tokio::test]
    async fn api_ok_counts_organizations() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/admin/organizations"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!([{"id": "o1", "name": "A"}, {"id": "o2", "name": "B"}])),
            )
            .mount(&s)
            .await;
        let d = tempdir().unwrap();
        let r = run(&with_token(inputs(&[d.path()]), &s)).await;
        let a = get(&r, Check::Api);
        assert_eq!(a.status, Status::Ok);
        assert!(a.message.contains("2 organization"), "{}", a.message);
    }

    #[tokio::test]
    async fn rejected_token_is_critical() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&s)
            .await;
        let d = tempdir().unwrap();
        let r = run(&with_token(inputs(&[d.path()]), &s)).await;
        assert_eq!(get(&r, Check::Api).status, Status::Critical);
        assert_eq!(r.exit_code(), 1);
    }

    #[tokio::test]
    async fn rate_limiting_is_only_a_warning() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&s)
            .await;
        let d = tempdir().unwrap();
        let r = run(&with_token(inputs(&[d.path()]), &s)).await;
        assert_eq!(get(&r, Check::Api).status, Status::Warning);
    }

    #[tokio::test]
    async fn unreachable_api_is_critical() {
        let d = tempdir().unwrap();
        let mut i = inputs(&[d.path()]);
        i.args.base_url = Some("http://127.0.0.1:1".into());
        i.token = Some(SecretString::from("tok"));
        assert_eq!(get(&run(&i).await, Check::Api).status, Status::Critical);
    }

    #[tokio::test]
    async fn no_token_skips_the_api_check() {
        let d = tempdir().unwrap();
        assert_eq!(
            get(&run(&inputs(&[d.path()])).await, Check::Api).status,
            Status::Skipped
        );
    }

    #[tokio::test]
    async fn token_never_appears_in_output() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&s)
            .await;
        let d = tempdir().unwrap();
        let out = run(&with_token(inputs(&[d.path()]), &s)).await.render();
        assert!(!out.contains("tok\n") && !out.contains("Bearer"));
    }

    // --- report ---

    #[tokio::test]
    async fn everything_healthy_exits_zero() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&s)
            .await;
        let d: TempDir = tempdir().unwrap();
        write_key(d.path(), &CUO);
        let mut i = with_token(inputs(&[d.path()]), &s);
        i.clock = clock_via(date_server(0).await);
        let r = run(&i).await;
        assert!(
            r.results.iter().all(|c| c.status == Status::Ok),
            "{}",
            r.render()
        );
        assert_eq!(r.exit_code(), 0);
        assert!(r.render().contains("All checks passed"));
    }

    #[tokio::test]
    async fn rendering_is_localized() {
        let d = tempdir().unwrap();
        let mut i = inputs(&[d.path()]);
        let en = run(&i).await.render();
        i.lang = Lang::Id;
        let id = run(&i).await.render();
        assert!(en.contains("Xentree Connect health check") && en.contains("Clock"));
        assert!(id.contains("Pemeriksaan kesehatan Xentree Connect") && id.contains("Jam"));
        // status words stay machine-greppable in every language
        assert!(en.contains("SKIPPED") && id.contains("SKIPPED"));
    }
}
