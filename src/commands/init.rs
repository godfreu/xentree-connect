//! `xentree-connect init`: generate a key, register the integration.
//!
//! [`perform`] is the whole side-effecting pipeline and takes no prompts, so
//! it is fully testable. [`run`] wraps it with the interactive wizard.

use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::Args;
use inquire::{Confirm, InquireError, Password, PasswordDisplayMode, Select, Text};
use secrecy::SecretString;
use zeroize::Zeroizing;

#[cfg(unix)]
use crate::detectors::moodle;
use crate::{
    api::{
        ApiError, ConnectClientResponse, CreateConnectClientRequest, OrganizationItem,
        XentreeAdminClient, DEFAULT_BASE_URL,
    },
    clock::{self, Severity},
    config::{self, Config, OwnershipConfig, FILE_NAME, KEY_FILE_NAME},
    crypto::{CryptoError, Jwks, SigningKey},
    detectors::DetectedPlatform,
    fs::{
        ensure_key_dir, verify_private_file, write_private_file, Existing, FsError,
        KeyOwnershipPolicy,
    },
    lang::{tr, Lang},
};

pub const DEFAULT_AUDIENCE: &str = "xentree";

#[derive(Debug, Clone, Default, Args)]
pub struct InitArgs {
    /// Xentree base URL, e.g. https://learn.example.com for a custom domain.
    #[arg(long)]
    pub base_url: Option<String>,
    /// Organization id to register under (otherwise chosen interactively).
    #[arg(long)]
    pub org: Option<String>,
    /// Display name of the integration.
    #[arg(long)]
    pub name: Option<String>,
    /// Unique client id (1-128 characters).
    #[arg(long)]
    pub client_id: Option<String>,
    /// Issuer URL placed in assertions, without a trailing slash.
    #[arg(long)]
    pub issuer: Option<String>,
    /// Audience placed in assertions.
    #[arg(long)]
    pub audience: Option<String>,
    /// Automatically assign a seat to consenting users (consumes seats).
    #[arg(long)]
    pub auto_enroll: bool,
    /// Project directory to inspect (default: current directory).
    #[arg(long)]
    pub dir: Option<PathBuf>,
    /// Directory for the private key.
    #[arg(long)]
    pub key_dir: Option<PathBuf>,
    /// Let this group (name or gid) read the key, e.g. www-data (Unix).
    #[arg(long)]
    pub key_group: Option<String>,
    /// Register an existing key instead of generating one (resume after a failed registration).
    #[arg(long)]
    pub reuse_key: bool,
    /// Never prompt; use flags, defaults and XENTREE_ADMIN_TOKEN.
    #[arg(short = 'y', long)]
    pub yes: bool,
}

// --- the pipeline ---------------------------------------------------------

#[derive(Debug, Clone)]
pub struct InitPlan {
    pub base_url: String,
    pub org_id: String,
    pub name: String,
    pub client_id: String,
    pub issuer: String,
    pub audience: String,
    pub auto_enroll: bool,
    pub key_path: PathBuf,
    pub policy: KeyOwnershipPolicy,
    pub reuse_key: bool,
}

#[derive(Debug)]
pub struct InitOutcome {
    pub client: ConnectClientResponse,
    pub kid: String,
    pub key_path: PathBuf,
    pub jwks_json: String,
    pub config_path: PathBuf,
    /// Registration succeeded but the config file couldn't be written.
    pub config_error: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("a key already exists at {0}")]
    KeyExists(PathBuf),
    #[error("cannot read key {path}: {source}")]
    ReadKey {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The key is on disk but the cloud rejected (or never received) the registration.
    #[error("registration failed: {source}")]
    Register { key_path: PathBuf, source: ApiError },
}

/// Obtains the key (generating and storing it first, so a failed registration
/// never loses it), registers the integration, and records a config file.
pub async fn perform(
    plan: &InitPlan,
    client: &XentreeAdminClient,
) -> Result<InitOutcome, InitError> {
    let key = obtain_key(plan)?;
    let jwks_json = Jwks::new(vec![key.jwk()]).to_json_string()?;

    let mut request = CreateConnectClientRequest::new(
        &plan.name,
        &plan.client_id,
        &plan.issuer,
        &plan.audience,
        &jwks_json,
    );
    request.auto_enroll = plan.auto_enroll;
    let registered = client
        .create_connect_client(&plan.org_id, &request)
        .await
        .map_err(|source| InitError::Register {
            key_path: plan.key_path.clone(),
            source,
        })?;

    let config_path = plan
        .key_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(FILE_NAME);
    let config = Config {
        base_url: client.base_url().as_str().trim_end_matches('/').to_string(),
        org_id: plan.org_id.clone(),
        client_record_id: registered.id.clone(),
        client_id: registered.client_id.clone(),
        issuer: plan.issuer.clone(),
        audience: plan.audience.clone(),
        kid: key.kid().to_string(),
        key_path: plan.key_path.clone(),
        ownership: OwnershipConfig::from_policy(&plan.policy),
    };
    let config_error = config
        .save(&config_path, &plan.policy)
        .err()
        .map(|e| e.to_string());

    Ok(InitOutcome {
        kid: key.kid().to_string(),
        client: registered,
        key_path: plan.key_path.clone(),
        jwks_json,
        config_path,
        config_error,
    })
}

fn obtain_key(plan: &InitPlan) -> Result<SigningKey, InitError> {
    let path = &plan.key_path;
    if path.exists() {
        if !plan.reuse_key {
            return Err(InitError::KeyExists(path.clone()));
        }
        verify_private_file(path, &plan.policy)?;
        let pem = std::fs::read_to_string(path)
            .map(Zeroizing::new)
            .map_err(|source| InitError::ReadKey {
                path: path.clone(),
                source,
            })?;
        return Ok(SigningKey::from_pem(&pem)?);
    }
    if plan.reuse_key {
        let source = std::io::Error::new(std::io::ErrorKind::NotFound, "no key to reuse");
        return Err(InitError::ReadKey {
            path: path.clone(),
            source,
        });
    }
    let key = SigningKey::generate()?;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        ensure_key_dir(dir, &plan.policy)?;
    }
    write_private_file(path, key.to_pem().as_bytes(), Existing::Fail, &plan.policy)?;
    Ok(key)
}

pub fn render_summary(lang: Lang, plan: &InitPlan, outcome: &InitOutcome) -> String {
    let line = |label: &str, value: &str| {
        format!("  {:<14} {value}\n", format!("{}:", tr(lang, label, &[])))
    };
    let mut s = format!("\n{}\n\n", tr(lang, "init.done.title", &[]));
    s += &line("init.summary.org", &plan.org_id);
    s += &line("init.summary.client_id", &outcome.client.client_id);
    s += &line("init.summary.record_id", &outcome.client.id);
    s += &line("init.summary.issuer", &plan.issuer);
    s += &line("init.summary.audience", &plan.audience);
    s += &line(
        "init.summary.key_file",
        &outcome.key_path.display().to_string(),
    );
    s += &line("init.summary.kid", &outcome.kid);
    s += &line("init.summary.auto_enroll", &plan.auto_enroll.to_string());
    match &outcome.config_error {
        None => {
            s += &line(
                "init.summary.config",
                &outcome.config_path.display().to_string(),
            )
        }
        Some(e) => {
            let args = [
                ("path", outcome.config_path.display().to_string()),
                ("error", e.clone()),
                ("id", outcome.client.id.clone()),
            ];
            let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (*k, v.as_str())).collect();
            let _ = writeln!(s, "\n{}", tr(lang, "init.warn.config_not_saved", &args));
        }
    }
    let _ = write!(s, "\n{}\n", tr(lang, "init.next.title", &[]));
    let _ = writeln!(
        s,
        "  1. {}",
        tr(lang, "init.next.sign", &[("kid", &outcome.kid)])
    );
    let _ = writeln!(s, "  2. {}", tr(lang, "init.next.health", &[]));
    let _ = writeln!(s, "  3. {}", tr(lang, "init.next.webhook", &[]));
    if matches!(plan.policy, KeyOwnershipPolicy::CurrentUserOnly) {
        return s;
    }
    let _ = writeln!(s, "  4. {}", tr(lang, "init.next.group", &[]));
    s
}

// --- helpers --------------------------------------------------------------

/// `Xentree Connect (Moodle)` -> `xentree-connect-moodle`, capped at the API's 128.
pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    out.trim_end_matches('-').chars().take(128).collect()
}

/// A numeric gid, or a group name looked up on this host.
#[cfg(unix)]
pub fn parse_key_group(s: &str) -> anyhow::Result<KeyOwnershipPolicy> {
    let gid = match s.parse::<u32>() {
        Ok(gid) => gid,
        Err(_) => moodle::lookup_gid(s).ok_or_else(|| anyhow::anyhow!("no such group: {s}"))?,
    };
    Ok(KeyOwnershipPolicy::GroupReadable { gid })
}

#[cfg(not(unix))]
pub fn parse_key_group(_: &str) -> anyhow::Result<KeyOwnershipPolicy> {
    anyhow::bail!("--key-group is only supported on Unix")
}

#[derive(Debug, thiserror::Error)]
#[error("cancelled")]
struct Cancelled;

fn ask<T>(r: Result<T, InquireError>) -> anyhow::Result<T> {
    match r {
        Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
            Err(Cancelled.into())
        }
        other => Ok(other?),
    }
}

struct OrgChoice(OrganizationItem);

impl std::fmt::Display for OrgChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.0.name, self.0.id)?;
        match &self.0.role {
            Some(r) => write!(f, " [{r}]"),
            None => Ok(()),
        }
    }
}

// --- the wizard -----------------------------------------------------------

pub async fn run(
    args: &InitArgs,
    token: Option<SecretString>,
    lang: Lang,
) -> anyhow::Result<ExitCode> {
    match wizard(args, token, lang).await {
        Err(e) if e.downcast_ref::<Cancelled>().is_some() => {
            eprintln!("{}", tr(lang, "init.cancelled", &[]));
            Ok(ExitCode::from(130))
        }
        other => other,
    }
}

async fn wizard(
    args: &InitArgs,
    token: Option<SecretString>,
    lang: Lang,
) -> anyhow::Result<ExitCode> {
    let yes = args.yes;
    println!("{}\n", tr(lang, "init.title", &[]));

    // 1. Base URL (before anything talks to the network).
    let base_url = match &args.base_url {
        Some(u) => u.clone(),
        None if yes => DEFAULT_BASE_URL.to_string(),
        None => required_prompt(
            lang,
            &tr(lang, "init.prompt.base_url", &[]),
            Some(DEFAULT_BASE_URL),
            MAX_URL,
        )?,
    };

    // 2. Clock.
    if !clock_step(&base_url, lang, yes).await? {
        eprintln!("{}", tr(lang, "init.cancelled", &[]));
        return Ok(ExitCode::from(1));
    }

    // 3. Token and organizations.
    let token = match token {
        Some(t) => t,
        None if yes => anyhow::bail!(tr(lang, "init.token.missing", &[])),
        None => SecretString::from(ask(Password::new(&tr(lang, "init.token.prompt", &[]))
            .with_help_message(&tr(lang, "init.token.help", &[]))
            .with_display_mode(PasswordDisplayMode::Masked)
            .without_confirmation()
            .prompt())?),
    };
    let client = XentreeAdminClient::with_base_url(&base_url, token)?;
    println!("{}", tr(lang, "init.orgs.fetching", &[]));
    let orgs = client.list_organizations().await?;
    let org = choose_org(orgs, args, lang)?;

    // 4. Platform.
    let dir = match &args.dir {
        Some(d) => d.clone(),
        None => std::env::current_dir()?,
    };
    let platform = DetectedPlatform::detect(&dir);
    let platform_name = tr(lang, &format!("platform.{}", platform.id()), &[]);
    println!(
        "{}",
        tr(
            lang,
            "init.platform.detected",
            &[
                ("platform", &platform_name),
                ("path", &dir.display().to_string())
            ]
        )
    );

    // 5. Integration details.
    let name = text_or_default(
        args.name.clone(),
        yes,
        lang,
        &tr(lang, "init.prompt.name", &[]),
        format!("Xentree Connect ({platform_name})"),
        MAX_NAME,
    )?;
    let client_id = text_or_default(
        args.client_id.clone(),
        yes,
        lang,
        &tr(lang, "init.prompt.client_id", &[]),
        format!("xentree-{}", platform.id().replace('_', "-")),
        MAX_CLIENT_ID,
    )?;
    let issuer = match args.issuer.clone().or_else(|| platform.suggested_issuer()) {
        Some(default) if args.issuer.is_some() || yes => default,
        Some(default) => required_prompt(
            lang,
            &tr(lang, "init.prompt.issuer", &[]),
            Some(&default),
            MAX_URL,
        )?,
        None if yes => anyhow::bail!(tr(lang, "init.err.issuer_required", &[])),
        None => required_prompt(lang, &tr(lang, "init.prompt.issuer", &[]), None, MAX_URL)?,
    };
    validate_text(lang, &issuer, MAX_URL)
        .map_err(|m| anyhow::anyhow!("{}: {m}", tr(lang, "init.prompt.issuer", &[])))?;
    let issuer = issuer.trim().trim_end_matches('/').to_string();
    let audience = text_or_default(
        args.audience.clone(),
        yes,
        lang,
        &tr(lang, "init.prompt.audience", &[]),
        DEFAULT_AUDIENCE.into(),
        MAX_NAME,
    )?;
    let auto_enroll = args.auto_enroll
        || (!yes
            && ask(Confirm::new(&tr(lang, "init.prompt.auto_enroll", &[]))
                .with_default(false)
                .prompt())?);

    // 6. Key location and permissions.
    let (mut key_dir, policy) = key_location(args, &platform, lang)?;
    println!(
        "{}",
        tr(
            lang,
            "init.key.location",
            &[("path", &key_dir.join(KEY_FILE_NAME).display().to_string())]
        )
    );
    println!("{}", describe_access(lang, &policy));
    if !yes
        && args.key_dir.is_none()
        && !ask(Confirm::new(&tr(lang, "init.key.confirm", &[]))
            .with_default(true)
            .prompt())?
    {
        key_dir = PathBuf::from(required_prompt(
            lang,
            &tr(lang, "init.key.dir_prompt", &[]),
            Some(&key_dir.display().to_string()),
            4096,
        )?);
    }
    // Absolute, so the gateway can find the key from any working directory.
    let key_path = std::path::absolute(key_dir.join(KEY_FILE_NAME))?;
    if key_path.exists() && !args.reuse_key {
        anyhow::bail!(tr(
            lang,
            "init.error.key_exists",
            &[("path", &key_path.display().to_string())]
        ));
    }

    // 7. Generate, store, register.
    let plan = InitPlan {
        base_url,
        org_id: org.id,
        name,
        client_id,
        issuer,
        audience,
        auto_enroll,
        key_path,
        policy,
        reuse_key: args.reuse_key,
    };
    println!(
        "{}",
        tr(
            lang,
            if plan.reuse_key {
                "init.reusing"
            } else {
                "init.generating"
            },
            &[]
        )
    );
    match perform(&plan, &client).await {
        Ok(outcome) => {
            print!("{}", render_summary(lang, &plan, &outcome));
            Ok(ExitCode::SUCCESS)
        }
        Err(InitError::Register { key_path, source }) => {
            let mut msg = tr(
                lang,
                "init.error.register_failed",
                &[
                    ("error", &source.to_string()),
                    ("path", &key_path.display().to_string()),
                ],
            );
            if matches!(source, ApiError::Conflict(_)) {
                msg += &format!(
                    "\n{}",
                    tr(
                        lang,
                        "init.error.client_id_taken",
                        &[("client_id", &plan.client_id)]
                    )
                );
            }
            eprintln!("{msg}");
            Ok(ExitCode::from(1))
        }
        Err(InitError::KeyExists(p)) => anyhow::bail!(tr(
            lang,
            "init.error.key_exists",
            &[("path", &p.display().to_string())]
        )),
        Err(e) => Err(e.into()),
    }
}

async fn clock_step(base_url: &str, lang: Lang, yes: bool) -> anyhow::Result<bool> {
    println!("{}", tr(lang, "init.clock.checking", &[]));
    let skew = match clock::measure(&clock::Options::new(base_url)).await {
        Ok(s) => s,
        Err(e) => {
            println!(
                "{}",
                tr(lang, "init.clock.unavailable", &[("error", &e.to_string())])
            );
            return Ok(true);
        }
    };
    let ms = format!("{:+.0}", skew.offset_secs * 1000.0);
    let unc = format!("{:.0}", skew.uncertainty_secs * 1000.0);
    let args = [("ms", ms.as_str()), ("unc", unc.as_str())];
    let (key, default_continue) = match skew.severity() {
        Severity::Ok => {
            println!("{}", tr(lang, "init.clock.ok", &args));
            return Ok(true);
        }
        Severity::Warn => ("init.clock.warn", true),
        Severity::High => ("init.clock.high", false),
    };
    println!("{}", tr(lang, key, &args));
    if yes {
        return Ok(true);
    }
    ask(Confirm::new(&tr(lang, "init.clock.continue_prompt", &[]))
        .with_default(default_continue)
        .prompt())
}

fn choose_org(
    orgs: Vec<OrganizationItem>,
    args: &InitArgs,
    lang: Lang,
) -> anyhow::Result<OrganizationItem> {
    if orgs.is_empty() {
        anyhow::bail!(tr(lang, "init.orgs.none", &[]));
    }
    if let Some(wanted) = &args.org {
        return orgs
            .into_iter()
            .find(|o| &o.id == wanted)
            .ok_or_else(|| anyhow::anyhow!(tr(lang, "init.orgs.not_found", &[("org", wanted)])));
    }
    if orgs.len() == 1 {
        return Ok(orgs.into_iter().next().expect("one org"));
    }
    if args.yes {
        anyhow::bail!(tr(lang, "init.orgs.choose_with_flag", &[]));
    }
    let choices: Vec<OrgChoice> = orgs.into_iter().map(OrgChoice).collect();
    Ok(ask(Select::new(&tr(lang, "init.orgs.select", &[]), choices).prompt())?.0)
}

/// Maximum lengths accepted by the Xentree API.
const MAX_NAME: usize = 255;
const MAX_CLIENT_ID: usize = 128;
const MAX_URL: usize = 2048;

/// Rejects blank and over-long input; shared by prompts and flags.
pub fn validate_text(lang: Lang, value: &str, max_chars: usize) -> Result<(), String> {
    let v = value.trim();
    if v.is_empty() {
        return Err(tr(lang, "init.validation.required", &[]));
    }
    if v.chars().count() > max_chars {
        return Err(tr(
            lang,
            "init.validation.too_long",
            &[("max", &max_chars.to_string())],
        ));
    }
    Ok(())
}

/// An `inquire` validator that applies [`validate_text`].
fn required(lang: Lang, max_chars: usize) -> impl inquire::validator::StringValidator + Clone {
    move |input: &str| {
        Ok(match validate_text(lang, input, max_chars) {
            Ok(()) => inquire::validator::Validation::Valid,
            Err(msg) => inquire::validator::Validation::Invalid(msg.into()),
        })
    }
}

fn required_prompt(
    lang: Lang,
    prompt: &str,
    default: Option<&str>,
    max_chars: usize,
) -> anyhow::Result<String> {
    let mut text = Text::new(prompt).with_validator(required(lang, max_chars));
    if let Some(d) = default {
        text = text.with_default(d);
    }
    Ok(ask(text.prompt())?.trim().to_string())
}

/// Flag value, else the default (`--yes`), else a validated prompt. Flag and
/// default values are validated too, so `--name ""` can't slip through.
fn text_or_default(
    flag: Option<String>,
    yes: bool,
    lang: Lang,
    prompt: &str,
    default: String,
    max_chars: usize,
) -> anyhow::Result<String> {
    let value = match flag {
        Some(v) => v,
        None if yes => default,
        None => return required_prompt(lang, prompt, Some(&default), max_chars),
    };
    validate_text(lang, &value, max_chars).map_err(|m| anyhow::anyhow!("{prompt}: {m}"))?;
    Ok(value.trim().to_string())
}

/// Where the key goes and who may read it.
fn key_location(
    args: &InitArgs,
    platform: &DetectedPlatform,
    lang: Lang,
) -> anyhow::Result<(PathBuf, KeyOwnershipPolicy)> {
    let dir = args
        .key_dir
        .clone()
        .or_else(|| platform.suggested_key_dir())
        .or_else(config::default_config_dir)
        .ok_or_else(|| anyhow::anyhow!(tr(lang, "init.err.no_key_dir", &[])))?;

    let policy = match &args.key_group {
        Some(g) => parse_key_group(g)?,
        #[cfg(unix)]
        None if matches!(platform, DetectedPlatform::Moodle { .. }) => {
            match moodle::web_server_group() {
                Some((_, gid)) => KeyOwnershipPolicy::GroupReadable { gid },
                None => {
                    println!(
                        "{}",
                        tr(
                            lang,
                            "init.key.group_missing",
                            &[("groups", &moodle::WEB_SERVER_GROUPS.join(", "))]
                        )
                    );
                    KeyOwnershipPolicy::CurrentUserOnly
                }
            }
        }
        None => KeyOwnershipPolicy::CurrentUserOnly,
    };
    Ok((dir, policy))
}

fn describe_access(lang: Lang, policy: &KeyOwnershipPolicy) -> String {
    match policy {
        KeyOwnershipPolicy::CurrentUserOnly => tr(lang, "init.key.access_user", &[]),
        #[cfg(unix)]
        KeyOwnershipPolicy::GroupReadable { gid } => {
            tr(lang, "init.key.access_group", &[("gid", &gid.to_string())])
        }
        #[cfg(unix)]
        KeyOwnershipPolicy::SpecificOwner { uid, gid, mode } => tr(
            lang,
            "init.key.access_owner",
            &[
                ("uid", &uid.to_string()),
                ("gid", &gid.to_string()),
                ("mode", &format!("{mode:04o}")),
            ],
        ),
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;
    use serde_json::{json, Value};
    use tempfile::tempdir;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::fs::write_private_file;

    const CUO: KeyOwnershipPolicy = KeyOwnershipPolicy::CurrentUserOnly;

    fn plan(key_dir: &Path) -> InitPlan {
        InitPlan {
            base_url: String::new(),
            org_id: "org_1".into(),
            name: "Moodle".into(),
            client_id: "moodle-prod".into(),
            issuer: "https://lms.example.com".into(),
            audience: "xentree".into(),
            auto_enroll: false,
            key_path: key_dir.join(KEY_FILE_NAME),
            policy: CUO,
            reuse_key: false,
        }
    }

    fn client(s: &MockServer) -> XentreeAdminClient {
        XentreeAdminClient::with_base_url(&s.uri(), SecretString::from("tok")).unwrap()
    }

    async fn accept_registration(s: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/api/admin/organizations/org_1/connect-clients"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(json!({"id": "rec_7", "client_id": "moodle-prod"})),
            )
            .mount(s)
            .await;
    }

    async fn sent_body(s: &MockServer) -> Value {
        let reqs = s.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1, "expected exactly one request");
        serde_json::from_slice(&reqs[0].body).unwrap()
    }

    #[tokio::test]
    async fn registers_the_public_half_of_the_key_it_stored() {
        let s = MockServer::start().await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        let p = plan(&d.path().join("keys"));

        let out = perform(&p, &client(&s)).await.unwrap();

        // The key on disk loads, is private, and matches what was registered.
        verify_private_file(&p.key_path, &CUO).unwrap();
        let key = SigningKey::from_pem(&std::fs::read_to_string(&p.key_path).unwrap()).unwrap();
        assert_eq!(key.kid(), out.kid);

        let body = sent_body(&s).await;
        assert_eq!(body["client_id"], "moodle-prod");
        assert_eq!(body["issuer"], "https://lms.example.com");
        assert_eq!(body["auto_enroll"], false);
        let jwks: Value = serde_json::from_str(body["jwks_json"].as_str().unwrap()).unwrap();
        assert_eq!(jwks["keys"].as_array().unwrap().len(), 1);
        assert_eq!(jwks["keys"][0]["kid"], key.kid());
        assert_eq!(jwks["keys"][0]["alg"], "ES256");
        assert!(
            jwks["keys"][0].get("d").is_none(),
            "no private parameter may be registered"
        );
        assert!(!body.to_string().contains("PRIVATE KEY"));
        assert_eq!(out.client.id, "rec_7");
    }

    #[tokio::test]
    async fn writes_a_config_that_health_can_use() {
        let s = MockServer::start().await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        let p = plan(d.path());
        let out = perform(&p, &client(&s)).await.unwrap();
        assert!(out.config_error.is_none());
        let cfg = Config::load(&out.config_path).unwrap();
        assert_eq!(cfg.client_record_id, "rec_7");
        assert_eq!(cfg.kid, out.kid);
        assert_eq!(cfg.key_path, p.key_path);
        assert_eq!(cfg.ownership, OwnershipConfig::CurrentUserOnly);
        assert!(cfg.base_url.starts_with("http://127.0.0.1"));
    }

    #[tokio::test]
    async fn existing_key_is_never_overwritten_and_nothing_is_sent() {
        let s = MockServer::start().await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        write_private_file(
            &d.path().join(KEY_FILE_NAME),
            b"precious",
            Existing::Fail,
            &CUO,
        )
        .unwrap();
        let err = perform(&plan(d.path()), &client(&s)).await.unwrap_err();
        assert!(matches!(err, InitError::KeyExists(_)));
        assert_eq!(
            std::fs::read(d.path().join(KEY_FILE_NAME)).unwrap(),
            b"precious"
        );
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_registration_keeps_the_key_and_reuse_resumes_with_the_same_kid() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(json!({"detail": "client_id already exists"})),
            )
            .up_to_n_times(1)
            .mount(&s)
            .await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        let mut p = plan(d.path());

        let err = perform(&p, &client(&s)).await.unwrap_err();
        let first_kid = match err {
            InitError::Register {
                key_path,
                source: ApiError::Conflict(m),
            } => {
                assert_eq!(key_path, p.key_path);
                assert!(m.contains("already exists"));
                SigningKey::from_pem(&std::fs::read_to_string(&key_path).unwrap())
                    .unwrap()
                    .kid()
                    .to_string()
            }
            other => panic!("{other:?}"),
        };

        p.reuse_key = true;
        p.client_id = "moodle-prod-2".into();
        let out = perform(&p, &client(&s)).await.unwrap();
        assert_eq!(
            out.kid, first_kid,
            "the same key must be registered on retry"
        );
    }

    #[tokio::test]
    async fn reuse_requires_an_existing_key() {
        let s = MockServer::start().await;
        let d = tempdir().unwrap();
        let mut p = plan(d.path());
        p.reuse_key = true;
        assert!(matches!(
            perform(&p, &client(&s)).await,
            Err(InitError::ReadKey { .. })
        ));
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reuse_refuses_a_key_with_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let s = MockServer::start().await;
        let d = tempdir().unwrap();
        let key = SigningKey::generate().unwrap();
        let kp = d.path().join(KEY_FILE_NAME);
        write_private_file(&kp, key.to_pem().as_bytes(), Existing::Fail, &CUO).unwrap();
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut p = plan(d.path());
        p.reuse_key = true;
        assert!(matches!(
            perform(&p, &client(&s)).await,
            Err(InitError::Fs(FsError::InsecurePermissions { .. }))
        ));
        assert!(s.received_requests().await.unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn moodle_style_group_policy_creates_traversable_dir_and_group_readable_key() {
        use std::os::unix::fs::MetadataExt;
        let gid = unsafe { libc::getegid() };
        let s = MockServer::start().await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        let mut p = plan(&d.path().join("keys")); // parent (tempdir) exists, "keys" doesn't
        p.policy = KeyOwnershipPolicy::GroupReadable { gid };

        let out = perform(&p, &client(&s)).await.unwrap();

        let key = std::fs::metadata(&p.key_path).unwrap();
        assert_eq!((key.mode() & 0o7777, key.gid()), (0o640, gid));
        assert_eq!(
            std::fs::metadata(d.path().join("keys")).unwrap().mode() & 0o7777,
            0o750
        );
        let cfg = Config::load(&out.config_path).unwrap();
        assert_eq!(cfg.ownership, OwnershipConfig::GroupReadable { gid });
        assert_eq!(
            std::fs::metadata(&out.config_path).unwrap().mode() & 0o7777,
            0o640
        );
    }

    #[tokio::test]
    async fn config_write_failure_is_reported_without_losing_the_registration() {
        let s = MockServer::start().await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        // A directory squatting on the config path makes the atomic replace fail.
        std::fs::create_dir(d.path().join(FILE_NAME)).unwrap();
        let p = plan(d.path());
        let out = perform(&p, &client(&s)).await.unwrap();
        assert!(out.config_error.is_some());
        assert_eq!(out.client.id, "rec_7");
        let summary = render_summary(Lang::En, &p, &out);
        assert!(summary.contains("rec_7") && summary.contains("could not be written"));
    }

    #[tokio::test]
    async fn auto_enroll_is_forwarded() {
        let s = MockServer::start().await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        let mut p = plan(d.path());
        p.auto_enroll = true;
        perform(&p, &client(&s)).await.unwrap();
        assert_eq!(sent_body(&s).await["auto_enroll"], true);
    }

    #[tokio::test]
    async fn summary_is_localized_and_mentions_the_essentials() {
        let s = MockServer::start().await;
        accept_registration(&s).await;
        let d = tempdir().unwrap();
        let p = plan(d.path());
        let out = perform(&p, &client(&s)).await.unwrap();
        let en = render_summary(Lang::En, &p, &out);
        let id = render_summary(Lang::Id, &p, &out);
        for text in [&en, &id] {
            assert!(
                text.contains("rec_7") && text.contains(&out.kid) && text.contains(KEY_FILE_NAME)
            );
            assert!(!text.contains("PRIVATE KEY"));
        }
        assert!(en.contains("Xentree Connect is set up.") && en.contains("Next steps"));
        assert!(
            id.contains("Xentree Connect telah disiapkan.") && id.contains("Langkah berikutnya")
        );
    }

    #[test]
    fn blank_and_overlong_text_is_rejected() {
        let l = Lang::En;
        for blank in ["", " ", "   \t  "] {
            assert!(validate_text(l, blank, 10).is_err(), "{blank:?}");
        }
        assert!(validate_text(l, "ok", 10).is_ok());
        assert!(
            validate_text(l, "  padded  ", 6).is_ok(),
            "length is measured after trimming"
        );
        assert!(validate_text(l, &"x".repeat(11), 10).is_err());
        assert!(
            validate_text(l, &"é".repeat(10), 10).is_ok(),
            "limits count characters, not bytes"
        );
        // localized messages
        assert_eq!(
            validate_text(Lang::Id, "", 5).unwrap_err(),
            "Kolom ini wajib diisi."
        );
        assert_eq!(
            validate_text(l, &"x".repeat(6), 5).unwrap_err(),
            "Maximum 5 characters."
        );
    }

    #[test]
    fn the_inquire_validator_marks_blank_input_invalid() {
        use inquire::validator::{StringValidator, Validation};
        let v = required(Lang::En, 128);
        assert!(matches!(v.validate("   "), Ok(Validation::Invalid(_))));
        assert!(matches!(
            v.validate("xentree-moodle"),
            Ok(Validation::Valid)
        ));
    }

    #[test]
    fn flags_and_defaults_are_validated_too() {
        let l = Lang::En;
        let run = |flag: Option<&str>, yes, default: &str| {
            text_or_default(
                flag.map(String::from),
                yes,
                l,
                "Name",
                default.into(),
                MAX_NAME,
            )
        };
        assert!(run(Some(""), true, "d").is_err(), "blank --name");
        assert!(run(Some("   "), false, "d").is_err());
        assert_eq!(run(Some("  Acme  "), true, "d").unwrap(), "Acme");
        assert!(run(None, true, "").is_err(), "blank default under --yes");
        assert_eq!(run(None, true, "default").unwrap(), "default");
        assert!(text_or_default(
            Some("x".repeat(129)),
            true,
            l,
            "Client ID",
            "d".into(),
            MAX_CLIENT_ID
        )
        .is_err());
    }

    #[test]
    fn slugify_produces_valid_client_ids() {
        assert_eq!(
            slugify("Xentree Connect (Moodle)"),
            "xentree-connect-moodle"
        );
        assert_eq!(slugify("  --Hello__World!! "), "hello-world");
        assert_eq!(slugify("***"), "");
        assert_eq!(slugify(&"a".repeat(300)).len(), 128);
    }

    #[cfg(unix)]
    #[test]
    fn key_group_accepts_gid_or_name() {
        assert_eq!(
            parse_key_group("33").unwrap(),
            KeyOwnershipPolicy::GroupReadable { gid: 33 }
        );
        let (gid, name) = unsafe {
            let gid = libc::getegid();
            let g = libc::getgrgid(gid);
            (
                gid,
                std::ffi::CStr::from_ptr((*g).gr_name)
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        assert_eq!(
            parse_key_group(&name).unwrap(),
            KeyOwnershipPolicy::GroupReadable { gid }
        );
        assert!(parse_key_group("no-such-group-xyz").is_err());
    }

    fn orgs() -> Vec<OrganizationItem> {
        vec![
            OrganizationItem {
                id: "o1".into(),
                name: "A".into(),
                role: None,
            },
            OrganizationItem {
                id: "o2".into(),
                name: "B".into(),
                role: Some("admin".into()),
            },
        ]
    }

    #[test]
    fn org_selection_rules() {
        let yes = InitArgs {
            yes: true,
            ..Default::default()
        };
        let l = Lang::En;
        assert!(choose_org(vec![], &yes, l).is_err(), "no admin orgs");
        assert_eq!(
            choose_org(orgs()[..1].to_vec(), &yes, l).unwrap().id,
            "o1",
            "single org is chosen"
        );
        assert!(
            choose_org(orgs(), &yes, l).is_err(),
            "ambiguous in non-interactive mode"
        );
        let by_flag = InitArgs {
            org: Some("o2".into()),
            yes: true,
            ..Default::default()
        };
        assert_eq!(choose_org(orgs(), &by_flag, l).unwrap().id, "o2");
        let bad = InitArgs {
            org: Some("nope".into()),
            ..Default::default()
        };
        assert!(
            choose_org(orgs(), &bad, l).is_err(),
            "must not fall back to another org"
        );
    }

    #[test]
    fn org_choice_label_shows_name_id_and_role() {
        assert_eq!(OrgChoice(orgs()[1].clone()).to_string(), "B (o2) [admin]");
        assert_eq!(OrgChoice(orgs()[0].clone()).to_string(), "A (o1)");
    }

    #[test]
    fn key_location_defaults() {
        let a = InitArgs::default();
        let (dir, policy) = key_location(&a, &DetectedPlatform::Generic, Lang::En).unwrap();
        assert_eq!(Some(dir), config::default_config_dir());
        assert_eq!(policy, CUO);
        let a = InitArgs {
            key_dir: Some("/x".into()),
            ..Default::default()
        };
        assert_eq!(
            key_location(&a, &DetectedPlatform::Generic, Lang::En)
                .unwrap()
                .0,
            PathBuf::from("/x")
        );
    }

    #[test]
    fn moodle_key_location_is_moodledata_keys() {
        let d = tempdir().unwrap();
        std::fs::write(
            d.path().join("version.php"),
            "<?php $version = 1; $release = '4';",
        )
        .unwrap();
        std::fs::write(
            d.path().join("config.php"),
            "<?php $CFG->dataroot = '/srv/moodledata';",
        )
        .unwrap();
        let platform = DetectedPlatform::detect(d.path());
        let (dir, _) = key_location(&InitArgs::default(), &platform, Lang::En).unwrap();
        assert_eq!(dir, PathBuf::from("/srv/moodledata/keys"));
    }
}
