//! Gateway command-line flags and the validated runtime settings built from them.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use axum::http::HeaderName;
use clap::Args;
use secrecy::{ExposeSecret, SecretString};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    api::is_loopback_url,
    config::{self, Config},
    crypto::SigningKey,
    fs::verify_private_file,
    lang::{tr, Lang},
};

/// Shorter secrets are guessable; `openssl rand -hex 32` makes 64 characters.
pub const MIN_SECRET_LEN: usize = 32;

#[derive(Debug, Clone, Args)]
pub struct GatewayArgs {
    /// Config written by `init` (default: ./xentree-connect.json).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Public listener: launch, webhook and health.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,
    /// Internal listener: deprovisioning. Keep it on loopback or a private network.
    #[arg(long, default_value = "127.0.0.1:8081")]
    pub internal_bind: SocketAddr,
    /// Shared secret (at least 32 characters) callers present as a bearer token.
    /// Prefer the environment variable: flags are visible in the process list.
    #[arg(long, env = "XENTREE_GATEWAY_SECRET", hide_env_values = true)]
    pub gateway_secret: Option<String>,
    /// Forward verified webhooks to this upstream (HRIS) URL.
    #[arg(long)]
    pub relay_webhook_url: Option<String>,
    /// Xentree webhook signing secret. Without it /webhook answers 503.
    #[arg(long, env = "XENTREE_WEBHOOK_SECRET", hide_env_values = true)]
    pub webhook_secret: Option<String>,
    /// The signing secret before the last rotation, accepted for 24 hours.
    #[arg(long, env = "XENTREE_PREVIOUS_WEBHOOK_SECRET", hide_env_values = true)]
    pub previous_webhook_secret: Option<String>,
    /// When the rotation happened, in Unix seconds (default: now, i.e. a full 24h from start).
    #[arg(long, env = "XENTREE_PREVIOUS_SECRET_ROTATED_AT")]
    pub previous_secret_rotated_at: Option<u64>,
    /// Trust this header as proof of identity, e.g. X-Remote-User. Repeatable.
    /// Only safe behind a proxy that strips it from client requests and sets it itself.
    #[arg(long = "trusted-identity-header")]
    pub trusted_identity_headers: Vec<String>,
    /// Also accept the gateway secret as a `secret` query/form parameter.
    /// Discouraged: URLs end up in logs, history and Referer headers.
    #[arg(long)]
    pub allow_query_secret: bool,
}

pub struct WebhookSecrets {
    pub active: SecretString,
    pub previous: Option<(SecretString, SystemTime)>,
}

pub struct Settings {
    pub config: Config,
    pub key: SigningKey,
    pub bind: SocketAddr,
    pub internal_bind: SocketAddr,
    pub gateway_secret: SecretString,
    pub trusted_headers: Vec<HeaderName>,
    pub allow_query_secret: bool,
    pub webhook: Option<WebhookSecrets>,
    pub relay_url: Option<Url>,
}

impl Settings {
    /// Validates everything up front so a misconfigured gateway fails at
    /// startup, not on the first request.
    pub fn from_args(args: GatewayArgs, cwd: &Path, lang: Lang) -> anyhow::Result<Self> {
        let secret = args
            .gateway_secret
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!(tr(lang, "gateway.error.secret_missing", &[])))?;
        if secret.chars().count() < MIN_SECRET_LEN {
            bail!(tr(
                lang,
                "gateway.error.secret_short",
                &[("min", &MIN_SECRET_LEN.to_string())]
            ));
        }

        let config_path = args.config.unwrap_or_else(|| cwd.join(config::FILE_NAME));
        let config =
            Config::load(&config_path).with_context(|| tr(lang, "gateway.error.config", &[]))?;
        let key = load_key(&config, &config_path)?;

        let mut trusted_headers = Vec::new();
        for h in &args.trusted_identity_headers {
            let name = HeaderName::try_from(h.trim()).map_err(|_| {
                anyhow::anyhow!(tr(lang, "gateway.error.bad_header", &[("name", h)]))
            })?;
            trusted_headers.push(name);
        }

        let webhook = match (
            args.webhook_secret.filter(|s| !s.is_empty()),
            args.previous_webhook_secret.filter(|s| !s.is_empty()),
        ) {
            (None, None) => None,
            (None, Some(_)) => bail!(tr(lang, "gateway.error.previous_without_active", &[])),
            (Some(active), previous) => {
                let rotated_at = args
                    .previous_secret_rotated_at
                    .map_or_else(SystemTime::now, |s| UNIX_EPOCH + Duration::from_secs(s));
                Some(WebhookSecrets {
                    active: SecretString::from(active),
                    previous: previous.map(|p| {
                        (
                            SecretString::from(p),
                            rotated_at + crate::webhook::ROTATION_GRACE,
                        )
                    }),
                })
            }
        };

        let relay_url = args
            .relay_webhook_url
            .map(|u| {
                parse_relay_url(&u).map_err(|m| {
                    anyhow::anyhow!(tr(lang, "gateway.error.relay_url", &[("reason", m)]))
                })
            })
            .transpose()?;

        Ok(Self {
            config,
            key,
            bind: args.bind,
            internal_bind: args.internal_bind,
            gateway_secret: SecretString::from(secret),
            trusted_headers,
            allow_query_secret: args.allow_query_secret,
            webhook,
            relay_url,
        })
    }

    pub fn expose_gateway_secret(&self) -> &str {
        self.gateway_secret.expose_secret()
    }
}

/// Loads the signing key named by the config, refusing one that is readable
/// beyond its declared policy or that isn't the key that was registered.
fn load_key(config: &Config, config_path: &Path) -> anyhow::Result<SigningKey> {
    let key_path = if config.key_path.is_absolute() {
        config.key_path.clone()
    } else {
        config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&config.key_path)
    };
    let policy = config.ownership.to_policy()?;
    verify_private_file(&key_path, &policy)?;
    let pem = Zeroizing::new(
        std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading {}", key_path.display()))?,
    );
    let key = SigningKey::from_pem(&pem)?;
    if key.kid() != config.kid {
        bail!(
            "{} holds key {} but the config registered {}",
            key_path.display(),
            key.kid(),
            config.kid
        );
    }
    Ok(key)
}

fn parse_relay_url(raw: &str) -> Result<Url, &'static str> {
    let url = Url::parse(raw.trim()).map_err(|_| "not a valid URL")?;
    if url.host().is_none() {
        return Err("missing host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials");
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback_url(&url) => Ok(url),
        "http" => Err("must use https (http only for localhost)"),
        _ => Err("must be an http(s) URL"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{OwnershipConfig, KEY_FILE_NAME},
        fs::{write_private_file, Existing, KeyOwnershipPolicy},
    };
    use tempfile::{tempdir, TempDir};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    pub(crate) fn args() -> GatewayArgs {
        GatewayArgs {
            config: None,
            bind: "127.0.0.1:0".parse().unwrap(),
            internal_bind: "127.0.0.1:0".parse().unwrap(),
            gateway_secret: Some(SECRET.into()),
            relay_webhook_url: None,
            webhook_secret: None,
            previous_webhook_secret: None,
            previous_secret_rotated_at: None,
            trusted_identity_headers: vec![],
            allow_query_secret: false,
        }
    }

    /// A directory with a valid key and matching config.
    fn site() -> (TempDir, SigningKey) {
        let d = tempdir().unwrap();
        let key = SigningKey::generate().unwrap();
        let kp = d.path().join(KEY_FILE_NAME);
        write_private_file(
            &kp,
            key.to_pem().as_bytes(),
            Existing::Fail,
            &KeyOwnershipPolicy::CurrentUserOnly,
        )
        .unwrap();
        Config {
            base_url: "https://my.xentree.ai".into(),
            org_id: "org_1".into(),
            client_record_id: "rec_1".into(),
            client_id: "c1".into(),
            issuer: "https://lms.example.com".into(),
            audience: "xentree".into(),
            kid: key.kid().into(),
            key_path: kp,
            ownership: OwnershipConfig::CurrentUserOnly,
        }
        .save(
            &d.path().join(config::FILE_NAME),
            &KeyOwnershipPolicy::CurrentUserOnly,
        )
        .unwrap();
        (d, key)
    }

    fn load(d: &Path, a: GatewayArgs) -> anyhow::Result<Settings> {
        Settings::from_args(a, d, Lang::En)
    }

    #[test]
    fn loads_config_and_key_from_the_working_directory() {
        let (d, key) = site();
        let s = load(d.path(), args()).unwrap();
        assert_eq!(s.key.kid(), key.kid());
        assert_eq!(s.config.client_id, "c1");
        assert!(s.webhook.is_none() && s.relay_url.is_none());
    }

    #[test]
    fn secret_is_mandatory_and_long_enough() {
        let (d, _) = site();
        let none = GatewayArgs {
            gateway_secret: None,
            ..args()
        };
        assert!(load(d.path(), none)
            .err()
            .unwrap()
            .to_string()
            .contains("XENTREE_GATEWAY_SECRET"));
        let empty = GatewayArgs {
            gateway_secret: Some(String::new()),
            ..args()
        };
        assert!(load(d.path(), empty).is_err());
        let short = GatewayArgs {
            gateway_secret: Some("x".repeat(31)),
            ..args()
        };
        assert!(load(d.path(), short)
            .err()
            .unwrap()
            .to_string()
            .contains("32"));
        let exact = GatewayArgs {
            gateway_secret: Some("x".repeat(32)),
            ..args()
        };
        assert!(load(d.path(), exact).is_ok());
    }

    #[test]
    fn missing_config_is_reported() {
        let d = tempdir().unwrap();
        assert!(load(d.path(), args()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_key_readable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (d, _) = site();
        let kp = d.path().join(KEY_FILE_NAME);
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let e = load(d.path(), args()).err().unwrap();
        assert!(format!("{e:#}").contains("insecure permissions"), "{e:#}");
    }

    #[test]
    fn a_key_that_differs_from_the_registered_one_is_refused() {
        let (d, _) = site();
        let kp = d.path().join(KEY_FILE_NAME);
        let other = SigningKey::generate().unwrap();
        write_private_file(
            &kp,
            other.to_pem().as_bytes(),
            Existing::Replace,
            &KeyOwnershipPolicy::CurrentUserOnly,
        )
        .unwrap();
        let e = load(d.path(), args()).err().unwrap();
        assert!(e.to_string().contains("registered"), "{e}");
    }

    #[test]
    fn relative_key_paths_resolve_against_the_config_directory() {
        let (d, key) = site();
        let cfg_path = d.path().join(config::FILE_NAME);
        let mut cfg = Config::load(&cfg_path).unwrap();
        cfg.key_path = KEY_FILE_NAME.into();
        cfg.save(&cfg_path, &KeyOwnershipPolicy::CurrentUserOnly)
            .unwrap();
        let elsewhere = tempdir().unwrap();
        let a = GatewayArgs {
            config: Some(cfg_path),
            ..args()
        };
        assert_eq!(load(elsewhere.path(), a).unwrap().key.kid(), key.kid());
    }

    #[test]
    fn webhook_secrets_and_rotation() {
        let (d, _) = site();
        let a = GatewayArgs {
            previous_webhook_secret: Some("old".into()),
            ..args()
        };
        assert!(
            load(d.path(), a).is_err(),
            "previous without active makes no sense"
        );
        let a = GatewayArgs {
            webhook_secret: Some("new".into()),
            previous_webhook_secret: Some("old".into()),
            previous_secret_rotated_at: Some(1_000),
            ..args()
        };
        let w = load(d.path(), a).unwrap().webhook.unwrap();
        assert_eq!(
            w.previous.unwrap().1,
            UNIX_EPOCH + Duration::from_secs(1_000 + 86_400)
        );
    }

    #[test]
    fn trusted_header_names_are_validated() {
        let (d, _) = site();
        let a = GatewayArgs {
            trusted_identity_headers: vec![
                "X-Remote-User".into(),
                " Cf-Access-Authenticated-User-Email ".into(),
            ],
            ..args()
        };
        assert_eq!(load(d.path(), a).unwrap().trusted_headers.len(), 2);
        let bad = GatewayArgs {
            trusted_identity_headers: vec!["not a header".into()],
            ..args()
        };
        assert!(load(d.path(), bad).is_err());
    }

    #[test]
    fn relay_url_must_be_https_or_loopback() {
        let (d, _) = site();
        for ok in [
            "https://hris.example.com/hooks/xentree",
            "http://127.0.0.1:9000/x",
            "http://localhost/x",
        ] {
            let a = GatewayArgs {
                relay_webhook_url: Some(ok.into()),
                ..args()
            };
            assert!(load(d.path(), a).is_ok(), "{ok}");
        }
        for bad in [
            "http://hris.example.com/x",
            "ftp://x.example/",
            "https://u:p@x.example/",
            "nope",
            "file:///etc/passwd",
        ] {
            let a = GatewayArgs {
                relay_webhook_url: Some(bad.into()),
                ..args()
            };
            assert!(load(d.path(), a).is_err(), "{bad}");
        }
    }
}
