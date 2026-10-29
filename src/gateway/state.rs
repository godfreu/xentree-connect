use std::{
    sync::{
        atomic::{AtomicI64, Ordering},
        Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axum::{
    body::Bytes,
    http::{HeaderName, HeaderValue},
};
use reqwest::header::CONTENT_TYPE;
use secrecy::ExposeSecret;
use tokio::task::JoinSet;
use url::Url;

use super::{
    auth::{digest_secret, AuthConfig},
    html::content_security_policy,
    seen::{SeenCache, CAPACITY, TTL},
    settings::Settings,
};
use crate::{
    api::{endpoint_url, normalize_base_url},
    crypto::{AssertionSigner, CryptoError, Purpose},
    webhook::Verifier,
};

/// Everything a request handler needs. Built once at startup and shared.
pub struct GatewayState {
    signer: AssertionSigner,
    clock_offset: AtomicI64,
    pub(crate) kid: String,
    pub(crate) launch_url: Url,
    pub(crate) deprovision_url: Url,
    pub(crate) csp: HeaderValue,
    secret_digest: [u8; 32],
    pub(crate) trusted_headers: Vec<HeaderName>,
    pub(crate) allow_query_secret: bool,
    pub(crate) verifier: Option<Verifier>,
    pub(crate) seen: Mutex<SeenCache>,
    relay: Option<Url>,
    pub(crate) http: reqwest::Client,
    /// Pause before the 2nd and 3rd relay attempts doubles from this.
    pub(crate) relay_backoff: Duration,
    tasks: Mutex<JoinSet<()>>,
}

impl GatewayState {
    pub fn new(settings: Settings) -> anyhow::Result<Self> {
        let cfg = &settings.config;
        let base = normalize_base_url(&cfg.base_url).context("config base_url")?;
        let launch_url = endpoint_url(&base, &["connect", "v1", "launch", &cfg.client_id])?;
        let deprovision_url =
            endpoint_url(&base, &["connect", "v1", "deprovision", &cfg.client_id])?;
        let csp = HeaderValue::from_str(&content_security_policy(
            &base.origin().ascii_serialization(),
        ))?;

        let kid = settings.key.kid().to_string();
        let signer = AssertionSigner::new(settings.key, &cfg.issuer, &cfg.audience, &cfg.org_id)?;

        let verifier = match &settings.webhook {
            None => None,
            Some(w) => {
                let mut v = Verifier::new(w.active.expose_secret())?;
                if let Some((prev, expires_at)) = &w.previous {
                    v = v.with_previous_until(prev.expose_secret(), *expires_at)?;
                }
                Some(v)
            }
        };

        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!(
                "xentree-connect-gateway/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;

        Ok(Self {
            signer,
            clock_offset: AtomicI64::new(0),
            kid,
            launch_url,
            deprovision_url,
            csp,
            secret_digest: digest_secret(settings.gateway_secret.expose_secret()),
            trusted_headers: settings.trusted_headers,
            allow_query_secret: settings.allow_query_secret,
            verifier,
            seen: Mutex::new(SeenCache::new(TTL, CAPACITY)),
            relay: settings.relay_url,
            http,
            relay_backoff: Duration::from_secs(1),
            tasks: Mutex::new(JoinSet::new()),
        })
    }

    pub(crate) fn auth(&self) -> AuthConfig<'_> {
        AuthConfig {
            secret_digest: &self.secret_digest,
            trusted_headers: &self.trusted_headers,
            allow_query_secret: self.allow_query_secret,
        }
    }

    /// Seconds to add to the local clock so assertions carry Xentree's time.
    pub fn set_clock_offset(&self, secs: i64) {
        self.clock_offset.store(secs, Ordering::Relaxed);
    }

    fn now_secs(&self) -> u64 {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        local.saturating_add_signed(self.clock_offset.load(Ordering::Relaxed))
    }

    /// Signs a 30-second assertion for `sub` using the calibrated clock.
    pub(crate) fn sign(&self, sub: &str, purpose: Purpose) -> Result<String, CryptoError> {
        self.signer.sign_at(sub, purpose, self.now_secs())
    }

    /// Forwards a verified webhook upstream without delaying the ack. Retries
    /// transient failures a couple of times, then gives up (logged).
    pub(crate) fn spawn_relay(&self, body: Bytes, signature: String, event_id: String) {
        let Some(url) = self.relay.clone() else {
            return;
        };
        let (http, backoff) = (self.http.clone(), self.relay_backoff);
        let mut tasks = self.tasks.lock().expect("task set");
        while tasks.try_join_next().is_some() {} // reap finished deliveries
        tasks.spawn(async move {
            for attempt in 0..3u32 {
                let sent = http
                    .post(url.clone())
                    .header(CONTENT_TYPE, "application/json")
                    .header("X-Xentree-Signature", &signature)
                    .header("X-Xentree-Event-Id", &event_id)
                    .body(body.clone())
                    .send()
                    .await;
                match sent {
                    Ok(r) if r.status().is_success() => {
                        tracing::info!(event_id, status = r.status().as_u16(), "relayed webhook");
                        return;
                    }
                    // The upstream rejected it; retrying the same request won't help.
                    Ok(r) if r.status().is_client_error() && r.status().as_u16() != 429 => {
                        tracing::warn!(
                            event_id,
                            status = r.status().as_u16(),
                            "upstream rejected relayed webhook"
                        );
                        return;
                    }
                    Ok(r) => tracing::warn!(
                        event_id,
                        attempt,
                        status = r.status().as_u16(),
                        "relay attempt failed"
                    ),
                    Err(e) => tracing::warn!(event_id, attempt, error = %e, "relay attempt failed"),
                }
                if attempt < 2 {
                    tokio::time::sleep(backoff * 2u32.pow(attempt)).await;
                }
            }
            tracing::error!(event_id, "gave up relaying webhook");
        });
    }

    /// Waits (bounded) for in-flight relay deliveries; used at shutdown.
    pub async fn drain(&self, timeout: Duration) {
        let mut set = std::mem::take(&mut *self.tasks.lock().expect("task set"));
        let _ =
            tokio::time::timeout(timeout, async { while set.join_next().await.is_some() {} }).await;
        set.abort_all();
    }
}
