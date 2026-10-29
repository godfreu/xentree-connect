use std::time::Duration;

use reqwest::{header::ACCEPT, RequestBuilder};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use url::{Host, Url};

use super::error::ApiError;

pub const DEFAULT_BASE_URL: &str = "https://my.xentree.ai";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Client for the Xentree admin API, authenticated with an Organization
/// Administrator bearer token.
pub struct XentreeAdminClient {
    http: reqwest::Client,
    base_url: Url,
    token: SecretString,
}

impl std::fmt::Debug for XentreeAdminClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XentreeAdminClient")
            .field("base_url", &self.base_url.as_str())
            .finish_non_exhaustive()
    }
}

impl XentreeAdminClient {
    /// Client for the default cloud, <https://my.xentree.ai>.
    pub fn new(token: SecretString) -> Result<Self, ApiError> {
        Self::with_base_url(DEFAULT_BASE_URL, token)
    }

    /// Client for a custom domain. The URL must be `https` (plain `http` is
    /// accepted only for loopback hosts, so a bearer token never crosses the
    /// network in clear text). A path prefix is kept; query, fragment and
    /// trailing slashes are dropped.
    pub fn with_base_url(base_url: &str, token: SecretString) -> Result<Self, ApiError> {
        let t = token.expose_secret();
        if t.trim().is_empty() || t.chars().any(char::is_control) {
            return Err(ApiError::InvalidInput(
                "bearer token is empty or contains control characters".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            // Never follow redirects with a bearer token attached.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("xentree-connect-cli/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            base_url: normalize_base_url(base_url)?,
            token,
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Builds `{base}/seg1/seg2/...`; see [`endpoint_url`].
    pub(crate) fn endpoint(&self, segments: &[&str]) -> Result<Url, ApiError> {
        endpoint_url(&self.base_url, segments)
    }

    pub(crate) fn get(&self, url: Url) -> RequestBuilder {
        self.http.get(url)
    }
    pub(crate) fn post(&self, url: Url) -> RequestBuilder {
        self.http.post(url)
    }
    pub(crate) fn patch(&self, url: Url) -> RequestBuilder {
        self.http.patch(url)
    }

    pub(crate) async fn send_json<T: DeserializeOwned>(
        &self,
        req: RequestBuilder,
    ) -> Result<T, ApiError> {
        let body = self.send(req).await?;
        serde_json::from_slice(&body).map_err(|e| {
            // Not `e.to_string()`: for type mismatches serde echoes the offending value.
            ApiError::Decode(format!(
                "response did not match the expected shape (line {}, column {})",
                e.line(),
                e.column()
            ))
        })
    }

    /// Sends the request and returns the body of a 2xx response.
    pub(crate) async fn send(&self, req: RequestBuilder) -> Result<bytes::Bytes, ApiError> {
        let resp = req
            .bearer_auth(self.token.expose_secret())
            .header(ACCEPT, "application/json")
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp.bytes().await?);
        }
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = resp.bytes().await.unwrap_or_default();
        Err(ApiError::from_response(
            status.as_u16(),
            retry_after.as_deref(),
            &body,
        ))
    }
}

/// Validates and canonicalizes a Xentree base URL (see
/// [`XentreeAdminClient::with_base_url`]).
pub(crate) fn normalize_base_url(raw: &str) -> Result<Url, ApiError> {
    let invalid = |m: &str| ApiError::InvalidInput(format!("base URL: {m}"));
    let mut url = Url::parse(raw.trim()).map_err(|e| invalid(&e.to_string()))?;
    if url.cannot_be_a_base() || url.host().is_none() {
        return Err(invalid("must be an absolute http(s) URL with a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("must not contain credentials"));
    }
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        "http" => {
            return Err(invalid(
                "must use https (http is allowed only for localhost)",
            ))
        }
        _ => return Err(invalid("must use https")),
    }
    url.set_query(None);
    url.set_fragment(None);
    let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
    let path = format!("/{}", segments.join("/"));
    url.set_path(&path);
    Ok(url)
}

pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Appends `segments` to `base`'s path, percent-encoding each one so an
/// attacker-influenced ID can't add path components or `..`.
pub(crate) fn endpoint_url(base: &Url, segments: &[&str]) -> Result<Url, ApiError> {
    if let Some(bad) = segments
        .iter()
        .find(|s| s.is_empty() || **s == "." || **s == "..")
    {
        return Err(ApiError::InvalidInput(format!(
            "invalid path segment {bad:?}"
        )));
    }
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|()| ApiError::InvalidInput("base URL cannot carry a path".into()))?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}
