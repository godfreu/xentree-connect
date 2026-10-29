use std::time::{Duration, SystemTime};

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// 401: the bearer token is invalid or expired.
    #[error("unauthorized: the admin bearer token was rejected")]
    Unauthorized,
    /// 403: missing Connect entitlement, or the caller isn't an org admin.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// 409: e.g. a duplicate `client_id`.
    #[error("conflict: {0}")]
    Conflict(String),
    /// 404: unknown organization or client record.
    #[error("not found: {0}")]
    NotFound(String),
    #[error("rate limited{}", retry_hint(.retry_after))]
    RateLimited { retry_after: Option<Duration> },
    /// 5xx.
    #[error("server error {0}: {1}")]
    Server(u16, String),
    /// Any other non-success status (400, 422, 3xx, ...).
    #[error("unexpected response {0}: {1}")]
    Unexpected(u16, String),
    /// Rejected locally before any request was sent.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// A success response whose body didn't match the expected shape. The
    /// body is deliberately not echoed: it may contain a one-time secret.
    #[error("could not decode response: {0}")]
    Decode(String),
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
}

fn retry_hint(d: &Option<Duration>) -> String {
    d.map_or(String::new(), |d| {
        format!(" (retry after {}s)", d.as_secs())
    })
}

const MAX_DETAIL_LEN: usize = 300;

impl ApiError {
    pub(crate) fn from_response(status: u16, retry_after: Option<&str>, body: &[u8]) -> Self {
        let detail = extract_detail(body, status);
        match status {
            401 => Self::Unauthorized,
            403 => Self::Forbidden(detail),
            404 => Self::NotFound(detail),
            409 => Self::Conflict(detail),
            429 => Self::RateLimited {
                retry_after: retry_after.and_then(parse_retry_after),
            },
            500..=599 => Self::Server(status, detail),
            _ => Self::Unexpected(status, detail),
        }
    }
}

/// `Retry-After` is either delta-seconds or an HTTP date.
fn parse_retry_after(v: &str) -> Option<Duration> {
    let v = v.trim();
    if let Ok(secs) = v.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = httpdate::parse_http_date(v).ok()?;
    Some(at.duration_since(SystemTime::now()).unwrap_or_default())
}

/// Xentree puts the message in `detail` (a string, or a list of validation
/// errors) or `error`. Anything else falls back to the truncated raw body.
fn extract_detail(body: &[u8], status: u16) -> String {
    let from_json = serde_json::from_slice::<Value>(body).ok().and_then(|v| {
        match v.get("detail") {
            Some(Value::String(s)) => return Some(s.clone()),
            Some(Value::Array(items)) => {
                let msgs: Vec<String> = items
                    .iter()
                    .filter_map(|i| match i {
                        Value::String(s) => Some(s.clone()),
                        Value::Object(o) => {
                            let msg = o.get("msg").and_then(Value::as_str)?;
                            let loc = o.get("loc").and_then(Value::as_array).map(|l| {
                                l.iter()
                                    .map(|p| p.as_str().map_or_else(|| p.to_string(), String::from))
                                    .collect::<Vec<_>>()
                                    .join(".")
                            });
                            Some(match loc {
                                Some(loc) if !loc.is_empty() => format!("{loc}: {msg}"),
                                _ => msg.to_string(),
                            })
                        }
                        _ => None,
                    })
                    .collect();
                if !msgs.is_empty() {
                    return Some(msgs.join("; "));
                }
            }
            _ => {}
        }
        v.get("error").and_then(Value::as_str).map(String::from)
    });

    let text = from_json.unwrap_or_else(|| {
        let raw = String::from_utf8_lossy(body);
        let raw = raw.trim();
        if raw.is_empty() {
            format!("HTTP {status}")
        } else {
            raw.to_string()
        }
    });
    truncate(text)
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_DETAIL_LEN {
        let mut end = MAX_DETAIL_LEN;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        s.truncate(end);
        s.push('…');
    }
    s
}
