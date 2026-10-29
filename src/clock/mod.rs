//! Local clock skew measurement.
//!
//! Xentree rejects assertions with an `iat` in the future and tolerates no
//! leeway, so the signer needs a calibrated clock. NTP (UDP 123) is the
//! primary source. Where UDP is blocked, an HTTPS `HEAD` against the Xentree
//! base URL is used instead: its `Date` header has only 1-second resolution,
//! which is reflected in the reported uncertainty.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, AGE, CACHE_CONTROL, DATE};

use crate::crypto::AssertionSigner;

/// Offsets above this (in absolute seconds) log a warning.
pub const WARN_THRESHOLD_SECS: f64 = 1.0;
/// Offsets above this log at error level.
pub const HIGH_THRESHOLD_SECS: f64 = 10.0;

pub const DEFAULT_NTP_SERVERS: [&str; 2] = ["pool.ntp.org", "time.cloudflare.com"];

#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    Ntp { server: String },
    HttpDate { url: String },
}

/// A clock measurement. `offset_secs` is *server minus local*: positive means
/// the local clock is behind.
#[derive(Debug, Clone, PartialEq)]
pub struct Skew {
    pub offset_secs: f64,
    /// Half-width of the error bar around `offset_secs`.
    pub uncertainty_secs: f64,
    pub source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Warn,
    High,
}

impl Skew {
    pub fn severity(&self) -> Severity {
        let abs = self.offset_secs.abs();
        if abs > HIGH_THRESHOLD_SECS {
            Severity::High
        } else if abs > WARN_THRESHOLD_SECS {
            Severity::Warn
        } else {
            Severity::Ok
        }
    }

    /// Whole-second correction for [`AssertionSigner::with_clock_offset_secs`].
    ///
    /// Rounds *down* after subtracting the uncertainty, so the corrected `iat`
    /// can only err into the past (costing a second of lifetime), never into
    /// the future, which Xentree rejects outright.
    pub fn signer_offset_secs(&self) -> i64 {
        (self.offset_secs - self.uncertainty_secs).floor() as i64
    }

    /// Emits the measurement at a level matching its [`Severity`].
    pub fn log(&self) {
        let direction = if self.offset_secs >= 0.0 {
            "behind"
        } else {
            "ahead of"
        };
        match self.severity() {
            Severity::Ok => {
                tracing::info!(offset_secs = self.offset_secs, source = ?self.source, "system clock within tolerance")
            }
            Severity::Warn => tracing::warn!(
                offset_secs = self.offset_secs,
                uncertainty_secs = self.uncertainty_secs,
                source = ?self.source,
                "system clock is {direction} true time; assertions will be offset-corrected"
            ),
            Severity::High => tracing::error!(
                offset_secs = self.offset_secs,
                uncertainty_secs = self.uncertainty_secs,
                source = ?self.source,
                "system clock is {direction} true time by more than {HIGH_THRESHOLD_SECS}s; fix NTP on this host"
            ),
        }
    }
}

/// Feeds a measured skew into the signer.
pub fn calibrate(signer: AssertionSigner, skew: &Skew) -> AssertionSigner {
    signer.with_clock_offset_secs(skew.signer_offset_secs())
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Tried in order; the first to answer wins. Empty skips NTP.
    pub ntp_servers: Vec<String>,
    pub ntp_timeout: Duration,
    /// Base URL for the HTTP `Date` fallback; `None` disables it.
    pub http_url: Option<String>,
    pub http_timeout: Duration,
}

impl Options {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            ntp_servers: DEFAULT_NTP_SERVERS.iter().map(|s| s.to_string()).collect(),
            ntp_timeout: Duration::from_secs(3),
            http_url: Some(base_url.into()),
            http_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpDateError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("response had no Date header")]
    MissingDate,
    #[error("unparseable Date header")]
    BadDate,
    #[error("unparseable Age header")]
    BadAge,
    #[error("response was served from a cache (Age: {0}s); its Date is stale")]
    StaleCache(u64),
}

#[derive(Debug, thiserror::Error)]
#[error("no time source available (ntp: [{}], http: {})", ntp_errors.join("; "), http_error.as_ref().map_or("not configured".into(), |e| e.to_string()))]
pub struct ClockError {
    pub ntp_errors: Vec<String>,
    pub http_error: Option<HttpDateError>,
}

/// Measures skew via NTP, falling back to the HTTP `Date` header.
pub async fn measure(opts: &Options) -> Result<Skew, ClockError> {
    let mut ntp_errors = Vec::new();
    let client = rsntp::AsyncSntpClient::new();
    for server in &opts.ntp_servers {
        match tokio::time::timeout(opts.ntp_timeout, client.synchronize(server.as_str())).await {
            Ok(Ok(r)) => {
                return Ok(Skew {
                    offset_secs: r.clock_offset().as_secs_f64(),
                    uncertainty_secs: r.round_trip_delay().as_secs_f64().abs() / 2.0,
                    source: Source::Ntp {
                        server: server.clone(),
                    },
                })
            }
            Ok(Err(e)) => ntp_errors.push(format!("{server}: {e}")),
            Err(_) => ntp_errors.push(format!("{server}: timed out")),
        }
    }

    let http_error = match &opts.http_url {
        None => None,
        Some(url) => match measure_http(url, opts.http_timeout).await {
            Ok(skew) => return Ok(skew),
            Err(e) => Some(e),
        },
    };
    Err(ClockError {
        ntp_errors,
        http_error,
    })
}

async fn measure_http(url: &str, timeout: Duration) -> Result<Skew, HttpDateError> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("xentree-connect/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let sent_at = SystemTime::now();
    let started = std::time::Instant::now();
    // Any status is fine: we only want the Date header.
    let resp = client
        .head(url)
        .header(CACHE_CONTROL, "no-cache")
        .send()
        .await?;
    let rtt = started.elapsed();
    skew_from_http_headers(resp.headers(), sent_at, rtt, url)
}

fn skew_from_http_headers(
    headers: &HeaderMap,
    sent_at: SystemTime,
    rtt: Duration,
    url: &str,
) -> Result<Skew, HttpDateError> {
    if let Some(age) = headers.get(AGE) {
        let age: u64 = age
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or(HttpDateError::BadAge)?;
        if age > 0 {
            return Err(HttpDateError::StaleCache(age));
        }
    }
    let date = headers.get(DATE).ok_or(HttpDateError::MissingDate)?;
    let date = date.to_str().map_err(|_| HttpDateError::BadDate)?;
    let date = httpdate::parse_http_date(date).map_err(|_| HttpDateError::BadDate)?;

    // The server stamped Date somewhere in the round trip; assume the midpoint.
    // Date is truncated to whole seconds, so true server time is in [date, date+1).
    let local_mid = sent_at + rtt / 2;
    let server_est = date + Duration::from_millis(500);
    Ok(Skew {
        offset_secs: signed_secs(server_est, local_mid),
        uncertainty_secs: 0.5 + rtt.as_secs_f64() / 2.0,
        source: Source::HttpDate {
            url: url.to_string(),
        },
    })
}

fn signed_secs(a: SystemTime, b: SystemTime) -> f64 {
    let since = |t: SystemTime| match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs_f64(),
        Err(e) => -e.duration().as_secs_f64(),
    };
    since(a) - since(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SigningKey;
    use reqwest::header::HeaderValue;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn skew(offset: f64, unc: f64) -> Skew {
        Skew {
            offset_secs: offset,
            uncertainty_secs: unc,
            source: Source::Ntp { server: "t".into() },
        }
    }

    #[test]
    fn severity_thresholds_are_strictly_greater_than() {
        assert_eq!(skew(0.0, 0.0).severity(), Severity::Ok);
        assert_eq!(skew(1.0, 0.0).severity(), Severity::Ok);
        assert_eq!(skew(-1.0, 0.0).severity(), Severity::Ok);
        assert_eq!(skew(1.01, 0.0).severity(), Severity::Warn);
        assert_eq!(skew(-10.0, 0.0).severity(), Severity::Warn);
        assert_eq!(skew(10.01, 0.0).severity(), Severity::High);
        assert_eq!(skew(-3600.0, 0.0).severity(), Severity::High);
    }

    #[test]
    fn signer_offset_rounds_toward_the_past() {
        assert_eq!(skew(3.0, 0.025).signer_offset_secs(), 2); // 2.975 -> 2, never 3
        assert_eq!(skew(3.4, 0.0).signer_offset_secs(), 3);
        assert_eq!(skew(0.0, 0.0).signer_offset_secs(), 0);
        assert_eq!(skew(-0.3, 0.0).signer_offset_secs(), -1);
        assert_eq!(skew(-7.2, 0.1).signer_offset_secs(), -8);
    }

    fn headers(date: Option<&str>, age: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(d) = date {
            h.insert(DATE, HeaderValue::from_str(d).unwrap());
        }
        if let Some(a) = age {
            h.insert(AGE, HeaderValue::from_str(a).unwrap());
        }
        h
    }

    // Sun, 06 Nov 1994 08:49:37 GMT == 784111777
    const DATE_784111777: &str = "Sun, 06 Nov 1994 08:49:37 GMT";

    #[test]
    fn http_date_offset_with_rtt_compensation() {
        // Local sent at T=784111770 with a 2s RTT -> local midpoint 784111771.
        // Server est = 784111777.5 -> offset +6.5, uncertainty 0.5 + 1.0.
        let sent = UNIX_EPOCH + Duration::from_secs(784_111_770);
        let s = skew_from_http_headers(
            &headers(Some(DATE_784111777), None),
            sent,
            Duration::from_secs(2),
            "u",
        )
        .unwrap();
        assert!((s.offset_secs - 6.5).abs() < 1e-9, "{}", s.offset_secs);
        assert!((s.uncertainty_secs - 1.5).abs() < 1e-9);
        assert_eq!(s.signer_offset_secs(), 5); // floor(6.5 - 1.5) = 5, strictly safe
        assert_eq!(s.severity(), Severity::Warn);
    }

    #[test]
    fn http_date_detects_local_clock_ahead() {
        let sent = UNIX_EPOCH + Duration::from_secs(784_111_800);
        let s = skew_from_http_headers(
            &headers(Some(DATE_784111777), None),
            sent,
            Duration::ZERO,
            "u",
        )
        .unwrap();
        assert!((s.offset_secs + 22.5).abs() < 1e-9);
        assert_eq!(s.severity(), Severity::High);
    }

    #[test]
    fn stale_cache_is_rejected_but_age_zero_is_fine() {
        let sent = UNIX_EPOCH + Duration::from_secs(784_111_777);
        let f = |age| {
            skew_from_http_headers(
                &headers(Some(DATE_784111777), age),
                sent,
                Duration::ZERO,
                "u",
            )
        };
        assert!(matches!(f(Some("30")), Err(HttpDateError::StaleCache(30))));
        assert!(matches!(f(Some("junk")), Err(HttpDateError::BadAge)));
        assert!(f(Some("0")).is_ok());
        assert!(f(None).is_ok());
    }

    #[test]
    fn missing_or_garbled_date_is_rejected() {
        let sent = SystemTime::now();
        assert!(matches!(
            skew_from_http_headers(&headers(None, None), sent, Duration::ZERO, "u"),
            Err(HttpDateError::MissingDate)
        ));
        assert!(matches!(
            skew_from_http_headers(&headers(Some("yesterday"), None), sent, Duration::ZERO, "u"),
            Err(HttpDateError::BadDate)
        ));
    }

    #[test]
    fn calibrate_shifts_signed_iat() {
        use crate::crypto::Purpose;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let signer = AssertionSigner::new(
            SigningKey::generate().unwrap(),
            "https://i.example",
            "aud",
            "org",
        )
        .unwrap();
        let signer = calibrate(signer, &skew(10.0, 0.0));
        let jwt = signer.sign("u", Purpose::Launch).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwt.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let iat = claims["iat"].as_u64().unwrap();
        assert!(
            (now + 9..=now + 11).contains(&iat),
            "iat {iat} vs now {now}"
        );
    }

    /// One-shot local HTTP server answering with the given raw header lines.
    async fn serve_once(extra_headers: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
        format!("http://{addr}/")
    }

    fn no_ntp(url: String) -> Options {
        Options {
            ntp_servers: vec![],
            ..Options::new(url)
        }
    }

    #[tokio::test]
    async fn measure_uses_http_date_when_ntp_is_unavailable() {
        let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(7));
        let url = serve_once(format!("Date: {date}\r\n")).await;
        let s = measure(&no_ntp(url)).await.unwrap();
        assert!(matches!(s.source, Source::HttpDate { .. }));
        assert!((6.0..8.5).contains(&s.offset_secs), "{}", s.offset_secs);
        assert!((5..=7).contains(&s.signer_offset_secs()));
    }

    #[tokio::test]
    async fn measure_falls_back_after_ntp_failure() {
        let date = httpdate::fmt_http_date(SystemTime::now());
        let url = serve_once(format!("Date: {date}\r\n")).await;
        let opts = Options {
            ntp_servers: vec!["127.0.0.1:9".into()],
            ntp_timeout: Duration::from_millis(300),
            ..Options::new(url)
        };
        let s = measure(&opts).await.unwrap();
        assert!(matches!(s.source, Source::HttpDate { .. }));
    }

    #[tokio::test]
    async fn measure_rejects_cdn_cached_response() {
        let date = httpdate::fmt_http_date(SystemTime::now());
        let url = serve_once(format!("Date: {date}\r\nAge: 120\r\n")).await;
        let err = measure(&no_ntp(url)).await.unwrap_err();
        assert!(matches!(
            err.http_error,
            Some(HttpDateError::StaleCache(120))
        ));
    }

    #[tokio::test]
    async fn measure_reports_when_nothing_works() {
        let opts = Options {
            http_url: None,
            ..no_ntp(String::new())
        };
        let err = measure(&opts).await.unwrap_err();
        assert!(err.http_error.is_none() && err.ntp_errors.is_empty());
    }
}
