use axum::http::{header::AUTHORIZATION, HeaderMap, HeaderName};
use ring::digest;
use subtle::ConstantTimeEq;

/// Who is calling a gateway endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// Presented the gateway secret: a trusted backend that names the user.
    Service,
    /// A trusted reverse proxy vouched for this identity (opt-in).
    Proxy(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unauthorized;

/// SHA-256 of the secret. Comparing digests keeps the comparison constant
/// time regardless of the candidate's length.
pub fn digest_secret(secret: &str) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, secret.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn secret_matches(expected: &[u8; 32], candidate: &str) -> bool {
    bool::from(expected.ct_eq(&digest_secret(candidate)))
}

/// `Authorization: Bearer <token>`; the scheme is case-insensitive.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

pub struct AuthConfig<'a> {
    pub secret_digest: &'a [u8; 32],
    pub trusted_headers: &'a [HeaderName],
    pub allow_query_secret: bool,
}

/// Order of precedence: bearer header, trusted proxy header, query/form
/// secret. A *presented but wrong* credential is rejected outright rather than
/// falling through to a weaker method.
pub fn authenticate(
    cfg: &AuthConfig<'_>,
    headers: &HeaderMap,
    query_secret: Option<&str>,
) -> Result<Caller, Unauthorized> {
    if headers.contains_key(AUTHORIZATION) {
        return match bearer_token(headers) {
            Some(t) if secret_matches(cfg.secret_digest, t) => Ok(Caller::Service),
            _ => Err(Unauthorized),
        };
    }
    for name in cfg.trusted_headers {
        if let Some(v) = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            return Ok(Caller::Proxy(v.to_string()));
        }
    }
    match query_secret {
        Some(s) if cfg.allow_query_secret && secret_matches(cfg.secret_digest, s) => {
            Ok(Caller::Service)
        }
        _ => Err(Unauthorized),
    }
}

/// Subjects end up in a signed claim and in logs: bound and sanitize them.
pub fn valid_subject(s: &str) -> bool {
    !s.is_empty() && s.chars().count() <= 256 && !s.chars().any(char::is_control) && s.trim() == s
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn cfg<'a>(d: &'a [u8; 32], th: &'a [HeaderName], q: bool) -> AuthConfig<'a> {
        AuthConfig {
            secret_digest: d,
            trusted_headers: th,
            allow_query_secret: q,
        }
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_static(k),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn bearer_scheme_is_case_insensitive_and_strict() {
        let d = digest_secret(SECRET);
        for ok in [
            format!("Bearer {SECRET}"),
            format!("bearer {SECRET}"),
            format!("BEARER {SECRET}"),
        ] {
            assert_eq!(
                authenticate(
                    &cfg(&d, &[], false),
                    &headers(&[("authorization", &ok)]),
                    None
                ),
                Ok(Caller::Service)
            );
        }
        for bad in [
            SECRET.to_string(),
            format!("Basic {SECRET}"),
            "Bearer ".into(),
            "Bearer wrong".into(),
            format!("Bearer {SECRET}x"),
        ] {
            assert_eq!(
                authenticate(
                    &cfg(&d, &[], false),
                    &headers(&[("authorization", &bad)]),
                    None
                ),
                Err(Unauthorized),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_wrong_bearer_never_falls_through_to_a_proxy_header() {
        let d = digest_secret(SECRET);
        let th = [HeaderName::from_static("x-remote-user")];
        let h = headers(&[
            ("authorization", "Bearer wrong"),
            ("x-remote-user", "alice"),
        ]);
        assert_eq!(
            authenticate(&cfg(&d, &th, false), &h, None),
            Err(Unauthorized)
        );
    }

    #[test]
    fn proxy_headers_are_only_trusted_when_configured() {
        let d = digest_secret(SECRET);
        let h = headers(&[("x-remote-user", "alice")]);
        assert_eq!(
            authenticate(&cfg(&d, &[], false), &h, None),
            Err(Unauthorized)
        );
        let th = [HeaderName::from_static("x-remote-user")];
        assert_eq!(
            authenticate(&cfg(&d, &th, false), &h, None),
            Ok(Caller::Proxy("alice".into()))
        );
        // blank header values don't count as an identity
        assert_eq!(
            authenticate(
                &cfg(&d, &th, false),
                &headers(&[("x-remote-user", "  ")]),
                None
            ),
            Err(Unauthorized)
        );
    }

    #[test]
    fn query_secret_requires_opt_in() {
        let d = digest_secret(SECRET);
        let h = HeaderMap::new();
        assert_eq!(
            authenticate(&cfg(&d, &[], false), &h, Some(SECRET)),
            Err(Unauthorized)
        );
        assert_eq!(
            authenticate(&cfg(&d, &[], true), &h, Some(SECRET)),
            Ok(Caller::Service)
        );
        assert_eq!(
            authenticate(&cfg(&d, &[], true), &h, Some("nope")),
            Err(Unauthorized)
        );
        assert_eq!(
            authenticate(&cfg(&d, &[], true), &h, None),
            Err(Unauthorized)
        );
    }

    #[test]
    fn subject_validation() {
        assert!(valid_subject("emp-42"));
        assert!(valid_subject("a/b c@d.example"));
        for bad in ["", " lead", "trail ", "a\nb", "a\0b"] {
            assert!(!valid_subject(bad), "{bad:?}");
        }
        assert!(valid_subject(&"x".repeat(256)));
        assert!(!valid_subject(&"x".repeat(257)));
    }
}
