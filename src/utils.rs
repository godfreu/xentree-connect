//! Forgiving URL input handling for the setup wizard.

use std::net::IpAddr;

use url::Url;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UrlError {
    #[error("the URL is empty")]
    Empty,
    #[error("not a valid URL: {0}")]
    Invalid(String),
    #[error("unsupported scheme {0:?}; use http or https")]
    UnsupportedScheme(String),
}

/// Turns what a person types into a canonical URL: surrounding whitespace and
/// trailing slashes are dropped, and a missing scheme is filled in.
///
/// Local hosts (`localhost`, loopback and private IPs) get `http://`; any
/// other bare host gets `https://` when `default_https` is set, `http://`
/// otherwise. An explicit scheme is always kept.
pub fn normalize_url(input: &str, default_https: bool) -> Result<String, UrlError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(UrlError::Empty);
    }
    let with_scheme = if input.contains("://") {
        input.to_string()
    } else {
        let scheme = if is_local_host(bare_host(input)) || !default_https {
            "http"
        } else {
            "https"
        };
        format!("{scheme}://{input}")
    };
    let url = Url::parse(with_scheme.trim_end_matches('/'))
        .map_err(|e| UrlError::Invalid(e.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(UrlError::UnsupportedScheme(url.scheme().to_string()));
    }
    if url.host().is_none() {
        return Err(UrlError::Invalid("missing host".into()));
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

/// Whether two URLs point at the same scheme, host and port.
pub fn same_origin(a: &str, b: &str) -> bool {
    match (Url::parse(a), Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host() == b.host()
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// The host of a scheme-less `host[:port][/path]`, without port or brackets.
fn bare_host(input: &str) -> &str {
    let authority = input.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    }
}

fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(IpAddr::V6(ip)) => ip.is_loopback(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> String {
        normalize_url(s, true).unwrap()
    }

    #[test]
    fn bare_domains_get_https() {
        assert_eq!(n("my.xentree.ai"), "https://my.xentree.ai");
        assert_eq!(n("learn.traders.id"), "https://learn.traders.id");
        assert_eq!(n("  demo.wiseree.com  "), "https://demo.wiseree.com");
        assert_eq!(n("example.com:8443/lms"), "https://example.com:8443/lms");
    }

    #[test]
    fn explicit_schemes_are_kept() {
        assert_eq!(n("https://learn.traders.id"), "https://learn.traders.id");
        assert_eq!(n("http://example.com"), "http://example.com");
    }

    #[test]
    fn trailing_slashes_are_stripped() {
        assert_eq!(n("https://learn.traders.id/"), "https://learn.traders.id");
        assert_eq!(n("learn.traders.id///"), "https://learn.traders.id");
        assert_eq!(n("https://a.com/lms/"), "https://a.com/lms");
    }

    #[test]
    fn local_hosts_get_http() {
        assert_eq!(n("localhost"), "http://localhost");
        assert_eq!(n("LOCALHOST:8000/"), "http://localhost:8000");
        assert_eq!(n("127.0.0.1:3000"), "http://127.0.0.1:3000");
        assert_eq!(n("192.168.1.20"), "http://192.168.1.20");
        assert_eq!(n("10.0.0.5:8080"), "http://10.0.0.5:8080");
        assert_eq!(n("[::1]:9000"), "http://[::1]:9000");
        assert_eq!(n("https://localhost"), "https://localhost");
    }

    #[test]
    fn public_ips_are_not_local() {
        assert_eq!(n("8.8.8.8"), "https://8.8.8.8");
    }

    #[test]
    fn default_https_false_uses_http_for_bare_hosts() {
        assert_eq!(
            normalize_url("example.com", false).unwrap(),
            "http://example.com"
        );
    }

    #[test]
    fn invalid_input_is_rejected() {
        assert_eq!(normalize_url("   ", true), Err(UrlError::Empty));
        assert!(matches!(
            normalize_url("not a url", true),
            Err(UrlError::Invalid(_))
        ));
        assert!(matches!(
            normalize_url("ftp://example.com", true),
            Err(UrlError::UnsupportedScheme(_))
        ));
        assert!(normalize_url("https://", true).is_err());
    }

    #[test]
    fn same_origin_ignores_default_ports_and_case() {
        assert!(same_origin(
            "https://My.Xentree.ai",
            "https://my.xentree.ai:443"
        ));
        assert!(!same_origin("https://a.com", "http://a.com"));
        assert!(!same_origin("https://a.com", "https://b.com"));
    }
}
