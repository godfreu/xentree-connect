//! Email and password login against `POST /api/auth/token`.

use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::AuthError;
use crate::api::{endpoint_url, normalize_base_url, ApiError};

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// `{base_url}/api/auth/token`, always on the caller's own base URL.
fn token_url(base_url: &str) -> Result<url::Url, ApiError> {
    endpoint_url(&normalize_base_url(base_url)?, &["api", "auth", "token"])
}

/// Exchanges credentials for an access token. Never follows redirects, so the
/// password cannot be forwarded to another host.
pub async fn login_with_password(
    base_url: &str,
    email: &str,
    password: &SecretString,
) -> Result<SecretString, AuthError> {
    let url = token_url(base_url)?;
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("xentree-connect-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(ApiError::from)?;

    let body = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("username", email)
            .append_pair("password", password.expose_secret())
            .finish(),
    );
    let resp = http
        .post(url)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .body(body.as_str().to_owned())
        .send()
        .await
        .map_err(ApiError::from)?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(ApiError::from)?;
    if matches!(status.as_u16(), 400 | 401) {
        return Err(AuthError::InvalidCredentials);
    }
    if !status.is_success() {
        return Err(ApiError::from_response(status.as_u16(), None, &bytes).into());
    }
    // Not echoing the serde error: the body holds the token.
    let parsed: TokenResponse = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::Decode("login response did not contain an access_token".into()))?;
    if parsed.access_token.trim().is_empty() {
        return Err(ApiError::Decode("login response had an empty access_token".into()).into());
    }
    Ok(SecretString::from(parsed.access_token))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        matchers::{body_string_contains, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::from(s)
    }

    #[test]
    fn token_url_keeps_the_developers_base_url() {
        for (base, want) in [
            (
                "http://localhost:8000",
                "http://localhost:8000/api/auth/token",
            ),
            (
                "http://127.0.0.1:8000/",
                "http://127.0.0.1:8000/api/auth/token",
            ),
            (
                "https://learn.wiseree.com",
                "https://learn.wiseree.com/api/auth/token",
            ),
            (
                "https://stg.example.com/xt/",
                "https://stg.example.com/xt/api/auth/token",
            ),
        ] {
            assert_eq!(token_url(base).unwrap().as_str(), want, "{base}");
        }
    }

    #[tokio::test]
    async fn posts_a_form_and_returns_the_access_token() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/token"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string_contains("username=a%40b.co"))
            .and(body_string_contains("password=p%26ss+w%3Dd"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"access_token": "tok_1", "token_type": "bearer"})),
            )
            .mount(&s)
            .await;
        let t = login_with_password(&s.uri(), "a@b.co", &pw("p&ss w=d"))
            .await
            .unwrap();
        assert_eq!(t.expose_secret(), "tok_1");
    }

    #[tokio::test]
    async fn rejected_credentials_are_reported_distinctly() {
        for status in [400, 401] {
            let s = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(json!({"detail": "nope"})),
                )
                .mount(&s)
                .await;
            let err = login_with_password(&s.uri(), "a@b.co", &pw("x"))
                .await
                .unwrap_err();
            assert!(matches!(err, AuthError::InvalidCredentials), "{status}");
        }
    }

    #[tokio::test]
    async fn other_failures_and_bad_bodies_are_errors() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&s)
            .await;
        let err = login_with_password(&s.uri(), "a@b.co", &pw("x"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Api(ApiError::Server(503, _))));

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"access_token": " "})))
            .mount(&s)
            .await;
        let err = login_with_password(&s.uri(), "a@b.co", &pw("x"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Api(ApiError::Decode(_))));
    }

    #[tokio::test]
    async fn plain_http_to_a_public_host_is_refused_before_sending() {
        let err = login_with_password("http://example.com", "a@b.co", &pw("x"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Api(ApiError::InvalidInput(_))));
    }
}
