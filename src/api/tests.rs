use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use wiremock::{
    matchers::{body_json, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::*;

const TOKEN: &str = "adm_tok_123";

fn client(server: &MockServer) -> XentreeAdminClient {
    XentreeAdminClient::with_base_url(&server.uri(), SecretString::from(TOKEN)).unwrap()
}

fn base_err(url: &str) -> String {
    match XentreeAdminClient::with_base_url(url, SecretString::from(TOKEN)) {
        Err(ApiError::InvalidInput(m)) => m,
        other => panic!("expected InvalidInput for {url}, got {other:?}"),
    }
}

// --- request shape -------------------------------------------------------

#[tokio::test]
async fn sends_bearer_token_and_user_agent() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/admin/organizations"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(header(
            "user-agent",
            concat!("xentree-connect-cli/", env!("CARGO_PKG_VERSION")),
        ))
        .and(header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&s)
        .await;
    assert!(client(&s).list_organizations().await.unwrap().is_empty());
}

#[tokio::test]
async fn trailing_slashes_in_base_url_are_normalized() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/admin/organizations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(3)
        .mount(&s)
        .await;
    for suffix in ["/", "//", "///?x=1#frag"] {
        let c = XentreeAdminClient::with_base_url(
            &format!("{}{suffix}", s.uri()),
            SecretString::from(TOKEN),
        )
        .unwrap();
        c.list_organizations().await.unwrap();
    }
}

#[tokio::test]
async fn base_path_prefix_is_preserved() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/xentree/api/admin/organizations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&s)
        .await;
    let c = XentreeAdminClient::with_base_url(
        &format!("{}/xentree//", s.uri()),
        SecretString::from(TOKEN),
    )
    .unwrap();
    c.list_organizations().await.unwrap();
}

#[test]
fn base_url_normalization_is_pure() {
    let n = |u: &str| {
        XentreeAdminClient::with_base_url(u, SecretString::from(TOKEN))
            .unwrap()
            .base_url()
            .to_string()
    };
    assert_eq!(n("https://my.xentree.ai"), "https://my.xentree.ai/");
    assert_eq!(n("https://my.xentree.ai/"), "https://my.xentree.ai/");
    assert_eq!(
        n("https://connect.corp.example///a//b/?q=1#f"),
        "https://connect.corp.example/a/b"
    );
    assert_eq!(n("  https://x.example  "), "https://x.example/");
}

#[test]
fn default_base_url_is_the_cloud() {
    let c = XentreeAdminClient::new(SecretString::from(TOKEN)).unwrap();
    assert_eq!(c.base_url().as_str(), "https://my.xentree.ai/");
}

#[test]
fn rejects_unsafe_base_urls() {
    assert!(base_err("http://my.xentree.ai").contains("https"));
    assert!(base_err("ftp://my.xentree.ai").contains("https"));
    assert!(base_err("https://user:pw@my.xentree.ai").contains("credentials"));
    assert!(base_err("not a url").starts_with("base URL"));
    assert!(base_err("mailto:a@b.c").contains("absolute"));
    // loopback http is fine for local development and tests
    for ok in [
        "http://localhost:8080",
        "http://127.0.0.1:9",
        "http://[::1]:9",
    ] {
        assert!(
            XentreeAdminClient::with_base_url(ok, SecretString::from(TOKEN)).is_ok(),
            "{ok}"
        );
    }
}

#[test]
fn rejects_bad_tokens() {
    for t in ["", "   ", "abc\ndef", "ab\u{0}c"] {
        let r = XentreeAdminClient::new(SecretString::from(t));
        assert!(matches!(r, Err(ApiError::InvalidInput(_))), "{t:?}");
    }
}

#[test]
fn debug_output_hides_the_token() {
    let c = XentreeAdminClient::new(SecretString::from(TOKEN)).unwrap();
    assert!(!format!("{c:?}").contains(TOKEN));
}

#[tokio::test]
async fn path_segments_are_encoded_not_interpreted() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/admin/organizations/a%2Fb%3Fc/connect-clients"))
        .respond_with(
            ResponseTemplate::new(201).set_body_json(json!({"id": "rec_1", "client_id": "c"})),
        )
        .expect(1)
        .mount(&s)
        .await;
    client(&s)
        .create_connect_client("a/b?c", &sample_request())
        .await
        .unwrap();

    for bad in ["..", ".", ""] {
        let r = client(&s)
            .create_connect_client(bad, &sample_request())
            .await;
        assert!(matches!(r, Err(ApiError::InvalidInput(_))), "{bad:?}");
    }
}

// --- endpoints -----------------------------------------------------------

#[tokio::test]
async fn lists_organizations() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/admin/organizations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id": "org_1", "name": "Acme", "role": "admin", "extra": true},
            {"id": "org_2", "name": "Globex"}
        ])))
        .mount(&s)
        .await;
    let orgs = client(&s).list_organizations().await.unwrap();
    assert_eq!(
        orgs,
        vec![
            OrganizationItem {
                id: "org_1".into(),
                name: "Acme".into(),
                role: Some("admin".into())
            },
            OrganizationItem {
                id: "org_2".into(),
                name: "Globex".into(),
                role: None
            },
        ]
    );
}

fn sample_request() -> CreateConnectClientRequest {
    CreateConnectClientRequest::new(
        "Moodle",
        "moodle-prod",
        "https://lms.example.com",
        "xentree",
        r#"{"keys":[]}"#,
    )
}

#[tokio::test]
async fn creates_connect_client_with_exact_payload() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/admin/organizations/org_1/connect-clients"))
        .and(header("content-type", "application/json"))
        // Optional fields are omitted when None; auto_enroll is always sent.
        .and(body_json(json!({
            "name": "Moodle",
            "client_id": "moodle-prod",
            "issuer": "https://lms.example.com",
            "audience": "xentree",
            "jwks_json": r#"{"keys":[]}"#,
            "auto_enroll": false
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "rec_9", "client_id": "moodle-prod", "name": "Moodle",
            "issuer": "https://lms.example.com", "audience": "xentree",
            "auto_enroll": false, "created_at": "2026-01-01T00:00:00Z"
        })))
        .expect(1)
        .mount(&s)
        .await;
    let r = client(&s)
        .create_connect_client("org_1", &sample_request())
        .await
        .unwrap();
    assert_eq!(r.id, "rec_9");
    assert_eq!(r.client_id, "moodle-prod");
    assert_eq!(r.auto_enroll, Some(false));
}

#[tokio::test]
async fn optional_create_fields_are_sent_when_set() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_json(json!({
            "name": "Moodle", "client_id": "moodle-prod", "issuer": "https://lms.example.com",
            "audience": "xentree", "jwks_json": r#"{"keys":[]}"#, "auto_enroll": true,
            "default_team_id": "team_1", "policy_url": "https://lms.example.com/policy"
        })))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"id": "r", "client_id": "moodle-prod"})),
        )
        .expect(1)
        .mount(&s)
        .await;
    let mut req = sample_request();
    req.auto_enroll = true;
    req.default_team_id = Some("team_1".into());
    req.policy_url = Some("https://lms.example.com/policy".into());
    client(&s)
        .create_connect_client("org_1", &req)
        .await
        .unwrap();
}

#[tokio::test]
async fn create_validates_locally_without_a_request() {
    let s = MockServer::start().await; // no mocks: any request would 404
    let c = client(&s);
    let mut r = sample_request();
    r.client_id = "x".repeat(129);
    assert!(matches!(
        c.create_connect_client("o", &r).await,
        Err(ApiError::InvalidInput(_))
    ));
    let mut r = sample_request();
    r.name = String::new();
    assert!(matches!(
        c.create_connect_client("o", &r).await,
        Err(ApiError::InvalidInput(_))
    ));
    let mut r = sample_request();
    r.issuer = "https://lms.example.com/".into();
    assert!(matches!(
        c.create_connect_client("o", &r).await,
        Err(ApiError::InvalidInput(_))
    ));
    assert!(s.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn rotates_jwks() {
    let s = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/admin/organizations/org_1/connect-clients/rec_9"))
        .and(body_json(json!({"jwks_json": r#"{"keys":[{"kid":"a"}]}"#})))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&s)
        .await;
    client(&s)
        .rotate_jwks("org_1", "rec_9", r#"{"keys":[{"kid":"a"}]}"#)
        .await
        .unwrap();
    assert!(matches!(
        client(&s).rotate_jwks("org_1", "rec_9", "").await,
        Err(ApiError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn creates_webhook_and_captures_secret() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/api/admin/organizations/org_1/connect-clients/rec_9/webhooks",
        ))
        .and(body_json(json!({
            "url": "https://gw.example.com/webhook",
            "events": ["erpi.session.completed", "connect.consent.revoked"]
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": "wh_1", "url": "https://gw.example.com/webhook", "signing_secret": "whsec_abc123"
        })))
        .expect(1)
        .mount(&s)
        .await;
    let req = CreateWebhookRequest {
        url: "https://gw.example.com/webhook".into(),
        events: vec![EVENT_SESSION_COMPLETED.into(), EVENT_CONSENT_REVOKED.into()],
    };
    let r = client(&s)
        .create_webhook("org_1", "rec_9", &req)
        .await
        .unwrap();
    assert_eq!(r.id, "wh_1");
    assert_eq!(r.signing_secret.expose_secret(), "whsec_abc123");
    assert!(
        !format!("{r:?}").contains("whsec_abc123"),
        "secret must be redacted in Debug"
    );
}

#[tokio::test]
async fn webhook_decode_failure_never_echoes_the_secret_and_warns() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(json!({"id": 7, "signing_secret": "whsec_leakme"})),
        )
        .mount(&s)
        .await;
    let req = CreateWebhookRequest {
        url: "https://gw.example.com/w".into(),
        events: vec!["e".into()],
    };
    let err = client(&s).create_webhook("o", "r", &req).await.unwrap_err();
    assert!(matches!(err, ApiError::Decode(_)));
    let msg = err.to_string();
    assert!(!msg.contains("whsec_leakme"));
    assert!(msg.contains("rotate"));
}

#[tokio::test]
async fn webhook_input_is_validated_locally() {
    let s = MockServer::start().await;
    let c = client(&s);
    let ok = CreateWebhookRequest {
        url: "https://x.example/w".into(),
        events: vec!["e".into()],
    };
    let no_events = CreateWebhookRequest {
        events: vec![],
        ..ok.clone()
    };
    let bad_url = CreateWebhookRequest {
        url: "javascript:alert(1)".into(),
        ..ok.clone()
    };
    assert!(matches!(
        c.create_webhook("o", "r", &no_events).await,
        Err(ApiError::InvalidInput(_))
    ));
    assert!(matches!(
        c.create_webhook("o", "r", &bad_url).await,
        Err(ApiError::InvalidInput(_))
    ));
    assert!(s.received_requests().await.unwrap().is_empty());
}

// --- error mapping -------------------------------------------------------

async fn status_error(status: u16, body: serde_json::Value) -> ApiError {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&s)
        .await;
    client(&s).list_organizations().await.unwrap_err()
}

#[tokio::test]
async fn maps_401_to_unauthorized() {
    assert!(matches!(
        status_error(401, json!({"detail": "Invalid token"})).await,
        ApiError::Unauthorized
    ));
}

#[tokio::test]
async fn maps_403_to_forbidden_with_detail() {
    match status_error(
        403,
        json!({"detail": "Connect is not enabled for this plan"}),
    )
    .await
    {
        ApiError::Forbidden(m) => assert_eq!(m, "Connect is not enabled for this plan"),
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn maps_404_to_not_found() {
    match status_error(404, json!({"detail": "Organization not found"})).await {
        ApiError::NotFound(m) => assert_eq!(m, "Organization not found"),
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn maps_409_to_conflict_via_error_field() {
    match status_error(409, json!({"error": "client_id already exists"})).await {
        ApiError::Conflict(m) => assert_eq!(m, "client_id already exists"),
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn maps_5xx_to_server() {
    match status_error(503, json!({"detail": "upstream unavailable"})).await {
        ApiError::Server(503, m) => assert_eq!(m, "upstream unavailable"),
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn maps_429_with_retry_after() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "7"))
        .mount(&s)
        .await;
    match client(&s).list_organizations().await.unwrap_err() {
        ApiError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(Duration::from_secs(7)))
        }
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn maps_429_without_usable_retry_after() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "soon"))
        .mount(&s)
        .await;
    assert!(matches!(
        client(&s).list_organizations().await,
        Err(ApiError::RateLimited { retry_after: None })
    ));
}

#[tokio::test]
async fn other_statuses_are_unexpected_and_redirects_are_not_followed() {
    assert!(matches!(
        status_error(422, json!({"detail": "bad"})).await,
        ApiError::Unexpected(422, _)
    ));
    let s = MockServer::start().await;
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/steal", target.uri()).as_str()),
        )
        .mount(&s)
        .await;
    assert!(matches!(
        client(&s).list_organizations().await,
        Err(ApiError::Unexpected(302, _))
    ));
    assert!(
        target.received_requests().await.unwrap().is_empty(),
        "bearer token must not follow redirects"
    );
}

#[tokio::test]
async fn transport_error_when_server_is_unreachable() {
    let c =
        XentreeAdminClient::with_base_url("http://127.0.0.1:1", SecretString::from(TOKEN)).unwrap();
    assert!(matches!(
        c.list_organizations().await,
        Err(ApiError::Transport(_))
    ));
}

#[tokio::test]
async fn malformed_success_body_is_a_decode_error() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
        .mount(&s)
        .await;
    assert!(matches!(
        client(&s).list_organizations().await,
        Err(ApiError::Decode(_))
    ));
}

// --- error parsing (pure) ------------------------------------------------

#[test]
fn detail_extraction_handles_validation_lists_and_plain_text() {
    let e = |status, body: &str| ApiError::from_response(status, None, body.as_bytes()).to_string();
    // FastAPI-style validation errors
    assert!(e(422, r#"{"detail":[{"loc":["body","client_id"],"msg":"too long","type":"x"},{"msg":"bad issuer"}]}"#)
        .contains("body.client_id: too long; bad issuer"));
    // `detail` wins over `error`
    assert!(e(403, r#"{"detail":"a","error":"b"}"#).ends_with(": a"));
    // non-JSON and empty bodies
    assert!(e(500, "Bad Gateway").ends_with("Bad Gateway"));
    assert!(e(500, "").ends_with("HTTP 500"));
    // long bodies are truncated on a char boundary
    let long = "é".repeat(1000);
    assert!(e(500, &long).chars().count() < 400);
}

#[test]
fn retry_after_accepts_http_dates() {
    let in_30s = httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(30));
    match ApiError::from_response(429, Some(&in_30s), b"") {
        ApiError::RateLimited {
            retry_after: Some(d),
        } => assert!((28..=30).contains(&d.as_secs())),
        e => panic!("{e:?}"),
    }
    let past = httpdate::fmt_http_date(std::time::SystemTime::now() - Duration::from_secs(30));
    assert!(matches!(
        ApiError::from_response(429, Some(&past), b""),
        ApiError::RateLimited {
            retry_after: Some(Duration::ZERO)
        }
    ));
}
