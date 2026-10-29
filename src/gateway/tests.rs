use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{
    hmac,
    signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED},
};
use secrecy::SecretString;
use serde_json::{json, Value};
use tower::ServiceExt;
use wiremock::{
    matchers::{body_string_contains, header, method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{
    internal_router, public_router,
    settings::{Settings, WebhookSecrets},
    GatewayState,
};
use crate::{
    config::{Config, OwnershipConfig},
    crypto::{Jwk, SigningKey},
};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const WH_ACTIVE: &str = "whsec_active_secret_for_tests";
const WH_PREVIOUS: &str = "whsec_previous_secret_for_tests";

#[derive(Default)]
struct Opts {
    /// (active, previous secret and its expiry)
    webhook: Option<(&'static str, Option<(&'static str, SystemTime)>)>,
    relay: bool,
    trusted: Vec<&'static str>,
    allow_query_secret: bool,
    /// Overrides the Xentree base URL (default: the mock server).
    base_url: Option<&'static str>,
}

struct Harness {
    state: Arc<GatewayState>,
    public: Router,
    internal: Router,
    jwk: Jwk,
    /// Stands in for Xentree.
    xentree: MockServer,
    /// Stands in for the upstream HRIS.
    relay: Option<MockServer>,
}

async fn harness(o: Opts) -> Harness {
    let xentree = MockServer::start().await;
    let relay = if o.relay {
        Some(MockServer::start().await)
    } else {
        None
    };
    let key = SigningKey::generate().unwrap();
    let jwk = key.jwk();
    let settings = Settings {
        config: Config {
            base_url: o.base_url.map_or_else(|| xentree.uri(), String::from),
            org_id: "org_1".into(),
            client_record_id: "rec_1".into(),
            client_id: "c1".into(),
            issuer: "https://lms.example.com".into(),
            audience: "xentree".into(),
            kid: key.kid().into(),
            key_path: "unused".into(),
            ownership: OwnershipConfig::CurrentUserOnly,
        },
        key,
        bind: "127.0.0.1:0".parse().unwrap(),
        internal_bind: "127.0.0.1:0".parse().unwrap(),
        gateway_secret: SecretString::from(SECRET),
        trusted_headers: o
            .trusted
            .iter()
            .map(|h| axum::http::HeaderName::from_static(h))
            .collect(),
        allow_query_secret: o.allow_query_secret,
        webhook: o.webhook.map(|(active, previous)| WebhookSecrets {
            active: SecretString::from(active),
            previous: previous.map(|(p, until)| (SecretString::from(p), until)),
        }),
        relay_url: relay
            .as_ref()
            .map(|r| format!("{}/hooks", r.uri()).parse().unwrap()),
    };
    let mut state = GatewayState::new(settings).unwrap();
    state.relay_backoff = Duration::from_millis(10);
    let state = Arc::new(state);
    Harness {
        public: public_router(state.clone()),
        internal: internal_router(state.clone()),
        state,
        jwk,
        xentree,
        relay,
    }
}

async fn send(router: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    (
        parts.status,
        parts.headers,
        to_bytes(body, 4 * 1024 * 1024).await.unwrap(),
    )
}

fn req(method: &str, uri: &str, headers: &[(&str, &str)], body: impl Into<Body>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(body.into()).unwrap()
}

fn bearer() -> (&'static str, String) {
    ("authorization", format!("Bearer {SECRET}"))
}

fn text(b: &Bytes) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn json_of(b: &Bytes) -> Value {
    serde_json::from_slice(b).unwrap()
}

/// Verifies a JWT against the published JWK, independently of the signer.
fn verify_jwt(jwt: &str, jwk: &Jwk) -> (Value, Value) {
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    let dec = |s: &str| URL_SAFE_NO_PAD.decode(s).unwrap();
    let mut point = vec![0x04];
    point.extend(dec(&jwk.x));
    point.extend(dec(&jwk.y));
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &dec(parts[2]),
        )
        .expect("assertion signature verifies against the registered JWK");
    (
        serde_json::from_slice(&dec(parts[0])).unwrap(),
        serde_json::from_slice(&dec(parts[1])).unwrap(),
    )
}

fn assertion_from_page(page: &str) -> String {
    let marker = r#"name="assertion" value=""#;
    let start = page.find(marker).expect("assertion field") + marker.len();
    page[start..start + page[start..].find('"').unwrap()].to_string()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn event(id: &str) -> String {
    format!(r#"{{"id":"{id}","event":"erpi.session.completed"}}"#)
}

fn signature(secret: &str, t: u64, body: &str) -> String {
    let tag = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
        format!("{t}.{body}").as_bytes(),
    );
    let hex: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("t={t},v1={hex}")
}

fn webhook_req(sig: &str, body: &str) -> Request<Body> {
    req(
        "POST",
        "/webhook",
        &[
            ("x-xentree-signature", sig),
            ("content-type", "application/json"),
        ],
        body.to_string(),
    )
}

fn with_webhook() -> Opts {
    Opts {
        webhook: Some((WH_ACTIVE, None)),
        ..Default::default()
    }
}

// === /launch ================================================================

#[tokio::test]
async fn launch_rejects_unauthenticated_requests() {
    let h = harness(Opts::default()).await;
    let (status, headers, body) = send(
        &h.public,
        req("GET", "/launch?user_id=emp-1", &[], Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers["www-authenticate"]
        .to_str()
        .unwrap()
        .starts_with("Bearer"));
    assert!(!text(&body).contains("assertion"));

    for wrong in ["Bearer nope", "Basic abc", SECRET] {
        let (status, ..) = send(
            &h.public,
            req(
                "GET",
                "/launch?user_id=emp-1",
                &[("authorization", wrong)],
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{wrong}");
    }
}

#[tokio::test]
async fn launch_returns_an_auto_submitting_form_with_a_valid_assertion() {
    let h = harness(Opts::default()).await;
    let (k, v) = bearer();
    let (status, headers, body) = send(
        &h.public,
        req("GET", "/launch?user_id=emp-42", &[(k, &v)], Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers["content-type"]
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    let page = text(&body);

    // The form posts the assertion to this client's launch endpoint.
    let action = format!(
        r#"<form method="POST" action="{}/connect/v1/launch/c1">"#,
        h.xentree.uri()
    );
    assert!(page.contains(&action), "{page}");
    assert!(page.contains(r#"<script>document.forms[0].submit();</script>"#));

    let (header, claims) = verify_jwt(&assertion_from_page(&page), &h.jwk);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], h.state.kid);
    assert_eq!(claims["iss"], "https://lms.example.com");
    assert_eq!(claims["aud"], "xentree");
    assert_eq!(claims["sub"], "emp-42");
    assert_eq!(claims["organization_id"], "org_1");
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        30
    );
    assert!(uuid_like(claims["jti"].as_str().unwrap()));
    assert!(
        claims.get("purpose").is_none(),
        "launch assertions must never carry purpose"
    );
}

fn uuid_like(s: &str) -> bool {
    s.len() == 36 && s.as_bytes()[14] == b'4'
}

#[tokio::test]
async fn launch_sets_the_required_security_headers() {
    let h = harness(Opts::default()).await;
    let (k, v) = bearer();
    let (_, headers, _) = send(
        &h.public,
        req("GET", "/launch?user_id=e", &[(k, &v)], Body::empty()),
    )
    .await;
    let get = |n: &str| headers[n].to_str().unwrap().to_string();
    assert_eq!(get("cache-control"), "no-store");
    assert_eq!(get("referrer-policy"), "no-referrer");
    assert_eq!(get("x-content-type-options"), "nosniff");
    assert_eq!(get("x-frame-options"), "DENY");
    let csp = get("content-security-policy");
    assert!(csp.starts_with("default-src 'none';"), "{csp}");
    assert!(
        csp.contains(&format!("form-action {};", h.xentree.uri())),
        "{csp}"
    );
    assert!(csp.contains("script-src 'sha256-") && !csp.contains("unsafe-inline"));
}

#[tokio::test]
async fn every_response_carries_the_hardening_headers() {
    let h = harness(Opts::default()).await;
    for (router, uri) in [
        (&h.public, "/health"),
        (&h.public, "/nope"),
        (&h.internal, "/health"),
    ] {
        let (_, headers, _) = send(router, req("GET", uri, &[], Body::empty())).await;
        assert_eq!(headers["x-content-type-options"], "nosniff", "{uri}");
        assert_eq!(headers["x-frame-options"], "DENY", "{uri}");
        assert_eq!(headers["cache-control"], "no-store", "{uri}");
    }
}

#[tokio::test]
async fn launch_requires_a_valid_user_id() {
    let h = harness(Opts::default()).await;
    let (k, v) = bearer();
    for uri in [
        "/launch",
        "/launch?user_id=",
        "/launch?user_id=%0A",
        "/launch?user_id=%20lead",
    ] {
        let (status, ..) = send(&h.public, req("GET", uri, &[(k, &v)], Body::empty())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
    let long = format!("/launch?user_id={}", "x".repeat(257));
    assert_eq!(
        send(&h.public, req("GET", &long, &[(k, &v)], Body::empty()))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn launch_post_accepts_a_form_body() {
    let h = harness(Opts::default()).await;
    let (k, v) = bearer();
    let r = req(
        "POST",
        "/launch",
        &[
            (k, &v),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        "user_id=emp-7",
    );
    let (status, _, body) = send(&h.public, r).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        verify_jwt(&assertion_from_page(&text(&body)), &h.jwk).1["sub"],
        "emp-7"
    );

    let big = format!("user_id={}", "x".repeat(20 * 1024));
    let r = req(
        "POST",
        "/launch",
        &[
            (k, &v),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        big,
    );
    assert_eq!(send(&h.public, r).await.0, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn the_secret_in_a_url_is_refused_unless_explicitly_enabled() {
    let uri = format!("/launch?user_id=emp-1&secret={SECRET}");
    let off = harness(Opts::default()).await;
    assert_eq!(
        send(&off.public, req("GET", &uri, &[], Body::empty()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let on = harness(Opts {
        allow_query_secret: true,
        ..Default::default()
    })
    .await;
    assert_eq!(
        send(&on.public, req("GET", &uri, &[], Body::empty()))
            .await
            .0,
        StatusCode::OK
    );
    let wrong = "/launch?user_id=emp-1&secret=wrong";
    assert_eq!(
        send(&on.public, req("GET", wrong, &[], Body::empty()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn proxy_identity_headers_are_ignored_unless_configured() {
    let h = harness(Opts::default()).await;
    let (status, ..) = send(
        &h.public,
        req(
            "GET",
            "/launch",
            &[("x-remote-user", "alice")],
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an unconfigured header must not authenticate anyone"
    );
}

#[tokio::test]
async fn a_proxy_authenticated_user_can_only_launch_as_themselves() {
    let h = harness(Opts {
        trusted: vec!["x-remote-user"],
        ..Default::default()
    })
    .await;
    let who = [("x-remote-user", "alice")];

    let (status, _, body) = send(&h.public, req("GET", "/launch", &who, Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        verify_jwt(&assertion_from_page(&text(&body)), &h.jwk).1["sub"],
        "alice"
    );

    let same = send(
        &h.public,
        req("GET", "/launch?user_id=alice", &who, Body::empty()),
    )
    .await;
    assert_eq!(same.0, StatusCode::OK);

    let other = send(
        &h.public,
        req("GET", "/launch?user_id=bob", &who, Body::empty()),
    )
    .await;
    assert_eq!(other.0, StatusCode::FORBIDDEN, "impersonation via user_id");
}

#[tokio::test]
async fn a_wrong_bearer_is_not_rescued_by_a_proxy_header() {
    let h = harness(Opts {
        trusted: vec!["x-remote-user"],
        ..Default::default()
    })
    .await;
    let r = req(
        "GET",
        "/launch",
        &[
            ("authorization", "Bearer wrong"),
            ("x-remote-user", "alice"),
        ],
        Body::empty(),
    );
    assert_eq!(send(&h.public, r).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn hostile_configuration_cannot_inject_markup_into_the_page() {
    let h = harness(Opts::default()).await;
    // A subject full of markup lands inside a base64url JWT, never raw in HTML.
    let (k, v) = bearer();
    let (_, _, body) = send(
        &h.public,
        req(
            "GET",
            "/launch?user_id=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
            &[(k, &v)],
            Body::empty(),
        ),
    )
    .await;
    let page = text(&body);
    assert!(!page.contains("alert(1)"));
    assert_eq!(page.matches("<script>").count(), 1);
}

#[tokio::test]
async fn clock_offset_shifts_the_assertion_time() {
    let h = harness(Opts::default()).await;
    h.state.set_clock_offset(-7);
    let (k, v) = bearer();
    let (_, _, body) = send(
        &h.public,
        req("GET", "/launch?user_id=e", &[(k, &v)], Body::empty()),
    )
    .await;
    let iat = verify_jwt(&assertion_from_page(&text(&body)), &h.jwk).1["iat"]
        .as_u64()
        .unwrap();
    assert!(
        (now() - 8..=now() - 6).contains(&iat),
        "iat {iat} vs now {}",
        now()
    );
}

// === /health ================================================================

#[tokio::test]
async fn health_is_public_and_reports_the_key_id() {
    let h = harness(Opts::default()).await;
    let (status, _, body) = send(&h.public, req("GET", "/health", &[], Body::empty())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_of(&body),
        json!({"status": "healthy", "kid": h.state.kid})
    );
}

// === /webhook ===============================================================

#[tokio::test]
async fn webhook_accepts_a_valid_signature_and_relays_it() {
    let h = harness(Opts {
        relay: true,
        ..with_webhook()
    })
    .await;
    let relay = h.relay.as_ref().unwrap();
    Mock::given(method("POST"))
        .and(path("/hooks"))
        .and(header("content-type", "application/json"))
        .and(header("x-xentree-event-id", "evt-1"))
        .and(body_string_contains("erpi.session.completed"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(relay)
        .await;

    let body = event("evt-1");
    let sig = signature(WH_ACTIVE, now(), &body);
    let (status, _, resp) = send(&h.public, webhook_req(&sig, &body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_of(&resp), json!({"status": "received"}));

    h.state.drain(Duration::from_secs(5)).await;
    let got = relay.received_requests().await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(
        got[0].body,
        body.as_bytes(),
        "payload is forwarded byte for byte"
    );
    assert_eq!(got[0].headers["x-xentree-signature"].to_str().unwrap(), sig);
}

#[tokio::test]
async fn webhook_rejects_bad_signatures_without_relaying() {
    let h = harness(Opts {
        relay: true,
        ..with_webhook()
    })
    .await;
    let body = event("evt-2");
    let good = signature(WH_ACTIVE, now(), &body);

    let cases: Vec<(&str, Request<Body>)> = vec![
        (
            "wrong secret",
            webhook_req(&signature("whsec_other", now(), &body), &body),
        ),
        ("tampered body", webhook_req(&good, &event("evt-evil"))),
        (
            "stale timestamp",
            webhook_req(&signature(WH_ACTIVE, now() - 301, &body), &body),
        ),
        (
            "future timestamp",
            webhook_req(&signature(WH_ACTIVE, now() + 301, &body), &body),
        ),
        ("garbage header", webhook_req("nonsense", &body)),
        ("missing header", req("POST", "/webhook", &[], body.clone())),
    ];
    for (name, r) in cases {
        let (status, ..) = send(&h.public, r).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
    }
    h.state.drain(Duration::from_secs(1)).await;
    assert!(h
        .relay
        .as_ref()
        .unwrap()
        .received_requests()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn webhook_accepts_the_previous_secret_during_rotation() {
    let grace_end = SystemTime::now() + Duration::from_secs(3600);
    let h = harness(Opts {
        webhook: Some((WH_ACTIVE, Some((WH_PREVIOUS, grace_end)))),
        ..Default::default()
    })
    .await;
    for (id, secret) in [("rot-1", WH_ACTIVE), ("rot-2", WH_PREVIOUS)] {
        let body = event(id);
        let (status, ..) = send(
            &h.public,
            webhook_req(&signature(secret, now(), &body), &body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{secret}");
    }
}

#[tokio::test]
async fn webhook_rejects_the_previous_secret_after_the_grace_window() {
    let expired = SystemTime::now() - Duration::from_secs(1);
    let h = harness(Opts {
        webhook: Some((WH_ACTIVE, Some((WH_PREVIOUS, expired)))),
        ..Default::default()
    })
    .await;
    let body = event("rot-3");
    let (status, ..) = send(
        &h.public,
        webhook_req(&signature(WH_PREVIOUS, now(), &body), &body),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, ..) = send(
        &h.public,
        webhook_req(&signature(WH_ACTIVE, now(), &body), &body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn duplicate_event_ids_are_acknowledged_but_processed_once() {
    let h = harness(Opts {
        relay: true,
        ..with_webhook()
    })
    .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(h.relay.as_ref().unwrap())
        .await;

    let body = event("evt-dup");
    for attempt in 0..3 {
        // Each delivery is freshly signed (as Xentree's retries would be).
        let sig = signature(WH_ACTIVE, now() + attempt, &body);
        let (status, _, resp) = send(&h.public, webhook_req(&sig, &body)).await;
        assert_eq!(status, StatusCode::OK, "attempt {attempt}");
        assert_eq!(json_of(&resp), json!({"status": "received"}));
    }
    h.state.drain(Duration::from_secs(5)).await;
    assert_eq!(
        h.relay
            .as_ref()
            .unwrap()
            .received_requests()
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn an_unauthenticated_request_cannot_burn_an_event_id() {
    let h = harness(Opts {
        relay: true,
        ..with_webhook()
    })
    .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(h.relay.as_ref().unwrap())
        .await;
    let body = event("evt-burn");
    let forged = send(
        &h.public,
        webhook_req(&signature("whsec_attacker", now(), &body), &body),
    )
    .await;
    assert_eq!(forged.0, StatusCode::UNAUTHORIZED);
    let real = send(
        &h.public,
        webhook_req(&signature(WH_ACTIVE, now(), &body), &body),
    )
    .await;
    assert_eq!(real.0, StatusCode::OK);
    h.state.drain(Duration::from_secs(5)).await;
    assert_eq!(
        h.relay
            .as_ref()
            .unwrap()
            .received_requests()
            .await
            .unwrap()
            .len(),
        1,
        "genuine delivery still processed"
    );
}

#[tokio::test]
async fn webhook_payload_must_be_json_with_an_event_id() {
    let h = harness(with_webhook()).await;
    for (name, body) in [
        ("not json", "hello".to_string()),
        ("no id", r#"{"event":"x"}"#.into()),
        ("numeric id", r#"{"id":7}"#.into()),
        ("empty id", r#"{"id":""}"#.into()),
    ] {
        let (status, ..) = send(
            &h.public,
            webhook_req(&signature(WH_ACTIVE, now(), &body), &body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
    }
}

#[tokio::test]
async fn webhook_body_is_limited_to_one_megabyte() {
    let h = harness(with_webhook()).await;
    let body = format!(r#"{{"id":"big","pad":"{}"}}"#, "x".repeat(1024 * 1024));
    let (status, ..) = send(
        &h.public,
        webhook_req(&signature(WH_ACTIVE, now(), &body), &body),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    // just under the limit is fine
    let ok = format!(
        r#"{{"id":"edge","pad":"{}"}}"#,
        "x".repeat(1024 * 1024 - 100)
    );
    let (status, ..) = send(
        &h.public,
        webhook_req(&signature(WH_ACTIVE, now(), &ok), &ok),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn webhook_without_a_configured_secret_is_unavailable() {
    let h = harness(Opts::default()).await;
    let body = event("e");
    let (status, ..) = send(
        &h.public,
        webhook_req(&signature(WH_ACTIVE, now(), &body), &body),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn relay_retries_transient_failures_then_succeeds() {
    let h = harness(Opts {
        relay: true,
        ..with_webhook()
    })
    .await;
    let relay = h.relay.as_ref().unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(relay)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(relay)
        .await;
    let body = event("evt-retry");
    assert_eq!(
        send(
            &h.public,
            webhook_req(&signature(WH_ACTIVE, now(), &body), &body)
        )
        .await
        .0,
        StatusCode::OK
    );
    h.state.drain(Duration::from_secs(5)).await;
    assert_eq!(relay.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn relay_does_not_retry_when_the_upstream_rejects_the_payload() {
    let h = harness(Opts {
        relay: true,
        ..with_webhook()
    })
    .await;
    let relay = h.relay.as_ref().unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(422))
        .mount(relay)
        .await;
    let body = event("evt-422");
    assert_eq!(
        send(
            &h.public,
            webhook_req(&signature(WH_ACTIVE, now(), &body), &body)
        )
        .await
        .0,
        StatusCode::OK
    );
    h.state.drain(Duration::from_secs(5)).await;
    assert_eq!(relay.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_failing_relay_never_delays_or_fails_the_acknowledgement() {
    let h = harness(Opts {
        relay: true,
        ..with_webhook()
    })
    .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_delay(Duration::from_millis(300)))
        .mount(h.relay.as_ref().unwrap())
        .await;
    let body = event("evt-slow");
    let started = std::time::Instant::now();
    let (status, ..) = send(
        &h.public,
        webhook_req(&signature(WH_ACTIVE, now(), &body), &body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "ack must not wait for the relay"
    );
    h.state.drain(Duration::from_millis(1)).await;
}

// === /deprovision ===========================================================

async fn expect_deprovision(h: &Harness, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/connect/v1/deprovision/c1"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(response)
        .mount(&h.xentree)
        .await;
}

#[tokio::test]
async fn deprovision_does_not_exist_on_the_public_listener() {
    let h = harness(Opts::default()).await;
    let (k, v) = bearer();
    for r in [
        req("POST", "/deprovision/emp-1", &[(k, &v)], Body::empty()),
        req("POST", "/deprovision/emp-1", &[], Body::empty()),
    ] {
        assert_eq!(send(&h.public, r).await.0, StatusCode::NOT_FOUND);
    }
    assert!(h.xentree.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn deprovision_requires_the_bearer_even_on_the_internal_listener() {
    let h = harness(Opts {
        trusted: vec!["x-remote-user"],
        allow_query_secret: true,
        ..Default::default()
    })
    .await;
    let cases = [
        (
            "no credentials",
            req("POST", "/deprovision/emp-1", &[], Body::empty()),
        ),
        (
            "wrong bearer",
            req(
                "POST",
                "/deprovision/emp-1",
                &[("authorization", "Bearer nope")],
                Body::empty(),
            ),
        ),
        (
            "proxy header",
            req(
                "POST",
                "/deprovision/emp-1",
                &[("x-remote-user", "admin")],
                Body::empty(),
            ),
        ),
        (
            "query secret",
            req(
                "POST",
                &format!("/deprovision/emp-1?secret={SECRET}"),
                &[],
                Body::empty(),
            ),
        ),
    ];
    for (name, r) in cases {
        assert_eq!(
            send(&h.internal, r).await.0,
            StatusCode::UNAUTHORIZED,
            "{name}"
        );
    }
    assert!(
        h.xentree.received_requests().await.unwrap().is_empty(),
        "nothing may reach Xentree"
    );
}

#[tokio::test]
async fn deprovision_sends_a_purpose_scoped_assertion_and_returns_xentrees_answer() {
    let h = harness(Opts::default()).await;
    expect_deprovision(
        &h,
        ResponseTemplate::new(200).set_body_json(json!({"status": "ok", "seat_released": true})),
    )
    .await;
    let (k, v) = bearer();
    let (status, _, body) = send(
        &h.internal,
        req("POST", "/deprovision/emp-9", &[(k, &v)], Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        json_of(&body),
        json!({"status": "ok", "seat_released": true})
    );

    let sent = h.xentree.received_requests().await.unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].url.path(), "/connect/v1/deprovision/c1");
    let form: Vec<(String, String)> = url::form_urlencoded::parse(&sent[0].body)
        .into_owned()
        .collect();
    assert_eq!(form.len(), 1);
    assert_eq!(form[0].0, "assertion");
    let (header, claims) = verify_jwt(&form[0].1, &h.jwk);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(claims["purpose"], "deprovision");
    assert_eq!(claims["sub"], "emp-9");
    assert_eq!(claims["iss"], "https://lms.example.com");
    assert_eq!(claims["organization_id"], "org_1");
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        30
    );
}

#[tokio::test]
async fn every_deprovision_call_uses_a_fresh_jti() {
    let h = harness(Opts::default()).await;
    expect_deprovision(
        &h,
        ResponseTemplate::new(200).set_body_json(json!({"status": "ok", "seat_released": false})),
    )
    .await;
    let (k, v) = bearer();
    for _ in 0..2 {
        send(
            &h.internal,
            req("POST", "/deprovision/emp-9", &[(k, &v)], Body::empty()),
        )
        .await;
    }
    let jtis: Vec<String> = h
        .xentree
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| {
            let jwt = url::form_urlencoded::parse(&r.body)
                .next()
                .unwrap()
                .1
                .into_owned();
            verify_jwt(&jwt, &h.jwk).1["jti"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(jtis.len(), 2);
    assert_ne!(jtis[0], jtis[1]);
}

#[tokio::test]
async fn deprovision_encodes_awkward_user_ids_in_the_assertion_only() {
    let h = harness(Opts::default()).await;
    expect_deprovision(
        &h,
        ResponseTemplate::new(200)
            .set_body_json(json!({"status": "no_active_binding", "seat_released": false})),
    )
    .await;
    let (k, v) = bearer();
    let (status, ..) = send(
        &h.internal,
        req("POST", "/deprovision/a%2Fb%20c", &[(k, &v)], Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let sent = &h.xentree.received_requests().await.unwrap()[0];
    assert_eq!(
        sent.url.path(),
        "/connect/v1/deprovision/c1",
        "the user id must not leak into the upstream path"
    );
    let jwt = url::form_urlencoded::parse(&sent.body)
        .next()
        .unwrap()
        .1
        .into_owned();
    assert_eq!(verify_jwt(&jwt, &h.jwk).1["sub"], "a/b c");
}

#[tokio::test]
async fn deprovision_maps_upstream_errors() {
    let (k, v) = bearer();
    for (upstream, expected) in [
        (403, StatusCode::FORBIDDEN),
        (404, StatusCode::NOT_FOUND),
        (409, StatusCode::CONFLICT),
        (401, StatusCode::BAD_GATEWAY), // our own credentials/clock are wrong, not the caller's
        (500, StatusCode::BAD_GATEWAY),
    ] {
        let h = harness(Opts::default()).await;
        expect_deprovision(
            &h,
            ResponseTemplate::new(upstream).set_body_json(json!({"detail": "nope"})),
        )
        .await;
        let (status, _, body) = send(
            &h.internal,
            req("POST", "/deprovision/emp-1", &[(k, &v)], Body::empty()),
        )
        .await;
        assert_eq!(status, expected, "upstream {upstream}");
        let j = json_of(&body);
        assert_eq!(j["upstream_status"], upstream);
        assert!(j["error"].as_str().is_some());
    }
}

#[tokio::test]
async fn deprovision_reports_an_unreachable_xentree_as_a_bad_gateway() {
    let h = harness(Opts {
        base_url: Some("http://127.0.0.1:1"),
        ..Default::default()
    })
    .await;
    let (k, v) = bearer();
    let (status, _, body) = send(
        &h.internal,
        req("POST", "/deprovision/emp-1", &[(k, &v)], Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(json_of(&body)["error"].is_string());
}

#[tokio::test]
async fn deprovision_rejects_a_malformed_user_id() {
    let h = harness(Opts::default()).await;
    let (k, v) = bearer();
    let (status, ..) = send(
        &h.internal,
        req("POST", "/deprovision/%0A", &[(k, &v)], Body::empty()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(h.xentree.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn webhook_and_launch_do_not_exist_on_the_internal_listener() {
    let h = harness(with_webhook()).await;
    let (k, v) = bearer();
    assert_eq!(
        send(
            &h.internal,
            req("GET", "/launch?user_id=e", &[(k, &v)], Body::empty())
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&h.internal, req("POST", "/webhook", &[], Body::empty()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

// === real sockets: both listeners and graceful shutdown =====================

#[tokio::test]
async fn serves_both_listeners_over_tcp_and_shuts_down_gracefully() {
    let h = harness(Opts::default()).await;
    expect_deprovision(
        &h,
        ResponseTemplate::new(200).set_body_json(json!({"status": "ok", "seat_released": true})),
    )
    .await;
    let public = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let internal = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (pub_addr, int_addr) = (public.local_addr().unwrap(), internal.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(super::serve(
        h.state.clone(),
        public,
        internal,
        async move {
            let _ = stopped.await;
        },
    ));

    let http = reqwest::Client::new();
    let health = http
        .get(format!("http://{pub_addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);

    // The destructive endpoint is simply not on the public port...
    let on_public = http
        .post(format!("http://{pub_addr}/deprovision/emp-1"))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(on_public.status(), 404);
    // ...and works, with the secret, on the internal one.
    let denied = http
        .post(format!("http://{int_addr}/deprovision/emp-1"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    let ok = http
        .post(format!("http://{int_addr}/deprovision/emp-1"))
        .bearer_auth(SECRET)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(ok.json::<Value>().await.unwrap()["seat_released"], true);

    drop(http);
    stop.send(()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("shutdown completes")
        .unwrap();
    assert!(result.is_ok());
    // Both ports are released.
    assert!(tokio::net::TcpListener::bind(pub_addr).await.is_ok());
    assert!(tokio::net::TcpListener::bind(int_addr).await.is_ok());
}
