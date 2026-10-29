use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::{
    limit::RequestBodyLimitLayer, set_header::SetResponseHeaderLayer, timeout::TimeoutLayer,
};

use super::{
    auth::{authenticate, bearer_token, secret_matches, valid_subject, Caller},
    html::launch_page,
    state::GatewayState,
};
use crate::{api::ApiError, crypto::Purpose};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const WEBHOOK_BODY_LIMIT: usize = 1024 * 1024;
const LAUNCH_BODY_LIMIT: usize = 16 * 1024;

type S = Arc<GatewayState>;

/// Browser- and Xentree-facing endpoints. `/deprovision` is deliberately not here.
pub fn public_router(state: S) -> Router {
    harden(
        Router::new()
            .route("/health", get(health))
            .route(
                "/launch",
                get(launch_get)
                    .post(launch_post)
                    .layer(RequestBodyLimitLayer::new(LAUNCH_BODY_LIMIT)),
            )
            .route(
                "/webhook",
                post(webhook).layer(RequestBodyLimitLayer::new(WEBHOOK_BODY_LIMIT)),
            )
            .with_state(state),
    )
}

/// Backend-facing endpoints, for the internal listener only.
pub fn internal_router(state: S) -> Router {
    harden(
        Router::new()
            .route("/health", get(health))
            .route("/deprovision/{user_id}", post(deprovision))
            .with_state(state),
    )
}

/// Timeouts and headers every response carries, whichever route produced it.
fn harden(router: Router) -> Router {
    let set = |name, value: &'static str| {
        SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
    };
    router
        .layer(set(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(set(header::X_FRAME_OPTIONS, "DENY"))
        .layer(set(header::CACHE_CONTROL, "no-store"))
        .layer(set(header::REFERRER_POLICY, "no-referrer"))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn unauthorized() -> Response {
    let mut r = json_error(StatusCode::UNAUTHORIZED, "unauthorized");
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"xentree-connect\""),
    );
    r
}

// --- health ---------------------------------------------------------------

async fn health(State(s): State<S>) -> Response {
    Json(json!({ "status": "healthy", "kid": s.kid })).into_response()
}

// --- launch ---------------------------------------------------------------

#[derive(Deserialize, Default)]
struct LaunchParams {
    user_id: Option<String>,
    secret: Option<String>,
}

async fn launch_get(
    State(s): State<S>,
    headers: HeaderMap,
    Query(q): Query<LaunchParams>,
) -> Response {
    launch(&s, &headers, q.user_id, q.secret)
}

async fn launch_post(
    State(s): State<S>,
    headers: HeaderMap,
    Query(q): Query<LaunchParams>,
    Form(f): Form<LaunchParams>,
) -> Response {
    launch(&s, &headers, f.user_id.or(q.user_id), f.secret.or(q.secret))
}

/// The subject always comes from something we trust: the caller's `user_id`
/// when the caller proved the gateway secret, or the proxy-asserted identity.
/// A proxy-authenticated user can never name a different user.
fn launch(
    s: &GatewayState,
    headers: &HeaderMap,
    user_id: Option<String>,
    secret: Option<String>,
) -> Response {
    let caller = match authenticate(&s.auth(), headers, secret.as_deref()) {
        Ok(c) => c,
        Err(_) => return unauthorized(),
    };
    let sub = match (caller, user_id) {
        (Caller::Service, Some(u)) => u,
        (Caller::Service, None) => {
            return json_error(StatusCode::BAD_REQUEST, "user_id is required")
        }
        (Caller::Proxy(id), None) => id,
        (Caller::Proxy(id), Some(u)) if u == id => id,
        (Caller::Proxy(_), Some(_)) => {
            return json_error(
                StatusCode::FORBIDDEN,
                "user_id does not match the authenticated identity",
            )
        }
    };
    if !valid_subject(&sub) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user_id");
    }
    let assertion = match s.sign(&sub, Purpose::Launch) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "failed to sign launch assertion");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not sign assertion",
            );
        }
    };
    let mut resp = (
        StatusCode::OK,
        launch_page(s.launch_url.as_str(), &assertion),
    )
        .into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CONTENT_SECURITY_POLICY, s.csp.clone());
    resp
}

// --- webhook --------------------------------------------------------------

async fn webhook(State(s): State<S>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let Some(verifier) = &s.verifier else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "webhook receiving is not configured",
        );
    };
    let Some(signature) = headers
        .get("x-xentree-signature")
        .and_then(|v| v.to_str().ok())
    else {
        return unauthorized();
    };
    // Verify over the raw bytes before looking at the content.
    if let Err(e) = verifier.verify_now(signature, &body) {
        tracing::warn!(reason = %e, "rejected webhook");
        return unauthorized();
    }

    let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "body is not valid JSON");
    };
    let Some(event_id) = payload
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= 128)
    else {
        return json_error(StatusCode::BAD_REQUEST, "event id is missing");
    };

    // Only authenticated events reach the cache, so unsigned traffic can't fill it.
    let first_delivery = s
        .seen
        .lock()
        .expect("seen cache")
        .check_and_insert(event_id, Instant::now());
    if first_delivery {
        s.spawn_relay(body.clone(), signature.to_string(), event_id.to_string());
    } else {
        tracing::info!(event_id, "duplicate webhook delivery ignored");
    }
    Json(json!({ "status": "received" })).into_response()
}

// --- deprovision ----------------------------------------------------------

async fn deprovision(
    State(s): State<S>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    // Bearer header only: no query secret, no proxy identity for a destructive call.
    let authorized =
        bearer_token(&headers).is_some_and(|t| secret_matches(s.auth().secret_digest, t));
    if !authorized {
        return unauthorized();
    }
    if !valid_subject(&user_id) {
        return json_error(StatusCode::BAD_REQUEST, "invalid user_id");
    }
    // A fresh assertion (and jti) per call, so a retry is never a replay.
    let assertion = match s.sign(&user_id, Purpose::Deprovision) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "failed to sign deprovision assertion");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not sign assertion",
            );
        }
    };

    let sent = s
        .http
        .post(s.deprovision_url.clone())
        .form(&[("assertion", assertion.as_str())])
        .send()
        .await;
    let upstream = match sent {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "deprovision request failed");
            return json_error(StatusCode::BAD_GATEWAY, "could not reach Xentree");
        }
    };
    let status = upstream.status();
    let retry_after = upstream
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let Ok(bytes) = upstream.bytes().await else {
        return json_error(StatusCode::BAD_GATEWAY, "could not read Xentree's response");
    };

    if status.is_success() {
        return match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) => Json(v).into_response(),
            Err(_) => json_error(StatusCode::BAD_GATEWAY, "unexpected response from Xentree"),
        };
    }

    // Caller-actionable statuses pass through; our own 401 or an upstream
    // outage is the gateway's problem, so it is reported as a bad gateway.
    let err = ApiError::from_response(status.as_u16(), retry_after.as_deref(), &bytes);
    tracing::warn!(
        upstream_status = status.as_u16(),
        "deprovision rejected by Xentree"
    );
    let out = match status.as_u16() {
        403 | 404 | 409 | 429 => status,
        _ => StatusCode::BAD_GATEWAY,
    };
    (
        out,
        Json(json!({ "error": err.to_string(), "upstream_status": status.as_u16() })),
    )
        .into_response()
}
