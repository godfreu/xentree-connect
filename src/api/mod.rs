//! Typed client for the Xentree Cloud admin API.

mod client;
mod connect;
mod error;
mod models;
mod webhooks;

#[cfg(test)]
mod tests;

pub(crate) use client::{endpoint_url, is_loopback as is_loopback_url, normalize_base_url};
pub use client::{XentreeAdminClient, DEFAULT_BASE_URL};
pub use connect::{ConnectClientResponse, CreateConnectClientRequest};
pub use error::ApiError;
pub use models::OrganizationItem;
pub use webhooks::{
    CreateWebhookRequest, WebhookCreatedResponse, EVENT_CONSENT_REVOKED, EVENT_SESSION_COMPLETED,
};
