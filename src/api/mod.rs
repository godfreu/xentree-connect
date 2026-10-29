//! Typed client for the Xentree Cloud admin API.

mod client;
mod connect;
mod error;
mod models;
mod webhooks;

#[cfg(test)]
mod tests;

pub use client::{XentreeAdminClient, DEFAULT_BASE_URL};
pub use connect::{ConnectClientResponse, CreateConnectClientRequest};
pub use error::ApiError;
pub use models::OrganizationItem;
pub use webhooks::{
    CreateWebhookRequest, WebhookCreatedResponse, EVENT_CONSENT_REVOKED, EVENT_SESSION_COMPLETED,
};
