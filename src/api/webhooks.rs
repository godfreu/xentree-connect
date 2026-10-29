use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

use super::{client::XentreeAdminClient, error::ApiError};

pub const EVENT_SESSION_COMPLETED: &str = "erpi.session.completed";
pub const EVENT_CONSENT_REVOKED: &str = "connect.consent.revoked";

#[derive(Debug, Clone, Serialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<String>,
}

/// The webhook and its signing secret. **The secret is returned only once**:
/// persist it before doing anything else.
#[derive(Debug, Deserialize)]
pub struct WebhookCreatedResponse {
    pub id: String,
    /// Redacted in `Debug` output; read it with `ExposeSecret`.
    pub signing_secret: SecretString,
}

impl XentreeAdminClient {
    /// `POST /api/admin/organizations/{org_id}/connect-clients/{client_record_id}/webhooks`.
    ///
    /// If this fails with [`ApiError::Decode`] or a transport error *after*
    /// the server accepted the request, the webhook may exist while its
    /// secret is lost; rotate the secret to obtain a usable one.
    pub async fn create_webhook(
        &self,
        org_id: &str,
        client_record_id: &str,
        request: &CreateWebhookRequest,
    ) -> Result<WebhookCreatedResponse, ApiError> {
        if request.events.is_empty() || request.events.iter().any(String::is_empty) {
            return Err(ApiError::InvalidInput(
                "at least one non-empty event is required".into(),
            ));
        }
        match Url::parse(&request.url) {
            Ok(u) if matches!(u.scheme(), "https" | "http") && u.host().is_some() => {}
            _ => {
                return Err(ApiError::InvalidInput(
                    "webhook url must be an absolute http(s) URL".into(),
                ))
            }
        }
        let url = self.endpoint(&[
            "api",
            "admin",
            "organizations",
            org_id,
            "connect-clients",
            client_record_id,
            "webhooks",
        ])?;
        self.send_json(self.post(url).json(request))
            .await
            .map_err(|e| match e {
                ApiError::Decode(m) => ApiError::Decode(format!(
                    "{m}; the webhook may have been created, rotate its secret"
                )),
                other => other,
            })
    }
}
