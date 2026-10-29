use serde::{Deserialize, Serialize};

use super::{client::XentreeAdminClient, error::ApiError};

#[derive(Debug, Clone, Serialize)]
pub struct CreateConnectClientRequest {
    /// 1-255 characters.
    pub name: String,
    /// 1-128 characters, unique.
    pub client_id: String,
    /// Exactly the issuer placed in assertions (no trailing slash).
    pub issuer: String,
    pub audience: String,
    /// A JSON *string* holding the JWKS document, e.g. from
    /// [`Jwks::to_json_string`](crate::crypto::Jwks::to_json_string).
    pub jwks_json: String,
    pub auto_enroll: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_team_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_url: Option<String>,
}

impl CreateConnectClientRequest {
    /// `auto_enroll` defaults to `false`: enrolling consumes seats.
    pub fn new(
        name: impl Into<String>,
        client_id: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_json: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            client_id: client_id.into(),
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_json: jwks_json.into(),
            auto_enroll: false,
            default_team_id: None,
            policy_url: None,
        }
    }

    fn validate(&self) -> Result<(), ApiError> {
        let bad = |m: &str| Err(ApiError::InvalidInput(m.into()));
        if self.name.is_empty() || self.name.chars().count() > 255 {
            return bad("name must be 1-255 characters");
        }
        if self.client_id.is_empty() || self.client_id.chars().count() > 128 {
            return bad("client_id must be 1-128 characters");
        }
        if self.issuer.is_empty() || self.audience.is_empty() || self.jwks_json.is_empty() {
            return bad("issuer, audience and jwks_json are required");
        }
        if self.issuer.ends_with('/') {
            return bad("issuer must not have a trailing slash");
        }
        Ok(())
    }
}

/// A registered Connect integration. Unknown fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConnectClientResponse {
    /// The `client_record_id` used in follow-up calls (webhooks, key rotation).
    pub id: String,
    pub client_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub auto_enroll: Option<bool>,
    #[serde(default)]
    pub default_team_id: Option<String>,
}

#[derive(Serialize)]
struct RotateJwksRequest<'a> {
    jwks_json: &'a str,
}

impl XentreeAdminClient {
    /// `POST /api/admin/organizations/{org_id}/connect-clients`.
    /// A duplicate `client_id` yields [`ApiError::Conflict`].
    pub async fn create_connect_client(
        &self,
        org_id: &str,
        request: &CreateConnectClientRequest,
    ) -> Result<ConnectClientResponse, ApiError> {
        request.validate()?;
        let url = self.endpoint(&["api", "admin", "organizations", org_id, "connect-clients"])?;
        self.send_json(self.post(url).json(request)).await
    }

    /// `PATCH /api/admin/organizations/{org_id}/connect-clients/{client_record_id}`
    /// replacing the registered JWKS. Include the old key alongside the new
    /// one until all in-flight assertions have expired.
    ///
    /// The response body is not inspected beyond its 2xx status.
    pub async fn rotate_jwks(
        &self,
        org_id: &str,
        client_record_id: &str,
        jwks_json: &str,
    ) -> Result<(), ApiError> {
        if jwks_json.is_empty() {
            return Err(ApiError::InvalidInput("jwks_json is required".into()));
        }
        let url = self.endpoint(&[
            "api",
            "admin",
            "organizations",
            org_id,
            "connect-clients",
            client_record_id,
        ])?;
        self.send(self.patch(url).json(&RotateJwksRequest { jwks_json }))
            .await
            .map(drop)
    }
}
