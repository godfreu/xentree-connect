use serde::Deserialize;

use super::{client::XentreeAdminClient, error::ApiError};

/// An organization the caller administers.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OrganizationItem {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub role: Option<String>,
}

impl XentreeAdminClient {
    /// `GET /api/admin/organizations`. Only organizations where the caller is
    /// an administrator can be bound to Connect integrations.
    pub async fn list_organizations(&self) -> Result<Vec<OrganizationItem>, ApiError> {
        let url = self.endpoint(&["api", "admin", "organizations"])?;
        self.send_json(self.get(url)).await
    }
}
