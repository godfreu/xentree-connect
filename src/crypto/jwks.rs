use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

use super::error::CryptoError;

/// Public EC P-256 JWK. Deliberately has no field for private parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl Jwk {
    pub(crate) fn new_p256(kid: String, x: &[u8; 32], y: &[u8; 32]) -> Self {
        Self {
            kty: "EC".into(),
            kid,
            use_: "sig".into(),
            alg: "ES256".into(),
            crv: "P-256".into(),
            x: URL_SAFE_NO_PAD.encode(x),
            y: URL_SAFE_NO_PAD.encode(y),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

impl Jwks {
    pub fn new(keys: Vec<Jwk>) -> Self {
        Self { keys }
    }

    /// The value for the Admin API `jwks_json` field: a JSON *string*
    /// containing the JWKS document. Wrap it as a string value when building
    /// the request body (serialize it once, not twice).
    pub fn to_json_string(&self) -> Result<String, CryptoError> {
        Ok(serde_json::to_string(self)?)
    }
}
