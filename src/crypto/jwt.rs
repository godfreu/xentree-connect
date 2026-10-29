use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;
use uuid::Uuid;

use super::{error::CryptoError, keys::SigningKey};

/// Default assertion lifetime. Xentree rejects anything over 60 seconds, and
/// the browser round trip counts against the window, so we use half of it.
pub const DEFAULT_TTL_SECS: u64 = 30;
/// Hard server-side limit: `exp <= iat + 60`.
pub const MAX_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Browser launch. The assertion must NOT carry a `purpose` claim.
    Launch,
    /// Server-to-server deprovision. Carries `"purpose": "deprovision"`.
    Deprovision,
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    organization_id: &'a str,
    iat: u64,
    exp: u64,
    jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purpose: Option<&'static str>,
}

/// Signs Xentree Connect assertions (ES256).
pub struct AssertionSigner {
    key: SigningKey,
    issuer: String,
    audience: String,
    organization_id: String,
    ttl_secs: u64,
    /// Seconds to add to the local clock, from skew calibration against Xentree.
    clock_offset_secs: i64,
}

impl AssertionSigner {
    pub fn new(
        key: SigningKey,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        organization_id: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let issuer = issuer.into();
        let audience = audience.into();
        let organization_id = organization_id.into();
        if issuer.is_empty() || audience.is_empty() || organization_id.is_empty() {
            return Err(CryptoError::InvalidConfig(
                "issuer, audience and organization_id are required",
            ));
        }
        if issuer.ends_with('/') {
            return Err(CryptoError::InvalidConfig(
                "issuer must not have a trailing slash",
            ));
        }
        Ok(Self {
            key,
            issuer,
            audience,
            organization_id,
            ttl_secs: DEFAULT_TTL_SECS,
            clock_offset_secs: 0,
        })
    }

    pub fn with_ttl_secs(mut self, ttl: u64) -> Result<Self, CryptoError> {
        if ttl == 0 || ttl > MAX_TTL_SECS {
            return Err(CryptoError::InvalidConfig(
                "ttl must be between 1 and 60 seconds",
            ));
        }
        self.ttl_secs = ttl;
        Ok(self)
    }

    pub fn with_clock_offset_secs(mut self, offset: i64) -> Self {
        self.clock_offset_secs = offset;
        self
    }

    pub fn key(&self) -> &SigningKey {
        &self.key
    }

    /// Signs an assertion using the (offset-corrected) system clock.
    pub fn sign(&self, sub: &str, purpose: Purpose) -> Result<String, CryptoError> {
        let local = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CryptoError::Sign)?
            .as_secs();
        let corrected = local
            .checked_add_signed(self.clock_offset_secs)
            .ok_or(CryptoError::Sign)?;
        self.sign_at(sub, purpose, corrected)
    }

    /// Signs with an explicit `iat`. `exp = iat + ttl`.
    pub fn sign_at(&self, sub: &str, purpose: Purpose, iat: u64) -> Result<String, CryptoError> {
        if sub.is_empty() {
            return Err(CryptoError::InvalidConfig("sub must not be empty"));
        }
        let header = Header {
            alg: "ES256",
            typ: "JWT",
            kid: self.key.kid(),
        };
        let claims = Claims {
            iss: &self.issuer,
            aud: &self.audience,
            sub,
            organization_id: &self.organization_id,
            iat,
            exp: iat + self.ttl_secs,
            jti: Uuid::new_v4().to_string(),
            purpose: match purpose {
                Purpose::Launch => None,
                Purpose::Deprovision => Some("deprovision"),
            },
        };

        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?),
        );
        let sig = self.key.sign(signing_input.as_bytes())?;
        Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Jwks;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};
    use serde_json::Value;

    fn signer() -> AssertionSigner {
        AssertionSigner::new(
            SigningKey::generate().unwrap(),
            "https://sso.example.com",
            "xentree",
            "org_123",
        )
        .unwrap()
    }

    fn b64(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    /// Verifies using only the published JWKS JSON, independent of our key code.
    fn verify(jwt: &str, jwks_json: &str) -> (Value, Value) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value = serde_json::from_slice(&b64(parts[0])).unwrap();
        let claims: Value = serde_json::from_slice(&b64(parts[1])).unwrap();
        let jwks: Value = serde_json::from_str(jwks_json).unwrap();
        let jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|k| k["kid"] == header["kid"])
            .expect("kid present in JWKS");
        let mut point = vec![0x04];
        point.extend(b64(jwk["x"].as_str().unwrap()));
        point.extend(b64(jwk["y"].as_str().unwrap()));
        let sig = b64(parts[2]);
        assert_eq!(sig.len(), 64, "ES256 signature is raw r||s");
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .expect("signature verifies");
        (header, claims)
    }

    #[test]
    fn launch_assertion_round_trip() {
        let s = signer();
        let jwks = Jwks::new(vec![s.key().jwk()]).to_json_string().unwrap();
        let jwt = s.sign_at("emp-42", Purpose::Launch, 1_700_000_000).unwrap();
        let (h, c) = verify(&jwt, &jwks);
        assert_eq!(h["alg"], "ES256");
        assert_eq!(h["kid"], s.key().kid());
        assert_eq!(c["iss"], "https://sso.example.com");
        assert_eq!(c["aud"], "xentree");
        assert_eq!(c["sub"], "emp-42");
        assert_eq!(c["organization_id"], "org_123");
        assert_eq!(c["iat"], 1_700_000_000u64);
        assert_eq!(c["exp"], 1_700_000_030u64);
        assert!(c.get("purpose").is_none(), "launch must not carry purpose");
        assert_eq!(
            Uuid::parse_str(c["jti"].as_str().unwrap())
                .unwrap()
                .get_version_num(),
            4
        );
    }

    #[test]
    fn deprovision_assertion_carries_purpose() {
        let s = signer();
        let jwks = Jwks::new(vec![s.key().jwk()]).to_json_string().unwrap();
        let (_, c) = verify(
            &s.sign_at("emp-42", Purpose::Deprovision, 100).unwrap(),
            &jwks,
        );
        assert_eq!(c["purpose"], "deprovision");
    }

    #[test]
    fn jti_is_unique() {
        let s = signer();
        let jti = |t: &str| -> String {
            let c: Value = serde_json::from_slice(&b64(t.split('.').nth(1).unwrap())).unwrap();
            c["jti"].as_str().unwrap().to_string()
        };
        let a = s.sign_at("u", Purpose::Launch, 1).unwrap();
        let b = s.sign_at("u", Purpose::Launch, 1).unwrap();
        assert_ne!(jti(&a), jti(&b));
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let s = signer();
        let jwks = Jwks::new(vec![s.key().jwk()]).to_json_string().unwrap();
        let jwt = s.sign_at("emp-42", Purpose::Launch, 1).unwrap();
        let mut p: Vec<String> = jwt.split('.').map(String::from).collect();
        p[1] = URL_SAFE_NO_PAD.encode(br#"{"sub":"admin"}"#);
        let forged = p.join(".");
        let r = std::panic::catch_unwind(|| verify(&forged, &jwks));
        assert!(r.is_err());
    }

    #[test]
    fn ttl_and_config_validation() {
        let k = || SigningKey::generate().unwrap();
        assert!(AssertionSigner::new(k(), "https://a.example/", "aud", "org").is_err());
        assert!(AssertionSigner::new(k(), "", "aud", "org").is_err());
        let s = AssertionSigner::new(k(), "https://a.example", "aud", "org").unwrap();
        assert!(s.with_ttl_secs(61).is_err());
        let s = AssertionSigner::new(k(), "https://a.example", "aud", "org").unwrap();
        assert!(s.with_ttl_secs(0).is_err());
        let s = AssertionSigner::new(k(), "https://a.example", "aud", "org")
            .unwrap()
            .with_ttl_secs(60)
            .unwrap();
        let c: Value = serde_json::from_slice(&b64(s
            .sign_at("u", Purpose::Launch, 10)
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap()))
        .unwrap();
        assert_eq!(c["exp"], 70u64);
        assert!(s.sign_at("", Purpose::Launch, 10).is_err());
    }

    #[test]
    fn clock_offset_applies_to_iat() {
        let s = signer().with_clock_offset_secs(-5);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let c: Value = serde_json::from_slice(&b64(s
            .sign("u", Purpose::Launch)
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap()))
        .unwrap();
        let iat = c["iat"].as_u64().unwrap();
        assert!((now - 6..=now - 4).contains(&iat));
    }
}
