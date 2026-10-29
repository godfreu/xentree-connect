use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{
    digest,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use zeroize::Zeroizing;

use super::{error::CryptoError, jwks::Jwk};

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

/// An ECDSA P-256 signing key. The PKCS#8 DER is held in a zeroizing buffer.
///
/// `ring`'s internal copy of the key is outside our control, so zeroization
/// is best-effort.
pub struct SigningKey {
    pkcs8: Zeroizing<Vec<u8>>,
    pair: EcdsaKeyPair,
    kid: String,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| CryptoError::Rng)?;
        Self::from_pkcs8_der(doc.as_ref())
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|_| CryptoError::InvalidKey)?;
        let (x, y) = split_point(pair.public_key().as_ref())?;
        let kid = thumbprint(&x, &y);
        Ok(Self {
            pkcs8: Zeroizing::new(der.to_vec()),
            pair,
            kid,
        })
    }

    pub fn from_pem(pem: &str) -> Result<Self, CryptoError> {
        let body = pem
            .trim()
            .strip_prefix(PEM_BEGIN)
            .ok_or(CryptoError::InvalidPem("missing BEGIN PRIVATE KEY line"))?
            .strip_suffix(PEM_END)
            .ok_or(CryptoError::InvalidPem("missing END PRIVATE KEY line"))?;
        let b64: Zeroizing<String> =
            Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
        let der = Zeroizing::new(
            STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| CryptoError::InvalidPem("bad base64"))?,
        );
        Self::from_pkcs8_der(&der)
    }

    pub fn to_pem(&self) -> Zeroizing<String> {
        let b64 = Zeroizing::new(STANDARD.encode(&*self.pkcs8));
        let mut out = Zeroizing::new(String::with_capacity(b64.len() + 80));
        out.push_str(PEM_BEGIN);
        out.push('\n');
        for line in b64.as_bytes().chunks(64) {
            // base64 output is ASCII, so chunk boundaries are char boundaries.
            out.push_str(std::str::from_utf8(line).expect("ascii"));
            out.push('\n');
        }
        out.push_str(PEM_END);
        out.push('\n');
        out
    }

    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    /// RFC 7638 thumbprint of the public key, base64url without padding.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Public JWK (no private parameters).
    pub fn jwk(&self) -> Jwk {
        let (x, y) = split_point(self.pair.public_key().as_ref()).expect("validated at load");
        Jwk::new_p256(self.kid.clone(), &x, &y)
    }

    /// Returns the raw 64-byte `r || s` signature required by JWS ES256.
    pub(crate) fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let rng = SystemRandom::new();
        self.pair
            .sign(&rng, msg)
            .map(|s| s.as_ref().to_vec())
            .map_err(|_| CryptoError::Sign)
    }
}

/// Splits an uncompressed SEC1 point (`0x04 || x || y`) into fixed 32-byte
/// coordinates. ring emits fixed-width values, so leading zeros are preserved.
fn split_point(point: &[u8]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    if point.len() != 65 || point[0] != 0x04 {
        return Err(CryptoError::InvalidKey);
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&point[1..33]);
    y.copy_from_slice(&point[33..65]);
    Ok((x, y))
}

fn thumbprint(x: &[u8; 32], y: &[u8; 32]) -> String {
    // RFC 7638: required members only, lexicographic order, no whitespace.
    let json = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(x),
        URL_SAFE_NO_PAD.encode(y)
    );
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, json.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Jwks;
    use serde_json::Value;

    #[test]
    fn generates_distinct_keys() {
        let (a, b) = (
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
        );
        assert_ne!(a.kid(), b.kid());
        assert_ne!(a.pkcs8_der(), b.pkcs8_der());
    }

    #[test]
    fn pem_round_trip_preserves_key() {
        let k = SigningKey::generate().unwrap();
        let pem = k.to_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(pem.lines().all(|l| l.len() <= 64 || l.starts_with("-----")));
        let k2 = SigningKey::from_pem(&pem).unwrap();
        assert_eq!(k.kid(), k2.kid());
        assert_eq!(k.pkcs8_der(), k2.pkcs8_der());
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(SigningKey::from_pem("garbage").is_err());
        assert!(SigningKey::from_pem(
            "-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----"
        )
        .is_err());
        assert!(SigningKey::from_pkcs8_der(&[0u8; 16]).is_err());
    }

    #[test]
    fn jwks_format_matches_spec() {
        let k = SigningKey::generate().unwrap();
        let s = Jwks::new(vec![k.jwk()]).to_json_string().unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        let jwk = &v["keys"][0];
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["kid"], k.kid());
        // Public members only.
        let mut names: Vec<_> = jwk.as_object().unwrap().keys().cloned().collect();
        names.sort();
        assert_eq!(names, ["alg", "crv", "kid", "kty", "use", "x", "y"]);
        for c in ["x", "y"] {
            let raw = jwk[c].as_str().unwrap();
            assert!(!raw.contains(['=', '+', '/']), "base64url, no padding");
            assert_eq!(URL_SAFE_NO_PAD.decode(raw).unwrap().len(), 32);
        }
    }

    #[test]
    fn coordinates_are_left_padded_for_leading_zeros() {
        // Keep generating until a coordinate has a leading zero byte
        // (~1/128 per key); each must still be exactly 32 bytes.
        let mut seen_zero = false;
        for _ in 0..3000 {
            let j = SigningKey::generate().unwrap().jwk();
            for c in [&j.x, &j.y] {
                let raw = URL_SAFE_NO_PAD.decode(c).unwrap();
                assert_eq!(raw.len(), 32);
                seen_zero |= raw[0] == 0;
            }
            if seen_zero {
                break;
            }
        }
        assert!(seen_zero, "never hit a leading-zero coordinate");
    }

    #[test]
    fn kid_matches_rfc7638_thumbprint() {
        let k = SigningKey::generate().unwrap();
        let j = k.jwk();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            j.x, j.y
        );
        let expect = URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, canonical.as_bytes()));
        assert_eq!(k.kid(), expect);
    }

    #[test]
    fn debug_does_not_leak_key_material() {
        let k = SigningKey::generate().unwrap();
        let d = format!("{k:?}");
        assert!(!d.contains("pkcs8") && !d.contains("pair"));
    }
}
