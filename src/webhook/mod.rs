//! Xentree webhook signature verification.
//!
//! Header: `X-Xentree-Signature: t={unix_seconds},v1={hex_hmac_sha256}`.
//! The MAC covers the UTF-8 string `{t}.{raw_body}` exactly as received, so
//! verify against the raw request bytes *before* any JSON parsing.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::hmac;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

pub const SIGNATURE_HEADER: &str = "X-Xentree-Signature";
/// Maximum `|now - t|` in seconds.
pub const TOLERANCE_SECS: u64 = 300;
/// How long the previous secret stays valid after rotation.
pub const ROTATION_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

const MAC_LEN: usize = 32;
const MAX_TIMESTAMP_DIGITS: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebhookError {
    #[error("malformed signature header: {0}")]
    MalformedHeader(&'static str),
    #[error("timestamp outside the {TOLERANCE_SECS}s tolerance window ({skew_secs}s off)")]
    TimestampOutOfWindow { skew_secs: i64 },
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("webhook secret must not be empty")]
    EmptySecret,
}

/// Which secret authenticated a request. For operator visibility only; never
/// expose this to the caller of the webhook endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedSecret {
    Active,
    Previous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    pub timestamp: u64,
    pub matched: MatchedSecret,
}

struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    fn new(s: impl AsRef<[u8]>) -> Result<Self, WebhookError> {
        let s = s.as_ref();
        if s.is_empty() {
            return Err(WebhookError::EmptySecret);
        }
        Ok(Self(Zeroizing::new(s.to_vec())))
    }

    fn key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, &self.0)
    }
}

struct Previous {
    secret: Secret,
    expires_at: SystemTime,
}

/// Verifies webhook signatures against the active secret and, during the
/// rotation grace window, the previous one.
///
/// Secrets are used as their UTF-8 bytes exactly as Xentree issued them
/// (do not hex- or base64-decode them).
pub struct Verifier {
    active: Secret,
    previous: Option<Previous>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("has_previous", &self.previous.is_some())
            .finish_non_exhaustive()
    }
}

impl Verifier {
    pub fn new(active_secret: impl AsRef<[u8]>) -> Result<Self, WebhookError> {
        Ok(Self {
            active: Secret::new(active_secret)?,
            previous: None,
        })
    }

    /// Also accepts `previous_secret` until `rotated_at + 24h`.
    pub fn with_previous(
        self,
        previous_secret: impl AsRef<[u8]>,
        rotated_at: SystemTime,
    ) -> Result<Self, WebhookError> {
        self.with_previous_until(previous_secret, rotated_at + ROTATION_GRACE)
    }

    pub fn with_previous_until(
        mut self,
        previous_secret: impl AsRef<[u8]>,
        expires_at: SystemTime,
    ) -> Result<Self, WebhookError> {
        self.previous = Some(Previous {
            secret: Secret::new(previous_secret)?,
            expires_at,
        });
        Ok(self)
    }

    pub fn verify_now(&self, header: &str, body: &[u8]) -> Result<Verified, WebhookError> {
        self.verify(header, body, SystemTime::now())
    }

    pub fn verify(
        &self,
        header: &str,
        body: &[u8],
        now: SystemTime,
    ) -> Result<Verified, WebhookError> {
        let parsed = parse_header(header)?;

        let now_secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
        let skew_secs = now_secs - parsed.timestamp as i64;
        if skew_secs.unsigned_abs() > TOLERANCE_SECS {
            return Err(WebhookError::TimestampOutOfWindow { skew_secs });
        }

        // Both MACs are always computed and compared before looking at either
        // result. Whether a previous secret is configured/unexpired depends
        // on the clock and config, not on attacker-controlled secret data.
        let active_ok = check(&self.active, parsed.timestamp_text, body, &parsed.mac);
        let previous_ok = match &self.previous {
            Some(p) if now < p.expires_at => {
                check(&p.secret, parsed.timestamp_text, body, &parsed.mac)
            }
            _ => Choice::from(0),
        };

        let (active_ok, previous_ok) = (bool::from(active_ok), bool::from(previous_ok));
        let matched = if active_ok {
            MatchedSecret::Active
        } else if previous_ok {
            MatchedSecret::Previous
        } else {
            return Err(WebhookError::SignatureMismatch);
        };
        Ok(Verified {
            timestamp: parsed.timestamp,
            matched,
        })
    }
}

fn check(secret: &Secret, timestamp_text: &str, body: &[u8], provided: &[u8; MAC_LEN]) -> Choice {
    let mut ctx = hmac::Context::with_key(&secret.key());
    ctx.update(timestamp_text.as_bytes());
    ctx.update(b".");
    ctx.update(body);
    let tag = ctx.sign();
    tag.as_ref().ct_eq(provided.as_slice())
}

struct ParsedHeader<'a> {
    /// The `t` value exactly as sent; this is what was signed.
    timestamp_text: &'a str,
    timestamp: u64,
    mac: [u8; MAC_LEN],
}

/// Strict parser: exactly one `t` and one `v1`, unknown keys ignored.
fn parse_header(header: &str) -> Result<ParsedHeader<'_>, WebhookError> {
    let (mut t, mut v1) = (None, None);
    for part in header.split(',') {
        let Some((k, v)) = part.trim().split_once('=') else {
            return Err(WebhookError::MalformedHeader("expected key=value pairs"));
        };
        let slot = match k {
            "t" => &mut t,
            "v1" => &mut v1,
            _ => continue,
        };
        if slot.replace(v).is_some() {
            return Err(WebhookError::MalformedHeader("duplicate field"));
        }
    }
    let timestamp_text = t.ok_or(WebhookError::MalformedHeader("missing t"))?;
    let v1 = v1.ok_or(WebhookError::MalformedHeader("missing v1"))?;

    if timestamp_text.is_empty()
        || timestamp_text.len() > MAX_TIMESTAMP_DIGITS
        || !timestamp_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(WebhookError::MalformedHeader("t must be unix seconds"));
    }
    let timestamp = timestamp_text
        .parse()
        .map_err(|_| WebhookError::MalformedHeader("t must be unix seconds"))?;
    let mac = decode_hex_mac(v1).ok_or(WebhookError::MalformedHeader(
        "v1 must be 64 hex characters",
    ))?;
    Ok(ParsedHeader {
        timestamp_text,
        timestamp,
        mac,
    })
}

fn decode_hex_mac(s: &str) -> Option<[u8; MAC_LEN]> {
    let s = s.as_bytes();
    if s.len() != MAC_LEN * 2 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut out = [0u8; MAC_LEN];
    for (i, pair) in s.chunks_exact(2).enumerate() {
        out[i] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACTIVE: &str = "whsec_active_secret_for_tests";
    const PREVIOUS: &str = "whsec_previous_secret_for_tests";
    const BODY: &str =
        r#"{"id":"7f0c1b0e-2b5a-4a5e-9d3a-0c4f8e6b1a11","event":"erpi.session.completed"}"#;
    const T: u64 = 1_700_000_000;
    // Generated independently: printf '%s' "$T.$BODY" | openssl dgst -sha256 -hmac $SECRET
    const SIG_ACTIVE: &str = "0b00d47822b735d0d3f060b612c5d01c9fadd9432a7b5df617018e61fb018012";
    const SIG_PREVIOUS: &str = "be69ad35b6540a9cfc11873fee80fb23bf0befa28543ba5cddb5a5d84b8f2311";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn hdr(sig: &str) -> String {
        format!("t={T},v1={sig}")
    }

    fn sign(secret: &str, t: &str, body: &str) -> String {
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
            format!("{t}.{body}").as_bytes(),
        );
        tag.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn independent_vectors_match_ring() {
        assert_eq!(sign(ACTIVE, "1700000000", BODY), SIG_ACTIVE);
        assert_eq!(sign(PREVIOUS, "1700000000", BODY), SIG_PREVIOUS);
    }

    #[test]
    fn accepts_valid_signature() {
        let v = Verifier::new(ACTIVE).unwrap();
        let r = v.verify(&hdr(SIG_ACTIVE), BODY.as_bytes(), at(T)).unwrap();
        assert_eq!(
            r,
            Verified {
                timestamp: T,
                matched: MatchedSecret::Active
            }
        );
    }

    #[test]
    fn accepts_uppercase_hex_and_unknown_fields_and_spaces() {
        let v = Verifier::new(ACTIVE).unwrap();
        let h = format!("t={T}, v0=ignored, v1={}", SIG_ACTIVE.to_uppercase());
        assert!(v.verify(&h, BODY.as_bytes(), at(T)).is_ok());
    }

    #[test]
    fn rejects_wrong_secret() {
        let v = Verifier::new("whsec_other").unwrap();
        assert_eq!(
            v.verify(&hdr(SIG_ACTIVE), BODY.as_bytes(), at(T)),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let v = Verifier::new(ACTIVE).unwrap();
        let tampered = BODY.replace("erpi.session.completed", "connect.consent.revoked");
        assert_eq!(
            v.verify(&hdr(SIG_ACTIVE), tampered.as_bytes(), at(T)),
            Err(WebhookError::SignatureMismatch)
        );
        // A single appended byte (e.g. trailing newline from re-serialization) also fails.
        let mut extra = BODY.as_bytes().to_vec();
        extra.push(b'\n');
        assert_eq!(
            v.verify(&hdr(SIG_ACTIVE), &extra, at(T)),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn rejects_tampered_timestamp() {
        // Same MAC, but the attacker bumps t to dodge the replay window.
        let v = Verifier::new(ACTIVE).unwrap();
        let h = format!("t={},v1={SIG_ACTIVE}", T + 1000);
        assert_eq!(
            v.verify(&h, BODY.as_bytes(), at(T + 1000)),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn replay_window_boundaries() {
        let v = Verifier::new(ACTIVE).unwrap();
        let b = BODY.as_bytes();
        assert!(v.verify(&hdr(SIG_ACTIVE), b, at(T + 300)).is_ok());
        assert!(v.verify(&hdr(SIG_ACTIVE), b, at(T - 300)).is_ok());
        assert_eq!(
            v.verify(&hdr(SIG_ACTIVE), b, at(T + 301)),
            Err(WebhookError::TimestampOutOfWindow { skew_secs: 301 })
        );
        assert_eq!(
            v.verify(&hdr(SIG_ACTIVE), b, at(T - 301)),
            Err(WebhookError::TimestampOutOfWindow { skew_secs: -301 })
        );
    }

    #[test]
    fn expired_timestamp_is_rejected_even_with_valid_mac() {
        let v = Verifier::new(ACTIVE).unwrap();
        let err = v
            .verify(&hdr(SIG_ACTIVE), BODY.as_bytes(), at(T + 86_400))
            .unwrap_err();
        assert!(matches!(err, WebhookError::TimestampOutOfWindow { .. }));
    }

    #[test]
    fn rotation_accepts_both_secrets_during_grace() {
        let rotated = at(T - 3600);
        let v = Verifier::new(ACTIVE)
            .unwrap()
            .with_previous(PREVIOUS, rotated)
            .unwrap();
        let b = BODY.as_bytes();
        assert_eq!(
            v.verify(&hdr(SIG_ACTIVE), b, at(T)).unwrap().matched,
            MatchedSecret::Active
        );
        assert_eq!(
            v.verify(&hdr(SIG_PREVIOUS), b, at(T)).unwrap().matched,
            MatchedSecret::Previous
        );
    }

    #[test]
    fn previous_secret_stops_working_after_24h() {
        let rotated = at(T - 24 * 3600 + 10); // expires at T + 10
        let v = Verifier::new(ACTIVE)
            .unwrap()
            .with_previous(PREVIOUS, rotated)
            .unwrap();
        let b = BODY.as_bytes();
        assert!(v.verify(&hdr(SIG_PREVIOUS), b, at(T + 9)).is_ok());
        assert_eq!(
            v.verify(&hdr(SIG_PREVIOUS), b, at(T + 10)),
            Err(WebhookError::SignatureMismatch)
        );
        // Active keeps working after the grace window closes.
        assert!(v.verify(&hdr(SIG_ACTIVE), b, at(T + 10)).is_ok());
    }

    #[test]
    fn without_previous_old_signatures_fail() {
        let v = Verifier::new(ACTIVE).unwrap();
        assert_eq!(
            v.verify(&hdr(SIG_PREVIOUS), BODY.as_bytes(), at(T)),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn rotation_transition_new_active_old_previous() {
        // Before rotation: S1 active. After rotation: S2 active, S1 previous.
        let (s1, s2) = (PREVIOUS, ACTIVE);
        let before = Verifier::new(s1).unwrap();
        let after = Verifier::new(s2)
            .unwrap()
            .with_previous(s1, at(T - 5))
            .unwrap();
        let b = BODY.as_bytes();
        assert!(before.verify(&hdr(SIG_PREVIOUS), b, at(T)).is_ok());
        assert_eq!(
            before.verify(&hdr(SIG_ACTIVE), b, at(T)),
            Err(WebhookError::SignatureMismatch)
        );
        assert_eq!(
            after.verify(&hdr(SIG_PREVIOUS), b, at(T)).unwrap().matched,
            MatchedSecret::Previous
        );
        assert_eq!(
            after.verify(&hdr(SIG_ACTIVE), b, at(T)).unwrap().matched,
            MatchedSecret::Active
        );
    }

    #[test]
    fn signs_the_header_timestamp_text_verbatim() {
        // "t=01700000000" is numerically T but the signed string uses the raw text.
        let v = Verifier::new(ACTIVE).unwrap();
        let h = format!("t=01700000000,v1={SIG_ACTIVE}");
        assert_eq!(
            v.verify(&h, BODY.as_bytes(), at(T)),
            Err(WebhookError::SignatureMismatch)
        );
        let h = format!("t=01700000000,v1={}", sign(ACTIVE, "01700000000", BODY));
        assert!(v.verify(&h, BODY.as_bytes(), at(T)).is_ok());
    }

    #[test]
    fn rejects_malformed_headers() {
        let v = Verifier::new(ACTIVE).unwrap();
        let b = BODY.as_bytes();
        let bad = |h: &str| matches!(v.verify(h, b, at(T)), Err(WebhookError::MalformedHeader(_)));
        assert!(bad(""));
        assert!(bad("garbage"));
        assert!(bad(&format!("v1={SIG_ACTIVE}")));
        assert!(bad(&format!("t={T}")));
        assert!(bad(&format!("t={T},v1=")));
        assert!(bad(&format!("t={T},v1={}", &SIG_ACTIVE[..62])));
        assert!(bad(&format!("t={T},v1={SIG_ACTIVE}00")));
        assert!(bad(&format!("t={T},v1={}zz", &SIG_ACTIVE[..62])));
        assert!(bad(&format!("t=-{T},v1={SIG_ACTIVE}")));
        assert!(bad(&format!("t=+{T},v1={SIG_ACTIVE}")));
        assert!(bad(&format!("t=17e8,v1={SIG_ACTIVE}")));
        assert!(bad(&format!("t=99999999999999999999,v1={SIG_ACTIVE}")));
        assert!(bad(&format!("t={T},t={T},v1={SIG_ACTIVE}")));
        assert!(bad(&format!("t={T},v1={SIG_ACTIVE},v1={SIG_ACTIVE}")));
    }

    #[test]
    fn empty_secrets_are_rejected_at_construction() {
        assert_eq!(Verifier::new("").err(), Some(WebhookError::EmptySecret));
        assert_eq!(
            Verifier::new(ACTIVE)
                .unwrap()
                .with_previous("", at(0))
                .err(),
            Some(WebhookError::EmptySecret)
        );
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let v = Verifier::new(ACTIVE)
            .unwrap()
            .with_previous(PREVIOUS, at(T))
            .unwrap();
        let d = format!("{v:?}");
        assert!(!d.contains("whsec") && !d.contains("secret_for_tests"));
    }
}
