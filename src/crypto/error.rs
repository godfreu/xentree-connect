#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("system random number generator failed")]
    Rng,
    #[error("invalid PKCS#8 private key")]
    InvalidKey,
    #[error("invalid PEM: {0}")]
    InvalidPem(&'static str),
    #[error("signing failed")]
    Sign,
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}
