//! Ways to obtain an admin bearer token without copy-pasting one.

mod browser;
mod password;

pub use browser::{open_browser, BrowserLogin};
pub use password::login_with_password;

use crate::api::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The cloud rejected the email/password pair.
    #[error("incorrect email or password")]
    InvalidCredentials,
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("cannot start the local callback listener: {0}")]
    Listen(std::io::Error),
    #[error("timed out waiting for the browser login")]
    TimedOut,
    #[error("browser login failed: {0}")]
    Callback(String),
}
