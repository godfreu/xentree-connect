//! Xentree Connect core: ES256 key management, JWKS construction, assertion
//! signing, and hardened private-key storage.

pub mod api;
pub mod auth;
pub mod clock;
pub mod crypto;
pub mod fs;
pub mod utils;
pub mod webhook;

rust_i18n::i18n!("locales", fallback = "en");
pub mod commands;
pub mod config;
pub mod detectors;
pub mod gateway;
pub mod lang;
