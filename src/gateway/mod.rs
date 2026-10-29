//! The standalone gateway: a small Axum service that lets closed SaaS
//! platforms (which can't run a plugin) start Xentree Connect sessions,
//! deliver webhooks and deprovision users.
//!
//! Two listeners with different trust levels:
//! - **public** (`/launch`, `/webhook`, `/health`): reachable by browsers and Xentree;
//! - **internal** (`/deprovision/{user_id}`): reachable only by trusted backends,
//!   and still behind the gateway secret.

mod auth;
mod html;
mod routes;
mod seen;
mod server;
mod settings;
mod state;

#[cfg(test)]
mod tests;

pub use routes::{internal_router, public_router};
pub use server::{run, serve};
pub use settings::{GatewayArgs, Settings, MIN_SECRET_LEN};
pub use state::GatewayState;
