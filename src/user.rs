use axum::routing::{get, post};
use axum::Router;

use crate::user::handler::register;

mod handler;
pub mod model;
mod service;
mod mail;

pub fn user_router() -> Router {
    Router::new()
        .route("/api/user", get(|| async { "get_user" }))
        .route("/api/user/me", get(|| async { "get_user/me" }))
        .route("/api/user/login", get(|| async { "get_user/login" }))
        .route("/api/user/register", post(register))
}