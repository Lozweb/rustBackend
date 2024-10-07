use axum::routing::{get, post};
use axum::Router;

use crate::user::handler::{confirm, get_users, login, register, reset};

mod handler;
pub mod model;
mod service;
mod mail;
mod extractor;

pub fn user_router() -> Router {
    Router::new()
        .route("/api/user", get(get_users))
        .route("/api/user/login", post(login))
        .route("/api/user/register", post(register))
        .route("/api/user/confirm/:token", post(confirm))
        .route("/api/user/reset", post(reset))
}