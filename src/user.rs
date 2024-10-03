use axum::routing::post;
use axum::Router;

use crate::user::handler::{confirm, login, register};

mod handler;
pub mod model;
mod service;
mod mail;

pub fn user_router() -> Router {
    Router::new()
        .route("/api/user/login", post(login))
        .route("/api/user/register", post(register))
        .route("/api/user/confirm/:token", post(confirm))
}