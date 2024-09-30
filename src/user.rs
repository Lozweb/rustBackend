mod handler;

use axum::routing::get;
use axum::Router;

pub fn user_router() -> Router {
    Router::new()
        .route("/api/user", get(|| async { "get_user" }))
        .route("/api/user/me", get(|| async { "get_user/me" }))
        .route("/api/user/login", get(|| async { "get_user/login" }))
}