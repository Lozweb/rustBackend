use std::net::SocketAddr;

use anyhow::Result;
use axum::http::Method;
use axum::{http, Extension, Router};
use dotenvy::dotenv;
use moka::sync::Cache;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace;
use tower_http::trace::TraceLayer;
use tracing::Level;

use rust_backend::config::Config;
use rust_backend::db::init_db;
use rust_backend::error::handle_error;
use rust_backend::user::model::UserPendingQueryCache;
use rust_backend::user::user_router;

#[tokio::main]
async fn main() {
    configure_logger();
    handle_error(try_main).await;
}

fn configure_logger() {
    #[cfg(debug_assertions)]
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(Level::INFO)
        .compact()
        .init();

    #[cfg(not(debug_assertions))]
    tracing_subscriber::fmt()
        .json()
        .with_max_level(Level::INFO)
        .with_current_span(false)
        .init();
}

async fn try_main() -> Result<()> {
    dotenv().ok();
    let config = Config::load();
    let db = init_db().await?;

    let cache: UserPendingQueryCache = Cache::new(1000);

    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
        .on_response(trace::DefaultOnResponse::new().level(Level::INFO));

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            http::header::AUTHORIZATION,
            http::header::CONTENT_TYPE,
            http::header::CONTENT_LENGTH,
        ])
        .allow_origin(Any);

    let app = Router::new()
        .merge(user_router())
        .layer(trace_layer)
        .layer(cors)
        .layer(Extension(db))
        .layer(Extension(cache))
        .layer(Extension(config));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("expect tokio signal ctrl-c");
}