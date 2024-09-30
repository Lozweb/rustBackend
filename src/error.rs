use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::future::Future;
use tracing::error;

pub async fn handle_error<T: Future<Output=anyhow::Result<()>>>(run: fn() -> T) {
    if let Err(err) = run().await {
        error!("{}", err);
        err.chain().for_each(|cause| error!("because: {}", cause));
        std::process::exit(1);
    }
}

pub enum AppError {
    Unauthorized,
    NotFound,
    BadRequest,
    Conflict(String),
    Unexpected(anyhow::Error),
}

pub type Result<T> = anyhow::Result<T, AppError>;

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status_code, body) = match self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized : invalid username or password".to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Not Found".to_string()),
            AppError::BadRequest => (StatusCode::BAD_REQUEST, "Bad Request".to_string()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            AppError::Unexpected(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string()),
        };
        (status_code, body).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self::Unexpected(err.into())
    }
}