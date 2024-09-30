use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

pub async fn init_db() -> Result<PgPool> {
    let db = PgPoolOptions::new()
        .max_connections(50)
        .connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL env var not set"))
        .await
        .context("Could not connect to database")?;

    sqlx::migrate!("./migrations/").run(&db).await?;

    Ok(db)
}
