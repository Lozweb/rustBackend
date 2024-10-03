use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::{NoContext, Timestamp, Uuid};
//.connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL env var not set"))

pub fn new_uuid() -> Uuid {
    Uuid::new_v7(Timestamp::now(NoContext))
}

pub async fn init_db() -> Result<PgPool> {
    let db = PgPoolOptions::new()
        .max_connections(50)
        .connect("postgresql://rust:strong_password@localhost:5432/rust")
        .await
        .context("Could not connect to database")?;

    sqlx::migrate!("./migrations/").run(&db).await?;

    Ok(db)
}
