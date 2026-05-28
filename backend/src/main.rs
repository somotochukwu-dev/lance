use axum::Router;
use dotenvy::dotenv;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod db;
mod error;
mod models;
mod routes;
mod services;
mod worker;

pub use db::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "backend=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool_config = config::DatabasePoolConfig::from_env()?;
    let cors_config = config::CorsConfig::from_env()?;

    let pool = pool_config.connect_pool(&database_url).await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    let state = AppState::new(pool.clone());
    tokio::spawn(worker::run_judge_worker(pool));
    let app = build_router(state, cors_config);

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "3001".to_string())
        .parse()?;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("🚀 Backend listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: AppState, cors_config: config::CorsConfig) -> Router {
    Router::new()
        .nest("/api", routes::api_router())
        .layer(cors_config.layer())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
