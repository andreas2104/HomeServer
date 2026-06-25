pub mod middleware;
pub mod models;
pub mod routes;
pub mod utils;

use axum::{routing::post, Router};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    // Retrieve the database URL
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env");

    // Initialize PostgreSQL connection pool
    let pool = match PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
    {
        Ok(pool) => {
            println!("Connection to the database is successful!");
            pool
        }
        Err(err) => {
            eprintln!("Failed to connect to the database: {:?}", err);
            std::process::exit(1);
        }
    };

    let shared_pool = Arc::new(pool);

    // Build the application with auth routes
    let app = Router::new()
        .route("/auth/register", post(routes::auth::register))
        .route("/auth/login", post(routes::auth::login))
        .with_state(shared_pool);

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
