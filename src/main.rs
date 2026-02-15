use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type HmacSha256 = Hmac<Sha256>;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/line/webhook", post(line_webhook));

    let port: u16 = std::env::var("PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn line_webhook(headers: HeaderMap, body: Bytes) -> StatusCode {
    let secret = match std::env::var("LINE_CHANNEL_SECRET") {
        Ok(v) => v,
        Err(_) => {
            tracing::error!("LINE_CHANNEL_SECRET is not set");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let sig = match headers.get("x-line-signature").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => {
            tracing::warn!("missing x-line-signature");
            return StatusCode::BAD_REQUEST;
        }
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&body);
    let expected = general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    if expected != sig {
        tracing::warn!("invalid signature");
        return StatusCode::UNAUTHORIZED;
    }

    match std::str::from_utf8(&body) {
        Ok(s) => tracing::info!("webhook body={}", s),
        Err(_) => tracing::info!("webhook body=<non-utf8 {} bytes>", body.len()),
    }

    StatusCode::OK
}

