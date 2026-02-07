use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    cookie_domain: Arc<String>,
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    subject: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    subject: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().any(|arg| arg == "--healthcheck") {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_api=info,tower_http=info".into()),
        )
        .init();

    let cookie_domain = std::env::var("COOKIE_DOMAIN").unwrap_or_else(|_| ".localhost".to_string());
    let state = AppState {
        cookie_domain: Arc::new(cookie_domain),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/auth/session", post(create_session))
        .route("/auth/logout", post(logout))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8081));
    info!(%addr, "starting auth api");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn create_session(
    State(state): State<AppState>,
    Json(payload): Json<SessionRequest>,
) -> impl IntoResponse {
    let subject = payload.subject.unwrap_or_else(|| "local-user".to_string());
    let session_token = Uuid::new_v4().to_string();
    let csrf_token = Uuid::new_v4().to_string();

    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&session_cookie(
        &session_token,
        state.cookie_domain.as_str(),
    )) {
        headers.append(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&csrf_cookie(
        &csrf_token,
        state.cookie_domain.as_str(),
    )) {
        headers.append(SET_COOKIE, v);
    }

    (
        StatusCode::CREATED,
        headers,
        Json(SessionResponse {
            subject,
            message: "local session issued".to_string(),
        }),
    )
}

async fn logout(State(state): State<AppState>) -> impl IntoResponse {
    let mut headers = HeaderMap::new();

    if let Ok(v) = HeaderValue::from_str(&expired_cookie("session", state.cookie_domain.as_str(), true)) {
        headers.append(SET_COOKIE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&expired_cookie("csrf-token", state.cookie_domain.as_str(), false)) {
        headers.append(SET_COOKIE, v);
    }

    (StatusCode::OK, headers, Json(serde_json::json!({ "message": "logged out" })))
}

fn session_cookie(token: &str, domain: &str) -> String {
    let mut cookie = format!("session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900");
    if !domain.trim().is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

fn csrf_cookie(token: &str, domain: &str) -> String {
    let mut cookie =
        format!("csrf-token={token}; Path=/; Secure; SameSite=Strict; Max-Age=86400");
    if !domain.trim().is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}

fn expired_cookie(name: &str, domain: &str, http_only: bool) -> String {
    let mut cookie = format!("{name}=deleted; Path=/; Secure; SameSite=Strict; Max-Age=0");
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if !domain.trim().is_empty() {
        cookie.push_str(&format!("; Domain={domain}"));
    }
    cookie
}
