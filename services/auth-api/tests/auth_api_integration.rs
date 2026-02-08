use auth_api::{build_app, AppState};
use axum::{
    body::Body,
    http::{
        header::{CONTENT_TYPE, SET_COOKIE},
        Request, StatusCode,
    },
};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn create_session_sets_session_and_csrf_cookies() {
    let app = build_app(AppState::new(String::new(), false));
    let request = Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"subject":"alice"}"#))
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);

    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie must be valid utf8")
                .to_string()
        })
        .collect();

    assert_eq!(cookies.len(), 2);
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("session=") && cookie.contains("HttpOnly")));
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("csrf-token=")));

    let body = response
        .into_body()
        .collect()
        .await
        .expect("body should be readable")
        .to_bytes();
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response should be valid json");
    assert_eq!(json["subject"], "alice");
    assert_eq!(json["message"], "local session issued");
}

#[tokio::test]
async fn logout_expires_cookies() {
    let app = build_app(AppState::new(String::new(), false));
    let request = Request::builder()
        .method("POST")
        .uri("/auth/logout")
        .body(Body::empty())
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);

    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie must be valid utf8")
                .to_string()
        })
        .collect();

    assert_eq!(cookies.len(), 2);
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("session=deleted") && cookie.contains("Max-Age=0")));
    assert!(cookies
        .iter()
        .any(|cookie| cookie.starts_with("csrf-token=deleted") && cookie.contains("Max-Age=0")));
}

#[tokio::test]
async fn secure_domain_config_is_reflected_in_cookies() {
    let app = build_app(AppState::new("example.com".to_string(), true));
    let request = Request::builder()
        .method("POST")
        .uri("/auth/session")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{}"#))
        .expect("request should build");

    let response = app.oneshot(request).await.expect("request should succeed");
    assert_eq!(response.status(), StatusCode::CREATED);

    let cookies: Vec<String> = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie must be valid utf8")
                .to_string()
        })
        .collect();

    assert!(cookies
        .iter()
        .all(|cookie| cookie.contains("Secure") && cookie.contains("Domain=example.com")));
}
