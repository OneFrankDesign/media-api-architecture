use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::Result as AnyhowResult;
use axum::{routing::get, Router};
use prost_types::Timestamp;
use tokio::{
    net::TcpListener,
    sync::{broadcast, RwLock},
    task::JoinSet,
};
use tonic::{transport::Server, Request, Response, Status};
use tracing::{error, info};
use uuid::Uuid;

pub mod api {
    pub mod v1 {
        tonic::include_proto!("api.v1");
    }
}

use api::v1::metadata_service_server::{MetadataService, MetadataServiceServer};
use api::v1::{
    CreateMetadataRequest, CreateMetadataResponse, DeleteMetadataRequest, DeleteMetadataResponse,
    GetMetadataRequest, GetMetadataResponse, HealthRequest, HealthResponse, ListMetadataRequest,
    ListMetadataResponse, UpdateMetadataRequest, UpdateMetadataResponse, VideoMetadata,
};

pub const DEFAULT_GRPC_ADDR: &str = "0.0.0.0:50051";
pub const DEFAULT_HEALTH_ADDR: &str = "0.0.0.0:50052";

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub grpc_addr: SocketAddr,
    pub health_addr: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            grpc_addr: DEFAULT_GRPC_ADDR
                .parse()
                .expect("default gRPC listen address must parse"),
            health_addr: DEFAULT_HEALTH_ADDR
                .parse()
                .expect("default health listen address must parse"),
        }
    }
}

#[derive(Clone, Default)]
pub struct MetadataStore {
    records: Arc<RwLock<HashMap<String, VideoMetadata>>>,
}

#[derive(Clone, Default)]
pub struct MetadataServiceImpl {
    store: MetadataStore,
}

#[tonic::async_trait]
impl MetadataService for MetadataServiceImpl {
    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> std::result::Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: api::v1::health_response::Status::Healthy as i32,
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: now_timestamp(),
        }))
    }

    async fn create_metadata(
        &self,
        request: Request<CreateMetadataRequest>,
    ) -> std::result::Result<Response<CreateMetadataResponse>, Status> {
        let req = request.into_inner();

        if req.title.trim().is_empty() {
            return Err(Status::invalid_argument("title is required"));
        }

        let id = Uuid::new_v4().to_string();
        let metadata = VideoMetadata {
            id: id.clone(),
            resource_id: format!("res-{id}"),
            title: req.title,
            description: req.description,
            tags: req.tags,
            mime_type: req.mime_type,
            file_size: req.file_size,
            owner_id: "local-user".to_string(),
            visibility: req.visibility,
            created_at: now_timestamp(),
            updated_at: now_timestamp(),
        };

        validate_metadata(&metadata)?;

        self.store
            .records
            .write()
            .await
            .insert(id, metadata.clone());

        Ok(Response::new(CreateMetadataResponse {
            metadata: Some(metadata),
            from_cache: false,
        }))
    }

    async fn get_metadata(
        &self,
        request: Request<GetMetadataRequest>,
    ) -> std::result::Result<Response<GetMetadataResponse>, Status> {
        let id = request.into_inner().id;

        if id.trim().is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        let metadata = self
            .store
            .records
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or_else(|| Status::not_found("metadata not found"))?;

        Ok(Response::new(GetMetadataResponse {
            metadata: Some(metadata),
            from_cache: false,
        }))
    }

    async fn list_metadata(
        &self,
        request: Request<ListMetadataRequest>,
    ) -> std::result::Result<Response<ListMetadataResponse>, Status> {
        let req = request.into_inner();

        let page_size = normalize_page_size(req.page_size);
        let offset = parse_page_token(&req.page_token)?;

        let mut rows: Vec<VideoMetadata> =
            self.store.records.read().await.values().cloned().collect();

        if !req.filter_owner_id.is_empty() {
            rows.retain(|row| row.owner_id == req.filter_owner_id);
        }

        if req.filter_visibility != 0 {
            rows.retain(|row| row.visibility == req.filter_visibility);
        }

        if !req.filter_tags.is_empty() {
            rows.retain(|row| row.tags.iter().any(|tag| req.filter_tags.contains(tag)));
        }

        if !req.search_query.is_empty() {
            let needle = req.search_query.to_lowercase();
            rows.retain(|row| {
                row.title.to_lowercase().contains(&needle)
                    || row.description.to_lowercase().contains(&needle)
            });
        }

        rows.sort_by_key(sort_key);

        let total_count = rows.len() as i32;
        let start = offset.min(rows.len());
        let end = (start + page_size).min(rows.len());
        let next_page_token = if end < rows.len() {
            end.to_string()
        } else {
            String::new()
        };

        Ok(Response::new(ListMetadataResponse {
            metadata_list: rows[start..end].to_vec(),
            next_page_token,
            total_count,
        }))
    }

    async fn update_metadata(
        &self,
        request: Request<UpdateMetadataRequest>,
    ) -> std::result::Result<Response<UpdateMetadataResponse>, Status> {
        let req = request.into_inner();

        if req.id.trim().is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        let patch = req
            .metadata
            .ok_or_else(|| Status::invalid_argument("metadata payload is required"))?;

        let mut guard = self.store.records.write().await;
        let existing = guard
            .get_mut(&req.id)
            .ok_or_else(|| Status::not_found("metadata not found"))?;
        let mut candidate = existing.clone();

        let mask = req
            .update_mask
            .ok_or_else(|| Status::invalid_argument("update_mask is required"))?;
        if mask.paths.is_empty() {
            return Err(Status::invalid_argument(
                "update_mask.paths must not be empty when update_mask is provided",
            ));
        }

        for path in mask.paths {
            apply_field(&mut candidate, &patch, &path)?;
        }

        validate_metadata(&candidate)?;
        candidate.updated_at = now_timestamp();
        *existing = candidate.clone();

        Ok(Response::new(UpdateMetadataResponse {
            metadata: Some(candidate),
            from_cache: false,
        }))
    }

    async fn delete_metadata(
        &self,
        request: Request<DeleteMetadataRequest>,
    ) -> std::result::Result<Response<DeleteMetadataResponse>, Status> {
        let req = request.into_inner();

        if req.id.trim().is_empty() {
            return Err(Status::invalid_argument("id is required"));
        }

        let removed = self.store.records.write().await.remove(&req.id);
        if removed.is_none() {
            return Err(Status::not_found("metadata not found"));
        }

        Ok(Response::new(DeleteMetadataResponse {}))
    }
}

pub fn apply_field(
    target: &mut VideoMetadata,
    patch: &VideoMetadata,
    field: &str,
) -> std::result::Result<(), Status> {
    match field {
        "title" => target.title = patch.title.clone(),
        "description" => {
            target.description = patch.description.clone();
        }
        "tags" => target.tags = patch.tags.clone(),
        "mime_type" => target.mime_type = patch.mime_type.clone(),
        "file_size" => target.file_size = patch.file_size,
        "owner_id" => {
            return Err(Status::invalid_argument(
                "owner_id is server-managed and cannot be updated",
            ))
        }
        "visibility" => target.visibility = patch.visibility,
        _ => {
            return Err(Status::invalid_argument(format!(
                "unsupported update_mask field: {field}"
            )))
        }
    }

    Ok(())
}

pub fn validate_metadata(metadata: &VideoMetadata) -> std::result::Result<(), Status> {
    if metadata.title.trim().is_empty() {
        return Err(Status::invalid_argument("title cannot be empty"));
    }

    if metadata.mime_type.trim().is_empty() {
        return Err(Status::invalid_argument("mime_type cannot be empty"));
    }

    if metadata.file_size < 0 {
        return Err(Status::invalid_argument("file_size must be >= 0"));
    }

    if api::v1::Visibility::try_from(metadata.visibility).is_err() {
        return Err(Status::invalid_argument(
            "visibility must be a known enum value",
        ));
    }

    Ok(())
}

pub fn sort_key(row: &VideoMetadata) -> (i64, i32, String) {
    let (seconds, nanos) = row
        .created_at
        .as_ref()
        .map(|ts| (ts.seconds, ts.nanos))
        .unwrap_or((0, 0));

    (seconds, nanos, row.id.clone())
}

pub fn now_timestamp() -> Option<Timestamp> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;

    Some(Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    })
}

pub fn normalize_page_size(raw: i32) -> usize {
    if raw <= 0 {
        return 20;
    }

    raw.min(100) as usize
}

pub fn parse_page_token(token: &str) -> std::result::Result<usize, Status> {
    if token.is_empty() {
        return Ok(0);
    }

    token
        .parse::<usize>()
        .map_err(|_| Status::invalid_argument("invalid page_token: expected a numeric offset"))
}

pub fn build_health_router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

async fn healthz() -> &'static str {
    "ok"
}

pub async fn run(config: ServerConfig) -> AnyhowResult<()> {
    info!(grpc_addr = %config.grpc_addr, "starting gRPC server");
    info!(health_addr = %config.health_addr, "starting HTTP health endpoint");

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut tasks = JoinSet::new();

    let grpc_service = MetadataServiceImpl::default();
    let mut grpc_shutdown = shutdown_tx.subscribe();
    tasks.spawn(async move {
        let result = Server::builder()
            .add_service(MetadataServiceServer::new(grpc_service))
            .serve_with_shutdown(config.grpc_addr, async move {
                let _ = grpc_shutdown.recv().await;
            })
            .await
            .map_err(anyhow::Error::from);
        ("gRPC", result)
    });

    let mut health_shutdown = shutdown_tx.subscribe();
    let health_addr = config.health_addr;
    tasks.spawn(async move {
        let result: AnyhowResult<()> = async move {
            let listener = TcpListener::bind(health_addr)
                .await
                .map_err(anyhow::Error::from)?;
            axum::serve(listener, build_health_router())
                .with_graceful_shutdown(async move {
                    let _ = health_shutdown.recv().await;
                })
                .await
                .map_err(anyhow::Error::from)?;
            Ok(())
        }
        .await;
        ("health", result)
    });

    let mut first_error: Option<anyhow::Error> = None;
    tokio::select! {
        signal = shutdown_signal() => {
            match signal {
                Ok(signal_name) => info!(signal = signal_name, "shutdown signal received"),
                Err(err) => {
                    error!(error = %err, "failed to listen for shutdown signal");
                    first_error = Some(err);
                }
            }
        }
        joined = tasks.join_next() => {
            if let Some(joined) = joined {
                if let Some(err) = observe_server_exit(joined) {
                    first_error = Some(err);
                }
            }
        }
    }

    let _ = shutdown_tx.send(());
    while let Some(joined) = tasks.join_next().await {
        if let Some(err) = observe_server_exit(joined) {
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }

    info!("shutdown complete");
    if let Some(err) = first_error {
        return Err(err);
    }

    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> AnyhowResult<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).map_err(anyhow::Error::from)?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map(|_| "SIGINT").map_err(anyhow::Error::from),
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> AnyhowResult<&'static str> {
    tokio::signal::ctrl_c().await.map_err(anyhow::Error::from)?;
    Ok("SIGINT")
}

fn observe_server_exit(
    joined: std::result::Result<(&'static str, AnyhowResult<()>), tokio::task::JoinError>,
) -> Option<anyhow::Error> {
    match joined {
        Ok((name, Ok(()))) => {
            info!(server = name, "server stopped");
            None
        }
        Ok((name, Err(err))) => {
            error!(server = name, error = %err, "server exited with error");
            Some(err)
        }
        Err(err) => {
            error!(error = %err, "server task panicked");
            Some(anyhow::Error::from(err))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata(id: &str, seconds: i64, nanos: i32) -> VideoMetadata {
        VideoMetadata {
            id: id.to_string(),
            resource_id: format!("res-{id}"),
            title: "sample".to_string(),
            description: "sample description".to_string(),
            tags: vec!["tag".to_string()],
            mime_type: "video/mp4".to_string(),
            file_size: 10,
            owner_id: "owner".to_string(),
            visibility: api::v1::Visibility::Private as i32,
            created_at: Some(Timestamp { seconds, nanos }),
            updated_at: Some(Timestamp { seconds, nanos }),
        }
    }

    #[test]
    fn normalize_page_size_defaults_and_caps() {
        assert_eq!(normalize_page_size(0), 20);
        assert_eq!(normalize_page_size(-10), 20);
        assert_eq!(normalize_page_size(25), 25);
        assert_eq!(normalize_page_size(500), 100);
    }

    #[test]
    fn parse_page_token_parses_numeric_offsets() {
        assert_eq!(parse_page_token("").expect("empty token should parse"), 0);
        assert_eq!(
            parse_page_token("7").expect("numeric token should parse"),
            7
        );

        let err = parse_page_token("not-a-number").expect_err("token should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn validate_metadata_checks_required_fields() {
        let mut metadata = sample_metadata("id-1", 1, 0);
        assert!(validate_metadata(&metadata).is_ok());

        metadata.title = "   ".to_string();
        let err = validate_metadata(&metadata).expect_err("empty title should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        metadata.title = "ok".to_string();
        metadata.mime_type = "   ".to_string();
        let err = validate_metadata(&metadata).expect_err("empty mime type should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        metadata.mime_type = "video/mp4".to_string();
        metadata.file_size = -1;
        let err = validate_metadata(&metadata).expect_err("negative size should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        metadata.file_size = 1;
        metadata.visibility = 99;
        let err = validate_metadata(&metadata).expect_err("invalid visibility should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn apply_field_updates_supported_fields_and_rejects_others() {
        let mut target = sample_metadata("id-1", 1, 0);
        let mut patch = sample_metadata("id-2", 2, 0);
        patch.title = "updated".to_string();
        patch.file_size = 42;
        patch.owner_id = "other-owner".to_string();

        apply_field(&mut target, &patch, "title").expect("title update should succeed");
        apply_field(&mut target, &patch, "file_size").expect("file size update should succeed");

        assert_eq!(target.title, "updated");
        assert_eq!(target.file_size, 42);

        let err = apply_field(&mut target, &patch, "owner_id")
            .expect_err("owner_id update should be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(target.owner_id, "owner");

        let err = apply_field(&mut target, &patch, "unknown").expect_err("field should fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn sort_key_orders_by_timestamp_then_id() {
        let mut rows = vec![
            sample_metadata("b", 10, 1),
            sample_metadata("a", 10, 1),
            sample_metadata("c", 9, 999),
        ];

        rows.sort_by_key(sort_key);

        let ids: Vec<String> = rows.into_iter().map(|row| row.id).collect();
        assert_eq!(ids, vec!["c".to_string(), "a".to_string(), "b".to_string()]);
    }
}
