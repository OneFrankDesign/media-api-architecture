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

#[derive(Clone, Default)]
struct MetadataStore {
    records: Arc<RwLock<HashMap<String, VideoMetadata>>>,
}

#[derive(Clone, Default)]
struct MetadataServiceImpl {
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

        let mut rows: Vec<VideoMetadata> = self.store.records.read().await.values().cloned().collect();

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

fn apply_field(
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
        "owner_id" => target.owner_id = patch.owner_id.clone(),
        "visibility" => target.visibility = patch.visibility,
        _ => {
            return Err(Status::invalid_argument(format!(
                "unsupported update_mask field: {field}"
            )))
        }
    }

    Ok(())
}

fn validate_metadata(metadata: &VideoMetadata) -> std::result::Result<(), Status> {
    if metadata.title.trim().is_empty() {
        return Err(Status::invalid_argument("title cannot be empty"));
    }

    if metadata.file_size < 0 {
        return Err(Status::invalid_argument("file_size must be >= 0"));
    }

    Ok(())
}

fn sort_key(row: &VideoMetadata) -> (i64, i32, String) {
    let (seconds, nanos) = row
        .created_at
        .as_ref()
        .map(|ts| (ts.seconds, ts.nanos))
        .unwrap_or((0, 0));

    (seconds, nanos, row.id.clone())
}

fn now_timestamp() -> Option<Timestamp> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;

    Some(Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    })
}

fn normalize_page_size(raw: i32) -> usize {
    if raw <= 0 {
        return 20;
    }

    raw.min(100) as usize
}

fn parse_page_token(token: &str) -> std::result::Result<usize, Status> {
    if token.is_empty() {
        return Ok(0);
    }

    token
        .parse::<usize>()
        .map_err(|_| Status::invalid_argument("invalid page_token: expected a numeric offset"))
}

async fn healthz() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> AnyhowResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "main_api=info,tower_http=info".into()),
        )
        .init();

    let grpc_addr = SocketAddr::from(([0, 0, 0, 0], 50051));
    let health_addr = SocketAddr::from(([0, 0, 0, 0], 50052));

    info!(%grpc_addr, "starting gRPC server");
    info!(%health_addr, "starting HTTP health endpoint");

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut tasks = JoinSet::new();

    let grpc_service = MetadataServiceImpl::default();
    let mut grpc_shutdown = shutdown_tx.subscribe();
    tasks.spawn(async move {
        let result = Server::builder()
            .add_service(MetadataServiceServer::new(grpc_service))
            .serve_with_shutdown(grpc_addr, async move {
                let _ = grpc_shutdown.recv().await;
            })
            .await
            .map_err(anyhow::Error::from);
        ("gRPC", result)
    });

    let mut health_shutdown = shutdown_tx.subscribe();
    tasks.spawn(async move {
        let result: AnyhowResult<()> = async move {
            let app = Router::new().route("/healthz", get(healthz));
            let listener = TcpListener::bind(health_addr)
                .await
                .map_err(anyhow::Error::from)?;
            axum::serve(listener, app)
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
        _ = tokio::signal::ctrl_c() => {
            info!("shutdown signal received");
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
