//! The HTTP surface: `provider/v1` routes for service instances.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    PROVIDER_DELETE_ACTION, PROVIDER_RECONCILE_ACTION, PROVIDER_STATUS_GET_ACTION,
    auth::{AuthError, ProviderAuthenticator, ProviderClaims},
    pve::PveError,
    reconcile::{ReconcileError, Reconciler},
    spec::{MAX_NAME_BYTES, VmSpec},
};

pub struct AppState {
    pub authenticator: ProviderAuthenticator,
    pub reconciler: Arc<Reconciler>,
    pub region: String,
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route(
            "/internal/v1/service-instances/{service_instance_id}",
            put(reconcile).delete(remove).get(get_status),
        )
        .with_state(state)
}

async fn live() -> impl IntoResponse {
    Json(json!({"status": "live"}))
}

async fn ready(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
    state
        .reconciler
        .ping()
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(Json(json!({"status": "ready"})))
}

#[derive(Deserialize)]
struct ReconcileRequest {
    generation: i64,
    name: String,
    spec: Value,
}

#[derive(Serialize)]
struct AcceptedOperation {
    operation_id: Uuid,
    status: Value,
}

impl AcceptedOperation {
    fn new(service_instance_id: Uuid, generation: i64, action: &str, status: Value) -> Self {
        let key = format!("{service_instance_id}:{generation}:{action}");
        Self {
            operation_id: Uuid::new_v5(&Uuid::NAMESPACE_URL, key.as_bytes()),
            status,
        }
    }
}

fn validate_command(
    claims: &ProviderClaims,
    service_instance_id: Uuid,
    generation: i64,
) -> Result<(), ApiError> {
    if claims.service_instance_id != service_instance_id || claims.generation != generation {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn validate_display_name(value: &str) -> Result<(), ApiError> {
    if value.trim() != value || value.is_empty() || value.len() > MAX_NAME_BYTES {
        return Err(ApiError::BadRequest(
            "name must contain between 1 and 120 trimmed characters".into(),
        ));
    }
    Ok(())
}

async fn reconcile(
    State(state): State<Arc<AppState>>,
    Path(service_instance_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<ReconcileRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let claims = state
        .authenticator
        .authenticate(&headers, PROVIDER_RECONCILE_ACTION)?;
    validate_command(&claims, service_instance_id, request.generation)?;
    validate_display_name(&request.name)?;
    let spec: VmSpec = serde_json::from_value(request.spec)
        .map_err(|e| ApiError::BadRequest(format!("VM spec is invalid: {e}")))?;
    spec.validate(&state.region, &state.reconciler.settings().images)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let status = state
        .reconciler
        .advance(&claims, &request.name, &spec, request.generation)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedOperation::new(
            service_instance_id,
            request.generation,
            PROVIDER_RECONCILE_ACTION,
            status,
        )),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationQuery {
    generation: i64,
}

async fn remove(
    State(state): State<Arc<AppState>>,
    Path(service_instance_id): Path<Uuid>,
    Query(query): Query<GenerationQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let claims = state
        .authenticator
        .authenticate(&headers, PROVIDER_DELETE_ACTION)?;
    validate_command(&claims, service_instance_id, query.generation)?;
    let status = state.reconciler.remove(&claims, query.generation).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptedOperation::new(
            service_instance_id,
            query.generation,
            PROVIDER_DELETE_ACTION,
            status,
        )),
    ))
}

async fn get_status(
    State(state): State<Arc<AppState>>,
    Path(service_instance_id): Path<Uuid>,
    Query(query): Query<GenerationQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let claims = state
        .authenticator
        .authenticate(&headers, PROVIDER_STATUS_GET_ACTION)?;
    validate_command(&claims, service_instance_id, query.generation)?;
    Ok(Json(
        state.reconciler.status(&claims, query.generation).await?,
    ))
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("service instance was not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(String),
    #[error("provider is still reconciling the resource")]
    NotReady,
    #[error("{0}")]
    Conflict(String),
    #[error("provider command is forbidden")]
    Forbidden,
    #[error("{0}")]
    Capacity(String),
    #[error("virtualization backend is unavailable")]
    Unavailable,
    #[error("internal provider error")]
    Internal,
    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl From<ReconcileError> for ApiError {
    fn from(error: ReconcileError) -> Self {
        match error {
            ReconcileError::NotReady => Self::NotReady,
            ReconcileError::NotFound => Self::NotFound,
            ReconcileError::Conflict(m) => Self::Conflict(m),
            ReconcileError::BadRequest(m) => Self::BadRequest(m),
            ReconcileError::Forbidden => Self::Forbidden,
            ReconcileError::Capacity(m) => Self::Capacity(m),
            ReconcileError::Pve(PveError::Locked) => Self::NotReady,
            ReconcileError::Pve(PveError::NotFound) => Self::NotReady,
            ReconcileError::Pve(PveError::Unavailable(m)) => {
                tracing::warn!(error = %m, "Proxmox VE unavailable");
                Self::Unavailable
            }
            ReconcileError::Pve(PveError::Rejected { status, message }) => {
                tracing::error!(status, error = %message, "Proxmox VE rejected a request");
                Self::Internal
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::NotReady => (StatusCode::SERVICE_UNAVAILABLE, "operation_in_progress"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "generation_conflict"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Capacity(_) => (StatusCode::INSUFFICIENT_STORAGE, "capacity_exhausted"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "backend_unavailable"),
            Self::Auth(AuthError::MissingCredentials) => {
                (StatusCode::UNAUTHORIZED, "missing_credentials")
            }
            Self::Auth(_) => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        let mut response = (
            status,
            Json(json!({"error": {"code": code, "message": self.to_string()}})),
        )
            .into_response();
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static("2"));
        }
        response
    }
}
