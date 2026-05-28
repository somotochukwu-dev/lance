use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::{
    db::AppState,
    error::Result,
    models::{Evidence, SubmitEvidenceRequest},
    routes::pagination::PaginationQuery,
};

#[tracing::instrument(skip(state, pagination))]
pub async fn list_evidence(
    State(state): State<AppState>,
    Path(dispute_id): Path<Uuid>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<Vec<Evidence>>> {
    let bounds = pagination.bounds();
    let evidence = sqlx::query_as::<_, Evidence>(
        r#"SELECT id, dispute_id, submitted_by, content, file_hash, created_at
           FROM evidence
           WHERE dispute_id = $1
           ORDER BY created_at ASC, id ASC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(dispute_id)
    .bind(bounds.limit)
    .bind(bounds.offset)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(evidence))
}

#[tracing::instrument(skip(state, req))]
pub async fn submit_evidence(
    State(state): State<AppState>,
    Path(dispute_id): Path<Uuid>,
    Json(req): Json<SubmitEvidenceRequest>,
) -> Result<Json<Evidence>> {
    let evidence = sqlx::query_as::<_, Evidence>(
        r#"INSERT INTO evidence (dispute_id, submitted_by, content, file_hash)
           VALUES ($1, $2, $3, $4)
           RETURNING id, dispute_id, submitted_by, content, file_hash, created_at"#,
    )
    .bind(dispute_id)
    .bind(req.submitted_by)
    .bind(req.content)
    .bind(req.file_hash)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(evidence))
}
