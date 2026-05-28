use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

use crate::{
    db::AppState,
    error::{AppError, Result},
    models::{CreateJobRequest, Job, MarkJobFundedRequest},
    routes::{bids, deliverables, milestones},
};

const DEFAULT_JOB_PAGE_LIMIT: i64 = 25;
const MAX_JOB_PAGE_LIMIT: i64 = 100;

#[derive(Debug, Deserialize)]
struct ListJobsQuery {
    limit: Option<i64>,
    cursor_created_at: Option<DateTime<Utc>>,
    cursor_id: Option<Uuid>,
    min_budget: Option<i64>,
    max_budget: Option<i64>,
    skills: Option<String>,
    deadline_before: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct JobPage {
    items: Vec<Job>,
    next_cursor: Option<JobCursor>,
    limit: i64,
}

#[derive(Debug, Serialize)]
struct JobCursor {
    created_at: DateTime<Utc>,
    id: Uuid,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_jobs).post(create_job))
        .route("/:id", get(get_job))
        .route("/:id/fund", post(mark_job_funded))
        .route("/:id/bids", get(bids::list_bids).post(bids::create_bid))
        .route("/:id/bids/:bid_id/accept", post(bids::accept_bid))
        .route(
            "/:id/deliverables",
            get(deliverables::list_deliverables).post(deliverables::submit_deliverable),
        )
        .route(
            "/:id/dispute",
            get(crate::routes::disputes::get_job_dispute)
                .post(crate::routes::disputes::open_dispute_for_job),
        )
        .route("/:id/milestones", get(milestones::list_milestones))
        .route(
            "/:id/milestones/:mid/release",
            post(milestones::release_milestone),
        )
}

#[tracing::instrument(skip(state), fields(limit = query.limit.unwrap_or(DEFAULT_JOB_PAGE_LIMIT)))]
async fn list_jobs(
    State(state): State<AppState>,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<JobPage>> {
    if matches!(
        (query.cursor_created_at, query.cursor_id),
        (Some(_), None) | (None, Some(_))
    ) {
        return Err(AppError::BadRequest(
            "cursor_created_at and cursor_id must be provided together".into(),
        ));
    }
    if matches!((query.min_budget, query.max_budget), (Some(min), Some(max)) if min > max) {
        return Err(AppError::BadRequest(
            "min_budget cannot be greater than max_budget".into(),
        ));
    }

    let limit = query
        .limit
        .unwrap_or(DEFAULT_JOB_PAGE_LIMIT)
        .clamp(1, MAX_JOB_PAGE_LIMIT);
    let skill_filters: Vec<String> = query
        .skills
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|skill| !skill.is_empty())
        .map(str::to_owned)
        .collect();

    let mut builder = QueryBuilder::<Postgres>::new(
        r#"SELECT id, title, description, budget_usdc, milestones, client_address,
                  freelancer_address, status, metadata_hash, on_chain_job_id,
                  created_at, updated_at
           FROM jobs"#,
    );

    let mut has_where = false;
    append_where(&mut builder, &mut has_where);
    builder
        .push(" budget_usdc >= ")
        .push_bind(query.min_budget.unwrap_or(0));

    if let Some(max_budget) = query.max_budget {
        append_where(&mut builder, &mut has_where);
        builder.push(" budget_usdc <= ").push_bind(max_budget);
    }
    if !skill_filters.is_empty() {
        append_where(&mut builder, &mut has_where);
        builder.push(" skills && ").push_bind(skill_filters);
    }
    if let Some(deadline_before) = query.deadline_before {
        append_where(&mut builder, &mut has_where);
        builder.push(" deadline_at <= ").push_bind(deadline_before);
    }
    if let (Some(cursor_created_at), Some(cursor_id)) = (query.cursor_created_at, query.cursor_id) {
        append_where(&mut builder, &mut has_where);
        builder
            .push(" (created_at, id) < (")
            .push_bind(cursor_created_at)
            .push(", ")
            .push_bind(cursor_id)
            .push(")");
    }

    builder
        .push(" ORDER BY created_at DESC, id DESC LIMIT ")
        .push_bind(limit + 1);

    let mut jobs = builder
        .build_query_as::<Job>()
        .fetch_all(&state.pool)
        .await?;

    let has_next = jobs.len() > limit as usize;
    if has_next {
        jobs.truncate(limit as usize);
    }
    let next_cursor = if has_next {
        jobs.last().map(|job| JobCursor {
            created_at: job.created_at,
            id: job.id,
        })
    } else {
        None
    };

    tracing::debug!(returned = jobs.len(), has_next = next_cursor.is_some());
    Ok(Json(JobPage {
        items: jobs,
        next_cursor,
        limit,
    }))
}

fn append_where(builder: &mut QueryBuilder<'_, Postgres>, has_where: &mut bool) {
    if *has_where {
        builder.push(" AND");
    } else {
        builder.push(" WHERE");
        *has_where = true;
    }
}

async fn get_job(State(state): State<AppState>, Path(id): Path<Uuid>) -> Result<Json<Job>> {
    let job = sqlx::query_as::<_, Job>(
        r#"SELECT id, title, description, budget_usdc, milestones, client_address,
                  freelancer_address, status, metadata_hash, on_chain_job_id,
                  created_at, updated_at
           FROM jobs WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("job {id} not found")))?;
    Ok(Json(job))
}

async fn create_job(
    State(state): State<AppState>,
    Json(req): Json<CreateJobRequest>,
) -> Result<Json<Job>> {
    if req.title.is_empty() {
        return Err(AppError::BadRequest("title is required".into()));
    }
    if req.milestones < 1 {
        return Err(AppError::BadRequest("milestones must be at least 1".into()));
    }
    if req.budget_usdc <= 0 {
        return Err(AppError::BadRequest(
            "budget must be greater than zero".into(),
        ));
    }

    let mut tx = state.pool.begin().await?;

    let job = sqlx::query_as::<_, Job>(
        r#"INSERT INTO jobs (
               title, description, budget_usdc, milestones, client_address, status, skills, deadline_at
           )
           VALUES ($1, $2, $3, $4, $5, 'open', $6, $7)
           RETURNING id, title, description, budget_usdc, milestones, client_address,
                     freelancer_address, status, metadata_hash, on_chain_job_id,
                     created_at, updated_at"#,
    )
    .bind(req.title)
    .bind(req.description)
    .bind(req.budget_usdc)
    .bind(req.milestones)
    .bind(req.client_address)
    .bind(req.skills)
    .bind(req.deadline_at)
    .fetch_one(&mut *tx)
    .await?;

    let per_milestone = job.budget_usdc / i64::from(job.milestones);
    let remainder = job.budget_usdc % i64::from(job.milestones);

    for index in 0..job.milestones {
        let amount_usdc = if index == job.milestones - 1 {
            per_milestone + remainder
        } else {
            per_milestone
        };

        sqlx::query(
            r#"INSERT INTO milestones (job_id, index, title, amount_usdc, status)
               VALUES ($1, $2, $3, $4, 'pending')"#,
        )
        .bind(job.id)
        .bind(index + 1)
        .bind(format!("Milestone {}", index + 1))
        .bind(amount_usdc)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(Json(job))
}

async fn mark_job_funded(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
    Json(req): Json<MarkJobFundedRequest>,
) -> Result<Json<Job>> {
    let (client_address, freelancer_address, status): (String, Option<String>, String) =
        sqlx::query_as(
            r#"SELECT client_address, freelancer_address, status
               FROM jobs WHERE id = $1"#,
        )
        .bind(job_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("job {job_id} not found")))?;

    if client_address != req.client_address {
        return Err(AppError::BadRequest(
            "only the client can mark a job as funded".into(),
        ));
    }
    if freelancer_address.is_none() {
        return Err(AppError::BadRequest(
            "job must have an accepted freelancer first".into(),
        ));
    }
    if !matches!(
        status.as_str(),
        "awaiting_funding" | "funded" | "in_progress"
    ) {
        return Err(AppError::BadRequest(format!(
            "job status '{status}' cannot transition to funded"
        )));
    }

    let job = sqlx::query_as::<_, Job>(
        r#"UPDATE jobs
           SET status = 'funded'
           WHERE id = $1
           RETURNING id, title, description, budget_usdc, milestones, client_address,
                     freelancer_address, status, metadata_hash, on_chain_job_id,
                     created_at, updated_at"#,
    )
    .bind(job_id)
    .fetch_one(&state.pool)
    .await?;

    // Create milestone records in 'milestones' table
    if job.milestones > 0 {
        let amount_per = job.budget_usdc / (job.milestones as i64);
        for i in 0..job.milestones {
            sqlx::query(
                r#"INSERT INTO milestones (job_id, index, title, amount_usdc, status)
                   VALUES ($1, $2, $3, $4, 'pending')"#,
            )
            .bind(job.id)
            .bind(i)
            .bind(format!("Milestone {}", i + 1))
            .bind(amount_per)
            .execute(&state.pool)
            .await?;
        }
    }

    Ok(Json(job))
}
