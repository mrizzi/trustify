#[cfg(test)]
mod test;

use super::{model::*, service::RiskAssessmentService};
use crate::{Error, db::DatabaseExt};
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, web};
use futures_util::stream::TryStreamExt;
use sea_orm::TransactionTrait;
use serde_json::json;
use std::io::Write;
use trustify_auth::{
    CreateRiskAssessment, DeleteRiskAssessment, ReadRiskAssessment, authorizer::Require,
};
use trustify_common::{db::Database, hashing::Digests, id::Id};
use trustify_module_storage::service::{StorageBackend, StorageKey, dispatch::DispatchBackend};

pub fn configure(
    config: &mut utoipa_actix_web::service_config::ServiceConfig,
    db: Database,
    storage: DispatchBackend,
) {
    let service = RiskAssessmentService::new();

    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .app_data(web::Data::new(storage))
        .service(create)
        .service(read)
        .service(list_by_group)
        .service(delete_assessment)
        .service(upload_document)
        .service(download_document)
        .service(get_results);
}

#[utoipa::path(
    tag = "risk-assessment",
    operation_id = "createRiskAssessment",
    request_body = CreateRiskAssessmentRequest,
    responses(
        (
            status = 201, description = "Created the risk assessment",
            body = inline(serde_json::Value),
            headers(
                ("location" = String, description = "The relative URL to the created resource")
            )
        ),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[post("/v2/risk-assessment")]
/// Create a new risk assessment for a group
async fn create(
    req: HttpRequest,
    service: web::Data<RiskAssessmentService>,
    db: web::Data<Database>,
    web::Json(request): web::Json<CreateRiskAssessmentRequest>,
    _: Require<CreateRiskAssessment>,
) -> Result<impl Responder, Error> {
    let id = db
        .transaction(async |tx| service.create(request, tx).await)
        .await?;

    Ok(HttpResponse::Created()
        .append_header(("location", format!("{}/{}", req.path(), id)))
        .json(json!({"id": id})))
}

#[utoipa::path(
    tag = "risk-assessment",
    operation_id = "readRiskAssessment",
    params(
        ("id", Path, description = "The ID of the risk assessment"),
    ),
    responses(
        (status = 200, description = "The risk assessment details", body = RiskAssessment),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The risk assessment was not found"),
    )
)]
#[get("/v2/risk-assessment/{id}")]
/// Get risk assessment details
async fn read(
    service: web::Data<RiskAssessmentService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    _: Require<ReadRiskAssessment>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let result = service.read(&id, &tx).await?;

    Ok(match result {
        Some(assessment) => HttpResponse::Ok().json(assessment),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "risk-assessment",
    operation_id = "listRiskAssessmentsByGroup",
    params(
        ("groupId", Path, description = "The ID of the group"),
    ),
    responses(
        (status = 200, description = "Risk assessments for the group", body = Vec<RiskAssessment>),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[get("/v2/risk-assessment/group/{groupId}")]
/// Get risk assessments for a group
async fn list_by_group(
    service: web::Data<RiskAssessmentService>,
    db: web::Data<Database>,
    group_id: web::Path<String>,
    _: Require<ReadRiskAssessment>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let result = service.list_by_group(&group_id, &tx).await?;

    Ok(HttpResponse::Ok().json(result))
}

#[utoipa::path(
    tag = "risk-assessment",
    operation_id = "deleteRiskAssessment",
    params(
        ("id", Path, description = "The ID of the risk assessment to delete"),
    ),
    responses(
        (status = 204, description = "The risk assessment was deleted or did not exist"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
    )
)]
#[delete("/v2/risk-assessment/{id}")]
/// Delete a risk assessment
async fn delete_assessment(
    service: web::Data<RiskAssessmentService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    _: Require<DeleteRiskAssessment>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    service.delete(&id, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "risk-assessment",
    operation_id = "uploadRiskAssessmentDocument",
    params(
        ("id", Path, description = "The ID of the risk assessment"),
        ("category", Path, description = "The document category"),
    ),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses(
        (
            status = 201, description = "The document was uploaded",
            body = inline(serde_json::Value),
        ),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The risk assessment was not found"),
    )
)]
#[post("/v2/risk-assessment/{id}/document/{category}")]
/// Upload a document for an assessment category
async fn upload_document(
    service: web::Data<RiskAssessmentService>,
    db: web::Data<Database>,
    storage: web::Data<DispatchBackend>,
    path: web::Path<(String, String)>,
    body: web::Bytes,
    _: Require<CreateRiskAssessment>,
) -> Result<impl Responder, Error> {
    let (assessment_id, category) = path.into_inner();
    let size = body.len();

    // Compute digests
    let digests = Digests::digest(&body);

    // Store in storage backend
    storage
        .store(&body[..])
        .await
        .map_err(|e| Error::Storage(anyhow::anyhow!("{e}")))?;

    // Record in database
    let doc_id = db
        .transaction(async |tx| {
            service
                .upload_document(&assessment_id, &category, &digests, size, tx)
                .await
        })
        .await?;

    // If LLM processing is configured, evaluate the document
    if service.processing_enabled() {
        let mut tmp = tempfile::NamedTempFile::new()
            .map_err(|e| Error::Internal(format!("Failed to create temp file: {e}")))?;
        tmp.write_all(&body)
            .map_err(|e| Error::Internal(format!("Failed to write temp file: {e}")))?;

        db.transaction(async |tx| {
            service
                .process_document(&assessment_id, &doc_id, tmp.path(), tx)
                .await
        })
        .await?;
    }

    Ok(HttpResponse::Created().json(json!({"id": doc_id})))
}

#[utoipa::path(
    tag = "risk-assessment",
    operation_id = "downloadRiskAssessmentDocument",
    params(
        ("id", Path, description = "The ID of the risk assessment"),
        ("category", Path, description = "The document category"),
    ),
    responses(
        (status = 200, description = "The document content", content_type = "application/octet-stream"),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The document was not found"),
    )
)]
#[get("/v2/risk-assessment/{id}/document/{category}")]
/// Download an assessment document
async fn download_document(
    service: web::Data<RiskAssessmentService>,
    db: web::Data<Database>,
    storage: web::Data<DispatchBackend>,
    path: web::Path<(String, String)>,
    _: Require<ReadRiskAssessment>,
) -> Result<impl Responder, Error> {
    let (assessment_id, category) = path.into_inner();

    let tx = db.begin_read().await?;
    let source_doc = service
        .get_document_metadata(&assessment_id, &category, &tx)
        .await?;

    let Some(source_doc) = source_doc else {
        return Ok(HttpResponse::NotFound().finish());
    };

    let key = StorageKey::try_from(Id::Sha256(source_doc.sha256))?;

    let stream = storage.retrieve(key).await.map_err(Error::Storage)?;

    Ok(match stream {
        Some(stream) => HttpResponse::Ok()
            .content_type("application/octet-stream")
            .streaming(
                stream.map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string())),
            ),
        None => HttpResponse::NotFound().finish(),
    })
}

#[utoipa::path(
    tag = "risk-assessment",
    operation_id = "getRiskAssessmentResults",
    params(
        ("id", Path, description = "The ID of the risk assessment"),
    ),
    responses(
        (status = 200, description = "The assessment results", body = RiskAssessmentResults),
        (status = 400, description = "The request was not valid"),
        (status = 401, description = "The user was not authenticated"),
        (status = 403, description = "The user authenticated, but not authorized for this operation"),
        (status = 404, description = "The risk assessment was not found"),
    )
)]
#[get("/v2/risk-assessment/{id}/results")]
/// Get scoring results for a risk assessment
async fn get_results(
    service: web::Data<RiskAssessmentService>,
    db: web::Data<Database>,
    id: web::Path<String>,
    _: Require<ReadRiskAssessment>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let result = service.get_results(&id, &tx).await?;

    Ok(match result {
        Some(results) => HttpResponse::Ok().json(results),
        None => HttpResponse::NotFound().finish(),
    })
}
