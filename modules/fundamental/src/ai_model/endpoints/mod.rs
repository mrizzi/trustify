#[cfg(test)]
mod test;

use crate::{
    ai_model::service::{AiModelDetails, AiModelFilterParams, AiModelService, AiModelSummary},
    db::DatabaseExt,
};
use actix_web::{HttpResponse, Responder, get, web};
use trustify_auth::{ReadSbom, authorizer::Require};
use trustify_common::{
    db::{Database, query::Query},
    model::{Paginated, PaginatedResults},
};
use uuid::Uuid;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = AiModelService::new();
    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(all)
        .service(get);
}

#[utoipa::path(
    tag = "ai-model",
    operation_id = "listAiModels",
    params(
        Query,
        Paginated,
        AiModelFilterParams,
    ),
    responses(
        (status = 200, description = "Matching AI models", body = PaginatedResults<AiModelSummary>),
    ),
)]
#[get("/v2/ai-model")]
/// List all AI model components across all SBOMs
pub async fn all(
    state: web::Data<AiModelService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(filter): web::Query<AiModelFilterParams>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(
        state
            .fetch_all_ai_models(search, paginated, filter, &tx)
            .await?,
    ))
}

#[utoipa::path(
    tag = "ai-model",
    operation_id = "getAiModel",
    params(
        ("sbom_id", Path, description = "ID of the SBOM containing the AI model"),
        ("node_id", Path, description = "Node ID of the AI model component within the SBOM"),
    ),
    responses(
        (status = 200, description = "AI model details", body = AiModelDetails),
        (status = 404, description = "The AI model could not be found"),
    ),
)]
#[get("/v2/ai-model/{sbom_id}/{node_id}")]
/// Retrieve AI model component details
pub async fn get(
    state: web::Data<AiModelService>,
    db: web::Data<Database>,
    path: web::Path<(Uuid, String)>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let (sbom_id, node_id) = path.into_inner();
    let tx = db.begin_read().await?;
    let fetched = state.fetch_ai_model(sbom_id, &node_id, &tx).await?;

    if let Some(fetched) = fetched {
        Ok(HttpResponse::Ok().json(fetched))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}
