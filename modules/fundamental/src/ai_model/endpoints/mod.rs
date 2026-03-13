use crate::{
    ai_model::{model::AiModelSummary, service::AiModelService},
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
    let ai_model_service = AiModelService::new(db);

    config
        .app_data(web::Data::new(ai_model_service))
        .service(list_ai_models)
        .service(get_ai_model);
}

#[utoipa::path(
    tag = "ai-model",
    operation_id = "listAiModels",
    params(
        Query,
        Paginated,
    ),
    responses(
        (status = 200, description = "Matching AI models", body = PaginatedResults<AiModelSummary>),
    ),
)]
#[get("/v2/ai-model")]
/// List all AI models across SBOMs
pub async fn list_ai_models(
    state: web::Data<AiModelService>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    Ok(HttpResponse::Ok().json(state.list_ai_models(search, paginated).await?))
}

#[utoipa::path(
    tag = "ai-model",
    operation_id = "getAiModel",
    params(
        ("sbom_id", Path, description = "ID of the SBOM"),
        ("node_id", Path, description = "Node ID of the AI model component"),
    ),
    responses(
        (status = 200, description = "The AI model details"),
        (status = 404, description = "The AI model could not be found"),
    ),
)]
#[get("/v2/ai-model/{sbom_id}/{node_id}")]
/// Get AI model details
pub async fn get_ai_model(
    state: web::Data<AiModelService>,
    db: web::Data<Database>,
    path: web::Path<(Uuid, String)>,
    _: Require<ReadSbom>,
) -> actix_web::Result<impl Responder> {
    let (sbom_id, node_id) = path.into_inner();
    let tx = db.begin_read().await?;

    if let Some(details) = state.get_ai_model(sbom_id, &node_id, &tx).await? {
        Ok(HttpResponse::Ok().json(details))
    } else {
        Ok(HttpResponse::NotFound().finish())
    }
}

#[cfg(test)]
mod test;
