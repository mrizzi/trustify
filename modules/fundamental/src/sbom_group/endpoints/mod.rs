#[cfg(test)]
mod test;

use crate::{
    Error,
    db::DatabaseExt,
    sbom_group::{
        model::{SbomGroupDetails, SbomGroupRequest},
        service::SbomGroupService,
    },
};
use actix_web::{HttpRequest, HttpResponse, Responder, delete, get, post, put, web};
use sea_orm::TransactionTrait;
use trustify_auth::{
    CreateSbomGroup, DeleteSbomGroup, ReadSbomGroup, UpdateSbomGroup, authorizer::Require,
};
use trustify_common::{
    db::{Database, query::Query},
    model::Paginated,
};
use uuid::Uuid;

pub fn configure(config: &mut utoipa_actix_web::service_config::ServiceConfig, db: Database) {
    let service = SbomGroupService::new();
    config
        .app_data(web::Data::new(db))
        .app_data(web::Data::new(service))
        .service(list)
        .service(get_group)
        .service(get_by_path)
        .service(create)
        .service(update)
        .service(delete_group)
        .service(get_sbom_assignments)
        .service(set_sbom_assignments);
}

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
struct ListParams {
    #[serde(default)]
    totals: bool,
    #[serde(default)]
    parents: bool,
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "listSbomGroups",
    params(
        Query,
        Paginated,
        ListParams,
    ),
    responses(
        (status = 200, description = "Matching SBOM groups", body = inline(trustify_common::model::PaginatedResults<SbomGroupDetails>)),
    ),
)]
#[get("/v2/group/sbom")]
/// List SBOM groups
pub async fn list(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    web::Query(search): web::Query<Query>,
    web::Query(paginated): web::Query<Paginated>,
    web::Query(params): web::Query<ListParams>,
    _: Require<ReadSbomGroup>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    Ok(HttpResponse::Ok().json(
        service
            .list_groups(search, paginated, params.totals, params.parents, &tx)
            .await?,
    ))
}

#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
struct GetParams {
    #[serde(default)]
    children: bool,
    #[serde(default)]
    totals: bool,
    #[serde(default)]
    parents: bool,
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "getSbomGroup",
    params(
        ("id" = Uuid, Path, description = "Opaque ID of the group"),
        GetParams,
    ),
    responses(
        (status = 200, description = "Matching group", body = SbomGroupDetails),
        (status = 404, description = "The group could not be found"),
    ),
)]
#[get("/v2/group/sbom/{id}")]
/// Get SBOM group by ID
pub async fn get_group(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    web::Query(params): web::Query<GetParams>,
    _: Require<ReadSbomGroup>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let group = service
        .get_group(*id, params.children, params.totals, params.parents, &tx)
        .await?;

    match group {
        Some(g) => {
            let etag = format!("\"{}\"", g.group.revision);
            Ok(HttpResponse::Ok().insert_header(("ETag", etag)).json(g))
        }
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "getSbomGroupByPath",
    params(
        ("path" = String, Path, description = "Hierarchical path (e.g., A/B\\/C for group 'B/C' under 'A')"),
        GetParams,
    ),
    responses(
        (status = 200, description = "Matching group", body = SbomGroupDetails),
        (status = 404, description = "The group could not be found"),
        (status = 400, description = "Invalid path format"),
    ),
)]
#[get("/v2/group/sbom-by-path/{path:.*}")]
/// Get SBOM group by path
pub async fn get_by_path(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    path: web::Path<String>,
    web::Query(params): web::Query<GetParams>,
    _: Require<ReadSbomGroup>,
) -> actix_web::Result<impl Responder> {
    let tx = db.begin_read().await?;
    let group = service
        .get_group_by_path(&path, params.children, params.totals, params.parents, &tx)
        .await?;

    match group {
        Some(g) => {
            let etag = format!("\"{}\"", g.group.revision);
            Ok(HttpResponse::Ok().insert_header(("ETag", etag)).json(g))
        }
        None => Ok(HttpResponse::NotFound().finish()),
    }
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "createSbomGroup",
    request_body = SbomGroupRequest,
    responses(
        (status = 201, description = "Group created", body = crate::sbom_group::model::SbomGroup),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Parent group not found"),
    ),
)]
#[post("/v2/group/sbom")]
/// Create a new SBOM group
pub async fn create(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    web::Json(request): web::Json<SbomGroupRequest>,
    _: Require<CreateSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    let group = service.create_group(request, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::Created()
        .insert_header(("Location", format!("/api/v2/group/sbom/{}", group.id)))
        .json(group))
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "updateSbomGroup",
    params(
        ("id" = Uuid, Path, description = "Opaque ID of the group"),
    ),
    request_body = SbomGroupRequest,
    responses(
        (status = 204, description = "Group updated"),
        (status = 400, description = "Invalid request or revision mismatch"),
        (status = 404, description = "Group not found"),
        (status = 412, description = "Precondition failed (If-Match header required or doesn't match)"),
    ),
)]
#[put("/v2/group/sbom/{id}")]
/// Update an SBOM group
pub async fn update(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    web::Json(request): web::Json<SbomGroupRequest>,
    req: HttpRequest,
    _: Require<UpdateSbomGroup>,
) -> Result<impl Responder, Error> {
    // Extract revision from If-Match header
    let if_match = req
        .headers()
        .get("If-Match")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| Error::BadRequest("If-Match header required".into()))?;

    let revision: i32 = if_match
        .trim_matches('"')
        .parse()
        .map_err(|_| Error::BadRequest("Invalid revision in If-Match header".into()))?;

    let tx = db.begin().await?;
    service.update_group(*id, revision, request, &tx).await?;
    tx.commit().await?;

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "deleteSbomGroup",
    params(
        ("id" = Uuid, Path, description = "Opaque ID of the group"),
    ),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 400, description = "Group has children"),
        (status = 404, description = "Group not found"),
        (status = 409, description = "Cannot delete group with children"),
        (status = 412, description = "Precondition failed (If-Match header required or doesn't match)"),
    ),
)]
#[delete("/v2/group/sbom/{id}")]
/// Delete an SBOM group
pub async fn delete_group(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    req: HttpRequest,
    _: Require<DeleteSbomGroup>,
) -> Result<impl Responder, Error> {
    // Start transaction for delete
    let tx = db.begin().await?;

    // Extract revision from If-Match header (optional for delete)
    let revision = if let Some(if_match) = req.headers().get("If-Match") {
        let if_match_str = if_match
            .to_str()
            .map_err(|_| Error::BadRequest("Invalid If-Match header".into()))?;
        if_match_str
            .trim_matches('"')
            .parse()
            .map_err(|_| Error::BadRequest("Invalid revision in If-Match header".into()))?
    } else {
        // If no If-Match header, fetch current revision from within the same transaction
        let group = service.get_group(*id, false, false, false, &tx).await?;
        match group {
            Some(g) => g.group.revision,
            None => return Ok(HttpResponse::NotFound().finish()),
        }
    };

    match service.delete_group(*id, revision, &tx).await {
        Ok(_) => {
            tx.commit().await?;
            Ok(HttpResponse::NoContent().finish())
        }
        Err(e) => Err(e),
    }
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "getSbomGroupAssignments",
    params(
        ("id" = Uuid, Path, description = "ID of the SBOM"),
    ),
    responses(
        (status = 200, description = "List of group IDs assigned to the SBOM", body = inline(Vec<Uuid>)),
        (status = 404, description = "SBOM not found"),
    ),
)]
#[get("/v2/group/sbom-assignment/{id}")]
/// Get all group assignments for an SBOM
pub async fn get_sbom_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    _: Require<ReadSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin_read().await?;
    let assignments = service.get_sbom_assignments(*id, &tx).await?;
    Ok(HttpResponse::Ok().json(assignments))
}

#[utoipa::path(
    tag = "sbom_group",
    operation_id = "setSbomGroupAssignments",
    params(
        ("id" = Uuid, Path, description = "ID of the SBOM"),
    ),
    request_body = inline(Vec<Uuid>),
    responses(
        (status = 204, description = "Assignments updated successfully"),
        (status = 404, description = "SBOM or one or more groups not found"),
    ),
)]
#[put("/v2/group/sbom-assignment/{id}")]
/// Set (replace) all group assignments for an SBOM
pub async fn set_sbom_assignments(
    service: web::Data<SbomGroupService>,
    db: web::Data<Database>,
    id: web::Path<Uuid>,
    web::Json(group_ids): web::Json<Vec<Uuid>>,
    _: Require<UpdateSbomGroup>,
) -> Result<impl Responder, Error> {
    let tx = db.begin().await?;
    service.set_sbom_assignments(*id, group_ids, &tx).await?;
    tx.commit().await?;
    Ok(HttpResponse::NoContent().finish())
}
