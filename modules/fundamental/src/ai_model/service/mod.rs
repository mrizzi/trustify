use crate::Error;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, Query},
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{ai_model_component, sbom, sbom_node};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Summary representation of an AI model component.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AiModelSummary {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub name: String,
    #[schema(required)]
    pub model_type: Option<String>,
    #[schema(required)]
    pub primary_task: Option<String>,
    #[schema(required)]
    pub supplier: Option<String>,
    #[schema(required)]
    pub license: Option<String>,
}

/// Detailed representation of an AI model component.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AiModelDetails {
    #[serde(flatten)]
    pub summary: AiModelSummary,
    #[schema(required)]
    pub properties: Option<serde_json::Value>,
    #[schema(required)]
    pub external_references: Option<serde_json::Value>,
    #[schema(required)]
    pub sbom_document_id: Option<String>,
    pub sbom_authors: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct AiModelFilterParams {
    /// Filter by supplier name (substring match)
    pub supplier: Option<String>,
    /// Filter by license (substring match)
    pub license: Option<String>,
    /// Filter by model type (substring match)
    pub model_type: Option<String>,
}

#[derive(Default)]
pub struct AiModelService {}

impl AiModelService {
    pub fn new() -> Self {
        Self {}
    }

    /// Fetch AI models for a specific SBOM.
    pub async fn fetch_ai_models_for_sbom<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<AiModelSummary>, Error> {
        let query = ai_model_component::Entity::find()
            .filter(ai_model_component::Column::SbomId.eq(sbom_id))
            .find_also_related(sbom_node::Entity)
            .filtering(search)?;

        let limiter = query.limiting(connection, paginated.offset, paginated.limit);
        let total = limiter.total().await?;
        let items = limiter
            .fetch()
            .await?
            .into_iter()
            .map(|(model, node)| Self::to_summary(&model, node.as_ref()))
            .collect();

        Ok(PaginatedResults { items, total })
    }

    /// Fetch all AI models across all SBOMs.
    pub async fn fetch_all_ai_models<C: ConnectionTrait>(
        &self,
        search: Query,
        paginated: Paginated,
        filter: AiModelFilterParams,
        connection: &C,
    ) -> Result<PaginatedResults<AiModelSummary>, Error> {
        let mut query = ai_model_component::Entity::find()
            .find_also_related(sbom_node::Entity)
            .filtering(search)?;

        if let Some(ref supplier) = filter.supplier {
            query = query.filter(ai_model_component::Column::Supplier.contains(supplier));
        }
        if let Some(ref license) = filter.license {
            query = query.filter(ai_model_component::Column::License.contains(license));
        }
        if let Some(ref model_type) = filter.model_type {
            query = query.filter(ai_model_component::Column::ModelType.contains(model_type));
        }

        let limiter = query.limiting(connection, paginated.offset, paginated.limit);
        let total = limiter.total().await?;
        let items = limiter
            .fetch()
            .await?
            .into_iter()
            .map(|(model, node)| Self::to_summary(&model, node.as_ref()))
            .collect();

        Ok(PaginatedResults { items, total })
    }

    /// Fetch a single AI model by SBOM ID and node ID.
    pub async fn fetch_ai_model<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        node_id: &str,
        connection: &C,
    ) -> Result<Option<AiModelDetails>, Error> {
        let result = ai_model_component::Entity::find()
            .filter(ai_model_component::Column::SbomId.eq(sbom_id))
            .filter(ai_model_component::Column::NodeId.eq(node_id))
            .find_also_related(sbom_node::Entity)
            .one(connection)
            .await?;

        let (model, node) = match result {
            Some(r) => r,
            None => return Ok(None),
        };

        // Fetch SBOM metadata
        let sbom_model = sbom::Entity::find()
            .filter(sbom::Column::SbomId.eq(sbom_id))
            .one(connection)
            .await?;

        let (sbom_document_id, sbom_authors) = match sbom_model {
            Some(s) => (s.document_id, s.authors),
            None => (None, vec![]),
        };

        Ok(Some(AiModelDetails {
            summary: Self::to_summary(&model, node.as_ref()),
            properties: model
                .properties
                .map(|p| serde_json::to_value(p).unwrap_or_default()),
            external_references: model
                .external_references
                .map(|e| serde_json::to_value(e).unwrap_or_default()),
            sbom_document_id,
            sbom_authors,
        }))
    }

    fn to_summary(model: &ai_model_component::Model, node: Option<&sbom_node::Model>) -> AiModelSummary {
        AiModelSummary {
            sbom_id: model.sbom_id,
            node_id: model.node_id.clone(),
            name: node.map(|n| n.name.clone()).unwrap_or_default(),
            model_type: model.model_type.clone(),
            primary_task: model.primary_task.clone(),
            supplier: model.supplier.clone(),
            license: model.license.clone(),
        }
    }
}
