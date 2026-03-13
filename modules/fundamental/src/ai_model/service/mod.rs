use crate::{
    Error,
    ai_model::model::{AiModelDetails, AiModelSummary},
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, JoinType, QueryFilter, QuerySelect, RelationTrait};
use trustify_common::{
    db::{
        Database,
        limiter::LimiterTrait,
        query::{Filtering, Query},
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{ai_model_component, sbom_node};
use uuid::Uuid;

pub struct AiModelService {
    db: Database,
}

impl AiModelService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// List all AI models across all SBOMs
    pub async fn list_ai_models(
        &self,
        search: Query,
        paginated: Paginated,
    ) -> Result<PaginatedResults<AiModelSummary>, Error> {
        let query = ai_model_component::Entity::find()
            .join(JoinType::Join, ai_model_component::Relation::Node.def())
            .filtering(search)?;

        let limiter = query.limiting(&self.db, paginated.offset, paginated.limit);
        let total = limiter.total().await?;
        let items = limiter.fetch().await?;

        // Fetch node names for each model
        let mut summaries = Vec::with_capacity(items.len());
        for item in &items {
            let name = sbom_node::Entity::find()
                .filter(sbom_node::Column::SbomId.eq(item.sbom_id))
                .filter(sbom_node::Column::NodeId.eq(&item.node_id))
                .one(&self.db)
                .await?
                .map(|n| n.name)
                .unwrap_or_default();
            summaries.push(AiModelSummary::from_entity(item, name));
        }

        Ok(PaginatedResults {
            items: summaries,
            total,
        })
    }

    /// List AI models for a specific SBOM
    pub async fn list_ai_models_for_sbom<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        search: Query,
        paginated: Paginated,
        connection: &C,
    ) -> Result<PaginatedResults<AiModelSummary>, Error> {
        let query = ai_model_component::Entity::find()
            .filter(ai_model_component::Column::SbomId.eq(sbom_id))
            .join(JoinType::Join, ai_model_component::Relation::Node.def())
            .filtering(search)?;

        let limiter = query.limiting(connection, paginated.offset, paginated.limit);
        let total = limiter.total().await?;
        let items = limiter.fetch().await?;

        let mut summaries = Vec::with_capacity(items.len());
        for item in &items {
            let name = sbom_node::Entity::find()
                .filter(sbom_node::Column::SbomId.eq(item.sbom_id))
                .filter(sbom_node::Column::NodeId.eq(&item.node_id))
                .one(connection)
                .await?
                .map(|n| n.name)
                .unwrap_or_default();
            summaries.push(AiModelSummary::from_entity(item, name));
        }

        Ok(PaginatedResults {
            items: summaries,
            total,
        })
    }

    /// Get details of a specific AI model
    pub async fn get_ai_model<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        node_id: &str,
        connection: &C,
    ) -> Result<Option<AiModelDetails>, Error> {
        let model = ai_model_component::Entity::find()
            .filter(ai_model_component::Column::SbomId.eq(sbom_id))
            .filter(ai_model_component::Column::NodeId.eq(node_id))
            .one(connection)
            .await?;

        if let Some(model) = model {
            let name = sbom_node::Entity::find()
                .filter(sbom_node::Column::SbomId.eq(sbom_id))
                .filter(sbom_node::Column::NodeId.eq(node_id))
                .one(connection)
                .await?
                .map(|n| n.name)
                .unwrap_or_default();
            Ok(Some(AiModelDetails::from_entity(&model, name)))
        } else {
            Ok(None)
        }
    }
}
