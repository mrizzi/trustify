use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use trustify_entity::ai_model_component;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct AiModelSummary {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub name: String,
    pub model_type: Option<String>,
    pub primary_task: Option<String>,
    pub supplier: Option<String>,
    pub license: Option<String>,
}

#[derive(Serialize, Deserialize, ToSchema, Debug, Clone)]
pub struct AiModelDetails {
    pub sbom_id: Uuid,
    pub node_id: String,
    pub name: String,
    pub model_type: Option<String>,
    pub primary_task: Option<String>,
    pub supplier: Option<String>,
    pub license: Option<String>,
    pub properties: Option<HashMap<String, String>>,
    pub external_references: Option<HashMap<String, String>>,
}

impl AiModelDetails {
    pub fn from_entity(entity: &ai_model_component::Model, name: String) -> Self {
        Self {
            sbom_id: entity.sbom_id,
            node_id: entity.node_id.clone(),
            name,
            model_type: entity.model_type.clone(),
            primary_task: entity.primary_task.clone(),
            supplier: entity.supplier.clone(),
            license: entity.license.clone(),
            properties: entity.properties.as_ref().map(|l| l.0.clone()),
            external_references: entity.external_references.as_ref().map(|l| l.0.clone()),
        }
    }
}

impl AiModelSummary {
    pub fn from_entity(entity: &ai_model_component::Model, name: String) -> Self {
        Self {
            sbom_id: entity.sbom_id,
            node_id: entity.node_id.clone(),
            name,
            model_type: entity.model_type.clone(),
            primary_task: entity.primary_task.clone(),
            supplier: entity.supplier.clone(),
            license: entity.license.clone(),
        }
    }
}
