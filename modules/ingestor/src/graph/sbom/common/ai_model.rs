use sea_orm::{ActiveValue::Set, ConnectionTrait, DbErr, EntityTrait};
use sea_query::OnConflict;
use std::collections::HashMap;
use tracing::instrument;
use trustify_common::db::chunk::EntityChunkedIter;
use trustify_entity::{ai_model_component, labels::Labels};
use uuid::Uuid;

pub struct AiModelCreator {
    sbom_id: Uuid,
    models: Vec<ai_model_component::ActiveModel>,
}

pub struct AiModelInfo {
    pub node_id: String,
    pub model_type: Option<String>,
    pub primary_task: Option<String>,
    pub supplier: Option<String>,
    pub license: Option<String>,
    pub properties: Option<Labels>,
    pub external_references: Option<Labels>,
}

impl AiModelCreator {
    pub fn new(sbom_id: Uuid) -> Self {
        Self {
            sbom_id,
            models: Vec::new(),
        }
    }

    pub fn add(&mut self, info: AiModelInfo) {
        self.models.push(ai_model_component::ActiveModel {
            sbom_id: Set(self.sbom_id),
            node_id: Set(info.node_id),
            model_type: Set(info.model_type),
            primary_task: Set(info.primary_task),
            supplier: Set(info.supplier),
            license: Set(info.license),
            properties: Set(info.properties),
            external_references: Set(info.external_references),
        });
    }

    #[instrument(
        skip_all,
        fields(num_ai_models=self.models.len()),
        err(level=tracing::Level::INFO)
    )]
    pub async fn create(self, db: &impl ConnectionTrait) -> Result<(), DbErr> {
        for batch in &self.models.into_iter().chunked() {
            ai_model_component::Entity::insert_many(batch)
                .on_conflict(
                    OnConflict::columns([
                        ai_model_component::Column::SbomId,
                        ai_model_component::Column::NodeId,
                    ])
                    .do_nothing()
                    .to_owned(),
                )
                .do_nothing()
                .exec(db)
                .await?;
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.models.is_empty()
    }
}

/// Extract supplier name from an OrganizationalEntity-like structure.
pub fn extract_supplier_name(
    supplier: Option<&serde_cyclonedx::cyclonedx::v_1_6::OrganizationalEntity>,
    manufacturer: Option<&serde_cyclonedx::cyclonedx::v_1_6::OrganizationalEntity>,
) -> Option<String> {
    supplier
        .and_then(|s| s.name.clone())
        .or_else(|| manufacturer.and_then(|m| m.name.clone()))
}

/// Extract external references as a Labels map (type -> url).
pub fn extract_external_refs(
    refs: Option<&Vec<serde_cyclonedx::cyclonedx::v_1_6::ExternalReference>>,
) -> Option<Labels> {
    let refs = refs?;
    if refs.is_empty() {
        return None;
    }
    let map: HashMap<String, String> = refs
        .iter()
        .map(|r| {
            let url = match &r.url {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (r.type_.clone(), url)
        })
        .collect();
    Some(Labels(map))
}

/// Extract modelCard properties as a Labels map (name -> value).
pub fn extract_model_properties(
    properties: Option<&Vec<serde_cyclonedx::cyclonedx::v_1_6::Property>>,
) -> Option<Labels> {
    let props = properties?;
    if props.is_empty() {
        return None;
    }
    let map: HashMap<String, String> = props
        .iter()
        .filter_map(|p| {
            p.value
                .as_ref()
                .map(|v| (p.name.clone(), v.clone()))
        })
        .collect();
    if map.is_empty() {
        None
    } else {
        Some(Labels(map))
    }
}
