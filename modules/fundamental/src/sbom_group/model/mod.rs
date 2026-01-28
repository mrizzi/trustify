use sea_orm::prelude::Uuid;
use serde::{Deserialize, Serialize};
use trustify_entity::labels::Labels;
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomGroup {
    pub id: Uuid,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub parent: Option<Uuid>,

    pub name: String,

    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,

    pub revision: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomGroupDetails {
    #[serde(flatten)]
    pub group: SbomGroup,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<Uuid>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sbom_count: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_path: Option<Vec<Uuid>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomGroupRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub parent: Option<Uuid>,

    pub name: String,

    #[serde(default, skip_serializing_if = "Labels::is_empty")]
    pub labels: Labels,
}
