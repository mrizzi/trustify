use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(
    Copy,
    Clone,
    Eq,
    Hash,
    Debug,
    PartialEq,
    EnumIter,
    DeriveActiveEnum,
    strum::EnumString,
    strum::Display,
    Serialize,
    Deserialize,
    ToSchema,
)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "status")]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[sea_orm(string_value = "affected")]
    Affected,
    #[sea_orm(string_value = "fixed")]
    Fixed,
    #[sea_orm(string_value = "not_affected")]
    NotAffected,
    #[sea_orm(string_value = "under_investigation")]
    UnderInvestigation,
    #[sea_orm(string_value = "recommended")]
    Recommended,
}
