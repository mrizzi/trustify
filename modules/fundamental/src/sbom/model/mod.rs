pub mod details;
pub mod raw_sql;

use super::service::SbomService;
use crate::{
    Error, purl::model::summary::purl::PurlSummary, sbom::service::sbom::LicenseBasicInfo,
    source_document::model::SourceDocument,
};
use sea_orm::{ConnectionTrait, FromQueryResult, ModelTrait, PaginatorTrait, prelude::Uuid};
use sea_query::FromValueTuple;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::instrument;
use trustify_common::{cpe::Cpe, purl::Purl};
use trustify_entity::{
    labels::Labels, relationship::Relationship, sbom, sbom_node, sbom_package,
    sbom_package_license::LicenseCategory, source_document,
};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema, Default)]
pub struct SbomHead {
    #[serde(with = "uuid::serde::urn")]
    #[schema(value_type=String)]
    pub id: Uuid,

    pub document_id: Option<String>,
    pub labels: Labels,
    pub data_licenses: Vec<String>,

    #[schema(required)]
    #[serde(with = "time::serde::rfc3339::option")]
    pub published: Option<OffsetDateTime>,

    /// Authors of the SBOM
    pub authors: Vec<String>,
    /// Suppliers of the SBOMs content
    pub suppliers: Vec<String>,

    pub name: String,

    /// The number of packages this SBOM has
    pub number_of_packages: u64,
}

impl SbomHead {
    #[instrument(
        skip(sbom, db),
        fields(
            sbom=%sbom.sbom_id,
        )
        err(level=tracing::Level::INFO),
    )]
    pub async fn from_entity<C: ConnectionTrait>(
        sbom: &sbom::Model,
        sbom_node: Option<sbom_node::Model>,
        db: &C,
    ) -> Result<Self, Error> {
        let number_of_packages = sbom.find_related(sbom_package::Entity).count(db).await?;
        Ok(Self {
            id: sbom.sbom_id,
            document_id: sbom.document_id.clone(),
            labels: sbom.labels.clone(),
            published: sbom.published,
            authors: sbom.authors.clone(),
            suppliers: sbom.suppliers.clone(),
            name: sbom_node
                .map(|node| node.name.clone())
                .unwrap_or("".to_string()),
            data_licenses: sbom.data_licenses.clone(),
            number_of_packages,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SbomSummary {
    #[serde(flatten)]
    pub head: SbomHead,

    #[serde(flatten)]
    pub source_document: Option<SourceDocument>,

    pub described_by: Vec<SbomPackage>,
}

impl SbomSummary {
    #[instrument(skip(service, db), err(level=tracing::Level::INFO))]
    pub async fn from_entity<C: ConnectionTrait>(
        (sbom, node): (sbom::Model, Option<sbom_node::Model>),
        service: &SbomService,
        db: &C,
    ) -> Result<Option<SbomSummary>, Error> {
        // TODO: consider improving the n-select issues here
        let described_by = service.describes_packages(sbom.sbom_id, (), db).await?;

        let source_document = sbom.find_related(source_document::Entity).one(db).await?;

        Ok(match node {
            Some(_) => Some(SbomSummary {
                head: SbomHead::from_entity(&sbom, node, db).await?,
                source_document: source_document.as_ref().map(SourceDocument::from_entity),
                described_by,
            }),
            None => None,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, Default)]
#[cfg_attr(feature = "async-graphql", derive(async_graphql::SimpleObject))]
#[cfg_attr(
    feature = "async-graphql",
    graphql(concrete(name = "SbomPackage", params()))
)]
pub struct SbomPackage {
    /// The SBOM internal ID of a package
    pub id: String,
    /// The name of the package in the SBOM
    pub name: String,
    /// An optional group/namespace for an SBOM package
    pub group: Option<String>,
    /// An optional version for an SBOM package
    pub version: Option<String>,
    /// PURLs identifying the package
    #[cfg_attr(feature = "async-graphql", graphql(skip))]
    pub purl: Vec<PurlSummary>,
    /// CPEs identifying the package
    pub cpe: Vec<String>,
    /// License info
    #[cfg_attr(feature = "async-graphql", graphql(skip))]
    pub licenses: Vec<LicenseInfo>,
    /// LicenseRef mappings
    #[cfg_attr(feature = "async-graphql", graphql(skip))]
    pub licenses_ref_mapping: Vec<LicenseRefMapping>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct LicenseInfo {
    pub license_name: String,
    pub license_type: LicenseCategory,
}

impl From<LicenseBasicInfo> for LicenseInfo {
    fn from(license_basic_info: LicenseBasicInfo) -> Self {
        LicenseInfo {
            license_name: license_basic_info.license_name,
            license_type: LicenseCategory::from_value_tuple(license_basic_info.license_type),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema, FromQueryResult)]
pub struct LicenseRefMapping {
    pub license_id: String,
    pub license_name: String,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SbomPackageReference<'a> {
    Internal(&'a str),
    External(SbomExternalPackageReference<'a>),
}

impl<'a> From<SbomExternalPackageReference<'a>> for SbomPackageReference<'a> {
    fn from(value: SbomExternalPackageReference<'a>) -> Self {
        Self::External(value)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum SbomExternalPackageReference<'a> {
    Purl(&'a Purl),
    Cpe(&'a Cpe),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum SbomNodeReference<'a> {
    /// Reference all packages of the SBOM.
    All,
    /// Reference a package inside an SBOM, by its node id.
    // TODO: replace with `SbomPackageReference`
    Package(&'a str),
}

impl<'a> From<&'a str> for SbomNodeReference<'a> {
    fn from(value: &'a str) -> Self {
        Self::Package(value)
    }
}

impl From<()> for SbomNodeReference<'_> {
    fn from(_value: ()) -> Self {
        Self::All
    }
}

impl<'a> From<&'a SbomPackage> for SbomNodeReference<'a> {
    fn from(value: &'a SbomPackage) -> Self {
        Self::Package(&value.id)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, ToSchema)]
pub struct SbomPackageRelation {
    pub relationship: Relationship,
    pub package: SbomPackage,
}

#[derive(Clone, Eq, PartialEq, Default, Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Which {
    /// Originating side
    #[default]
    Left,
    /// Target side
    Right,
}
