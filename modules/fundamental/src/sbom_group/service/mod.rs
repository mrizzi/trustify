pub mod path;

use crate::{
    Error,
    sbom_group::model::{SbomGroup, SbomGroupDetails, SbomGroupRequest},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, PaginatorTrait,
    QueryFilter, Set, TransactionTrait,
};
use trustify_common::{
    db::{
        limiter::LimiterTrait,
        query::{Filtering, Query},
    },
    model::{Paginated, PaginatedResults},
};
use trustify_entity::{sbom_group, sbom_group_assignment};
use uuid::Uuid;

/// Maximum hierarchy depth for cycle detection
const MAX_HIERARCHY_DEPTH: i32 = 100;

#[derive(Default)]
pub struct SbomGroupService {}

impl SbomGroupService {
    pub fn new() -> Self {
        Self {}
    }

    /// Create a new SBOM group
    pub async fn create_group<C: ConnectionTrait>(
        &self,
        request: SbomGroupRequest,
        connection: &C,
    ) -> Result<SbomGroup, Error> {
        // Validate parent exists if provided
        if let Some(parent_id) = request.parent
            && sbom_group::Entity::find_by_id(parent_id)
                .one(connection)
                .await?
                .is_none()
        {
            return Err(Error::NotFound(format!(
                "Parent group {} not found",
                parent_id
            )));
        }

        // Validate labels
        let labels = request.labels.clone().validate()?;

        // Create the group
        let model = sbom_group::ActiveModel {
            id: Set(Uuid::new_v4()),
            parent_id: Set(request.parent),
            name: Set(request.name.clone()),
            labels: Set(labels.clone()),
            revision: Set(1),
        };

        let result = model.insert(connection).await?;

        Ok(SbomGroup {
            id: result.id,
            parent: result.parent_id,
            name: result.name,
            labels,
            revision: result.revision,
        })
    }

    /// Get a single group by ID
    pub async fn get_group<C: ConnectionTrait>(
        &self,
        id: Uuid,
        include_children: bool,
        include_totals: bool,
        connection: &C,
    ) -> Result<Option<SbomGroupDetails>, Error> {
        let group = sbom_group::Entity::find_by_id(id).one(connection).await?;

        match group {
            Some(g) => {
                let children = if include_children {
                    Some(self.get_children(id, connection).await?)
                } else {
                    None
                };

                let sbom_count = if include_totals {
                    Some(self.count_sboms(id, connection).await?)
                } else {
                    None
                };

                Ok(Some(SbomGroupDetails {
                    group: SbomGroup {
                        id: g.id,
                        parent: g.parent_id,
                        name: g.name,
                        labels: g.labels,
                        revision: g.revision,
                    },
                    children,
                    sbom_count,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get group by path
    pub async fn get_group_by_path<C: ConnectionTrait>(
        &self,
        path: &str,
        include_children: bool,
        include_totals: bool,
        connection: &C,
    ) -> Result<Option<SbomGroupDetails>, Error> {
        let names = path::parse_path(path)?;
        let group = path::find_by_path(names, connection).await?;

        match group {
            Some(g) => {
                let children = if include_children {
                    Some(self.get_children(g.id, connection).await?)
                } else {
                    None
                };

                let sbom_count = if include_totals {
                    Some(self.count_sboms(g.id, connection).await?)
                } else {
                    None
                };

                Ok(Some(SbomGroupDetails {
                    group: SbomGroup {
                        id: g.id,
                        parent: g.parent_id,
                        name: g.name,
                        labels: g.labels,
                        revision: g.revision,
                    },
                    children,
                    sbom_count,
                }))
            }
            None => Ok(None),
        }
    }

    /// Update an existing group
    pub async fn update_group<C: TransactionTrait>(
        &self,
        id: Uuid,
        revision: i32,
        request: SbomGroupRequest,
        connection: &C,
    ) -> Result<SbomGroup, Error> {
        let tx = connection.begin().await?;

        // Find the group and check revision
        let group = sbom_group::Entity::find_by_id(id)
            .one(&tx)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Group {} not found", id)))?;

        if group.revision != revision {
            return Err(Error::BadRequest(format!(
                "Revision mismatch: expected {}, got {}",
                group.revision, revision
            )));
        }

        // Validate parent change doesn't create a cycle
        if let Some(new_parent) = request.parent {
            if new_parent == id {
                return Err(Error::BadRequest("Group cannot be its own parent".into()));
            }

            if self.would_create_cycle(id, new_parent, &tx).await? {
                return Err(Error::BadRequest("Update would create a cycle".into()));
            }
        }

        // Validate labels
        let labels = request.labels.clone().validate()?;

        // Update the group
        let mut model: sbom_group::ActiveModel = group.into();
        model.parent_id = Set(request.parent);
        model.name = Set(request.name.clone());
        model.labels = Set(labels.clone());
        model.revision = Set(revision + 1);

        let result = model.update(&tx).await?;
        tx.commit().await?;

        Ok(SbomGroup {
            id: result.id,
            parent: result.parent_id,
            name: result.name,
            labels,
            revision: result.revision,
        })
    }

    /// Delete a group
    pub async fn delete_group<C: ConnectionTrait>(
        &self,
        id: Uuid,
        revision: i32,
        connection: &C,
    ) -> Result<(), Error> {
        // Find the group and check revision
        let group = sbom_group::Entity::find_by_id(id)
            .one(connection)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Group {} not found", id)))?;

        if group.revision != revision {
            return Err(Error::BadRequest(format!(
                "Revision mismatch: expected {}, got {}",
                group.revision, revision
            )));
        }

        // Check if group has children
        let children = self.get_children(id, connection).await?;
        if !children.is_empty() {
            return Err(Error::Conflict("Cannot delete group with children".into()));
        }

        // Delete the group (cascade will handle assignments)
        sbom_group::Entity::delete_by_id(id)
            .exec(connection)
            .await?;

        Ok(())
    }

    /// List groups with filtering and pagination
    pub async fn list_groups<C: ConnectionTrait>(
        &self,
        search: Query,
        paginated: Paginated,
        include_totals: bool,
        connection: &C,
    ) -> Result<PaginatedResults<SbomGroupDetails>, Error> {
        let limiter = sbom_group::Entity::find().filtering(search)?.limiting(
            connection,
            paginated.offset,
            paginated.limit,
        );

        let total = limiter.total().await?;
        let groups = limiter.fetch().await?;

        let mut items = Vec::new();
        for g in groups {
            let sbom_count = if include_totals {
                Some(self.count_sboms(g.id, connection).await?)
            } else {
                None
            };

            items.push(SbomGroupDetails {
                group: SbomGroup {
                    id: g.id,
                    parent: g.parent_id,
                    name: g.name,
                    labels: g.labels,
                    revision: g.revision,
                },
                children: None,
                sbom_count,
            });
        }

        Ok(PaginatedResults { total, items })
    }

    /// Check if changing parent would create a cycle
    async fn would_create_cycle<C: ConnectionTrait>(
        &self,
        group_id: Uuid,
        new_parent_id: Uuid,
        connection: &C,
    ) -> Result<bool, Error> {
        #[derive(Debug, FromQueryResult)]
        struct CycleCheck {
            exists: Option<bool>,
        }

        let result = CycleCheck::find_by_statement(sea_orm::Statement::from_sql_and_values(
            sea_orm::DatabaseBackend::Postgres,
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT id, parent_id, 1 AS depth
                FROM sbom_group
                WHERE id = $1

                UNION ALL

                SELECT g.id, g.parent_id, a.depth + 1
                FROM sbom_group g
                INNER JOIN ancestors a ON g.id = a.parent_id
                WHERE a.depth < $3
            )
            SELECT EXISTS(SELECT 1 FROM ancestors WHERE id = $2) AS exists
            "#,
            [
                new_parent_id.into(),
                group_id.into(),
                MAX_HIERARCHY_DEPTH.into(),
            ],
        ))
        .one(connection)
        .await?;

        Ok(result.and_then(|r| r.exists).unwrap_or(false))
    }

    /// Get direct children of a group
    async fn get_children<C: ConnectionTrait>(
        &self,
        parent_id: Uuid,
        connection: &C,
    ) -> Result<Vec<Uuid>, Error> {
        let children = sbom_group::Entity::find()
            .filter(sbom_group::Column::ParentId.eq(parent_id))
            .all(connection)
            .await?;

        Ok(children.into_iter().map(|g| g.id).collect())
    }

    /// Count SBOMs in a group
    async fn count_sboms<C: ConnectionTrait>(
        &self,
        group_id: Uuid,
        connection: &C,
    ) -> Result<u64, Error> {
        use sea_orm::EntityTrait;

        let count = sbom_group_assignment::Entity::find()
            .filter(sbom_group_assignment::Column::GroupId.eq(group_id))
            .count(connection)
            .await?;

        Ok(count)
    }
}
