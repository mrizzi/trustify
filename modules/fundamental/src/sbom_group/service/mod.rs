pub mod path;

use crate::{
    Error,
    sbom_group::model::{SbomGroup, SbomGroupDetails, SbomGroupRequest},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, PaginatorTrait,
    QueryFilter, Set, TransactionTrait,
};
use std::collections::HashSet;
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

    /// Validate group name according to ADR 00013 rules:
    /// - Length: 1-255 characters
    /// - No leading/trailing whitespace
    /// - Character classes: digits, letters, spaces, hyphens, underscores, periods, parentheses
    fn validate_name(name: &str) -> Result<(), Error> {
        // Check length
        if name.is_empty() {
            return Err(Error::BadRequest("Group name cannot be empty".into()));
        }
        if name.len() > 255 {
            return Err(Error::BadRequest(format!(
                "Group name exceeds maximum length of 255 characters ({})",
                name.len()
            )));
        }

        // Check for leading/trailing whitespace
        if name != name.trim() {
            return Err(Error::BadRequest(
                "Group name cannot have leading or trailing whitespace".into(),
            ));
        }

        // Check allowed characters: digits, letters, spaces, hyphens, underscores, periods, parentheses
        let valid_chars = name.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == ' '
                || c == '-'
                || c == '_'
                || c == '.'
                || c == '('
                || c == ')'
        });

        if !valid_chars {
            return Err(Error::BadRequest(
                "Group name contains invalid characters. Only letters, digits, spaces, hyphens, underscores, periods, and parentheses are allowed".into(),
            ));
        }

        Ok(())
    }

    /// Create a new SBOM group
    pub async fn create_group<C: ConnectionTrait>(
        &self,
        request: SbomGroupRequest,
        connection: &C,
    ) -> Result<SbomGroup, Error> {
        // Validate name
        Self::validate_name(&request.name)?;

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
        include_parents: bool,
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

                let parent_path = if include_parents {
                    Some(self.get_parent_path(id, connection).await?)
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
                    parent_path,
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
        include_parents: bool,
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

                let parent_path = if include_parents {
                    Some(self.get_parent_path(g.id, connection).await?)
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
                    parent_path,
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

        // Validate name
        Self::validate_name(&request.name)?;

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
        include_parents: bool,
        connection: &C,
    ) -> Result<PaginatedResults<SbomGroupDetails>, Error> {
        use sea_orm::QueryOrder;

        let limiter = sbom_group::Entity::find()
            .order_by_asc(sbom_group::Column::Name)
            .filtering(search)?
            .limiting(connection, paginated.offset, paginated.limit);

        let total = limiter.total().await?;
        let groups = limiter.fetch().await?;

        let mut items = Vec::new();
        for g in groups {
            let sbom_count = if include_totals {
                Some(self.count_sboms(g.id, connection).await?)
            } else {
                None
            };

            let parent_path = if include_parents {
                Some(self.get_parent_path(g.id, connection).await?)
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
                parent_path,
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

    /// Validate and deduplicate group IDs
    /// Returns deduplicated set of valid group IDs or error if any are missing
    async fn validate_and_deduplicate_groups<C: ConnectionTrait>(
        &self,
        group_ids: Vec<Uuid>,
        connection: &C,
    ) -> Result<HashSet<Uuid>, Error> {
        // Deduplicate group IDs
        let unique_groups: HashSet<_> = group_ids.into_iter().collect();

        if unique_groups.is_empty() {
            return Ok(unique_groups);
        }

        // Validate all groups exist
        let existing_groups: HashSet<Uuid> = sbom_group::Entity::find()
            .filter(sbom_group::Column::Id.is_in(unique_groups.iter().copied()))
            .all(connection)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();

        let missing_groups: Vec<_> = unique_groups
            .iter()
            .filter(|g| !existing_groups.contains(g))
            .collect();

        if !missing_groups.is_empty() {
            return Err(Error::NotFound(format!(
                "Group(s) not found: {}",
                missing_groups
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        Ok(unique_groups)
    }

    /// Get all group assignments for an SBOM
    pub async fn get_sbom_assignments<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        connection: &C,
    ) -> Result<Vec<Uuid>, Error> {
        let assignments = sbom_group_assignment::Entity::find()
            .filter(sbom_group_assignment::Column::SbomId.eq(sbom_id))
            .all(connection)
            .await?;

        Ok(assignments.into_iter().map(|a| a.group_id).collect())
    }

    /// Add group assignments to an SBOM (does not remove existing assignments)
    pub async fn add_sbom_assignments<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        group_ids: Vec<Uuid>,
        connection: &C,
    ) -> Result<(), Error> {
        use sea_orm::ActiveModelTrait;

        let unique_groups = self
            .validate_and_deduplicate_groups(group_ids, connection)
            .await?;

        // Insert new assignments (ignoring duplicates via ON CONFLICT DO NOTHING would be ideal,
        // but SeaORM doesn't support that cleanly, so we'll let the PK constraint handle it)
        for group_id in unique_groups {
            // Attempt insert, ignore if already exists
            let _ = sbom_group_assignment::ActiveModel {
                sbom_id: Set(sbom_id),
                group_id: Set(group_id),
            }
            .insert(connection)
            .await;
            // We ignore errors here since PK violations are expected if assignment already exists
        }

        Ok(())
    }

    /// Set (replace) all group assignments for an SBOM
    pub async fn set_sbom_assignments<C: ConnectionTrait>(
        &self,
        sbom_id: Uuid,
        group_ids: Vec<Uuid>,
        connection: &C,
    ) -> Result<(), Error> {
        use sea_orm::ActiveModelTrait;

        let unique_groups = self
            .validate_and_deduplicate_groups(group_ids, connection)
            .await?;

        // Delete existing assignments
        sbom_group_assignment::Entity::delete_many()
            .filter(sbom_group_assignment::Column::SbomId.eq(sbom_id))
            .exec(connection)
            .await?;

        // Insert new assignments
        for group_id in unique_groups {
            sbom_group_assignment::ActiveModel {
                sbom_id: Set(sbom_id),
                group_id: Set(group_id),
            }
            .insert(connection)
            .await?;
        }

        Ok(())
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

    /// Get parent path from root to the given group's parent (not including the group itself)
    /// Returns array of UUIDs from root to parent, or empty array if group has no parent
    async fn get_parent_path<C: ConnectionTrait>(
        &self,
        group_id: Uuid,
        connection: &C,
    ) -> Result<Vec<Uuid>, Error> {
        let group = sbom_group::Entity::find_by_id(group_id)
            .one(connection)
            .await?
            .ok_or_else(|| Error::NotFound(format!("Group {} not found", group_id)))?;

        if group.parent_id.is_none() {
            return Ok(Vec::new());
        }

        // Use recursive query to get path from root to parent
        #[derive(Debug, FromQueryResult)]
        struct PathResult {
            path: Vec<Uuid>,
        }

        let result = PathResult::find_by_statement(sea_orm::Statement::from_sql_and_values(
            sea_orm::DatabaseBackend::Postgres,
            r#"
            WITH RECURSIVE ancestors AS (
                SELECT id, parent_id, ARRAY[id] AS path
                FROM sbom_group
                WHERE id = $1

                UNION ALL

                SELECT g.id, g.parent_id, g.id || a.path
                FROM sbom_group g
                INNER JOIN ancestors a ON g.id = a.parent_id
            )
            SELECT path FROM ancestors WHERE parent_id IS NULL
            "#,
            [group.parent_id.into()],
        ))
        .one(connection)
        .await?;

        match result {
            Some(r) => Ok(r.path),
            None => Ok(Vec::new()),
        }
    }
}
