use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomGroup::Table)
                    .col(
                        ColumnDef::new(SbomGroup::Id)
                            .uuid()
                            .not_null()
                            .primary_key()
                            .extra("DEFAULT gen_random_uuid()".to_string()),
                    )
                    .col(ColumnDef::new(SbomGroup::ParentId).uuid())
                    .col(ColumnDef::new(SbomGroup::Name).text().not_null())
                    .col(
                        ColumnDef::new(SbomGroup::Labels)
                            .json_binary()
                            .not_null()
                            .extra("DEFAULT '{}'::jsonb".to_string()),
                    )
                    .col(
                        ColumnDef::new(SbomGroup::Revision)
                            .integer()
                            .not_null()
                            .extra("DEFAULT 1".to_string()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sbom_group_parent")
                            .from(SbomGroup::Table, SbomGroup::ParentId)
                            .to(SbomGroup::Table, SbomGroup::Id)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;

        // Create unique index for (parent_id, name) - handles NULL correctly
        manager
            .create_index(
                Index::create()
                    .name("sbom_group_unique_name_per_parent")
                    .table(SbomGroup::Table)
                    .col(SbomGroup::ParentId)
                    .col(SbomGroup::Name)
                    .unique()
                    .nulls_not_distinct()
                    .to_owned(),
            )
            .await?;

        // Index for parent lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_sbom_group_parent")
                    .table(SbomGroup::Table)
                    .col(SbomGroup::ParentId)
                    .to_owned(),
            )
            .await?;

        // GIN index for JSONB labels - using raw SQL as IndexType::Gin is not available
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX idx_sbom_group_labels ON sbom_group USING gin (labels)",
            )
            .await
            .map(|_| ())?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop the GIN index first
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .table(SbomGroup::Table)
                    .name("idx_sbom_group_labels")
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(SbomGroup::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum SbomGroup {
    Table,
    Id,
    ParentId,
    Name,
    Labels,
    Revision,
}
