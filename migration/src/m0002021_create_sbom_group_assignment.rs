use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SbomGroupAssignment::Table)
                    .col(
                        ColumnDef::new(SbomGroupAssignment::SbomId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(SbomGroupAssignment::GroupId)
                            .uuid()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(SbomGroupAssignment::SbomId)
                            .col(SbomGroupAssignment::GroupId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sbom_group_assignment_sbom")
                            .from(SbomGroupAssignment::Table, SbomGroupAssignment::SbomId)
                            .to(Sbom::Table, Sbom::SbomId)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_sbom_group_assignment_group")
                            .from(SbomGroupAssignment::Table, SbomGroupAssignment::GroupId)
                            .to(SbomGroup::Table, SbomGroup::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Index for SBOM -> groups queries
        manager
            .create_index(
                Index::create()
                    .name("idx_sbom_group_assignment_sbom")
                    .table(SbomGroupAssignment::Table)
                    .col(SbomGroupAssignment::SbomId)
                    .to_owned(),
            )
            .await?;

        // Index for group -> SBOMs queries
        manager
            .create_index(
                Index::create()
                    .name("idx_sbom_group_assignment_group")
                    .table(SbomGroupAssignment::Table)
                    .col(SbomGroupAssignment::GroupId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SbomGroupAssignment::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum SbomGroupAssignment {
    Table,
    SbomId,
    GroupId,
}

#[derive(DeriveIden)]
enum Sbom {
    Table,
    SbomId,
}

#[derive(DeriveIden)]
enum SbomGroup {
    Table,
    Id,
}
