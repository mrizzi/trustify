# Coding Conventions

## Language and Framework

- Rust (edition 2024, MSRV 1.92.0)
- Web framework: Actix-web 4
- ORM: SeaORM with `DeriveEntityModel`
- Database: PostgreSQL
- API docs: utoipa (OpenAPI generation)
- Async runtime: Tokio
- Error handling: `thiserror` for enum errors, `anyhow` for ad-hoc contexts
- Serialization: serde (JSON)

## Code Style

- Follow `rustfmt` defaults — run `cargo fmt --check` before committing
- Clippy is enforced with strict flags: `-D warnings -D clippy::unwrap_used -D clippy::expect_used`
- `unwrap()` and `expect()` are forbidden in production code; they are allowed in tests (configured in `.clippy.toml`)
- Use `?` operator for error propagation, not `.unwrap()`
- All CI checks: `cargo fmt --check`, `cargo clippy --all-targets --all-features`, `cargo test --all-features`

## Naming Conventions

- Structs: PascalCase (`SbomService`, `AdvisoryService`, `SbomSummary`)
- Functions/methods: snake_case (`fetch_sbom_summary`, `fetch_advisories`)
- Modules: snake_case (`sbom_group`, `source_document`)
- Entity models: `Model` struct inside each entity module, table names are snake_case (`sbom`, `advisory`, `sbom_group`)
- Service structs: `<Domain>Service` (e.g., `SbomService`, `AdvisoryService`)
- Endpoint functions: short verbs — `get`, `all`, `delete`, `upload`, `download`, `packages`, `related`
- API routes: `/v2/<resource>` (e.g., `/v2/sbom`, `/v2/advisory/{key}`)
- OpenAPI operation IDs: camelCase (`getSbom`, `listSboms`)
- Test functions: descriptive snake_case (`upload_with_groups`, `filter_packages`, `query_sboms_by_label`)

## File Organization

### Workspace layout

```
Cargo.toml              # workspace root
entity/src/             # SeaORM entity models (one file per table)
migration/src/          # Database migrations (m<number>_<description>.rs)
common/                 # Shared crates: common, common/auth, common/db, common/infrastructure
modules/                # Domain modules: fundamental, analysis, ingestor, importer, storage, ui, user
query/                  # Query framework and derive macro
server/                 # HTTP server assembly
trustd/                 # CLI binary
test-context/           # Test infrastructure (TrustifyTestContext)
e2e/                    # End-to-end tests (hurl files)
```

### Domain module structure (e.g., `modules/fundamental/src/sbom/`)

Each domain area follows the same three-submodule pattern:

```
<domain>/
  mod.rs                # Re-exports: pub mod endpoints, service, model
  endpoints/
    mod.rs              # configure() function, endpoint handlers
    test.rs             # Endpoint integration tests (#[cfg(test)])
    label.rs            # Label sub-endpoints (if applicable)
    query.rs            # Query parameter structs
    config.rs           # Endpoint config structs
  service/
    mod.rs              # <Domain>Service struct with pub methods
    test.rs             # Service integration tests (#[cfg(test)])
    <submodule>.rs      # Additional service logic
  model/
    mod.rs              # API response/request models (DTOs)
    details.rs          # Detailed model variants
```

### Entity files

One file per database table in `entity/src/` (e.g., `sbom.rs`, `advisory.rs`, `sbom_group.rs`).

### Migration files

Named `m<7-digit-number>_<description>.rs` (e.g., `m0002030_create_ai.rs`). SQL files go in a same-named directory when needed.

## Error Handling

- Each module defines its own `Error` enum in `error.rs`, using `#[derive(Debug, thiserror::Error)]`
- Common error variants: `Database(DbErr)`, `Query(query::Error)`, `NotFound(String)`, `BadRequest(...)`, `Any(anyhow::Error)`
- Every module error implements `actix_web::ResponseError` to map errors to HTTP status codes
- `From<DbErr>` is implemented manually (not via `#[from]`) to handle `RecordNotFound` → `NotFound` conversion
- Use `?` with automatic `From` conversions throughout service and endpoint code
- Endpoints return `actix_web::Result<impl Responder>`

## Testing Conventions

- Integration tests use `#[test_context(TrustifyContext)]` from the `trustify_test_context` crate
- Test functions are `async fn` annotated with `#[test(actix_web::test)]`
- Tests return `anyhow::Result<()>` for ergonomic error handling
- Tests live in `test.rs` files alongside the code they test, gated by `#[cfg(test)] mod test;`
- Endpoint tests use `TestRequest` builder pattern to construct HTTP requests and `call_service` to execute
- Service tests call service methods directly against a test database
- Test data is ingested via `TrustifyTestContext` helpers (`ingest_document`, `ingest_documents`, `document_bytes`)
- The `TrustifyContext` provides: `db`, `graph`, `storage`, `ingestor` fields
- Inline unit tests (e.g., in `sbom.rs`) use `#[cfg(test)] mod test { ... }` blocks

## Commit Messages

- Follow Conventional Commits: `<type>[optional scope]: <description>`
- Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`
- Reference the Jira issue in the commit footer (e.g., `Implements TC-123`)
- AI-assisted commits include `--trailer="Assisted-by: Claude Code"`

## Pre-commit Workflow

Before committing any changes, run:

```sh
cargo xtask precommit
```

This command performs the following steps in order:

1. **Regenerates JSON schemas** (`cargo xtask generate-schemas`) — updates schema files derived from Rust model types
2. **Regenerates `openapi.yaml`** (`cargo xtask openapi`) — rebuilds the OpenAPI spec from `#[utoipa::path(...)]` annotations
3. **Runs clippy** (`cargo clippy --all-targets --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used`)
4. **Runs `cargo fmt`** — applies standard Rust formatting
5. **Runs `cargo check`** (`--all-targets --all-features`) — verifies the project compiles cleanly

Any files modified by steps 1–2 (e.g., `openapi.yaml`, JSON schema files) must be included in the commit.

## Dependencies

- All dependencies are declared in `[workspace.dependencies]` in the root `Cargo.toml` with pinned versions
- Member crates reference workspace dependencies via `dependency.workspace = true`
- Edition 2024 with resolver 3
- Key crate choices: `actix-web` (HTTP), `sea-orm` (ORM), `utoipa` (OpenAPI), `tokio` (async), `serde` (serialization), `anyhow`/`thiserror` (errors), `clap` (CLI)

## Endpoint Patterns

- Endpoints are registered in a `configure()` function that takes `ServiceConfig`, `Database`, and config params
- Services are injected via `web::Data<T>` (Actix application data)
- Authorization uses `Require<Permission>` extractor or `authorizer.require(&user, Permission::...)` call
- Read operations acquire a read transaction: `let tx = db.begin_read().await?;`
- List endpoints accept `Query` (search/filter), `Paginated` (pagination), and return `PaginatedResults<T>`
- Every endpoint has a `#[utoipa::path(...)]` attribute for OpenAPI documentation with `tag`, `operation_id`, `params`, and `responses`
- Route attributes use Actix macros: `#[get("/v2/...")]`, `#[post("/v2/...")]`, `#[delete("/v2/...")]`

## Entity Model Patterns

- Entities use `#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]` with `#[sea_orm(table_name = "...")]`
- Primary keys annotated with `#[sea_orm(primary_key)]`
- Relations defined via `impl Related<T> for Entity` with `fn to()` and optionally `fn via()`
- Link structs (e.g., `SbomPurlsLink`) implement `Linked` for many-to-many joins
- `ActiveModelBehavior` is implemented (usually empty) for each entity
- API response models (DTOs) in `model/` use `#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]`

## Migration Patterns

- Use SeaORM migration framework (`MigrationTrait`)
- Index creation uses `.if_not_exists()` for idempotency
- Function definitions use `CREATE OR REPLACE FUNCTION`
- Column additions use `add_column_if_not_exists()`
- Drop operations use `.if_exists()`
- Raw SQL loaded via `include_str!("migration_dir/up.sql")`
- Data migrations are separate from schema migrations, run via `trustd db data <names>`

## Shared Table Insert Pattern (Duplicate Key Handling)

When inserting into a table that has unique constraints and is shared across multiple
modules, use a **nested transaction** to catch duplicate key errors and fall back to
looking up the existing row. This prevents the duplicate key error from aborting the
caller's transaction.

### When to use

Any insert into a table with unique constraints where concurrent or repeated inserts
are expected. The canonical example is the `source_document` table, but the pattern
applies to any shared table with uniqueness guarantees.

### How to implement

1. Wrap the insert in a **nested transaction** (`connection.transaction(...)`) so that
   a constraint violation rolls back only the inner transaction, not the outer one.
2. On success, return the newly created row ID.
3. On error, match `Err(TransactionError::Transaction(DbErr::Query(err)))` and check
   whether the error message contains `"duplicate key value violates unique constraint"`.
4. If it is a duplicate, look up the existing row by its unique column and return it.
5. Propagate any other error normally.

### Reference implementation

The authoritative implementation is `Graph::create_doc` in
`modules/ingestor/src/graph/mod.rs` (lines 52–101):

```rust
let result = connection
    .transaction::<_, _, DbErr>(|txn| {
        Box::pin(async move { source_document::Entity::insert(doc_model).exec(txn).await })
    })
    .await;

match result {
    Ok(doc) => Ok(CreateOutcome::Created(doc.last_insert_id)),
    Err(TransactionError::Transaction(DbErr::Query(err)))
        if err
            .to_string()
            .contains("duplicate key value violates unique constraint") =>
    {
        // look up the existing row by unique column and return it
    }
    Err(TransactionError::Transaction(err)) => Err(err.into()),
    Err(TransactionError::Connection(err)) => Err(err.into()),
}
```

### Shared infrastructure: `source_document`

The `source_document` table is shared infrastructure used by multiple modules —
including **ingestor**, **advisory**, **sbom**, and **risk_assessment**. All code paths
that insert into `source_document` must use the nested-transaction duplicate-handling
pattern described above. Failing to do so will cause unhandled constraint violations
under concurrent ingestion.
