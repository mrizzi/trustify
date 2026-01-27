use crate::Error;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use trustify_entity::sbom_group;
use uuid::Uuid;

/// Maximum path depth to prevent DoS attacks
const MAX_PATH_DEPTH: usize = 20;

/// Parse URL-encoded path with escape sequences
/// Format: "A/B\/C/D\\E" where \/ = literal /, \\ = literal \
pub fn parse_path(encoded_path: &str) -> Result<Vec<String>, Error> {
    let decoded = urlencoding::decode(encoded_path)
        .map_err(|e| Error::BadRequest(format!("Invalid URL encoding: {e}")))?;

    let mut names = Vec::new();
    let mut current = String::new();
    let mut chars = decoded.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some('/') => current.push('/'),
                Some('\\') => current.push('\\'),
                Some(other) => return Err(Error::BadRequest(format!("Invalid escape: \\{other}"))),
                None => return Err(Error::BadRequest("Path ends with incomplete escape".into())),
            },
            '/' => {
                if current.is_empty() {
                    return Err(Error::BadRequest("Empty group name in path".into()));
                }
                names.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        names.push(current);
    } else if !names.is_empty() {
        return Err(Error::BadRequest("Path ends with delimiter".into()));
    }

    if names.is_empty() {
        return Err(Error::BadRequest("Empty path".into()));
    }

    if names.len() > MAX_PATH_DEPTH {
        return Err(Error::BadRequest(format!(
            "Path depth {} exceeds maximum of {}",
            names.len(),
            MAX_PATH_DEPTH
        )));
    }

    Ok(names)
}

/// Find group by hierarchical path
pub async fn find_by_path<C: ConnectionTrait>(
    names: Vec<String>,
    tx: &C,
) -> Result<Option<sbom_group::Model>, Error> {
    let mut current_parent: Option<Uuid> = None;
    let mut current_group: Option<sbom_group::Model> = None;

    for name in names {
        let filter = if let Some(parent) = current_parent {
            sbom_group::Column::ParentId.eq(parent)
        } else {
            sbom_group::Column::ParentId.is_null()
        };

        let group = sbom_group::Entity::find()
            .filter(sbom_group::Column::Name.eq(&name))
            .filter(filter)
            .one(tx)
            .await?;

        match group {
            Some(g) => {
                current_parent = Some(g.id);
                current_group = Some(g);
            }
            None => return Ok(None),
        }
    }

    Ok(current_group)
}
