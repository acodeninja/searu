//! Engagement-file repositories: reads rules of engagement from JSON on disk.

use searu_domain::ports::{RepoError, Roe, RoeRepository};
use searu_domain::scope::{EntryKind, Scope, ScopeEntry};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct RoeDoc {
    scope: ScopeDoc,
}

#[derive(Deserialize)]
struct ScopeDoc {
    #[serde(default)]
    targets: Vec<EntryDoc>,
    #[serde(default)]
    exclusions: Vec<EntryDoc>,
}

#[derive(Deserialize)]
struct EntryDoc {
    #[serde(rename = "type")]
    kind: String,
    value: String,
}

pub fn parse_roe(json: &str) -> Result<Roe, RepoError> {
    let doc: RoeDoc = serde_json::from_str(json).map_err(|e| RepoError::Parse(e.to_string()))?;
    let targets = doc
        .scope
        .targets
        .into_iter()
        .map(entry)
        .collect::<Result<Vec<_>, _>>()?;
    let exclusions = doc
        .scope
        .exclusions
        .into_iter()
        .map(entry)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Roe {
        scope: Scope {
            targets,
            exclusions,
        },
    })
}

fn entry(doc: EntryDoc) -> Result<ScopeEntry, RepoError> {
    let kind = match doc.kind.as_str() {
        "domain" => EntryKind::Domain,
        "ip" => EntryKind::Ip,
        "cidr" => EntryKind::Cidr,
        "url" => EntryKind::Url,
        other => {
            return Err(RepoError::Parse(format!(
                "unknown scope entry type: {other}"
            )))
        }
    };
    Ok(ScopeEntry {
        kind,
        value: doc.value,
    })
}

pub struct JsonRoeRepository {
    path: PathBuf,
}

impl JsonRoeRepository {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl RoeRepository for JsonRoeRepository {
    fn load(&self) -> Result<Roe, RepoError> {
        let text = std::fs::read_to_string(&self.path).map_err(|e| RepoError::Io(e.to_string()))?;
        parse_roe(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "scope": {
            "targets": [
                { "type": "domain", "value": "staging.example.com" },
                { "type": "cidr", "value": "10.20.0.0/24" }
            ],
            "exclusions": [
                { "type": "domain", "value": "billing.staging.example.com" }
            ]
        }
    }"#;

    #[test]
    fn parses_a_scope_document() {
        let roe = parse_roe(SAMPLE).unwrap();
        assert_eq!(roe.scope.targets.len(), 2);
        assert_eq!(roe.scope.exclusions.len(), 1);
        assert_eq!(roe.scope.targets[0].kind, EntryKind::Domain);
        assert_eq!(roe.scope.targets[1].kind, EntryKind::Cidr);
    }

    #[test]
    fn ignores_unknown_top_level_fields() {
        let json = r#"{ "scope": { "targets": [] }, "authorization": { "x": 1 } }"#;
        assert!(parse_roe(json).is_ok());
    }

    #[test]
    fn rejects_an_unknown_entry_type() {
        let json = r#"{ "scope": { "targets": [ { "type": "carrier-pigeon", "value": "x" } ] } }"#;
        assert!(parse_roe(json).is_err());
    }
}
