//! Engagement-file repositories: reads rules of engagement from JSON on disk.

use searu_domain::ports::{Authorisation, Authoriser, RepoError, Roe, RoeRepository};
use searu_domain::scope::{EntryKind, Scope, ScopeEntry};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct RoeDoc {
    scope: ScopeDoc,
    #[serde(default)]
    allowed_techniques: Vec<String>,
    #[serde(default)]
    authorisation: AuthorisationDoc,
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

#[derive(Deserialize, Default)]
struct AuthorisationDoc {
    #[serde(default)]
    exploitation_authorised_by: Option<AuthoriserDoc>,
    #[serde(default)]
    destructive_authorised: bool,
}

#[derive(Deserialize)]
struct AuthoriserDoc {
    name: String,
    email: String,
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
    let authorisation = Authorisation {
        exploitation_authorised_by: doc.authorisation.exploitation_authorised_by.map(|a| {
            Authoriser {
                name: a.name,
                email: a.email,
            }
        }),
        destructive_authorised: doc.authorisation.destructive_authorised,
    };
    Ok(Roe {
        scope: Scope {
            targets,
            exclusions,
        },
        allowed_techniques: doc.allowed_techniques,
        authorisation,
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

    #[test]
    fn parses_allowed_techniques_and_the_authoriser() {
        let json = r#"{
            "scope": { "targets": [ { "type": "url", "value": "http://localhost:5000" } ] },
            "allowed_techniques": ["T1190", "T1059"],
            "authorisation": {
                "exploitation_authorised_by": { "name": "Jane Tester", "email": "jane@example.com" }
            }
        }"#;
        let roe = parse_roe(json).unwrap();
        assert!(roe.authorises("T1190"));
        assert!(roe.authorises("T1059"));
        assert!(!roe.authorises("T1595"));
        let authoriser = roe.authorisation.exploitation_authorised_by.unwrap();
        assert_eq!(authoriser.email, "jane@example.com");
        assert!(!roe.authorisation.destructive_authorised);
    }

    #[test]
    fn a_scope_only_document_has_no_authorisation() {
        let roe = parse_roe(SAMPLE).unwrap();
        assert!(roe.allowed_techniques.is_empty());
        assert!(roe.authorisation.exploitation_authorised_by.is_none());
    }
}
