//! Engagement-file repositories: reads rules of engagement from JSON on disk.

use searu_domain::findings::{Finding, Loot};
use searu_domain::ports::{
    Authorisation, Authoriser, FindingsStore, Fingerprinter, LootStore, RepoError, Roe,
    RoeRepository, StoreError,
};
use searu_domain::scope::{EntryKind, Scope, ScopeEntry};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

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

pub struct Sha256Fingerprinter;

impl Fingerprinter for Sha256Fingerprinter {
    fn fingerprint(&self, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        let digest = hasher.finalize();
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        hex[..12].to_string()
    }
}

#[derive(Serialize)]
struct FindingRecord<'a> {
    kind: &'a str,
    tool: &'a str,
    target: &'a str,
    title: &'a str,
    severity: &'a str,
    status: &'a str,
    attack_technique: &'a [String],
    cwe: &'a [u32],
    evidence: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    loot_fingerprint: Option<&'a str>,
}

#[derive(Serialize)]
struct LootRecord<'a> {
    fingerprint: &'a str,
    category: &'a str,
    value: &'a str,
}

pub struct JsonlFindingsStore {
    path: PathBuf,
}

impl JsonlFindingsStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join("findings.jsonl"),
        }
    }
}

impl FindingsStore for JsonlFindingsStore {
    fn emit(&self, finding: &Finding) -> Result<(), StoreError> {
        let record = FindingRecord {
            kind: "finding",
            tool: &finding.tool,
            target: &finding.target,
            title: &finding.title,
            severity: finding.severity.as_str(),
            status: finding.status.as_str(),
            attack_technique: &finding.attack_technique,
            cwe: &finding.cwe,
            evidence: &finding.evidence,
            loot_fingerprint: finding.loot_fingerprint.as_deref(),
        };
        let line =
            serde_json::to_string(&record).map_err(|e| StoreError::Serialise(e.to_string()))?;
        append_line(&self.path, &line)
    }
}

pub struct JsonlLootStore {
    dir: PathBuf,
}

impl JsonlLootStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}

impl LootStore for JsonlLootStore {
    fn emit(&self, loot: &Loot) -> Result<(), StoreError> {
        let record = LootRecord {
            fingerprint: &loot.fingerprint,
            category: &loot.category,
            value: &loot.value,
        };
        let line =
            serde_json::to_string(&record).map_err(|e| StoreError::Serialise(e.to_string()))?;
        let path = self.dir.join("loot.jsonl");
        append_line(&path, &line)?;
        harden_loot(&self.dir, &path);
        Ok(())
    }
}

fn append_line(path: &Path, line: &str) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| StoreError::Io(e.to_string()))?;
    writeln!(file, "{line}").map_err(|e| StoreError::Io(e.to_string()))
}

#[cfg(unix)]
fn harden_loot(dir: &Path, path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn harden_loot(_dir: &Path, _path: &Path) {}

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

    #[test]
    fn fingerprints_are_the_first_twelve_hex_of_sha256() {
        assert_eq!(Sha256Fingerprinter.fingerprint("abc"), "ba7816bf8f01");
    }

    #[test]
    fn a_finding_records_the_fingerprint_never_the_secret() {
        use searu_domain::findings::{Severity, Status};
        let dir = tempfile::tempdir().unwrap();
        let store = JsonlFindingsStore::new(dir.path());
        let finding = Finding {
            tool: "commix".to_string(),
            target: "http://localhost:5000".to_string(),
            title: "OS command injection".to_string(),
            severity: Severity::Critical,
            status: Status::Confirmed,
            attack_technique: vec!["T1190".to_string(), "T1059".to_string()],
            cwe: vec![78],
            evidence: "ip_addr parameter".to_string(),
            loot_fingerprint: Some("ba7816bf8f01".to_string()),
        };
        store.emit(&finding).unwrap();

        let text = std::fs::read_to_string(dir.path().join("findings.jsonl")).unwrap();
        assert!(text.contains("\"kind\":\"finding\""));
        assert!(text.contains("T1190"));
        assert!(text.contains("\"cwe\":[78]"));
        assert!(text.contains("ba7816bf8f01"));
        assert!(!text.contains("postgres://"));
    }

    #[test]
    fn loot_keeps_the_plaintext_value() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonlLootStore::new(dir.path());
        let loot = Loot {
            fingerprint: "ba7816bf8f01".to_string(),
            category: "database-url".to_string(),
            value: "postgres://admin:s3cr3t@db/app".to_string(),
        };
        store.emit(&loot).unwrap();

        let text = std::fs::read_to_string(dir.path().join("loot.jsonl")).unwrap();
        assert!(text.contains("postgres://admin:s3cr3t@db/app"));
        assert!(text.contains("ba7816bf8f01"));
    }
}
