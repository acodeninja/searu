//! Engagement-file repositories: reads rules of engagement from JSON on disk.

use searu_domain::findings::{
    Finding, Loot, Observation, RecordContext, Severity, Status, StoredFinding, StoredLoot,
    StoredObservation,
};
use searu_domain::ports::{
    AuditEntry, AuditLog, AuditReader, Authorisation, Authoriser, FindingsStore, LootStore,
    ObservationStore, OutputDir, OutputError, OutputStore, ProjectSettings, RepoError, Roe,
    RoeRepository, SettingsError, SourceError, SourceProvider, StoreError, StoredAudit,
};
use searu_domain::scope::{HostForm, Scope, ScopeEntry};
use serde::{Deserialize, Serialize};
use serde_json::json;
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
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(rename = "type", default)]
    host_type: Option<String>,
    value: String,
    #[serde(default)]
    port: Option<u16>,
}

fn default_kind() -> String {
    "host".to_string()
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
    match doc.kind.as_str() {
        "host" => {
            let form = match doc.host_type.as_deref() {
                Some("domain") => HostForm::Domain,
                Some("ip") => HostForm::Ip,
                Some("cidr") => HostForm::Cidr,
                Some("url") => HostForm::Url,
                Some(other) => return Err(RepoError::Parse(format!("unknown host type: {other}"))),
                None => {
                    return Err(RepoError::Parse(
                        "a host target needs a \"type\"".to_string(),
                    ))
                }
            };
            Ok(ScopeEntry::Host {
                form,
                value: doc.value,
                port: doc.port,
            })
        }
        "file" => Ok(ScopeEntry::File { value: doc.value }),
        "person" => Ok(ScopeEntry::Person { value: doc.value }),
        "osint-domain" => Ok(ScopeEntry::OsintDomain { value: doc.value }),
        other => Err(RepoError::Parse(format!("unknown target kind: {other}"))),
    }
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

pub struct FileProjectSettings {
    path: PathBuf,
}

impl FileProjectSettings {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join(".claude").join("settings.json"),
        }
    }

    fn read_document(&self) -> Result<serde_json::Value, SettingsError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => {
                serde_json::from_str(&text).map_err(|e| SettingsError::Parse(e.to_string()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
            Err(e) => Err(SettingsError::Io(e.to_string())),
        }
    }
}

impl ProjectSettings for FileProjectSettings {
    fn denied_egress(&self) -> Result<Vec<String>, SettingsError> {
        let document = self.read_document()?;
        Ok(document
            .get("permissions")
            .and_then(|permissions| permissions.get("deny"))
            .and_then(|deny| deny.as_array())
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn set_denied_egress(&self, deny: &[String]) -> Result<(), SettingsError> {
        let mut document = self.read_document()?;
        let object = document.as_object_mut().ok_or_else(|| {
            SettingsError::Parse("settings.json is not a JSON object".to_string())
        })?;
        let permissions = object.entry("permissions").or_insert_with(|| json!({}));
        let permissions = permissions.as_object_mut().ok_or_else(|| {
            SettingsError::Parse("\"permissions\" is not a JSON object".to_string())
        })?;
        permissions.insert("deny".to_string(), json!(deny));
        self.write_document(&document)
    }

    fn set_pretooluse_hook(&self, command: &str) -> Result<(), SettingsError> {
        let mut document = self.read_document()?;
        let object = document.as_object_mut().ok_or_else(|| {
            SettingsError::Parse("settings.json is not a JSON object".to_string())
        })?;
        let hooks = object.entry("hooks").or_insert_with(|| json!({}));
        let hooks = hooks
            .as_object_mut()
            .ok_or_else(|| SettingsError::Parse("\"hooks\" is not a JSON object".to_string()))?;
        hooks.insert(
            "PreToolUse".to_string(),
            json!([{ "matcher": "*", "hooks": [{ "type": "command", "command": command }] }]),
        );
        self.write_document(&document)
    }
}

impl FileProjectSettings {
    fn write_document(&self, document: &serde_json::Value) -> Result<(), SettingsError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| SettingsError::Io(e.to_string()))?;
        }
        let text = serde_json::to_string_pretty(document)
            .map_err(|e| SettingsError::Parse(e.to_string()))?;
        std::fs::write(&self.path, format!("{text}\n"))
            .map_err(|e| SettingsError::Io(e.to_string()))
    }
}

fn internet() -> String {
    "internet".to_string()
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct FindingRecord {
    kind: String,
    tool: String,
    target: String,
    title: String,
    severity: String,
    status: String,
    #[serde(default)]
    attack_technique: Vec<String>,
    #[serde(default)]
    cwe: Vec<u32>,
    #[serde(default)]
    evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    loot_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default = "internet")]
    network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(default)]
    first_seen: u64,
    #[serde(default)]
    last_seen: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct LootRecord {
    fingerprint: String,
    category: String,
    value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authenticates: Option<String>,
    #[serde(default)]
    tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default = "internet")]
    network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(default)]
    first_seen: u64,
    #[serde(default)]
    last_seen: u64,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
struct ObservationRecord {
    kind: String,
    value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(default)]
    tool: String,
    #[serde(default)]
    technique: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    #[serde(default = "internet")]
    network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(default)]
    first_seen: u64,
    #[serde(default)]
    last_seen: u64,
}

/// A stored record whose first/last-seen timestamps are metadata, not identity — so an upsert can
/// recognise the same fact across runs and advance `last_seen` in place rather than re-appending.
trait Upsertable: Serialize + serde::de::DeserializeOwned + Clone + PartialEq {
    fn clear_seen(&mut self);
    fn stamp_new(&mut self, now: u64);
    fn touch(&mut self, now: u64);
}

impl Upsertable for FindingRecord {
    fn clear_seen(&mut self) {
        self.first_seen = 0;
        self.last_seen = 0;
    }
    fn stamp_new(&mut self, now: u64) {
        self.first_seen = now;
        self.last_seen = now;
    }
    fn touch(&mut self, now: u64) {
        self.last_seen = now;
    }
}

impl Upsertable for LootRecord {
    fn clear_seen(&mut self) {
        self.first_seen = 0;
        self.last_seen = 0;
    }
    fn stamp_new(&mut self, now: u64) {
        self.first_seen = now;
        self.last_seen = now;
    }
    fn touch(&mut self, now: u64) {
        self.last_seen = now;
    }
}

impl Upsertable for ObservationRecord {
    fn clear_seen(&mut self) {
        self.first_seen = 0;
        self.last_seen = 0;
    }
    fn stamp_new(&mut self, now: u64) {
        self.first_seen = now;
        self.last_seen = now;
    }
    fn touch(&mut self, now: u64) {
        self.last_seen = now;
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Upsert a record into an append-only JSONL file: if a record with the same identity (all content bar
/// the timestamps) is already present, advance its `last_seen`; otherwise append it with
/// `first_seen`/`last_seen` set to now. The whole file is rewritten so an in-place update is durable.
fn upsert<R: Upsertable>(path: &Path, incoming: &R) -> Result<Vec<R>, StoreError> {
    let now = now_secs();
    let mut records: Vec<R> = read_lines(path)?
        .iter()
        .filter_map(|line| serde_json::from_str::<R>(line).ok())
        .collect();
    let mut key = incoming.clone();
    key.clear_seen();
    let existing = records.iter_mut().find(|record| {
        let mut probe = (*record).clone();
        probe.clear_seen();
        probe == key
    });
    match existing {
        Some(record) => record.touch(now),
        None => {
            let mut fresh = incoming.clone();
            fresh.stamp_new(now);
            records.push(fresh);
        }
    }
    write_records(path, &records)?;
    Ok(records)
}

fn write_records<R: Serialize>(path: &Path, records: &[R]) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
    }
    let mut body = String::new();
    for record in records {
        body.push_str(
            &serde_json::to_string(record).map_err(|e| StoreError::Serialise(e.to_string()))?,
        );
        body.push('\n');
    }
    std::fs::write(path, body).map_err(|e| StoreError::Io(e.to_string()))
}

fn read_lines(path: &Path) -> Result<Vec<String>, StoreError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().map(str::to_string).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(StoreError::Io(e.to_string())),
    }
}

fn severity_from(name: &str) -> Severity {
    match name {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

fn status_from(name: &str) -> Status {
    match name {
        "confirmed" => Status::Confirmed,
        _ => Status::NeedsReview,
    }
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
    fn emit(&self, finding: &Finding, context: &RecordContext) -> Result<(), StoreError> {
        let record = FindingRecord {
            kind: "finding".to_string(),
            tool: finding.tool.clone(),
            target: finding.target.clone(),
            title: finding.title.clone(),
            severity: finding.severity.as_str().to_string(),
            status: finding.status.as_str().to_string(),
            attack_technique: finding.attack_technique.clone(),
            cwe: finding.cwe.clone(),
            evidence: finding.evidence.clone(),
            loot_fingerprint: finding.loot_fingerprint.clone(),
            host: context.host.clone(),
            network: context.network.clone(),
            service: context.service.clone(),
            first_seen: 0,
            last_seen: 0,
        };
        upsert(&self.path, &record).map(|_| ())
    }

    fn list(&self) -> Result<Vec<StoredFinding>, StoreError> {
        let mut findings = Vec::new();
        for line in read_lines(&self.path)? {
            let Ok(row) = serde_json::from_str::<FindingRecord>(&line) else {
                continue;
            };
            if row.kind != "finding" {
                continue;
            }
            findings.push(StoredFinding {
                finding: Finding {
                    tool: row.tool,
                    target: row.target,
                    title: row.title,
                    severity: severity_from(&row.severity),
                    status: status_from(&row.status),
                    attack_technique: row.attack_technique,
                    cwe: row.cwe,
                    evidence: row.evidence,
                    loot_fingerprint: row.loot_fingerprint,
                },
                host: row.host,
                network: row.network,
                service: row.service,
                first_seen: row.first_seen,
                last_seen: row.last_seen,
            });
        }
        Ok(findings)
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
    fn emit(&self, loot: &Loot, context: &RecordContext) -> Result<(), StoreError> {
        let record = LootRecord {
            fingerprint: loot.fingerprint.clone(),
            category: loot.category.clone(),
            value: loot.value.clone(),
            principal: loot.principal.clone(),
            authenticates: loot.authenticates.clone(),
            tool: context.tool.clone(),
            host: context.host.clone(),
            network: context.network.clone(),
            service: context.service.clone(),
            first_seen: 0,
            last_seen: 0,
        };
        let path = self.dir.join("loot.jsonl");
        upsert(&path, &record)?;
        harden_loot(&self.dir, &path);
        Ok(())
    }

    fn list(&self) -> Result<Vec<StoredLoot>, StoreError> {
        let mut loot = Vec::new();
        for line in read_lines(&self.dir.join("loot.jsonl"))? {
            if let Ok(row) = serde_json::from_str::<LootRecord>(&line) {
                loot.push(StoredLoot {
                    loot: Loot {
                        fingerprint: row.fingerprint,
                        category: row.category,
                        value: row.value,
                        principal: row.principal,
                        authenticates: row.authenticates,
                    },
                    tool: row.tool,
                    host: row.host,
                    network: row.network,
                    service: row.service,
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                });
            }
        }
        Ok(loot)
    }
}

pub struct JsonlObservationStore {
    path: PathBuf,
}

impl JsonlObservationStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join("observations.jsonl"),
        }
    }
}

impl ObservationStore for JsonlObservationStore {
    fn emit(&self, observation: &Observation, context: &RecordContext) -> Result<(), StoreError> {
        let record = ObservationRecord {
            kind: observation.kind.clone(),
            value: observation.value.clone(),
            detail: observation.detail.clone(),
            tool: context.tool.clone(),
            technique: context.technique.clone(),
            host: context.host.clone(),
            network: context.network.clone(),
            service: context.service.clone(),
            first_seen: 0,
            last_seen: 0,
        };
        upsert(&self.path, &record).map(|_| ())
    }

    fn list(&self) -> Result<Vec<StoredObservation>, StoreError> {
        let mut observations = Vec::new();
        for line in read_lines(&self.path)? {
            if let Ok(row) = serde_json::from_str::<ObservationRecord>(&line) {
                observations.push(StoredObservation {
                    observation: Observation {
                        kind: row.kind,
                        value: row.value,
                        detail: row.detail,
                    },
                    tool: row.tool,
                    technique: row.technique,
                    host: row.host,
                    network: row.network,
                    service: row.service,
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                });
            }
        }
        Ok(observations)
    }
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    kind: &'a str,
    at: u64,
    tool: &'a str,
    technique: &'a str,
    target: &'a str,
    decision: &'a str,
    args: &'a [String],
}

#[derive(Deserialize)]
struct AuditRow {
    #[serde(default)]
    at: u64,
    #[serde(default)]
    tool: String,
    #[serde(default)]
    technique: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    decision: String,
    #[serde(default)]
    args: Vec<String>,
}

pub struct JsonlAuditLog {
    path: PathBuf,
}

impl JsonlAuditLog {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            path: dir.into().join("audit.jsonl"),
        }
    }
}

impl AuditLog for JsonlAuditLog {
    fn record(&self, entry: &AuditEntry) -> Result<(), StoreError> {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let record = AuditRecord {
            kind: "audit",
            at,
            tool: entry.tool,
            technique: entry.technique,
            target: entry.target,
            decision: entry.decision,
            args: entry.args,
        };
        let line =
            serde_json::to_string(&record).map_err(|e| StoreError::Serialise(e.to_string()))?;
        append_line(&self.path, &line)
    }
}

impl AuditReader for JsonlAuditLog {
    fn list(&self) -> Result<Vec<StoredAudit>, StoreError> {
        let mut entries = Vec::new();
        for line in read_lines(&self.path)? {
            if let Ok(row) = serde_json::from_str::<AuditRow>(&line) {
                entries.push(StoredAudit {
                    tool: row.tool,
                    technique: row.technique,
                    target: row.target,
                    decision: row.decision,
                    args: row.args,
                    at: row.at,
                });
            }
        }
        Ok(entries)
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

/// Resolves a `src:<path>` source target to a confined absolute host path. The path is workspace
/// relative (against the engagement directory); `..`, absolute and missing paths are refused, so a
/// static-analysis container only ever mounts a tree inside the engagement.
pub struct FsSourceProvider {
    root: PathBuf,
}

impl FsSourceProvider {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl Default for FsSourceProvider {
    fn default() -> Self {
        Self {
            root: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        }
    }
}

impl SourceProvider for FsSourceProvider {
    fn resolve(&self, relative: &str) -> Result<String, SourceError> {
        if relative.is_empty()
            || Path::new(relative).is_absolute()
            || relative
                .split(['/', '\\'])
                .any(|segment| segment == ".." || segment.is_empty())
        {
            return Err(SourceError::Invalid(format!(
                "source path must be workspace-relative without `..`: {relative}"
            )));
        }
        let path = self.root.join(relative);
        if !path.exists() {
            return Err(SourceError::Invalid(format!(
                "source path not found in the workspace: {relative}"
            )));
        }
        Ok(path.to_string_lossy().into_owned())
    }
}

/// Per-invocation output directories under the engagement, at `outputs/<tool>/<invocation-id>/`. Each
/// call takes a fresh zero-padded id (the next free number in the tool's directory), so repeated runs of
/// the same tool never overwrite one another. The raw stdout/stderr are saved into the directory and
/// writer tools mount it to deposit their files.
pub struct FsOutputStore {
    root: PathBuf,
}

impl FsOutputStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }
}

impl OutputStore for FsOutputStore {
    fn prepare(&self, tool: &str) -> Result<OutputDir, OutputError> {
        let tool_dir = self.root.join("outputs").join(tool);
        std::fs::create_dir_all(&tool_dir).map_err(|e| OutputError::Io(e.to_string()))?;
        let id = next_invocation_id(&tool_dir)?;
        let dir = tool_dir.join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| OutputError::Io(e.to_string()))?;
        harden_dir(&dir);
        let workspace = format!(
            "{}/outputs/{}/{}",
            self.root.to_string_lossy().replace('\\', "/"),
            tool,
            id
        );
        let absolute = std::env::current_dir()
            .map(|cwd| cwd.join(&dir))
            .unwrap_or(dir);
        Ok(OutputDir {
            host: absolute.to_string_lossy().into_owned(),
            workspace,
        })
    }

    fn save_raw(&self, dir: &OutputDir, stdout: &str, stderr: &str) -> Result<(), OutputError> {
        let host = Path::new(&dir.host);
        std::fs::write(host.join("stdout.txt"), stdout)
            .map_err(|e| OutputError::Io(e.to_string()))?;
        std::fs::write(host.join("stderr.txt"), stderr)
            .map_err(|e| OutputError::Io(e.to_string()))?;
        Ok(())
    }

    fn collect(&self, dir: &OutputDir) -> Result<Vec<String>, OutputError> {
        let host = PathBuf::from(&dir.host);
        let mut files = Vec::new();
        collect_files(&host, &host, &mut files)?;
        Ok(files)
    }
}

fn next_invocation_id(tool_dir: &Path) -> Result<String, OutputError> {
    let mut highest = 0u32;
    if let Ok(entries) = std::fs::read_dir(tool_dir) {
        for entry in entries.flatten() {
            if let Some(number) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            {
                highest = highest.max(number);
            }
        }
    }
    Ok(format!("{:04}", highest + 1))
}

fn collect_files(base: &Path, current: &Path, out: &mut Vec<String>) -> Result<(), OutputError> {
    for entry in std::fs::read_dir(current).map_err(|e| OutputError::Io(e.to_string()))? {
        let path = entry.map_err(|e| OutputError::Io(e.to_string()))?.path();
        if path.is_dir() {
            collect_files(base, &path, out)?;
        } else {
            let relative = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            if relative != "stdout.txt" && relative != "stderr.txt" {
                out.push(relative);
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn harden_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn harden_dir(_dir: &Path) {}

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
        assert!(matches!(
            &roe.scope.targets[0],
            ScopeEntry::Host {
                form: HostForm::Domain,
                ..
            }
        ));
        assert!(matches!(
            &roe.scope.targets[1],
            ScopeEntry::Host {
                form: HostForm::Cidr,
                ..
            }
        ));
    }

    #[test]
    fn source_provider_resolves_a_workspace_relative_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("app/web")).unwrap();
        let provider = FsSourceProvider::new(dir.path());
        let resolved = provider.resolve("app/web").unwrap();
        assert!(resolved.replace('\\', "/").ends_with("app/web"));
    }

    #[test]
    fn source_provider_refuses_escapes_absolutes_and_missing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let provider = FsSourceProvider::new(dir.path());
        assert!(provider.resolve("../etc").is_err());
        assert!(provider.resolve("/etc").is_err());
        assert!(provider.resolve("nope").is_err());
        assert!(provider.resolve("").is_err());
    }

    #[test]
    fn output_store_prepares_saves_collects_and_increments() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsOutputStore::new(dir.path().join("pentest"));

        let out = store.prepare("gowitness").unwrap();
        assert!(out
            .workspace
            .replace('\\', "/")
            .ends_with("outputs/gowitness/0001"));

        std::fs::write(std::path::Path::new(&out.host).join("shot.png"), b"png").unwrap();
        store.save_raw(&out, "the stdout", "the stderr").unwrap();
        assert_eq!(
            std::fs::read_to_string(std::path::Path::new(&out.host).join("stdout.txt")).unwrap(),
            "the stdout"
        );

        let files = store.collect(&out).unwrap();
        assert_eq!(files, vec!["shot.png".to_string()]);

        let second = store.prepare("gowitness").unwrap();
        assert!(second
            .workspace
            .replace('\\', "/")
            .ends_with("outputs/gowitness/0002"));
    }

    #[test]
    fn parses_typed_non_host_targets() {
        let json = r#"{ "scope": { "targets": [
            { "kind": "file", "value": "/etc/passwd" },
            { "kind": "person", "value": "Joe Bloggs" },
            { "kind": "osint-domain", "value": "example.com" }
        ] } }"#;
        let roe = parse_roe(json).unwrap();
        assert!(
            matches!(&roe.scope.targets[0], ScopeEntry::File { value } if value == "/etc/passwd")
        );
        assert!(matches!(&roe.scope.targets[1], ScopeEntry::Person { .. }));
        assert!(matches!(
            &roe.scope.targets[2],
            ScopeEntry::OsintDomain { .. }
        ));
    }

    #[test]
    fn ignores_unknown_top_level_fields() {
        let json = r#"{ "scope": { "targets": [] }, "authorization": { "x": 1 } }"#;
        assert!(parse_roe(json).is_ok());
    }

    #[test]
    fn parses_a_port_limited_entry() {
        let json = r#"{ "scope": { "targets": [ { "type": "ip", "value": "127.0.0.1", "port": 5000 } ] } }"#;
        let roe = parse_roe(json).unwrap();
        assert!(matches!(
            roe.scope.targets[0],
            ScopeEntry::Host {
                port: Some(5000),
                ..
            }
        ));
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
    fn a_finding_records_the_fingerprint_never_the_secret() {
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
        store.emit(&finding, &RecordContext::default()).unwrap();

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
        let loot = Loot::secret(
            "ba7816bf8f01".to_string(),
            "database-url".to_string(),
            "postgres://admin:s3cr3t@db/app".to_string(),
        );
        store.emit(&loot, &RecordContext::default()).unwrap();

        let text = std::fs::read_to_string(dir.path().join("loot.jsonl")).unwrap();
        assert!(text.contains("postgres://admin:s3cr3t@db/app"));
        assert!(text.contains("ba7816bf8f01"));
    }

    #[test]
    fn lists_emitted_findings() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonlFindingsStore::new(dir.path());
        store
            .emit(
                &Finding {
                    tool: "commix".to_string(),
                    target: "http://localhost:5000".to_string(),
                    title: "OS command injection".to_string(),
                    severity: Severity::Critical,
                    status: Status::Confirmed,
                    attack_technique: vec!["T1190".to_string()],
                    cwe: vec![78],
                    evidence: "x".to_string(),
                    loot_fingerprint: Some("ba7816bf8f01".to_string()),
                },
                &RecordContext::default(),
            )
            .unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].finding.severity, Severity::Critical);
        assert_eq!(listed[0].finding.status, Status::Confirmed);
        assert_eq!(listed[0].finding.attack_technique, vec!["T1190"]);
        assert_eq!(listed[0].finding.cwe, vec![78]);
    }

    #[test]
    fn lists_emitted_loot() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonlLootStore::new(dir.path());
        store
            .emit(
                &Loot::secret(
                    "ba7816bf8f01".to_string(),
                    "database-url".to_string(),
                    "testing".to_string(),
                ),
                &RecordContext::default(),
            )
            .unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].loot.category, "database-url");
        assert_eq!(listed[0].loot.value, "testing");
    }

    #[test]
    fn listing_a_missing_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(JsonlFindingsStore::new(dir.path())
            .list()
            .unwrap()
            .is_empty());
        assert!(JsonlLootStore::new(dir.path()).list().unwrap().is_empty());
    }

    #[test]
    fn audit_records_the_decision_the_args_and_a_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let audit = JsonlAuditLog::new(dir.path());
        audit
            .record(&AuditEntry {
                tool: "commix",
                technique: "T1190",
                target: "http://evil.example.org",
                decision: "OUT OF SCOPE",
                args: &["--batch".to_string()],
            })
            .unwrap();

        let text = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(text.contains("\"kind\":\"audit\""));
        assert!(text.contains("OUT OF SCOPE"));
        assert!(text.contains("T1190"));
        assert!(text.contains("--batch"));
        assert!(text.contains("\"at\":"));
    }

    #[test]
    fn audit_entries_are_read_back_for_coverage() {
        let dir = tempfile::tempdir().unwrap();
        let audit = JsonlAuditLog::new(dir.path());
        audit
            .record(&AuditEntry {
                tool: "sqlmap",
                technique: "T1190",
                target: "http://h/rest/products/search?q=test",
                decision: "authorised",
                args: &["-p".to_string(), "q".to_string()],
            })
            .unwrap();

        let entries = AuditReader::list(&audit).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool, "sqlmap");
        assert_eq!(entries[0].decision, "authorised");
        assert_eq!(entries[0].args, vec!["-p".to_string(), "q".to_string()]);
    }

    #[test]
    fn egress_deny_round_trips_and_defaults_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let settings = FileProjectSettings::new(dir.path());
        assert!(settings.denied_egress().unwrap().is_empty());
        settings
            .set_denied_egress(&["WebFetch".to_string(), "WebSearch".to_string()])
            .unwrap();
        assert_eq!(
            settings.denied_egress().unwrap(),
            vec!["WebFetch".to_string(), "WebSearch".to_string()]
        );
    }

    #[test]
    fn setting_egress_deny_preserves_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(
            claude.join("settings.json"),
            r#"{"model":"opus","permissions":{"allow":["Bash(ls)"]}}"#,
        )
        .unwrap();

        FileProjectSettings::new(dir.path())
            .set_denied_egress(&["WebFetch".to_string()])
            .unwrap();

        let text = std::fs::read_to_string(claude.join("settings.json")).unwrap();
        assert!(text.contains("\"model\""));
        assert!(text.contains("opus"));
        assert!(text.contains("Bash(ls)"));
        assert!(text.contains("WebFetch"));
    }

    #[test]
    fn pretooluse_hook_is_written_with_the_command_and_preserves_other_settings() {
        let dir = tempfile::tempdir().unwrap();
        let claude = dir.path().join(".claude");
        std::fs::create_dir_all(&claude).unwrap();
        std::fs::write(
            claude.join("settings.json"),
            r#"{"permissions":{"deny":["WebFetch"]}}"#,
        )
        .unwrap();

        FileProjectSettings::new(dir.path())
            .set_pretooluse_hook("/opt/searu scope-hook")
            .unwrap();

        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(claude.join("settings.json")).unwrap())
                .unwrap();
        let entry = &document["hooks"]["PreToolUse"][0];
        assert_eq!(entry["matcher"], "*");
        assert_eq!(entry["hooks"][0]["type"], "command");
        assert_eq!(entry["hooks"][0]["command"], "/opt/searu scope-hook");
        assert_eq!(document["permissions"]["deny"][0], "WebFetch");
    }

    #[test]
    fn setting_the_pretooluse_hook_twice_does_not_duplicate_it() {
        let dir = tempfile::tempdir().unwrap();
        let settings = FileProjectSettings::new(dir.path());
        settings
            .set_pretooluse_hook("/opt/searu scope-hook")
            .unwrap();
        settings
            .set_pretooluse_hook("/opt/searu scope-hook")
            .unwrap();

        let document: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.path().join(".claude").join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(document["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn lists_emitted_observations() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonlObservationStore::new(dir.path());
        store
            .emit(
                &Observation {
                    kind: "endpoint".to_string(),
                    value: "/login".to_string(),
                    detail: Some("fields: username,password".to_string()),
                },
                &RecordContext::default(),
            )
            .unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].observation.kind, "endpoint");
        assert_eq!(listed[0].observation.value, "/login");
        assert_eq!(
            listed[0].observation.detail.as_deref(),
            Some("fields: username,password")
        );
    }

    #[test]
    fn re_emitting_an_identical_finding_dedups_and_advances_last_seen() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonlFindingsStore::new(dir.path());
        let finding = Finding {
            tool: "commix".to_string(),
            target: "http://localhost:5000".to_string(),
            title: "OS command injection".to_string(),
            severity: Severity::Critical,
            status: Status::Confirmed,
            attack_technique: vec!["T1190".to_string()],
            cwe: vec![78],
            evidence: "x".to_string(),
            loot_fingerprint: None,
        };
        store.emit(&finding, &RecordContext::default()).unwrap();
        store.emit(&finding, &RecordContext::default()).unwrap();

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1, "identical findings must not re-append");
        assert!(listed[0].first_seen <= listed[0].last_seen);
        let lines = std::fs::read_to_string(dir.path().join("findings.jsonl")).unwrap();
        assert_eq!(lines.lines().count(), 1);
    }

    #[test]
    fn findings_differing_in_one_field_stay_distinct() {
        let dir = tempfile::tempdir().unwrap();
        let store = JsonlFindingsStore::new(dir.path());
        let base = Finding {
            tool: "commix".to_string(),
            target: "http://localhost:5000".to_string(),
            title: "OS command injection".to_string(),
            severity: Severity::Critical,
            status: Status::Confirmed,
            attack_technique: vec!["T1190".to_string()],
            cwe: vec![78],
            evidence: "a".to_string(),
            loot_fingerprint: None,
        };
        let mut other = base.clone();
        other.evidence = "b".to_string();
        store.emit(&base, &RecordContext::default()).unwrap();
        store.emit(&other, &RecordContext::default()).unwrap();

        assert_eq!(store.list().unwrap().len(), 2);
    }
}
