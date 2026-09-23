//! Ports: the traits the application depends on, implemented by adapters.

use crate::benchmark::Challenge;
use crate::findings::{
    Finding, Loot, Observation, RecordContext, StoredFinding, StoredLoot, StoredObservation,
};
use crate::scope::Scope;

#[derive(Default)]
pub struct Roe {
    pub scope: Scope,
    pub allowed_techniques: Vec<String>,
    pub authorisation: Authorisation,
}

impl Roe {
    pub fn authorises(&self, technique_id: &str) -> bool {
        self.allowed_techniques.iter().any(|id| id == technique_id)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Authorisation {
    pub exploitation_authorised_by: Option<Authoriser>,
    pub destructive_authorised: bool,
}

#[derive(Debug, Clone)]
pub struct Authoriser {
    pub name: String,
    pub email: String,
}

#[derive(Debug)]
pub enum RepoError {
    Io(String),
    Parse(String),
}

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RepoError::Io(message) => write!(f, "could not read rules of engagement: {message}"),
            RepoError::Parse(message) => write!(f, "invalid rules of engagement: {message}"),
        }
    }
}

impl std::error::Error for RepoError {}

#[derive(Debug)]
pub enum RunnerError {
    Launch(String),
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::Launch(message) => write!(f, "could not launch the tool: {message}"),
        }
    }
}

impl std::error::Error for RunnerError {}

pub trait RoeRepository {
    fn load(&self) -> Result<Roe, RepoError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub host: String,
    pub container: String,
    pub readonly: bool,
}

pub struct ToolInvocation<'a> {
    pub tool: &'a str,
    pub target: &'a str,
    pub args: &'a [String],
    pub dockerfile: &'a str,
    pub mounts: &'a [Mount],
}

pub struct ToolOutcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait ToolRunner {
    fn run(&self, invocation: &ToolInvocation) -> Result<ToolOutcome, RunnerError>;
}

#[derive(Debug)]
pub enum StoreError {
    Io(String),
    Serialise(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(message) => {
                write!(f, "could not access the engagement store: {message}")
            }
            StoreError::Serialise(message) => {
                write!(f, "could not (de)serialise the record: {message}")
            }
        }
    }
}

impl std::error::Error for StoreError {}

pub trait FindingsStore {
    fn emit(&self, finding: &Finding, context: &RecordContext) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<StoredFinding>, StoreError>;
}

pub trait LootStore {
    fn emit(&self, loot: &Loot, context: &RecordContext) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<StoredLoot>, StoreError>;
}

pub trait ObservationStore {
    fn emit(&self, observation: &Observation, context: &RecordContext) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<StoredObservation>, StoreError>;
}

#[derive(Debug)]
pub enum WordlistError {
    Fetch(String),
    NotFound(String),
}

impl std::fmt::Display for WordlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WordlistError::Fetch(message) => write!(f, "could not fetch the wordlist: {message}"),
            WordlistError::NotFound(relative) => write!(
                f,
                "no such SecLists wordlist: {relative}. Only a `seclists:<path>` reference resolves \
                 inside the container — host filesystem paths and URLs are invisible to the tool. \
                 Check the path exists in SecLists (e.g. \
                 seclists:Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt)."
            ),
        }
    }
}

impl std::error::Error for WordlistError {}

pub trait WordlistProvider {
    fn root(&self) -> String;
    fn ensure(&self, relative: &str) -> Result<(), WordlistError>;
}

#[derive(Debug)]
pub enum SourceError {
    Invalid(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::Invalid(message) => write!(f, "invalid source target: {message}"),
        }
    }
}

impl std::error::Error for SourceError {}

pub trait SourceProvider {
    /// Resolve a workspace-relative source path to a confined absolute host path to mount read-only.
    fn resolve(&self, relative: &str) -> Result<String, SourceError>;
}

/// A per-invocation output directory: `host` is the absolute path to mount writable; `workspace` is the
/// workspace-relative path to show the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDir {
    pub host: String,
    pub workspace: String,
}

#[derive(Debug)]
pub enum OutputError {
    Io(String),
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputError::Io(message) => {
                write!(f, "could not access the output directory: {message}")
            }
        }
    }
}

impl std::error::Error for OutputError {}

pub trait OutputStore {
    /// Create a fresh per-invocation output directory for `tool` (a new id each call).
    fn prepare(&self, tool: &str) -> Result<OutputDir, OutputError>;
    /// Persist the run's raw stdout/stderr into the directory.
    fn save_raw(&self, dir: &OutputDir, stdout: &str, stderr: &str) -> Result<(), OutputError>;
    /// List the tool-produced files in the directory (excluding the saved raw output).
    fn collect(&self, dir: &OutputDir) -> Result<Vec<String>, OutputError>;
}

#[derive(Debug)]
pub enum SettingsError {
    Io(String),
    Parse(String),
}

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SettingsError::Io(message) => {
                write!(f, "could not access the project settings: {message}")
            }
            SettingsError::Parse(message) => write!(f, "invalid project settings: {message}"),
        }
    }
}

impl std::error::Error for SettingsError {}

pub trait ProjectSettings {
    fn denied_egress(&self) -> Result<Vec<String>, SettingsError>;
    fn set_denied_egress(&self, deny: &[String]) -> Result<(), SettingsError>;
    /// Install a `PreToolUse` hook (matcher `*`) that runs `command`. Unlike a skill-frontmatter hook,
    /// a settings-level hook reaches a spawned specialist, so this is where the scope-hook allowlist
    /// must live to constrain a subagent's Bash.
    fn set_pretooluse_hook(&self, command: &str) -> Result<(), SettingsError>;
}

pub struct AuditEntry<'a> {
    pub tool: &'a str,
    pub technique: &'a str,
    pub target: &'a str,
    pub decision: &'a str,
    pub args: &'a [String],
}

pub trait AuditLog {
    fn record(&self, entry: &AuditEntry) -> Result<(), StoreError>;
}

/// A recorded run as read back from the audit log: the same fields as an [`AuditEntry`] but owned, plus
/// the timestamp the store stamped. Coverage reads these to know which techniques have been attempted.
#[derive(Debug, Clone)]
pub struct StoredAudit {
    pub tool: String,
    pub technique: String,
    pub target: String,
    pub decision: String,
    pub args: Vec<String>,
    pub at: u64,
}

pub trait AuditReader {
    fn list(&self) -> Result<Vec<StoredAudit>, StoreError>;
}

#[derive(Debug)]
pub enum BenchmarkError {
    Fetch(String),
    Parse(String),
}

impl std::fmt::Display for BenchmarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BenchmarkError::Fetch(message) => {
                write!(f, "could not read the benchmark score board: {message}")
            }
            BenchmarkError::Parse(message) => {
                write!(f, "could not parse the benchmark score board: {message}")
            }
        }
    }
}

impl std::error::Error for BenchmarkError {}

/// Reads a benchmark target's own progress API (its answer key) — a decoupled measurement source, never
/// consulted by the engine while it attacks.
pub trait ScoreboardProvider {
    fn challenges(&self, target: &str) -> Result<Vec<Challenge>, BenchmarkError>;
}

/// Persists each scoring run so the next one can report progress since last time.
pub trait BenchmarkStore {
    fn record(&self, solved: usize, total: usize) -> Result<(), StoreError>;
    fn last(&self) -> Result<Option<(usize, usize)>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_wordlist_names_the_path_and_steers_away_from_host_paths() {
        let message =
            WordlistError::NotFound("Passwords/darkweb2017-top100.txt".to_string()).to_string();
        assert!(message.contains("Passwords/darkweb2017-top100.txt"));
        assert!(message.contains("seclists:"));
        assert!(message.contains("host filesystem paths and URLs are invisible"));
    }
}
