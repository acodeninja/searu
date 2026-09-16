//! Ports: the traits the application depends on, implemented by adapters.

use crate::findings::{Finding, Loot, Observation};
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
    fn emit(&self, finding: &Finding) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<Finding>, StoreError>;
}

pub trait LootStore {
    fn emit(&self, loot: &Loot) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<Loot>, StoreError>;
}

pub trait ObservationStore {
    fn emit(&self, observation: &Observation) -> Result<(), StoreError>;
    fn list(&self) -> Result<Vec<Observation>, StoreError>;
}

#[derive(Debug)]
pub enum WordlistError {
    Fetch(String),
}

impl std::fmt::Display for WordlistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WordlistError::Fetch(message) => write!(f, "could not fetch the wordlist: {message}"),
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
