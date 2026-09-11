//! Ports: the traits the application depends on, implemented by adapters.

use crate::findings::{Finding, Loot};
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

pub struct ToolInvocation<'a> {
    pub tool: &'a str,
    pub target: &'a str,
    pub args: &'a [String],
    pub dockerfile: &'a str,
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
