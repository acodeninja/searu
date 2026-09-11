//! Ports: the traits the application depends on, implemented by adapters.

use crate::scope::Scope;

pub struct Roe {
    pub scope: Scope,
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
}

pub trait ToolRunner {
    fn run(&self, invocation: &ToolInvocation) -> Result<i32, RunnerError>;
}
