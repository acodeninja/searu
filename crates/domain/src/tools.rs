//! The `Tool` abstraction. A tool is a thin crate that knows how to invoke one containerised security
//! tool and normalise its output into findings/loot; searu's core runs it and stores the result but
//! never parses tool output itself. `domain` owns the trait; concrete tools live in their own crates.

use crate::findings::{Finding, Loot, Observation};
use crate::ports::ToolOutcome;

#[derive(Default)]
pub struct ParsedOutput {
    pub findings: Vec<Finding>,
    pub loot: Vec<Loot>,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Reconnaissance,
    Discovery,
    InitialAccess,
    Exploitation,
    Analysis,
}

impl Phase {
    pub const ALL: [Phase; 5] = [
        Phase::Reconnaissance,
        Phase::Discovery,
        Phase::InitialAccess,
        Phase::Exploitation,
        Phase::Analysis,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Phase::Reconnaissance => "reconnaissance",
            Phase::Discovery => "discovery",
            Phase::InitialAccess => "initial-access",
            Phase::Exploitation => "exploitation",
            Phase::Analysis => "analysis",
        }
    }

    pub fn parse(id: &str) -> Option<Phase> {
        Phase::ALL.into_iter().find(|phase| phase.id() == id)
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// A tool's manifest entry for one phase: when to reach for it, and how to drive, read and chain it.
pub struct PhaseAdvice {
    pub phase: Phase,
    pub when: &'static str,
    pub invoke: &'static str,
    pub interpret: &'static str,
    pub chain: &'static str,
}

pub trait Tool: Sync {
    /// The tool's short name, used to select it and to tag findings.
    fn name(&self) -> &'static str;
    /// Every ATT&CK technique this tool can perform across its actions.
    fn techniques(&self) -> &'static [&'static str];
    /// The build recipe for the tool's container image, compiled into the binary.
    fn dockerfile(&self) -> &'static str;
    /// The tool's per-phase manifest: one entry per engagement phase it serves.
    fn uses(&self) -> &'static [PhaseAdvice];
    /// The tool arguments (not `docker`) for a run against `target` with the caller's extra `args`.
    fn invocation(&self, target: &str, args: &[String]) -> Vec<String>;
    /// Normalise the tool's output into findings/loot for a run against `target` under `technique` — the
    /// ATT&CK technique the run performed, so a tool can label or branch on what the run was for.
    fn parse(&self, target: &str, technique: &str, outcome: &ToolOutcome) -> ParsedOutput;
}

pub trait ToolRegistry {
    fn tool(&self, name: &str) -> Option<&'static dyn Tool>;
    fn tools_for(&self, technique: &str) -> Vec<&'static dyn Tool>;
    fn all(&self) -> Vec<&'static dyn Tool>;
}
