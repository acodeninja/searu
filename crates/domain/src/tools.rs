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

pub trait Tool: Sync {
    /// The tool's short name, used to select it and to tag findings.
    fn name(&self) -> &'static str;
    /// Every ATT&CK technique this tool can perform across its actions.
    fn techniques(&self) -> &'static [&'static str];
    /// The build recipe for the tool's container image, compiled into the binary.
    fn dockerfile(&self) -> &'static str;
    /// Prose guidance for Claude on how to drive the tool.
    fn advice(&self) -> &'static str;
    /// The tool arguments (not `docker`) for a run against `target` with the caller's extra `args`.
    fn invocation(&self, target: &str, args: &[String]) -> Vec<String>;
    /// Normalise the tool's output into findings/loot for a run against `target`.
    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput;
}

pub trait ToolRegistry {
    fn tool(&self, name: &str) -> Option<&'static dyn Tool>;
    fn tools_for(&self, technique: &str) -> Vec<&'static dyn Tool>;
    fn all(&self) -> Vec<&'static dyn Tool>;
}
