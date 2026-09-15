//! The tool registry: the set of concrete tools searu knows about, exposed through the domain
//! `ToolRegistry` port. Adding a tool = depending on its crate and adding it to `TOOLS`.

use searu_domain::tools::{Tool, ToolRegistry};
use searu_tool_commix::COMMIX;
use searu_tool_ffuf::FFUF;
use searu_tool_httpx::HTTPX;
use searu_tool_katana::KATANA;
use searu_tool_nmap::NMAP;
use searu_tool_sqlmap::SQLMAP;

static TOOLS: &[&'static dyn Tool] = &[&COMMIX, &HTTPX, &KATANA, &NMAP, &SQLMAP, &FFUF];

#[derive(Default)]
pub struct Registry;

impl ToolRegistry for Registry {
    fn tool(&self, name: &str) -> Option<&'static dyn Tool> {
        TOOLS.iter().copied().find(|t| t.name() == name)
    }

    fn tools_for(&self, technique: &str) -> Vec<&'static dyn Tool> {
        TOOLS
            .iter()
            .copied()
            .filter(|t| {
                // `contains` cannot typecheck against `&'static str` elements and a borrowed arg.
                #[allow(clippy::manual_contains)]
                let performs = t.techniques().iter().any(|id| *id == technique);
                performs
            })
            .collect()
    }

    fn all(&self) -> Vec<&'static dyn Tool> {
        TOOLS.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_commix_by_name() {
        assert!(Registry.tool("commix").is_some());
        assert!(Registry.tool("nope").is_none());
    }

    #[test]
    fn finds_tools_for_a_technique() {
        assert!(Registry
            .tools_for("T1190")
            .iter()
            .any(|t| t.name() == "commix"));
        assert!(Registry.tools_for("T9999").is_empty());
    }
}
