//! The tool registry: the set of concrete tools searu knows about, exposed through the domain
//! `ToolRegistry` port. Adding a tool = depending on its crate and adding it to `TOOLS`.

use searu_domain::tools::{Tool, ToolRegistry};
use searu_tool_arjun::ARJUN;
use searu_tool_bandit::BANDIT;
use searu_tool_brakeman::BRAKEMAN;
use searu_tool_checkov::CHECKOV;
use searu_tool_commix::COMMIX;
use searu_tool_dalfox::DALFOX;
use searu_tool_dnsx::DNSX;
use searu_tool_feroxbuster::FEROXBUSTER;
use searu_tool_ffuf::FFUF;
use searu_tool_ghauri::GHAURI;
use searu_tool_gitleaks::GITLEAKS;
use searu_tool_gobuster::GOBUSTER;
use searu_tool_gosec::GOSEC;
use searu_tool_gospider::GOSPIDER;
use searu_tool_grype::GRYPE;
use searu_tool_hadolint::HADOLINT;
use searu_tool_httpx::HTTPX;
use searu_tool_katana::KATANA;
use searu_tool_nikto::NIKTO;
use searu_tool_njsscan::NJSSCAN;
use searu_tool_nmap::NMAP;
use searu_tool_nuclei::NUCLEI;
use searu_tool_osv_scanner::OSV_SCANNER;
use searu_tool_semgrep::SEMGREP;
use searu_tool_sqlmap::SQLMAP;
use searu_tool_subfinder::SUBFINDER;
use searu_tool_tlsx::TLSX;
use searu_tool_trivy::TRIVY;
use searu_tool_trufflehog::TRUFFLEHOG;
use searu_tool_wafw00f::WAFW00F;
use searu_tool_whatweb::WHATWEB;

static TOOLS: &[&'static dyn Tool] = &[
    &ARJUN,
    &BANDIT,
    &BRAKEMAN,
    &CHECKOV,
    &COMMIX,
    &DALFOX,
    &DNSX,
    &FEROXBUSTER,
    &GHAURI,
    &GITLEAKS,
    &GOBUSTER,
    &GOSEC,
    &GOSPIDER,
    &GRYPE,
    &HADOLINT,
    &HTTPX,
    &KATANA,
    &NIKTO,
    &NJSSCAN,
    &NMAP,
    &NUCLEI,
    &OSV_SCANNER,
    &SEMGREP,
    &SQLMAP,
    &SUBFINDER,
    &TLSX,
    &TRIVY,
    &TRUFFLEHOG,
    &WAFW00F,
    &WHATWEB,
    &FFUF,
];

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
