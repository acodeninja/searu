//! The git-dumper tool wrapper: reconstruct a source tree from an exposed `.git` directory. git-dumper
//! does the fetching and checkout, writing the reconstructed repository into the run's output directory
//! (mounted writable at `/out` via the `out:` token); this crate shapes the invocation and reads the
//! result. The target is the `http://host/.git` URL.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct GitDumper;

pub static GIT_DUMPER: GitDumper = GitDumper;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Discovery,
    when: "source disclosure — reconstruct a web app's source tree from an exposed `.git` directory (CWE-527/540), turning a misconfiguration into the full codebase (T1595, Active: allow-listing the technique is enough)",
    invoke: "searu run git-dumper --technique T1595 --target http://host:port/.git  (git-dumper's own flags after `--`)",
    interpret: "searu findings --tool git-dumper — a source-disclosure finding when the repository is reconstructed; searu observations --kind output — the run's output directory holding the recovered tree",
    chain: "scan the recovered tree with SAST — `searu run semgrep --target src:pentest/outputs/git-dumper/<id>` — and sweep it for secrets (gitleaks/trufflehog)",
}];

impl Tool for GitDumper {
    fn name(&self) -> &'static str {
        "git-dumper"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // git-dumper takes the `.git` URL and an output directory; the `out:` token mounts the run's
        // output directory writable at `/out`, where the reconstructed tree lands.
        let mut argv = vec![target.to_string(), "out:".to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        // git-dumper runs `git checkout` once it has fetched enough of the .git to reconstruct the tree.
        let reconstructed = outcome
            .stdout
            .lines()
            .chain(outcome.stderr.lines())
            .any(|line| line.contains("Running git checkout"));
        if !reconstructed {
            return ParsedOutput::default();
        }
        ParsedOutput {
            findings: vec![Finding {
                tool: "git-dumper".to_string(),
                target: target.to_string(),
                title: "Source code disclosure".to_string(),
                severity: Severity::High,
                status: Status::Confirmed,
                attack_technique: vec!["T1595".to_string()],
                cwe: vec![527],
                evidence: format!("reconstructed the repository from {target}"),
                loot_fingerprint: None,
            }],
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_dumps_the_git_url_into_the_output_mount() {
        let argv = GIT_DUMPER.invocation("http://h/.git", &[]);
        assert_eq!(argv, vec!["http://h/.git", "out:"]);
    }

    #[test]
    fn parses_a_reconstructed_repository_into_a_disclosure_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[-] Sanitizing .git/config\n[-] Running git checkout .\nUpdated 1 path from the index\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = GIT_DUMPER.parse("http://h/.git", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Source code disclosure");
        assert_eq!(parsed.findings[0].cwe, vec![527]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1595"]);
        assert_eq!(
            parsed.findings[0].evidence,
            "reconstructed the repository from http://h/.git"
        );
    }

    #[test]
    fn a_missing_git_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[-] Testing http://h/.git/HEAD [404]\n".to_string(),
            stderr: String::new(),
        };
        let parsed = GIT_DUMPER.parse("http://h/.git", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
