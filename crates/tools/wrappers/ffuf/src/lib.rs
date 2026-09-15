//! The ffuf tool wrapper: fuzz a `FUZZ` keyword against a wordlist and normalise the matches into
//! either a path-traversal finding (when the matched payloads are traversals) or endpoint
//! observations (content discovery). ffuf does the fuzzing; this crate shapes the invocation and
//! reads the result.

use searu_domain::findings::{Finding, Observation, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Ffuf;

pub static FFUF: Ffuf = Ffuf;

static USES: &[PhaseAdvice] = &[
    PhaseAdvice {
        phase: Phase::Discovery,
        when: "content discovery — find unlinked routes by fuzzing a `FUZZ` keyword against a wordlist",
        invoke: "searu run ffuf --technique T1595 --target 'http://host:port/FUZZ' -- -w seclists:Discovery/Web-Content/common.txt -mc 200  (searu fetches the list once and mounts it read-only; `-mc 200` keeps only successful reads)",
        interpret: "searu observations --kind endpoint — one per hit",
        chain: "discovered routes/parameters feed Initial access — the parameters are where you test for injection",
    },
    PhaseAdvice {
        phase: Phase::InitialAccess,
        when: "LFI / path traversal — read files off the host by fuzzing a traversal wordlist against a file parameter (T1190, CWE-22; Exploitation tier, needs an authoriser)",
        invoke: "searu run ffuf --technique T1190 --target 'http://host:port/download?file=FUZZ' -- -w seclists:Fuzzing/LFI/LFI-Jhaddix.txt -mc 200  (pick the OS-appropriate LFI list from recon's tech/server hints)",
        interpret: "searu findings — a confirmed path-traversal finding (CWE-22) when the matched payloads are traversals",
        chain: "a confirmed weakness with its evidence authorises moving to Exploitation",
    },
];

impl Tool for Ffuf {
    fn name(&self) -> &'static str {
        "ffuf"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595", "T1190"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // Target via `-u` with a FUZZ keyword (the runner rewrites the host for reachability); `-s`
        // prints only the matched payloads. The caller supplies -w (a seclists: token) and matchers.
        let mut argv = vec!["-u".to_string(), target.to_string(), "-s".to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let hits: Vec<&str> = outcome
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        if hits.is_empty() {
            return ParsedOutput::default();
        }

        if hits.iter().any(|hit| is_traversal(hit)) {
            let sample = hits.iter().take(3).copied().collect::<Vec<_>>().join(", ");
            return ParsedOutput {
                findings: vec![Finding {
                    tool: "ffuf".to_string(),
                    target: target.to_string(),
                    title: "Path traversal".to_string(),
                    severity: Severity::High,
                    status: Status::Confirmed,
                    attack_technique: vec!["T1190".to_string()],
                    cwe: vec![22],
                    evidence: format!(
                        "ffuf matched {} traversal payload(s), e.g. {sample}",
                        hits.len()
                    ),
                    loot_fingerprint: None,
                }],
                ..Default::default()
            };
        }

        ParsedOutput {
            observations: hits
                .into_iter()
                .map(|hit| Observation {
                    kind: "endpoint".to_string(),
                    value: hit.to_string(),
                    detail: Some("ffuf match".to_string()),
                })
                .collect(),
            ..Default::default()
        }
    }
}

fn is_traversal(hit: &str) -> bool {
    let lower = hit.to_ascii_lowercase();
    hit.contains("..")
        || lower.contains("etc/passwd")
        || lower.contains("%2e")
        || lower.contains("%252e")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_targets_the_url_in_silent_mode() {
        let argv = FFUF.invocation(
            "http://t/download?file=FUZZ",
            &[
                "-w".to_string(),
                "seclists:Fuzzing/LFI/LFI-Jhaddix.txt".to_string(),
                "-mc".to_string(),
                "200".to_string(),
            ],
        );
        assert_eq!(
            argv,
            vec![
                "-u",
                "http://t/download?file=FUZZ",
                "-s",
                "-w",
                "seclists:Fuzzing/LFI/LFI-Jhaddix.txt",
                "-mc",
                "200",
            ]
        );
    }

    #[test]
    fn traversal_matches_become_a_path_traversal_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "../../../../../../etc/passwd\n%2e%2e/%2e%2e/etc/passwd\n".to_string(),
            stderr: String::new(),
        };
        let parsed = FFUF.parse("http://localhost:5000/download?file=FUZZ", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].cwe, vec![22]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1190"]);
        assert!(parsed.observations.is_empty());
    }

    #[test]
    fn plain_matches_become_endpoint_observations() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "admin\nlogin\n".to_string(),
            stderr: String::new(),
        };
        let parsed = FFUF.parse("http://localhost:5000/FUZZ", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "endpoint" && o.value == "admin"));
    }

    #[test]
    fn no_matches_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let parsed = FFUF.parse("http://localhost:5000/FUZZ", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed.observations.is_empty());
    }
}
