//! The corsy tool wrapper: probe a URL's CORS policy and normalise corsy's console report into
//! misconfiguration findings. corsy does the detection; this crate shapes the invocation and reads the
//! result. The target is a URL. corsy writes JSON only to a file, so this parses its console output.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Corsy;

pub static CORSY: Corsy = Corsy;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "CORS misconfiguration detection — check whether a host's cross-origin policy trusts attacker origins (wildcard, reflected origin, null) (T1595, CWE-942; Active: allow-listing the technique is enough)",
    invoke: "searu run corsy --technique T1595 --target http://host:port  (corsy's own flags after `--`, e.g. `-- --headers \"Cookie: session=…\"` to test an authenticated endpoint)",
    interpret: "searu findings --tool corsy — one finding per misconfiguration class; the evidence is the offending Access-Control-Allow-Origin header and the class corsy assigned",
    chain: "a reflected-origin or credentialed-wildcard policy authorises a cross-origin data-theft PoC; a bare wildcard without credentials is lower impact — note it and move on",
}];

impl Tool for Corsy {
    fn name(&self) -> &'static str {
        "corsy"
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
        // corsy takes the URL with `-u` and prints its report to stdout.
        let mut argv = vec!["-u".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        let mut class: Option<String> = None;
        let mut severity = String::new();
        let mut acao: Option<String> = None;

        let mut flush = |class: &mut Option<String>,
                         severity: &str,
                         acao: &Option<String>|
         -> Option<Finding> {
            let class = class.take()?;
            let evidence = match acao {
                Some(value) => format!("{class}; ACAO: {value}"),
                None => class.clone(),
            };
            if !seen.insert(evidence.clone()) {
                return None;
            }
            Some(Finding {
                tool: "corsy".to_string(),
                target: target.to_string(),
                title: "CORS misconfiguration".to_string(),
                severity: severity_of(severity),
                status: Status::NeedsReview,
                attack_technique: vec!["T1595".to_string()],
                cwe: vec![942],
                evidence,
                loot_fingerprint: None,
            })
        };

        for raw in outcome.stdout.lines() {
            let line = strip_ansi(raw);
            let line = line.trim();
            if let Some((_, value)) = line.split_once("Class:") {
                if let Some(finding) = flush(&mut class, &severity, &acao) {
                    findings.push(finding);
                }
                severity.clear();
                acao = None;
                class = Some(value.trim().to_string());
            } else if let Some((_, value)) = line.split_once("Severity:") {
                severity = value.trim().to_string();
            } else if let Some((_, value)) = line.split_once("ACAO Header:") {
                acao = Some(value.trim().to_string());
            }
        }
        if let Some(finding) = flush(&mut class, &severity, &acao) {
            findings.push(finding);
        }
        ParsedOutput {
            findings,
            ..Default::default()
        }
    }
}

fn severity_of(name: &str) -> Severity {
    match name {
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_escape = false;
    for c in line.chars() {
        if in_escape {
            in_escape = !c.is_ascii_alphabetic();
        } else if c == '\u{1b}' {
            in_escape = true;
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_probes_the_target_url() {
        let argv = CORSY.invocation("http://h:3000", &[]);
        assert_eq!(argv, vec!["-u", "http://h:3000"]);
    }

    #[test]
    fn parses_a_wildcard_misconfiguration_into_a_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: " + http://h:3000\n\
                     \u{1b}[93m   - \u{1b}[0mClass: wildcard value\n\
                        - Description: allows any origin\n\
                        - Severity: low\n\
                        - Exploitation: Not possible\n\
                        - ACAO Header: *\n\
                        - ACAC Header: None\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = CORSY.parse("http://h:3000", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "CORS misconfiguration");
        assert_eq!(parsed.findings[0].cwe, vec![942]);
        assert_eq!(parsed.findings[0].severity, Severity::Low);
        assert_eq!(parsed.findings[0].evidence, "wildcard value; ACAO: *");
    }

    #[test]
    fn a_clean_policy_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "    CORSY  {v1.0-beta}\n\n".to_string(),
            stderr: String::new(),
        };
        let parsed = CORSY.parse("http://h:3000", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
