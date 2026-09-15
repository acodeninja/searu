//! The sqlmap tool wrapper: how searu invokes sqlmap and normalises its output into a SQL-injection
//! finding plus the back-end DBMS it fingerprints. sqlmap does the exploiting; this crate only shapes
//! the invocation and reads the result.

use searu_domain::findings::{Finding, Observation, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Sqlmap;

pub static SQLMAP: Sqlmap = Sqlmap;

static USES: &[PhaseAdvice] = &[
    PhaseAdvice {
        phase: Phase::InitialAccess,
        when: "SQL injection detection — confirm an injectable parameter (T1190, CWE-89). Exploitation tier: the ROE must allow-list T1190 and name an authoriser",
        invoke: "searu run sqlmap --technique T1190 --target 'http://host:port/path?id=1' -- -p id  (POST body and flags after `--`). Blind login form: `-- -p username --level 3 --risk 3 --ignore-redirects --not-string login`, and `--suffix \"/*\"` if the query spans lines",
        interpret: "searu findings — a confirmed SQL-injection finding (CWE-89); searu observations --kind tech — the back-end DBMS. A negative with no oracle means 'sqlmap could not tell', not 'clean'",
        chain: "a confirmed injection with evidence authorises extraction in Exploitation",
    },
    PhaseAdvice {
        phase: Phase::Exploitation,
        when: "SQL injection extraction — enumerate/extract within what the ROE authorises, once detection confirmed the injection",
        invoke: "searu run sqlmap --technique T1190 --target '...' -- -p id --dump / --current-db  (sqlmap's own flags after `--`)",
        interpret: "searu findings / searu loot --reveal",
        chain: "let recorded state guide the next command; stop when the ROE-authorised objective is met",
    },
];

impl Tool for Sqlmap {
    fn name(&self) -> &'static str {
        "sqlmap"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1190"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // Target via `-u` (the runner rewrites it for container reachability); --batch keeps sqlmap
        // non-interactive. The caller supplies --data/--dump and any further flags.
        let mut argv = vec!["-u".to_string(), target.to_string(), "--batch".to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let lower = outcome.stdout.to_ascii_lowercase();
        let confirmed = lower.contains("is vulnerable")
            || lower.contains("identified the following injection point");

        let mut observations = Vec::new();
        if let Some(dbms) = back_end_dbms(&outcome.stdout) {
            observations.push(Observation {
                kind: "tech".to_string(),
                value: dbms,
                detail: Some("back-end DBMS".to_string()),
            });
        }

        let mut findings = Vec::new();
        if confirmed {
            findings.push(Finding {
                tool: "sqlmap".to_string(),
                target: target.to_string(),
                title: "SQL injection".to_string(),
                severity: Severity::Critical,
                status: Status::Confirmed,
                attack_technique: vec!["T1190".to_string()],
                cwe: vec![89],
                evidence: "sqlmap confirmed an injectable parameter".to_string(),
                loot_fingerprint: None,
            });
        }

        ParsedOutput {
            findings,
            observations,
            ..Default::default()
        }
    }
}

fn back_end_dbms(stdout: &str) -> Option<String> {
    const MARKER: &str = "back-end dbms:";
    stdout.lines().find_map(|line| {
        let index = line.to_ascii_lowercase().find(MARKER)?;
        let value = line[index + MARKER.len()..].trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_targets_the_url_in_batch_mode() {
        let argv = SQLMAP.invocation(
            "http://t/login",
            &["--data".to_string(), "username=a&password=a".to_string()],
        );
        assert_eq!(
            argv,
            vec![
                "-u",
                "http://t/login",
                "--batch",
                "--data",
                "username=a&password=a"
            ]
        );
    }

    #[test]
    fn parses_an_injection_transcript_into_a_finding_and_the_dbms() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "sqlmap identified the following injection point with a total of 74 HTTP(s) requests:\n\
                     Parameter: username (POST)\n    Type: boolean-based blind\n\
                     back-end DBMS: SQLite\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = SQLMAP.parse("http://localhost:5000/login", &outcome);

        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].cwe, vec![89]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1190"]);
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "tech" && o.value == "SQLite"));
    }

    #[test]
    fn a_clean_run_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "all tested parameters do not appear to be injectable".to_string(),
            stderr: String::new(),
        };
        let parsed = SQLMAP.parse("http://localhost:5000/login", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed.observations.is_empty());
    }
}
