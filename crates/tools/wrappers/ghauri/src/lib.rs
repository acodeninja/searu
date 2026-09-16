//! The ghauri tool wrapper: how searu invokes ghauri and normalises its output into a SQL-injection
//! finding plus the back-end DBMS it fingerprints. ghauri is a sqlmap-style detector and exploiter;
//! this crate only shapes the invocation and reads the result.

use searu_domain::findings::{Finding, Observation, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Ghauri;

pub static GHAURI: Ghauri = Ghauri;

static USES: &[PhaseAdvice] = &[
    PhaseAdvice {
        phase: Phase::InitialAccess,
        when: "SQL injection detection — confirm an injectable parameter (T1190, CWE-89), a leaner alternative to sqlmap. Exploitation tier: the ROE must allow-list T1190 and name an authoriser",
        invoke: "searu run ghauri --technique T1190 --target 'http://host:port/path?id=1' -- -p id  (POST body and flags after `--`). ghauri has no `--ignore-redirects`; on a form that redirects on success give it an in-page oracle with `--string`/`--not-string`, and `--prefix`/`--suffix` if the query needs them",
        interpret: "searu findings — a confirmed SQL-injection finding (CWE-89); searu observations --kind tech — the back-end DBMS. A negative without an oracle means 'ghauri could not tell', not 'clean'",
        chain: "a confirmed injection with evidence authorises extraction in Exploitation",
    },
    PhaseAdvice {
        phase: Phase::Exploitation,
        when: "SQL injection extraction — enumerate/extract within what the ROE authorises, once detection confirmed the injection",
        invoke: "searu run ghauri --technique T1190 --target '...' -- -p id --dump / --dbs  (ghauri's own flags after `--`)",
        interpret: "searu findings / searu loot --reveal",
        chain: "let recorded state guide the next command; stop when the ROE-authorised objective is met",
    },
];

impl Tool for Ghauri {
    fn name(&self) -> &'static str {
        "ghauri"
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
        // Target via `-u` (the runner rewrites it for container reachability); --batch keeps ghauri
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
                tool: "ghauri".to_string(),
                target: target.to_string(),
                title: "SQL injection".to_string(),
                severity: Severity::Critical,
                status: Status::Confirmed,
                attack_technique: vec!["T1190".to_string()],
                cwe: vec![89],
                evidence: "ghauri confirmed an injectable parameter".to_string(),
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
    const MARKER: &str = "the back-end dbms is";
    stdout.lines().find_map(|line| {
        if line.contains('?') {
            return None;
        }
        let index = line.to_ascii_lowercase().find(MARKER)?;
        let value = line[index + MARKER.len()..]
            .trim()
            .trim_matches(|c: char| c == '\'' || c == '.' || c.is_whitespace());
        (!value.is_empty()).then(|| value.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_targets_the_url_in_batch_mode() {
        let argv = GHAURI.invocation("http://t/item?id=1", &["-p".to_string(), "id".to_string()]);
        assert_eq!(
            argv,
            vec!["-u", "http://t/item?id=1", "--batch", "-p", "id"]
        );
    }

    #[test]
    fn parses_an_injection_transcript_into_a_finding_and_the_dbms() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N\n\
                     Ghauri identified the following injection point(s) with a total of 17 HTTP(s) requests:\n\
                     Parameter: id (GET)\n    Type: boolean-based blind\n\
                     [06:44:44] [INFO] the back-end DBMS is MySQL\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = GHAURI.parse("http://localhost:5091/item?id=1", &outcome);

        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].cwe, vec![89]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1190"]);
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "tech" && o.value == "MySQL"));
    }

    #[test]
    fn a_clean_run_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "all tested parameters do not appear to be injectable.".to_string(),
            stderr: String::new(),
        };
        let parsed = GHAURI.parse("http://localhost:5091/item?id=1", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed.observations.is_empty());
    }
}
