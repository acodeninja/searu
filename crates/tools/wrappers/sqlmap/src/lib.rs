//! The sqlmap tool wrapper: how searu invokes sqlmap and normalises its output into a SQL-injection
//! finding plus the back-end DBMS it fingerprints. sqlmap does the exploiting; this crate only shapes
//! the invocation and reads the result.

use searu_domain::findings::{Finding, Loot, Observation, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::scope::target_host;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use searu_tool_parser::{fingerprint, text};

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

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let decoded = text::strip_ansi(&outcome.stdout);
        let lower = decoded.to_ascii_lowercase();
        let confirmed = lower.contains("is vulnerable")
            || lower.contains("identified the following injection point");

        let mut observations = Vec::new();
        if let Some(dbms) = back_end_dbms(&decoded) {
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

        // A `--dump` recovers credentials: each becomes loot plus an exposed-credential finding
        // (CWE-522) linked by fingerprint — the finding never carries the plaintext.
        let loot = dump_loot(target, &decoded);
        for item in &loot {
            let evidence = match item.authenticates.as_deref() {
                Some(authenticates) if !authenticates.is_empty() => format!(
                    "{} dumped via SQL injection, authenticates against {authenticates}",
                    item.category
                ),
                _ => format!("{} dumped via SQL injection", item.category),
            };
            findings.push(Finding {
                tool: "sqlmap".to_string(),
                target: target.to_string(),
                title: "Exposed credential".to_string(),
                severity: Severity::High,
                status: Status::Confirmed,
                attack_technique: vec!["T1552".to_string()],
                cwe: vec![522],
                evidence,
                loot_fingerprint: Some(item.fingerprint.clone()),
            });
        }

        ParsedOutput {
            findings,
            loot,
            observations,
        }
    }
}

/// Turn sqlmap `--dump` tables into credential loot: for each row with a secret column
/// (`password`/`hash`/…) record the secret, its subject (a `username`/`email` column, or the userinfo
/// of a connection string), and the host it authenticates against. Deduped by fingerprint.
fn dump_loot(target: &str, stdout: &str) -> Vec<Loot> {
    let host = target_host(target);
    let mut loot: Vec<Loot> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for table in text::dump_tables(stdout) {
        let Some(secret_col) = table.headers.iter().position(|h| is_secret_column(h)) else {
            continue;
        };
        let principal_col = table.headers.iter().position(|h| is_principal_column(h));
        let category = table.headers[secret_col].to_ascii_lowercase();
        for row in &table.rows {
            let value = row
                .get(secret_col)
                .map(|cell| cell.trim())
                .filter(|cell| !cell.is_empty());
            let Some(value) = value else { continue };
            let value = value.to_string();
            let fp = fingerprint(&value);
            if seen.contains(&fp) {
                continue;
            }
            let subject = text::credential_subject(&value);
            let principal = subject
                .as_ref()
                .map(|(principal, _)| principal.clone())
                .or_else(|| {
                    principal_col
                        .and_then(|index| row.get(index))
                        .map(|cell| cell.trim())
                        .filter(|cell| !cell.is_empty())
                        .map(str::to_string)
                });
            let authenticates = subject
                .map(|(_, authenticates)| authenticates)
                .unwrap_or_else(|| host.clone());
            seen.push(fp.clone());
            loot.push(Loot {
                fingerprint: fp,
                category: category.clone(),
                value,
                principal,
                authenticates: Some(authenticates),
            });
        }
    }
    loot
}

fn is_secret_column(header: &str) -> bool {
    matches!(
        header.to_ascii_lowercase().as_str(),
        "password" | "passwd" | "pass" | "pwd" | "hash" | "secret"
    )
}

fn is_principal_column(header: &str) -> bool {
    matches!(
        header.to_ascii_lowercase().as_str(),
        "email" | "username" | "user" | "login"
    )
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
        let parsed = SQLMAP.parse("http://localhost:5000/login", "T1046", &outcome);

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
        let parsed = SQLMAP.parse("http://localhost:5000/login", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed.observations.is_empty());
        assert!(parsed.loot.is_empty());
    }

    #[test]
    fn a_dump_records_each_credential_as_loot_and_a_cwe_522_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "sqlmap identified the following injection point:\nback-end DBMS: SQLite\n\
Database: juiceshop\nTable: Users\n[2 entries]\n\
+----+-------------------+----------------------------------+\n\
| id | email             | password                         |\n\
+----+-------------------+----------------------------------+\n\
| 1  | admin@juice-sh.op | 0192023a7bbd73250516f069df18b500 |\n\
| 2  | jim@juice-sh.op   | e10adc3949ba59abbe56e057f20f883e |\n\
+----+-------------------+----------------------------------+\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = SQLMAP.parse(
            "http://localhost:3000/rest/products/search?q=1",
            "T1190",
            &outcome,
        );

        assert_eq!(parsed.loot.len(), 2);
        let admin = parsed
            .loot
            .iter()
            .find(|l| l.principal.as_deref() == Some("admin@juice-sh.op"))
            .expect("admin loot");
        assert_eq!(admin.category, "password");
        assert_eq!(admin.value, "0192023a7bbd73250516f069df18b500");
        assert_eq!(admin.authenticates.as_deref(), Some("localhost"));

        let cwe522: Vec<_> = parsed
            .findings
            .iter()
            .filter(|f| f.cwe == vec![522])
            .collect();
        assert_eq!(cwe522.len(), 2);
        assert!(cwe522
            .iter()
            .all(|f| f.attack_technique == vec!["T1552"] && f.loot_fingerprint.is_some()));
        assert!(parsed.findings.iter().any(|f| f.cwe == vec![89]));

        // The plaintext never leaks into a finding — only the loot store holds it.
        assert!(!format!("{:?}", parsed.findings).contains("0192023a7bbd73250516f069df18b500"));
    }

    #[test]
    fn a_repeated_secret_is_deduped() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "Table: Users\n\
+----+----------+\n| id | password |\n+----+----------+\n| 1  | reused   |\n| 2  | reused   |\n+----+----------+\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = SQLMAP.parse("http://localhost:3000/", "T1190", &outcome);
        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(
            parsed
                .findings
                .iter()
                .filter(|f| f.cwe == vec![522])
                .count(),
            1
        );
    }
}
