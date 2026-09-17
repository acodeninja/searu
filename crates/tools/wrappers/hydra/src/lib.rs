//! The hydra tool wrapper: brute-force an authentication endpoint and normalise hydra's output into a
//! weak-credentials finding plus the cracked credential as loot. hydra does the guessing; this crate
//! shapes the invocation and reads the result. The target is the host; the service, form spec and
//! login/password lists are the caller's own flags after `--`.

use searu_domain::findings::{Finding, Loot, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Hydra;

pub static HYDRA: Hydra = Hydra;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::InitialAccess,
    when: "online credential brute-force — guess valid login/password pairs against a live auth endpoint (web form, basic auth, a service) (T1110, CWE-307). Exploitation tier: the ROE must allow-list T1110 and name an authoriser",
    invoke: "searu run hydra --technique T1110 --target <host> -- -s <port> -l <user> -P seclists:Passwords/… http-post-form '<path>:<body-with-^USER^/^PASS^>:H=Content-Type\\: application/json:<fail-string>'  (the host is the target; everything else — service, spec, login/password lists — after `--`)",
    interpret: "searu findings --tool hydra — a weak-credentials finding (CWE-307) per cracked account; the password is stored as loot (searu loot --reveal), not in the finding",
    chain: "log in with the cracked credential and pivot to the authenticated attack surface (IDOR, admin functions) within the ROE",
}];

impl Tool for Hydra {
    fn name(&self) -> &'static str {
        "hydra"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1110"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // hydra takes the host as its first positional (the runner rewrites it for reachability) and
        // permutes the caller's options/service/spec that follow.
        let mut argv = vec![target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut loot = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            // The credential fields are `login: <x>   password: <y>`; the `misc:` field echoes the spec
            // (which contains `/login:`), so key on the colon-space form unique to the result fields.
            let (Some(login), Some(password)) =
                (credential(line, "login: "), credential(line, "password: "))
            else {
                continue;
            };
            if !seen.insert(format!("{login}|{password}")) {
                continue;
            }
            let value = format!("{login}:{password}");
            let fingerprint = searu_tool_parser::fingerprint(&value);
            findings.push(Finding {
                tool: "hydra".to_string(),
                target: target.to_string(),
                title: "Weak credentials".to_string(),
                severity: Severity::High,
                status: Status::Confirmed,
                attack_technique: vec!["T1110".to_string()],
                cwe: vec![307],
                evidence: format!("guessable credentials for login {login}"),
                loot_fingerprint: Some(fingerprint.clone()),
            });
            loot.push(Loot {
                fingerprint,
                category: "credential".to_string(),
                value,
            });
        }
        ParsedOutput {
            findings,
            loot,
            ..Default::default()
        }
    }
}

fn credential(line: &str, marker: &str) -> Option<String> {
    let (_, rest) = line.split_once(marker)?;
    let value = rest
        .split_once("password:")
        .map(|(head, _)| head)
        .unwrap_or(rest)
        .split("   ")
        .next()
        .unwrap_or(rest)
        .trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_puts_the_host_first_then_passes_the_service_through() {
        let argv = HYDRA.invocation(
            "localhost",
            &[
                "-s".to_string(),
                "5090".to_string(),
                "http-post-form".to_string(),
            ],
        );
        assert_eq!(argv, vec!["localhost", "-s", "5090", "http-post-form"]);
    }

    #[test]
    fn parses_a_cracked_credential_into_a_finding_and_loot() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[5090][http-post-form] host: h   misc: /rest/user/login:{}:F   login: admin@juice-sh.op   password: admin123\n\
                     [5090][http-post-form] host: h   misc: /rest/user/login:{}:F   login: admin@juice-sh.op   password: admin123\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = HYDRA.parse("localhost", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Weak credentials");
        assert_eq!(parsed.findings[0].cwe, vec![307]);
        assert_eq!(parsed.findings[0].attack_technique, vec!["T1110"]);
        assert_eq!(
            parsed.findings[0].evidence,
            "guessable credentials for login admin@juice-sh.op"
        );
        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(parsed.loot[0].category, "credential");
        assert_eq!(parsed.loot[0].value, "admin@juice-sh.op:admin123");
        assert_eq!(
            parsed.findings[0].loot_fingerprint.as_deref(),
            Some(parsed.loot[0].fingerprint.as_str())
        );
    }

    #[test]
    fn a_run_with_no_valid_pair_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "1 of 1 target completed, 0 valid passwords found\n".to_string(),
            stderr: String::new(),
        };
        let parsed = HYDRA.parse("localhost", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed.loot.is_empty());
    }
}
