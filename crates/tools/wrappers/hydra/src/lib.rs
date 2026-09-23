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
    invoke: "searu run hydra --technique T1110 --target <host> -- -s <port> -l <user> -P seclists:Passwords/Common-Credentials/Pwdb_top-10000.txt http-post-form '<path>:<body-with-^USER^/^PASS^>:H=Content-Type\\: application/json:S=<success-token>'  (the host is the target; everything else after `--`. A JSON/REST login answers failure with 401/403, so match the success response with S=<token>, not a fail-string; F=<text> only works when failure returns 200)",
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
        // hydra's first positional must be a *bare host* (the port is the separate `-s` flag), but the
        // driver naturally hands over a web URL like every other tool. Strip it to host + port so hydra
        // does not try to DNS-resolve `http://host:port/path`; synthesize `-s <port>` unless the caller
        // already passed one. The runner rewrites the bare host for container reachability.
        let (host, port) = split_host_port(target);
        let mut argv = vec![host];
        if let Some(port) = port {
            if !args.iter().any(|arg| arg == "-s") {
                argv.push("-s".to_string());
                argv.push(port);
            }
        }
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
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
                principal: Some(login),
                authenticates: Some(target.to_string()),
            });
        }
        ParsedOutput {
            findings,
            loot,
            ..Default::default()
        }
    }
}

/// Reduce a target to hydra's `(host, port)`: drop any `scheme://` and `/path`, and split a trailing
/// numeric `:port`. A bare host with no port yields `None` (the caller supplies `-s` itself).
fn split_host_port(target: &str) -> (String, Option<String>) {
    let after_scheme = target.split_once("://").map_or(target, |(_, rest)| rest);
    let host_port = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    match host_port.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), Some(port.to_string()))
        }
        _ => (host_port.to_string(), None),
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
    fn the_recommended_wordlist_is_a_live_seclists_path() {
        let invoke = HYDRA.uses()[0].invoke;
        assert!(invoke.contains("seclists:Passwords/Common-Credentials/Pwdb_top-10000.txt"));
        assert!(!invoke.contains("darkweb2017-top100.txt"));
    }

    #[test]
    fn the_json_login_hint_matches_the_success_response_not_a_fail_string() {
        let invoke = HYDRA.uses()[0].invoke;
        assert!(invoke.contains("S=<success-token>"));
        assert!(!invoke.contains(":<fail-string>'"));
    }

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
    fn a_url_target_is_reduced_to_a_bare_host_with_a_synthesized_port() {
        let argv = HYDRA.invocation(
            "http://localhost:3000/rest/user/login",
            &["-l".to_string(), "admin".to_string()],
        );
        assert_eq!(argv, vec!["localhost", "-s", "3000", "-l", "admin"]);
    }

    #[test]
    fn a_host_port_target_splits_the_port() {
        let argv = HYDRA.invocation("host.docker.internal:3000", &[]);
        assert_eq!(argv, vec!["host.docker.internal", "-s", "3000"]);
    }

    #[test]
    fn a_caller_supplied_port_is_not_duplicated() {
        let argv = HYDRA.invocation("http://h:3000", &["-s".to_string(), "443".to_string()]);
        assert_eq!(argv, vec!["h", "-s", "443"]);
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
        let parsed = HYDRA.parse("localhost", "T1046", &outcome);
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
        let parsed = HYDRA.parse("localhost", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed.loot.is_empty());
    }
}
