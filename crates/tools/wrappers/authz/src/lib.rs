//! The authz tool wrapper: replay a single HTTP request against an in-scope URL with a chosen identity
//! (a low-privilege, another user's, a forged, or no token) to test broken access control and IDOR.
//! The caller asserts the request *should* be denied with `--should-deny`; if the resource is served
//! anyway (a 2xx/3xx), that is a confirmed access-control finding. Otherwise the run just records the
//! response as an observation. jwt's forged tokens and hydra/SQLi credentials feed the headers.

use searu_domain::findings::{Finding, Observation, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Authz;

pub static AUTHZ: Authz = Authz;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Exploitation,
    when: "test broken access control / IDOR — request a resource you should not be allowed (another user's object by id, an admin route, an unauthenticated call) and prove it is served (T1190, CWE-639/CWE-862). Exploitation tier: the ROE must allow-list T1190 and name an authoriser",
    invoke: "searu run authz --technique T1190 --target 'http://host:port/rest/basket/{id}' -- --should-deny --range 1-20 --header 'Authorization: Bearer <your-own-JWT>'  (authenticated IDOR: carry your token and sweep other ids; a served id that is not yours is the bug. Drop the header for unauth access; add --method/--data for write tampering. A single object needs no {id}/--range)",
    interpret: "searu findings --tool authz — one confirmed broken-access-control finding per served id; searu observations --kind replay for the status/length of every request",
    chain: "read or tamper each exposed object (`--method PUT --data ...`), and sweep the neighbouring routes (/api/Cards/{id}, /api/Addresss/{id}) the same way",
}];

impl Tool for Authz {
    fn name(&self) -> &'static str {
        "authz"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1190"]
    }

    fn dockerfile(&self) -> &'static str {
        // The replay script is spliced into a heredoc so it stays a lint-able file while travelling
        // inside the single Dockerfile the adapter builds.
        concat!(
            include_str!("../Dockerfile.head"),
            include_str!("../replay.py"),
            include_str!("../Dockerfile.tail"),
        )
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The target URL is the resource under test; the runner rewrites it for container reachability.
        let mut argv = vec!["--url".to_string(), target.to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut observations = Vec::new();
        for line in outcome.stdout.lines() {
            if let Some(rest) = line.strip_prefix("VIOLATION ") {
                let status = field(rest, "status=");
                // Each served id in a sweep carries its own url, so record a distinct finding per object
                // rather than collapsing the whole range into one.
                let url = field(rest, "url=");
                findings.push(Finding {
                    tool: "authz".to_string(),
                    target: url.clone().unwrap_or_else(|| target.to_string()),
                    title: "Broken access control".to_string(),
                    severity: Severity::High,
                    status: Status::Confirmed,
                    attack_technique: vec!["T1190".to_string()],
                    cwe: vec![639],
                    evidence: format!(
                        "a request that should have been denied was served (status {}){}",
                        status.as_deref().unwrap_or("2xx"),
                        url.as_deref().map(|u| format!(": {u}")).unwrap_or_default()
                    ),
                    loot_fingerprint: None,
                });
                continue;
            }
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
                if record["kind"] == "replay" {
                    if let Some(url) = record["url"].as_str() {
                        let status = record["status"].as_i64().unwrap_or_default();
                        let length = record["length"].as_i64().unwrap_or_default();
                        observations.push(Observation {
                            kind: "replay".to_string(),
                            value: url.to_string(),
                            detail: Some(format!("status {status}, {length} bytes")),
                        });
                    }
                }
            }
        }
        ParsedOutput {
            findings,
            observations,
            ..Default::default()
        }
    }
}

fn field(line: &str, marker: &str) -> Option<String> {
    line.split_once(marker)
        .map(|(_, rest)| rest.split_whitespace().next().unwrap_or(rest).to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outcome(stdout: &str) -> ToolOutcome {
        ToolOutcome {
            code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invocation_puts_the_target_url_first() {
        let argv = AUTHZ.invocation(
            "http://h:3000/rest/basket/2",
            &["--should-deny".to_string()],
        );
        assert_eq!(
            argv,
            vec!["--url", "http://h:3000/rest/basket/2", "--should-deny"]
        );
    }

    #[test]
    fn a_served_should_deny_request_is_a_confirmed_finding() {
        let out = outcome(
            "{\"kind\":\"replay\",\"status\":200,\"length\":812,\"url\":\"http://h:3000/rest/basket/2\"}\n\
             VIOLATION status=200 length=812 label=basket-2 url=http://h:3000/rest/basket/2\n",
        );
        let parsed = AUTHZ.parse("http://h:3000/rest/basket/2", "T1190", &out);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "Broken access control");
        assert_eq!(parsed.findings[0].cwe, vec![639]);
        assert_eq!(parsed.findings[0].status, Status::Confirmed);
        assert!(parsed.findings[0].evidence.contains("200"));
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(parsed.observations[0].kind, "replay");
    }

    #[test]
    fn an_id_sweep_records_one_finding_per_served_object() {
        // Baskets 3 and 5 were served to a token that owns neither (4 correctly denied) — two distinct
        // IDOR findings, each pinned to its own object url, not one collapsed finding.
        let out = outcome(
            "{\"kind\":\"replay\",\"status\":200,\"length\":90,\"url\":\"http://h/rest/basket/3\"}\n\
             VIOLATION status=200 length=90 label=b#3 url=http://h/rest/basket/3\n\
             {\"kind\":\"replay\",\"status\":401,\"length\":9,\"url\":\"http://h/rest/basket/4\"}\n\
             {\"kind\":\"replay\",\"status\":200,\"length\":88,\"url\":\"http://h/rest/basket/5\"}\n\
             VIOLATION status=200 length=88 label=b#5 url=http://h/rest/basket/5\n",
        );
        let parsed = AUTHZ.parse("http://h/rest/basket/{id}", "T1190", &out);
        assert_eq!(parsed.findings.len(), 2);
        assert_eq!(parsed.findings[0].target, "http://h/rest/basket/3");
        assert_eq!(parsed.findings[1].target, "http://h/rest/basket/5");
        assert!(parsed.findings[1]
            .evidence
            .contains("http://h/rest/basket/5"));
        assert_eq!(parsed.observations.len(), 3);
    }

    #[test]
    fn a_denied_request_records_only_the_replay_observation() {
        let out = outcome(
            "{\"kind\":\"replay\",\"status\":401,\"length\":20,\"url\":\"http://h:3000/rest/basket/2\"}\n",
        );
        let parsed = AUTHZ.parse("http://h:3000/rest/basket/2", "T1190", &out);
        assert!(parsed.findings.is_empty());
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(
            parsed.observations[0].detail.as_deref(),
            Some("status 401, 20 bytes")
        );
    }
}
