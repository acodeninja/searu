//! The commix tool wrapper: how searu invokes commix and normalises its output into findings/loot.
//! commix does the exploiting; this crate only shapes the invocation and reads the result.

use searu_domain::assets::{ClaimKind, IdentityClaim, IDENTITY_CLAIM_KIND};
use searu_domain::findings::{Finding, Loot, Observation, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Commix;

pub static COMMIX: Commix = Commix;

static USES: &[PhaseAdvice] = &[
    PhaseAdvice {
        phase: Phase::InitialAccess,
        when: "OS command injection — confirm a foothold with a harmless probe (T1190/T1059, CWE-78). Exploitation tier: allow-list the technique and name an authoriser",
        invoke: "searu run commix --technique T1190 --target 'http://host:port/path?param=1' -- --os-cmd id  (confirm with a harmless command first; commix auto-detects GET parameters)",
        interpret: "searu findings — an OS-command-injection finding; a run that confirms nothing records nothing",
        chain: "a confirmed foothold authorises collection in Exploitation",
    },
    PhaseAdvice {
        phase: Phase::Exploitation,
        when: "post-exploitation collection through the confirmed foothold — pick the ATT&CK technique matching intent so the gate authorises it",
        invoke: "searu run commix --target '...' -- --os-cmd <cmd> with the matching technique: `--technique T1552 -- --os-cmd env` (env credentials); `--technique T1518` (installed software); `--technique T1083 -- --os-cmd 'ls -la /app'` (files). Each technique needs allow-listing in its own right",
        interpret: "searu findings / searu loot --reveal — secrets from the foothold land in loot; findings keep only a fingerprint, never the value",
        chain: "let the recorded state guide the next command; stop when the objective the ROE authorised is met",
    },
];

impl Tool for Commix {
    fn name(&self) -> &'static str {
        "commix"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1190", "T1059", "T1082", "T1083", "T1518", "T1552"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, _target: &str, args: &[String]) -> Vec<String> {
        // commix reads its target from stdin (searu feeds it there), so the invocation is just the
        // batch flag plus the caller's action arguments.
        let mut argv = vec!["--batch".to_string()];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let decoded = searu_tool_parser::text::strip_ansi(&searu_tool_parser::text::html_unescape(
            &outcome.stdout,
        ));

        let loot: Vec<Loot> = searu_tool_parser::text::secrets(&decoded)
            .into_iter()
            .map(|(category, value)| {
                let subject = searu_tool_parser::text::credential_subject(&value);
                Loot {
                    fingerprint: searu_tool_parser::fingerprint(&value),
                    category,
                    value,
                    principal: subject.as_ref().map(|(principal, _)| principal.clone()),
                    authenticates: subject.map(|(_, authenticates)| authenticates),
                }
            })
            .collect();

        let command_outputs = searu_tool_parser::text::commix_command_outputs(&decoded);

        let lower = decoded.to_ascii_lowercase();
        let confirmed = !loot.is_empty()
            || !command_outputs.is_empty()
            || lower.contains("vulnerable")
            || lower.contains("injectable");

        // The injection itself is one finding (T1190 → T1059), recorded when the run that confirms the
        // foothold executes; collection runs through the foothold record observations, not findings.
        let mut findings = Vec::new();
        if confirmed && (technique == "T1190" || technique == "T1059") {
            findings.push(Finding {
                tool: "commix".to_string(),
                target: target.to_string(),
                title: "OS command injection".to_string(),
                severity: Severity::Critical,
                status: Status::Confirmed,
                attack_technique: vec!["T1190".to_string(), "T1059".to_string()],
                cwe: vec![78],
                evidence: "commix executed an injected OS command via the request parameter"
                    .to_string(),
                loot_fingerprint: loot.first().map(|l| l.fingerprint.clone()),
            });
        }

        // Each recovered secret is an exposed credential (CWE-522), linked to its loot by fingerprint —
        // the finding never carries the plaintext.
        for item in &loot {
            let evidence = match &item.authenticates {
                Some(authenticates) => {
                    format!(
                        "{} recovered from the foothold, unlocks {authenticates}",
                        item.category
                    )
                }
                None => format!("{} recovered from the foothold", item.category),
            };
            findings.push(Finding {
                tool: "commix".to_string(),
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

        let observations = command_outputs
            .iter()
            .flat_map(|(command, output)| observations_for(command, output))
            .collect();

        ParsedOutput {
            findings,
            loot,
            observations,
        }
    }
}

/// Turn one executed command's output into structured observations: the accounts in `/etc/passwd`, the
/// current user, the OS, a file listing — and the identity claims (machine-id, hostname, ssh host key)
/// that sharpen which host this is. Anything unrecognised is kept verbatim so no intel is lost.
fn observations_for(command: &str, output: &str) -> Vec<Observation> {
    let command = command.trim();
    let output = output.trim();
    if output.is_empty() {
        return Vec::new();
    }

    if command.contains("/etc/machine-id") {
        return vec![claim_observation(ClaimKind::MachineId, output)];
    }
    if command == "hostname" || command.contains("/etc/hostname") {
        return vec![claim_observation(ClaimKind::Hostname, output)];
    }
    if command.contains("ssh_host_") && command.contains("key.pub") {
        return vec![claim_observation(ClaimKind::SshHostKey, output)];
    }

    if command.contains("/etc/passwd") {
        let users: Vec<Observation> = output
            .split_whitespace()
            .filter(|entry| entry.matches(':').count() >= 6)
            .map(|entry| Observation {
                kind: "user".to_string(),
                value: entry.split(':').next().unwrap_or(entry).to_string(),
                detail: Some(entry.to_string()),
            })
            .collect();
        if !users.is_empty() {
            return users;
        }
    }

    if command == "id" || command == "whoami" || command.starts_with("id ") {
        return vec![Observation {
            kind: "user".to_string(),
            value: principal_of(output).unwrap_or_else(|| output.to_string()),
            detail: Some(output.to_string()),
        }];
    }

    if command.starts_with("uname") || command.contains("/etc/os-release") {
        return vec![Observation {
            kind: "os".to_string(),
            value: output.to_string(),
            detail: Some(command.to_string()),
        }];
    }

    if command.starts_with("ls") {
        return vec![Observation {
            kind: "file".to_string(),
            value: command.split_whitespace().last().unwrap_or("/").to_string(),
            detail: Some(output.to_string()),
        }];
    }

    vec![Observation {
        kind: "command-output".to_string(),
        value: command.to_string(),
        detail: Some(output.to_string()),
    }]
}

fn claim_observation(kind: ClaimKind, value: &str) -> Observation {
    Observation {
        kind: IDENTITY_CLAIM_KIND.to_string(),
        value: IdentityClaim {
            kind,
            value: value.to_string(),
        }
        .label(),
        detail: None,
    }
}

fn principal_of(output: &str) -> Option<String> {
    let start = output.find("uid=")?;
    let open = output[start..].find('(')? + start + 1;
    let close = output[open..].find(')')? + open;
    Some(output[open..close].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_is_batch_plus_the_caller_args() {
        let argv = COMMIX.invocation(
            "http://t/cmd/dig?ip_addr=1",
            &["--os-cmd".to_string(), "env".to_string()],
        );
        assert_eq!(argv, vec!["--batch", "--os-cmd", "env"]);
    }

    #[test]
    fn parses_a_transcript_into_a_finding_and_loot() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "The (GET) 'ip_addr' parameter is vulnerable.\nDATABASE_URL&#x3D;testing\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = COMMIX.parse("http://localhost:5000/cmd/dig?ip_addr=1", "T1190", &outcome);

        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(parsed.loot[0].category, "database-url");
        assert_eq!(parsed.loot[0].value, "testing");

        let injection = parsed
            .findings
            .iter()
            .find(|finding| finding.cwe == vec![78])
            .expect("an injection finding");
        assert_eq!(injection.attack_technique, vec!["T1190", "T1059"]);

        let exposure = parsed
            .findings
            .iter()
            .find(|finding| finding.cwe == vec![522])
            .expect("a CWE-522 credential-exposure finding");
        assert_eq!(
            exposure.loot_fingerprint.as_deref(),
            Some(parsed.loot[0].fingerprint.as_str())
        );
        assert!(!format!("{:?}", parsed.findings).contains("testing"));
    }

    #[test]
    fn a_credential_url_records_its_subject_and_a_cwe_522_finding() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[info] 'env' execution output: DATABASE_URL=postgres://application:s3cr3t@db:5432/main"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = COMMIX.parse("http://localhost:5000/cmd/dig?ip_addr=1", "T1552", &outcome);

        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(parsed.loot[0].principal.as_deref(), Some("application"));
        assert_eq!(parsed.loot[0].authenticates.as_deref(), Some("db:5432"));

        // A collection technique records the exposure, not a duplicate injection finding.
        assert!(parsed
            .findings
            .iter()
            .all(|finding| finding.cwe == vec![522]));
        let exposure = &parsed.findings[0];
        assert_eq!(
            exposure.loot_fingerprint.as_deref(),
            Some(parsed.loot[0].fingerprint.as_str())
        );
        assert!(exposure.evidence.contains("db:5432"));
        assert!(!format!("{:?}", parsed.findings).contains("s3cr3t"));
    }

    #[test]
    fn a_run_that_confirms_nothing_records_nothing() {
        let outcome = ToolOutcome {
            code: 1,
            stdout: "no command injection identified".to_string(),
            stderr: String::new(),
        };
        let parsed = COMMIX.parse("http://localhost:5000/", "T1046", &outcome);
        assert!(parsed.findings.is_empty());
        assert!(parsed.loot.is_empty());
    }

    #[test]
    fn a_passwd_read_decomposes_into_one_observation_per_account() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[info] 'cat /etc/passwd' execution output: root:x:0:0:root:/root:/bin/sh application:x:100:101::/app:/sbin/nologin"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = COMMIX.parse("http://localhost:5000/cmd/dig?ip_addr=1", "T1083", &outcome);

        let users: Vec<&str> = parsed
            .observations
            .iter()
            .filter(|observation| observation.kind == "user")
            .map(|observation| observation.value.as_str())
            .collect();
        assert!(users.contains(&"root"));
        assert!(users.contains(&"application"));
        // A collection run records observations, not a duplicate injection finding.
        assert!(parsed.findings.is_empty());
    }

    #[test]
    fn a_machine_id_read_records_an_identity_claim() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "[info] 'cat /etc/machine-id' execution output: 3f2b1c9d4e5a6f70".to_string(),
            stderr: String::new(),
        };
        let parsed = COMMIX.parse("http://localhost:5000/cmd/dig?ip_addr=1", "T1082", &outcome);

        assert!(parsed
            .observations
            .iter()
            .any(|observation| observation.kind == IDENTITY_CLAIM_KIND
                && observation.value == "machine-id:3f2b1c9d4e5a6f70"));
    }
}
