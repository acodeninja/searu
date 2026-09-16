//! The trufflehog tool wrapper: how searu runs trufflehog over a mounted source tree and normalises its
//! JSONL detections into hardcoded-credential findings. trufflehog does the detection; this crate shapes
//! the invocation and reads the result. The target is a `src:<path>` tree mounted read-only at `/src`.
//! Verification is off by default so the target's secrets are never sent to third-party services.

use searu_domain::findings::{Finding, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Trufflehog;

pub static TRUFFLEHOG: Trufflehog = Trufflehog;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Analysis,
    when: "secret scanning with a detector catalogue — find hardcoded credentials, keys and tokens in source you obtained, complementing gitleaks' regex sweep (T1593.003, CWE-798; Passive: allow-listing T1593.003 in the ROE is enough)",
    invoke: "searu run trufflehog --technique T1593.003 --target src:<workspace-relative-dir>  (verification is off by default; add `-- --results=verified,unknown,unverified` to verify — this sends found secrets to third-party services, so only with authorisation)",
    interpret: "searu findings --tool trufflehog — one finding per detection, titled by the detector, evidence `file:line` (the secret value itself is not stored). A verified detection is a live credential",
    chain: "verify a leaked credential out of band; a live one authorises a credential-access run within the ROE",
}];

impl Tool for Trufflehog {
    fn name(&self) -> &'static str {
        "trufflehog"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1593.003"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The app rewrites the `src:` target token to the read-only `/src` mount. `--no-verification`
        // reports every detection without sending secrets to third parties; `--no-update` keeps it
        // from phoning home for a self-update.
        let mut argv = vec![
            "filesystem".to_string(),
            target.to_string(),
            "--json".to_string(),
            "--no-update".to_string(),
            "--no-verification".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let Ok(detection) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let Some(detector) = detection.get("DetectorName").and_then(Value::as_str) else {
                continue;
            };
            let filesystem = detection
                .get("SourceMetadata")
                .and_then(|source| source.get("Data"))
                .and_then(|data| data.get("Filesystem"));
            let file = filesystem
                .and_then(|fs| fs.get("file"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let line_no = filesystem
                .and_then(|fs| fs.get("line"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            if !seen.insert(format!("{detector}|{file}|{line_no}")) {
                continue;
            }
            let verified = detection
                .get("Verified")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            findings.push(Finding {
                tool: "trufflehog".to_string(),
                target: target.to_string(),
                title: detector.to_string(),
                severity: if verified {
                    Severity::Critical
                } else {
                    Severity::High
                },
                status: if verified {
                    Status::Confirmed
                } else {
                    Status::NeedsReview
                },
                attack_technique: vec!["T1593.003".to_string()],
                cwe: vec![798],
                evidence: format!("{file}:{line_no}"),
                loot_fingerprint: None,
            });
        }
        ParsedOutput {
            findings,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_scans_the_mounted_source_as_jsonl_without_verifying() {
        let argv = TRUFFLEHOG.invocation("src:app", &[]);
        assert_eq!(
            argv,
            vec![
                "filesystem",
                "src:app",
                "--json",
                "--no-update",
                "--no-verification",
            ]
        );
    }

    #[test]
    fn parses_jsonl_detections_into_credential_findings() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"DetectorName\":\"PrivateKey\",\"Verified\":false,\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"/src/id_rsa\",\"line\":1}}}}\n\
                     {\"DetectorName\":\"PrivateKey\",\"Verified\":false,\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"/src/id_rsa\",\"line\":1}}}}\n\
                     not-json-log-line\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = TRUFFLEHOG.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].title, "PrivateKey");
        assert_eq!(parsed.findings[0].cwe, vec![798]);
        assert_eq!(parsed.findings[0].severity, Severity::High);
        assert_eq!(parsed.findings[0].evidence, "/src/id_rsa:1");
    }

    #[test]
    fn a_verified_detection_is_confirmed_and_critical() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"DetectorName\":\"AWS\",\"Verified\":true,\"SourceMetadata\":{\"Data\":{\"Filesystem\":{\"file\":\"/src/env\",\"line\":3}}}}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = TRUFFLEHOG.parse("src:app", &outcome);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].severity, Severity::Critical);
        assert_eq!(parsed.findings[0].status, Status::Confirmed);
    }

    #[test]
    fn a_clean_scan_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: String::new(),
            stderr: String::new(),
        };
        let parsed = TRUFFLEHOG.parse("src:app", &outcome);
        assert!(parsed.findings.is_empty());
    }
}
