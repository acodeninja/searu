//! The crack tool wrapper: recover plaintext from a password hash or a KeePass database with John the
//! Ripper. A hash comes from `--hash` (a value lifted from `searu loot` — the MD5s a SQL dump yields),
//! a file from `--file` (a downloaded `.kdbx`); the wordlist is a `seclists:` reference. Each recovered
//! secret is stored as loot with a confirmed weak-hash finding (CWE-916). The target is only for scope;
//! the cracking is offline.

use searu_domain::findings::{Finding, Loot, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Crack;

pub static CRACK: Crack = Crack;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Exploitation,
    when: "recover a plaintext password from a captured hash, or the master password of a downloaded KeePass/Office/zip file, with a wordlist (T1110.002 password cracking, CWE-916). Exploitation tier: the ROE must allow-list T1110.002 and name an authoriser",
    invoke: "searu run crack --technique T1110.002 --target <url> -- --hash <hash-from-loot> --format raw-md5 --wordlist seclists:Passwords/Common-Credentials/Pwdb_top-10000.txt   (a file instead: --file out:incident.kdbx, format auto-detected)",
    interpret: "searu loot --reveal (the recovered plaintext, category password) and searu findings --tool crack (a confirmed CWE-916 finding)",
    chain: "log in with the recovered credential and re-crawl the authenticated surface (browser --login), then re-run searu coverage",
}];

impl Tool for Crack {
    fn name(&self) -> &'static str {
        "crack"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1110.002"]
    }

    fn dockerfile(&self) -> &'static str {
        // The cracking script is spliced into a heredoc so it stays a lint-able file while travelling
        // inside the single Dockerfile the adapter builds.
        concat!(
            include_str!("../Dockerfile.head"),
            include_str!("../crack.sh"),
            include_str!("../Dockerfile.tail"),
        )
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The hash/file/wordlist are the caller's flags; a `seclists:` wordlist is resolved by the
        // runner. To crack a downloaded file, point the *target* at it with `src:<path>` — the runner
        // mounts it read-only at the source mount, and we hand that mount to `--file` here (only a
        // `src:` target mounts a file, so this is the way to feed crack a `.kdbx`/zip).
        let mut argv = args.to_vec();
        let has_input = args.iter().any(|a| a == "--file" || a == "--hash");
        if target.starts_with("src:") && !has_input {
            argv.push("--file".to_string());
            argv.push(searu_domain::scope::SOURCE_MOUNT.to_string());
        }
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut loot = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let Some(rest) = line.strip_prefix("CRACKED ") else {
                continue;
            };
            let Some(password) = field(rest, "password=") else {
                continue;
            };
            if !seen.insert(password.clone()) {
                continue;
            }
            let hash = field(rest, "hash=").unwrap_or_default();
            let fingerprint = searu_tool_parser::fingerprint(&password);
            findings.push(Finding {
                tool: "crack".to_string(),
                target: target.to_string(),
                title: "Cracked password hash".to_string(),
                severity: Severity::High,
                status: Status::Confirmed,
                attack_technique: vec!["T1110.002".to_string()],
                cwe: vec![916],
                evidence: format!("plaintext recovered from a wordlist for hash {hash}"),
                loot_fingerprint: Some(fingerprint.clone()),
            });
            loot.push(Loot::secret(fingerprint, "password".to_string(), password));
        }
        ParsedOutput {
            findings,
            loot,
            ..Default::default()
        }
    }
}

fn field(line: &str, marker: &str) -> Option<String> {
    let (_, rest) = line.split_once(marker)?;
    // `hash=` is followed by ` password=`; the password runs to end of line.
    let value = match marker {
        "hash=" => rest.split_whitespace().next().unwrap_or(rest),
        _ => rest,
    };
    (!value.is_empty() && value != "?").then(|| value.to_string())
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
    fn invocation_passes_the_flags_through() {
        let argv = CRACK.invocation(
            "http://h:3000",
            &[
                "--hash".to_string(),
                "0192023a7bbd73250516f069df18b500".to_string(),
                "--format".to_string(),
                "raw-md5".to_string(),
            ],
        );
        assert_eq!(
            argv,
            vec![
                "--hash",
                "0192023a7bbd73250516f069df18b500",
                "--format",
                "raw-md5"
            ]
        );
    }

    #[test]
    fn a_src_file_target_is_handed_to_john_as_the_source_mount() {
        let argv = CRACK.invocation(
            "src:incident-support.kdbx",
            &[
                "--wordlist".to_string(),
                "seclists:Passwords/Common-Credentials/Pwdb_top-10000.txt".to_string(),
            ],
        );
        assert!(argv
            .windows(2)
            .any(|w| w[0] == "--file" && w[1] == searu_domain::scope::SOURCE_MOUNT));
    }

    #[test]
    fn an_explicit_input_is_not_overridden_by_a_src_target() {
        let argv = CRACK.invocation("src:x", &["--hash".to_string(), "abc".to_string()]);
        assert!(!argv.iter().any(|a| a == "--file"));
    }

    #[test]
    fn a_cracked_hash_is_loot_with_a_confirmed_finding() {
        let out = outcome("CRACKED hash=0192023a7bbd73250516f069df18b500 password=admin123\n");
        let parsed = CRACK.parse("http://h:3000", "T1110.002", &out);
        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(parsed.loot[0].category, "password");
        assert_eq!(parsed.loot[0].value, "admin123");
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].cwe, vec![916]);
        assert_eq!(parsed.findings[0].status, Status::Confirmed);
        assert_eq!(
            parsed.findings[0].loot_fingerprint.as_deref(),
            Some(parsed.loot[0].fingerprint.as_str())
        );
    }

    #[test]
    fn a_keepass_crack_without_a_hash_still_captures_the_password() {
        let out = outcome("CRACKED hash=? password=masterkey\n");
        let parsed = CRACK.parse("http://h:3000", "T1110.002", &out);
        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(parsed.loot[0].value, "masterkey");
        assert!(parsed.findings[0].evidence.contains("hash "));
    }

    #[test]
    fn duplicate_cracks_are_recorded_once() {
        let out = outcome(
            "CRACKED hash=a password=secret\n\
             CRACKED hash=a password=secret\n",
        );
        let parsed = CRACK.parse("http://h:3000", "T1110.002", &out);
        assert_eq!(parsed.loot.len(), 1);
    }

    #[test]
    fn a_run_with_no_crack_records_nothing() {
        let out = outcome("0 password hashes cracked, 1 left\n");
        let parsed = CRACK.parse("http://h:3000", "T1110.002", &out);
        assert!(parsed.findings.is_empty());
        assert!(parsed.loot.is_empty());
    }
}
