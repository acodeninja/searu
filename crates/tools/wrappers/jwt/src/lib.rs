//! The jwt tool wrapper: attack a JSON Web Token with jwt_tool and normalise the result. The token —
//! typically lifted from `searu loot` after a login or SQLi — is the caller's first argument after
//! `--`; the target is the in-scope URL the token belongs to, so the run is scope-gated even though the
//! forging itself is offline. A forged token (alg:none, key confusion) is recorded as loot with a
//! signature-verification finding; a cracked HMAC key is recorded as loot with a weak-key finding.

use searu_domain::findings::{Finding, Loot, Severity, Status};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use std::collections::HashSet;

pub struct Jwt;

pub static JWT: Jwt = Jwt;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Exploitation,
    when: "attack a JSON Web Token — forge an unsigned (alg:none) or key-confused token, or crack a weak HMAC signing key (T1606.001 forge web credentials, T1110.002 password cracking; CWE-347). Exploitation tier: the ROE must allow-list the technique and name an authoriser",
    invoke: "searu run jwt --technique T1606.001 --target <url> -- <JWT-from-loot> -X a -b   (forge alg:none, bare output); crack a weak secret with `-- <JWT> -C -d seclists:Passwords/Common-Credentials/Pwdb_top-10000.txt`",
    interpret: "searu loot --reveal (a forged token is loot category forged-jwt; a cracked key is loot category jwt-secret) and searu findings --tool jwt (CWE-347)",
    chain: "replay the forged token as the Authorization: Bearer header against an authenticated endpoint (browser --login or an authz replay) to confirm the app accepts it",
}];

impl Tool for Jwt {
    fn name(&self) -> &'static str {
        "jwt"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1606.001", "T1110.002"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, _target: &str, args: &[String]) -> Vec<String> {
        // jwt_tool takes the token as its first positional and the attack flags after it; the target is
        // only for scope, so the caller's args pass straight through.
        args.to_vec()
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut findings = Vec::new();
        let mut loot = Vec::new();
        let mut forged = HashSet::new();
        let mut forged_finding = false;

        for raw in outcome.stdout.lines() {
            let line = strip_ansi(raw);
            let line = line.trim();

            if let Some(key) = cracked_key(line) {
                let value = key.to_string();
                let fingerprint = searu_tool_parser::fingerprint(&value);
                findings.push(Finding {
                    tool: "jwt".to_string(),
                    target: target.to_string(),
                    title: "Weak JWT signing key".to_string(),
                    severity: Severity::High,
                    status: Status::Confirmed,
                    attack_technique: vec!["T1110.002".to_string()],
                    cwe: vec![347],
                    evidence: "the HMAC signing key was recovered from a wordlist".to_string(),
                    loot_fingerprint: Some(fingerprint.clone()),
                });
                loot.push(Loot::secret(fingerprint, "jwt-secret".to_string(), value));
                continue;
            }

            if is_jwt(line) && forged.insert(line.to_string()) {
                let fingerprint = searu_tool_parser::fingerprint(line);
                loot.push(Loot::secret(
                    fingerprint,
                    "forged-jwt".to_string(),
                    line.to_string(),
                ));
                forged_finding = true;
            }
        }

        if forged_finding {
            findings.push(Finding {
                tool: "jwt".to_string(),
                target: target.to_string(),
                title: "JWT accepts a forged token".to_string(),
                severity: Severity::High,
                status: Status::NeedsReview,
                attack_technique: vec!["T1606.001".to_string()],
                cwe: vec![347],
                evidence: "jwt_tool produced a forged token (alg:none / key confusion); replay it against the target to confirm".to_string(),
                loot_fingerprint: None,
            });
        }

        ParsedOutput {
            findings,
            loot,
            ..Default::default()
        }
    }
}

fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for tail in chars.by_ref() {
                if tail.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn is_jwt(line: &str) -> bool {
    let segments: Vec<&str> = line.split('.').collect();
    (segments.len() == 3 || segments.len() == 2)
        && line.starts_with("eyJ")
        && !line.contains(char::is_whitespace)
        && segments[0].len() > 4
        && segments[1].len() > 4
}

fn cracked_key(line: &str) -> Option<&str> {
    let (head, _) = line.split_once(" is the CORRECT key")?;
    head.rsplit(']')
        .next()
        .map(str::trim)
        .filter(|k| !k.is_empty())
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
    fn invocation_passes_the_token_and_flags_through() {
        let argv = JWT.invocation(
            "http://h:3000",
            &[
                "eyJhbGciOiJSUzI1NiJ9.e30.sig".to_string(),
                "-X".to_string(),
                "a".to_string(),
            ],
        );
        assert_eq!(argv, vec!["eyJhbGciOiJSUzI1NiJ9.e30.sig", "-X", "a"]);
    }

    #[test]
    fn a_forged_token_is_loot_with_a_signature_finding() {
        let out = outcome(
            "/root/.jwt_tool/jwtconf.ini\n\
             eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.\n\
             eyJ0eXAiOiJKV1QiLCJhbGciOiJOb25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.\n",
        );
        let parsed = JWT.parse("http://h:3000", "T1606.001", &out);
        assert_eq!(parsed.loot.len(), 2, "each distinct forged token is loot");
        assert!(parsed.loot.iter().all(|l| l.category == "forged-jwt"));
        assert_eq!(
            parsed.findings.len(),
            1,
            "one signature finding, not one per token"
        );
        assert_eq!(parsed.findings[0].title, "JWT accepts a forged token");
        assert_eq!(parsed.findings[0].cwe, vec![347]);
        assert_eq!(parsed.findings[0].status, Status::NeedsReview);
    }

    #[test]
    fn a_cracked_key_is_loot_with_a_confirmed_weak_key_finding() {
        let out = outcome("\x1b[32m[+] secret123 is the CORRECT key!\x1b[0m\n");
        let parsed = JWT.parse("http://h:3000", "T1110.002", &out);
        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(parsed.loot[0].category, "jwt-secret");
        assert_eq!(parsed.loot[0].value, "secret123");
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.findings[0].status, Status::Confirmed);
        assert_eq!(parsed.findings[0].title, "Weak JWT signing key");
    }

    #[test]
    fn a_plain_decode_records_nothing() {
        let out = outcome(
            "=====================\n\
             Decoded Token Values:\n\
             [+] alg = \"RS256\"\n\
             [+] role = \"admin\"\n",
        );
        let parsed = JWT.parse("http://h:3000", "T1606.001", &out);
        assert!(parsed.findings.is_empty());
        assert!(parsed.loot.is_empty());
    }
}
