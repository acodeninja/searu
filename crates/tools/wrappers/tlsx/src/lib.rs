//! The tlsx tool wrapper: read a host's TLS certificate and connection details and normalise tlsx's
//! JSONL into recon observations. tlsx does the handshake; this crate shapes the invocation and reads
//! the result. The target is a `host:port` endpoint; searu rewrites it for container reachability.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};
use serde_json::Value;
use std::collections::HashSet;

pub struct Tlsx;

pub static TLSX: Tlsx = Tlsx;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "TLS surface — read a host's certificate (subject, SANs, issuer, validity) and negotiated TLS version/cipher, expanding the attack surface and finding related hostnames (T1595, Active: allow-listing the technique is enough)",
    invoke: "searu run tlsx --technique T1595 --target host:port  (defaults to :443 semantics; tlsx's own flags after `--`, e.g. `-- -ve -ce` to enumerate versions/ciphers)",
    interpret: "searu observations --kind tls — value is the certificate subject, detail carries the endpoint and negotiated version/cipher; the SANs surface additional in-scope hostnames",
    chain: "add the certificate SAN hostnames to the surface (resolve with dnsx, fingerprint with httpx); a weak/expired TLS config is a reportable weakness",
}];

impl Tool for Tlsx {
    fn name(&self) -> &'static str {
        "tlsx"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // `-u` takes the host:port (the runner rewrites it for reachability); `-json` carries the full
        // certificate and connection detail, `-silent` keeps the banner off stdout.
        let mut argv = vec![
            "-u".to_string(),
            target.to_string(),
            "-json".to_string(),
            "-silent".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        let mut seen = HashSet::new();
        for line in outcome.stdout.lines() {
            let Ok(record) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let host = record.get("host").and_then(Value::as_str).unwrap_or("");
            let port = record.get("port").and_then(Value::as_str).unwrap_or("");
            let subject = record
                .get("subject_cn")
                .and_then(Value::as_str)
                .unwrap_or("");
            if subject.is_empty() || !seen.insert(format!("{host}:{port}|{subject}")) {
                continue;
            }
            let version = record
                .get("tls_version")
                .and_then(Value::as_str)
                .unwrap_or("");
            let cipher = record.get("cipher").and_then(Value::as_str).unwrap_or("");
            observations.push(Observation {
                kind: "tls".to_string(),
                value: subject.to_string(),
                detail: Some(
                    format!("{host}:{port} {version} {cipher}")
                        .trim()
                        .to_string(),
                ),
            });
        }
        ParsedOutput {
            observations,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_reads_the_endpoint_certificate_as_json() {
        let argv = TLSX.invocation("host:443", &[]);
        assert_eq!(argv, vec!["-u", "host:443", "-json", "-silent"]);
    }

    #[test]
    fn parses_certificate_json_into_a_tls_observation() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"host\":\"one.one.one.one\",\"port\":\"443\",\"tls_version\":\"tls13\",\"cipher\":\"TLS_AES_128_GCM_SHA256\",\"subject_cn\":\"cloudflare-dns.com\",\"subject_an\":[\"one.one.one.one\"]}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = TLSX.parse("one.one.one.one:443", &outcome);
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(parsed.observations[0].kind, "tls");
        assert_eq!(parsed.observations[0].value, "cloudflare-dns.com");
        assert_eq!(
            parsed.observations[0].detail.as_deref(),
            Some("one.one.one.one:443 tls13 TLS_AES_128_GCM_SHA256")
        );
    }

    #[test]
    fn a_host_with_no_certificate_records_nothing() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"host\":\"h\",\"port\":\"443\",\"probe_status\":false}\n".to_string(),
            stderr: String::new(),
        };
        let parsed = TLSX.parse("h:443", &outcome);
        assert!(parsed.observations.is_empty());
    }
}
