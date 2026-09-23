//! The fetch tool wrapper: a general HTTP request. GET downloads an in-scope file to the run's output
//! directory (the `.bak`, backup and KeePass files an app leaves exposed); `--method POST/PUT` with
//! `--data` drives an API — most importantly `POST /rest/user/login` to **mint a session token**, which
//! is surfaced as loot so `authz --header`/`jwt` can carry it. The response body is written to the
//! output mount (`/out` via the `out:` token) and recorded as a download observation.

use searu_domain::findings::{Loot, Observation};
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Fetch;

pub static FETCH: Fetch = Fetch;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Discovery,
    when: "make an HTTP request — GET to retrieve an exposed file (.bak/config/archive/KeePass) for offline work, or POST/PUT to drive an API, above all to mint a session token by logging in (T1083). Active tier: allow-listing the technique is enough",
    invoke: "GET a file: searu run fetch --technique T1083 --target http://host:port/ftp/incident-support.kdbx  (403 backups often yield to a null-byte suffix .../x.bak%2500.md). Mint a JWT: searu run fetch --technique T1083 --target http://host:port/rest/user/login -- --method POST --header 'Content-Type: application/json' --data '{\"email\":\"<u>\",\"password\":\"<p>\"}'  (add --name to rename the saved body)",
    interpret: "searu loot --category session-token --reveal for a minted token; searu observations --kind download for a saved file (also under --kind output)",
    chain: "carry a minted token into `authz --header 'Authorization: Bearer <token>'` (IDOR) and `jwt` (forge); feed a downloaded KeePass/zip to `searu run crack --target src:<path>`; POST/PUT a `$ne`/`$where` body for NoSQL",
}];

impl Tool for Fetch {
    fn name(&self) -> &'static str {
        "fetch"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1083"]
    }

    fn dockerfile(&self) -> &'static str {
        // The download script is spliced into a heredoc so it stays a lint-able file while travelling
        // inside the single Dockerfile the adapter builds.
        concat!(
            include_str!("../Dockerfile.head"),
            include_str!("../fetch.py"),
            include_str!("../Dockerfile.tail"),
        )
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The target is the file URL; the runner rewrites it for reachability. `out:` mounts the run's
        // output directory writable, where the download is saved.
        let mut argv = vec![
            "--url".to_string(),
            target.to_string(),
            "--out".to_string(),
            "out:".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv
    }

    fn parse(&self, _target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        let mut loot = Vec::new();
        for line in outcome.stdout.lines() {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            match record["kind"].as_str() {
                Some("download") => {
                    let (Some(name), Some(url)) = (record["name"].as_str(), record["url"].as_str())
                    else {
                        continue;
                    };
                    let bytes = record["bytes"].as_i64().unwrap_or_default();
                    let status = record["status"].as_i64().unwrap_or_default();
                    observations.push(Observation {
                        kind: "download".to_string(),
                        value: name.to_string(),
                        detail: Some(format!("{bytes} bytes from {url} (status {status})")),
                    });
                }
                Some("token") => {
                    if let Some(token) = record["value"].as_str() {
                        loot.push(Loot::secret(
                            searu_tool_parser::fingerprint(token),
                            "session-token".to_string(),
                            token.to_string(),
                        ));
                    }
                }
                _ => {}
            }
        }
        ParsedOutput {
            observations,
            loot,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_downloads_the_target_into_the_output_mount() {
        let argv = FETCH.invocation("http://h:3000/ftp/x.kdbx", &[]);
        assert_eq!(
            argv,
            vec!["--url", "http://h:3000/ftp/x.kdbx", "--out", "out:"]
        );
    }

    #[test]
    fn a_minted_token_is_recorded_as_loot() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"kind\":\"download\",\"url\":\"http://h/rest/user/login\",\"name\":\"login\",\"bytes\":784,\"status\":200}\n\
                     {\"kind\":\"token\",\"value\":\"eyJhbGciOiJSUzI1NiJ9.payload.sig\"}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = FETCH.parse("http://h/rest/user/login", "T1083", &outcome);
        assert_eq!(parsed.loot.len(), 1);
        assert_eq!(parsed.loot[0].category, "session-token");
        assert_eq!(parsed.loot[0].value, "eyJhbGciOiJSUzI1NiJ9.payload.sig");
        assert_eq!(
            parsed.observations.len(),
            1,
            "the login body is still recorded"
        );
    }

    #[test]
    fn a_download_is_recorded_as_an_observation() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"kind\":\"download\",\"url\":\"http://h/ftp/x.kdbx\",\"name\":\"x.kdbx\",\"bytes\":2048,\"status\":200}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = FETCH.parse("http://h/ftp/x.kdbx", "T1083", &outcome);
        assert_eq!(parsed.observations.len(), 1);
        assert_eq!(parsed.observations[0].kind, "download");
        assert_eq!(parsed.observations[0].value, "x.kdbx");
        assert!(parsed.observations[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("2048 bytes"));
    }
}
