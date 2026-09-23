//! The fetch tool wrapper: download an in-scope file to the run's output directory so a later tool can
//! work on it — the `.bak`, backup and KeePass files an app leaves exposed. It writes the body to the
//! output mount (`/out` via the `out:` token) and records the saved file as a download observation; the
//! generic output collector lists it too. Pair it with crack to open a downloaded `.kdbx`.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Fetch;

pub static FETCH: Fetch = Fetch;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Discovery,
    when: "retrieve an exposed file for offline work — a backup (.bak), a config, an archive or a KeePass database found in a listing or by forced browsing (T1083). Active tier: allow-listing the technique is enough",
    invoke: "searu run fetch --technique T1083 --target http://host:port/ftp/incident-support.kdbx  (a 403 backup often yields to a null-byte suffix, e.g. .../coupons.md.bak%2500.md; add --name to rename, --header for auth)",
    interpret: "searu observations --kind download (the saved file and its size); the file lands in the run's output directory (searu observations --kind output)",
    chain: "feed the file to the tool that opens it — a KeePass/zip to `searu run crack --file out:<name>`, source to a src: analysis, secrets to loot",
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
        for line in outcome.stdout.lines() {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if record["kind"] != "download" {
                continue;
            }
            let (Some(name), Some(url)) = (record["name"].as_str(), record["url"].as_str()) else {
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
    fn invocation_downloads_the_target_into_the_output_mount() {
        let argv = FETCH.invocation("http://h:3000/ftp/x.kdbx", &[]);
        assert_eq!(
            argv,
            vec!["--url", "http://h:3000/ftp/x.kdbx", "--out", "out:"]
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
