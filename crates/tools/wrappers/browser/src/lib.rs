//! The browser tool wrapper: drive the target as a real headless browser to *understand* it before
//! attacking. A baked-in Playwright script loads the app (an SPA the blind scanners never execute),
//! optionally authenticates, crawls its client-side routes and records every same-origin API call the
//! app makes — so the true attack surface (routes, endpoints, parameters, forms) becomes observations
//! the later phases can work through. Screenshots and other artefacts land in the run's output
//! directory (mounted writable at `/out` via the `out:` token). The target is a URL.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Browser;

pub static BROWSER: Browser = Browser;

const KNOWN_KINDS: &[&str] = &["route", "endpoint", "param", "form", "note"];

static USES: &[PhaseAdvice] = &[
    PhaseAdvice {
        phase: Phase::Reconnaissance,
        when: "understand a web app before attacking it — drive it as a real browser to render an SPA, follow its client-side routes and capture the API calls it makes, mapping the surface a blind scanner cannot see (T1595, Active: allow-listing the technique is enough)",
        invoke: "searu run browser --technique T1595 --target http://host:port  (authenticate to reach the logged-in surface with `-- --login-email <user> --login-password <pass>`; widen with `--depth 3`)",
        interpret: "searu observations --kind route / --kind endpoint / --kind param / --kind form — the client routes, API endpoints (detail = method), their parameters (detail = endpoint) and forms (detail = fields); screenshots are under the run's output directory (searu observations --kind output)",
        chain: "the recorded endpoints and parameters are the surface Initial access and Exploitation work through — feed each into the injection, access-control and auth tools",
    },
    PhaseAdvice {
        phase: Phase::Discovery,
        when: "enumerate the routes and API endpoints hidden behind client-side JavaScript when a passive crawl (katana/gospider) missed them",
        invoke: "searu run browser --technique T1595 --target http://host:port",
        interpret: "searu observations --kind endpoint / --kind param",
        chain: "the parameters are where injection and access-control testing begin (Initial access)",
    },
];

impl Tool for Browser {
    fn name(&self) -> &'static str {
        "browser"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1595"]
    }

    fn dockerfile(&self) -> &'static str {
        // The Docker adapter builds a context holding only this string, so the crawl script cannot be
        // COPYed in — it is spliced into a heredoc between the image setup and the entrypoint, keeping
        // crawl.js its own lint-able file while still travelling inside the one embedded Dockerfile.
        concat!(
            include_str!("../Dockerfile.head"),
            include_str!("../crawl.js"),
            include_str!("../Dockerfile.tail"),
        )
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        // The `out:` token mounts the run's output directory writable at `/out`; the script writes
        // screenshots there. The runner rewrites the target URL for container reachability.
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
        // The script speaks the observation shape directly, one JSON object per line; we keep the known
        // kinds and de-duplicate, letting the crawl own what the surface *is*.
        let mut observations = Vec::new();
        for line in outcome.stdout.lines() {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let (Some(kind), Some(value)) = (record["kind"].as_str(), record["value"].as_str())
            else {
                continue;
            };
            if !KNOWN_KINDS.contains(&kind) || value.is_empty() {
                continue;
            }
            push_unique(
                &mut observations,
                Observation {
                    kind: kind.to_string(),
                    value: value.to_string(),
                    detail: record["detail"].as_str().map(str::to_string),
                },
            );
        }
        ParsedOutput {
            observations,
            ..Default::default()
        }
    }
}

fn push_unique(observations: &mut Vec<Observation>, observation: Observation) {
    if !observations
        .iter()
        .any(|o| o.kind == observation.kind && o.value == observation.value)
    {
        observations.push(observation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_drives_the_target_and_writes_artefacts_to_the_output_mount() {
        let argv = BROWSER.invocation("http://h:3000", &[]);
        assert_eq!(argv, vec!["--url", "http://h:3000", "--out", "out:"]);
    }

    #[test]
    fn invocation_passes_authentication_flags_through() {
        let argv = BROWSER.invocation(
            "http://h:3000",
            &[
                "--login-email".to_string(),
                "admin@juice-sh.op".to_string(),
                "--login-password".to_string(),
                "admin123".to_string(),
            ],
        );
        assert_eq!(
            argv,
            vec![
                "--url",
                "http://h:3000",
                "--out",
                "out:",
                "--login-email",
                "admin@juice-sh.op",
                "--login-password",
                "admin123",
            ]
        );
    }

    #[test]
    fn parses_the_surface_map_into_deduped_observations() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "{\"kind\":\"route\",\"value\":\"/#/search\"}\n\
                     {\"kind\":\"endpoint\",\"value\":\"/rest/products/search\",\"detail\":\"GET\"}\n\
                     {\"kind\":\"endpoint\",\"value\":\"/rest/products/search\",\"detail\":\"GET\"}\n\
                     {\"kind\":\"param\",\"value\":\"q\",\"detail\":\"/rest/products/search\"}\n\
                     {\"kind\":\"form\",\"value\":\"/#/login\",\"detail\":\"email,password\"}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = BROWSER.parse("http://h:3000", "T1595", &outcome);
        assert_eq!(parsed.observations.len(), 4);
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "route" && o.value == "/#/search"));
        assert!(parsed.observations.iter().any(|o| o.kind == "endpoint"
            && o.value == "/rest/products/search"
            && o.detail.as_deref() == Some("GET")));
        assert!(parsed
            .observations
            .iter()
            .any(|o| o.kind == "param" && o.value == "q"));
        assert!(parsed.observations.iter().any(|o| o.kind == "form"
            && o.value == "/#/login"
            && o.detail.as_deref() == Some("email,password")));
    }

    #[test]
    fn ignores_unknown_kinds_and_malformed_lines() {
        let outcome = ToolOutcome {
            code: 0,
            stdout: "not json\n\
                     {\"kind\":\"cookie\",\"value\":\"session\"}\n\
                     {\"kind\":\"endpoint\"}\n\
                     {\"kind\":\"route\",\"value\":\"\"}\n"
                .to_string(),
            stderr: String::new(),
        };
        let parsed = BROWSER.parse("http://h:3000", "T1595", &outcome);
        assert!(parsed.observations.is_empty());
    }
}
