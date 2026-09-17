//! The nmap tool wrapper: a TCP connect + version scan whose grepable output normalises into
//! service observations. SYN/OS-detection needs raw sockets (a privileged container), deferred.

use searu_domain::findings::Observation;
use searu_domain::ports::ToolOutcome;
use searu_domain::tools::{ParsedOutput, Phase, PhaseAdvice, Tool};

pub struct Nmap;

pub static NMAP: Nmap = Nmap;

static USES: &[PhaseAdvice] = &[PhaseAdvice {
    phase: Phase::Reconnaissance,
    when: "port & service discovery — reach for it first to map a host's open TCP services",
    invoke: "searu run nmap --technique T1046 --target <host>  (a host or IP, never a URL; TCP connect + version scan. Extra nmap flags after `--`, e.g. `-- -p-`, `-- --top-ports 2000`. SYN/OS-detection needs a privileged container, not available.)",
    interpret: "searu observations --kind service — one line per open port: host:port + service/version. An empty result means nothing open in the scanned range, not host-down; widen the ports.",
    chain: "the open services and versions pick the next tool and the weakness to probe (an HTTP port -> httpx/katana).",
}];

impl Tool for Nmap {
    fn name(&self) -> &'static str {
        "nmap"
    }

    fn techniques(&self) -> &'static [&'static str] {
        &["T1046"]
    }

    fn dockerfile(&self) -> &'static str {
        include_str!("../Dockerfile")
    }

    fn uses(&self) -> &'static [PhaseAdvice] {
        USES
    }

    fn invocation(&self, target: &str, args: &[String]) -> Vec<String> {
        let mut argv = vec![
            "-sT".to_string(),
            "-sV".to_string(),
            "-oG".to_string(),
            "-".to_string(),
        ];
        argv.extend(args.iter().cloned());
        argv.push(target.to_string());
        argv
    }

    fn parse(&self, target: &str, _technique: &str, outcome: &ToolOutcome) -> ParsedOutput {
        let mut observations = Vec::new();
        for line in outcome.stdout.lines() {
            let Some(ports) = line
                .split('\t')
                .find_map(|field| field.strip_prefix("Ports: "))
            else {
                continue;
            };
            for entry in ports.split(", ") {
                let fields: Vec<&str> = entry.split('/').collect();
                if fields.get(1) != Some(&"open") {
                    continue;
                }
                let port = fields[0];
                let service = fields.get(4).copied().unwrap_or_default().trim();
                let version = fields.get(6).copied().unwrap_or_default().trim();
                let detail = match (service, version) {
                    ("", "") => None,
                    (service, "") => Some(service.to_string()),
                    ("", version) => Some(version.to_string()),
                    (service, version) => Some(format!("{service} {version}")),
                };
                observations.push(Observation {
                    kind: "service".to_string(),
                    value: format!("{target}:{port}"),
                    detail,
                });
            }
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

    fn outcome(stdout: &str) -> ToolOutcome {
        ToolOutcome {
            code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    #[test]
    fn invocation_is_a_connect_version_scan_with_passthrough_before_the_target() {
        assert_eq!(
            Nmap.invocation("10.0.0.5", &["-p".to_string(), "1-100".to_string()]),
            vec!["-sT", "-sV", "-oG", "-", "-p", "1-100", "10.0.0.5"]
        );
    }

    #[test]
    fn parses_open_ports_into_service_observations() {
        let grepable = "# Nmap 7.95 scan initiated\n\
Host: 10.0.0.5 ()\tStatus: Up\n\
Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh//OpenSSH 9.6//, 80/open/tcp//http//nginx//\tIgnored State: closed (998)\n\
# Nmap done\n";
        let parsed = Nmap.parse("10.0.0.5", "T1046", &outcome(grepable));
        assert!(parsed.observations.iter().any(|o| o.kind == "service"
            && o.value == "10.0.0.5:22"
            && o.detail.as_deref() == Some("ssh OpenSSH 9.6")));
        assert!(parsed.observations.iter().any(|o| o.kind == "service"
            && o.value == "10.0.0.5:80"
            && o.detail.as_deref() == Some("http nginx")));
        assert_eq!(parsed.observations.len(), 2);
    }

    #[test]
    fn a_scan_with_no_open_ports_records_nothing() {
        let grepable = "Host: 10.0.0.5 ()\tStatus: Up\n\
Host: 10.0.0.5 ()\tPorts: 81/closed/tcp//hosts2-ns//\tIgnored State: closed (999)\n";
        assert!(Nmap
            .parse("10.0.0.5", "T1046", &outcome(grepable))
            .observations
            .is_empty());
    }
}
