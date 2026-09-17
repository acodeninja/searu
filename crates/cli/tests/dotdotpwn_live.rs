//! Live dotdotpwn run against the CWE-22 path-traversal lab: the image builds, dotdotpwn fuzzes the
//! `file` parameter and records a confirmed path-traversal finding. The lab leaks `/etc/passwd` (which
//! contains `root:`) on a climbing payload, so `-k "root:"` makes the assertion deterministic. Ignored
//! by default: needs the Docker daemon and network, and builds the dotdotpwn image. Run with
//! `cargo test -p searu --test dotdotpwn_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-22:main";
const CONTAINER: &str = "searu-dotdotpwn-it";
const HOST_PORT: u16 = 5023;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5023 },
        { "type": "ip", "value": "127.0.0.1", "port": 5023 }
    ] },
    "allowed_techniques": ["T1190"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the dotdotpwn image"]
fn dotdotpwn_confirms_the_cwe22_traversal() {
    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    let run = Process::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--name",
            CONTAINER,
            "-p",
            &format!("{HOST_PORT}:5000"),
            IMAGE,
        ])
        .output()
        .expect("docker run");
    assert!(
        run.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    wait_for_port();

    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let target = format!("http://localhost:{HOST_PORT}/download?file=TRAVERSAL");

    let scan = searu(&dir)
        .args([
            "run",
            "dotdotpwn",
            "--technique",
            "T1190",
            "--target",
            &target,
            "--",
            "-k",
            "root:",
            "-b",
            "-q",
            "-d",
            "6",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "dotdotpwn"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "dotdotpwn run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1190") && findings.contains("Path traversal"),
        "no path-traversal finding recorded; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}

fn wait_for_port() {
    for _ in 0..60 {
        if TcpStream::connect(("127.0.0.1", HOST_PORT)).is_ok() {
            std::thread::sleep(Duration::from_millis(500));
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    panic!("the CWE-22 lab never bound port {HOST_PORT}");
}
