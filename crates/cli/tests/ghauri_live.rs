//! Live ghauri run against the CWE-89 lab. The lab's login redirects identically once ghauri follows
//! it (ghauri has no `--ignore-redirects`), so ghauri cannot confirm this particular injection without
//! an in-page oracle — the run therefore exercises the build/invoke/parse pipeline end-to-end and
//! records no false finding. The positive-parse path is covered by the wrapper unit test against
//! ghauri's real confirmation transcript. Ignored by default: needs the Docker daemon and network, and
//! builds the ghauri image. Run with `cargo test -p searu --test ghauri_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-89:main";
const CONTAINER: &str = "searu-ghauri-it";
const HOST_PORT: u16 = 5092;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5092 },
        { "type": "ip", "value": "127.0.0.1", "port": 5092 }
    ] },
    "allowed_techniques": ["T1190"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the ghauri image"]
fn ghauri_runs_clean_against_the_redirecting_login() {
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
    let target = format!("http://localhost:{HOST_PORT}/login");

    let scan = searu(&dir)
        .args([
            "run",
            "ghauri",
            "--technique",
            "T1190",
            "--target",
            &target,
            "--",
            "--data",
            "username=a&password=x",
            "-p",
            "username",
            "--level",
            "1",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "ghauri"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "ghauri run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.trim().is_empty(),
        "ghauri recorded a finding without an oracle; findings were:\n{findings}"
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
    panic!("the CWE-89 target never bound port {HOST_PORT}");
}
