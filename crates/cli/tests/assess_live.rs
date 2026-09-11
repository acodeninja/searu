//! Live end-to-end exploit of the CWE-78 lab target. Ignored by default: it needs the Docker daemon
//! and network access, and pulls `ghcr.io/ere-be-dragons/cwe-78`. Run it explicitly with
//! `cargo test -p searu --test assess_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-78:main";
const CONTAINER: &str = "searu-cwe78-it";
const SECRET: &str = "testing";
const HOST_PORT: u16 = 5000;

const LAB_ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "localhost", "port": 5000 }, { "type": "ip", "value": "127.0.0.1", "port": 5000 } ] },
    "allowed_techniques": ["T1190", "T1059"],
    "authorisation": {
        "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" }
    }
}"#;

#[test]
#[ignore = "requires the docker daemon, network access, and pulls the CWE-78 image"]
fn assess_exploits_the_live_cwe78_target() {
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
            "-e",
            &format!("DATABASE_URL={SECRET}"),
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
    let roe = dir.path().join("rules-of-engagement.json");
    std::fs::write(&roe, LAB_ROE).unwrap();

    let output = Command::cargo_bin("searu")
        .unwrap()
        .current_dir(&dir)
        .args([
            "assess",
            "--roe",
            roe.to_str().unwrap(),
            "--target",
            &format!("http://localhost:{HOST_PORT}/cmd/dig?ip_addr=1"),
        ])
        .output()
        .unwrap();

    let loot = std::fs::read_to_string(dir.path().join("pentest/loot.jsonl")).unwrap_or_default();
    let findings =
        std::fs::read_to_string(dir.path().join("pentest/findings.jsonl")).unwrap_or_default();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        output.status.success(),
        "assess failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        loot.contains(&format!("\"value\":\"{SECRET}\"")),
        "loot did not capture the secret: {loot}"
    );
    assert!(
        findings.contains("T1190"),
        "finding missing T1190: {findings}"
    );
    assert!(
        !findings.contains(&format!("\"value\":\"{SECRET}\"")),
        "the finding leaked the plaintext secret"
    );
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
    panic!("the CWE-78 target never bound port {HOST_PORT}");
}
