//! Live end-to-end run against the CWE-78 lab, playing Claude's loop: confirm the injection, then use
//! the foothold to read the environment, and query the recorded loot. Ignored by default: it needs
//! the Docker daemon and network access, and builds the commix image from its embedded Dockerfile.
//! Run with `cargo test -p searu --test run_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-78:main";
const CONTAINER: &str = "searu-cwe78-it";
const SECRET: &str = "testing";
// A dedicated host port for the ephemeral test container, so it never clashes with a manually-run
// lab instance on the usual 5000. It still maps to the container's 5000.
const HOST_PORT: u16 = 5099;

const LAB_ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5099 },
        { "type": "ip", "value": "127.0.0.1", "port": 5099 }
    ] },
    "allowed_techniques": ["T1190", "T1059", "T1552", "T1082", "T1083", "T1518"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds and runs the commix image"]
fn runs_commix_against_the_live_cwe78_target() {
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

    // The engagement directory: searu defaults the ROE to pentest/rules-of-engagement.json and writes
    // findings/loot under pentest/, all relative to the working directory.
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), LAB_ROE).unwrap();
    let target = format!("http://localhost:{HOST_PORT}/cmd/dig?ip_addr=1");

    // Confirm the foothold, then use it to read the environment.
    let confirm = searu(&dir)
        .args([
            "run",
            "commix",
            "--technique",
            "T1190",
            "--target",
            &target,
            "--",
            "--os-cmd",
            "id",
        ])
        .output()
        .unwrap();
    let exfil = searu(&dir)
        .args([
            "run",
            "commix",
            "--technique",
            "T1552",
            "--target",
            &target,
            "--",
            "--os-cmd",
            "env",
        ])
        .output()
        .unwrap();

    // Query the recorded state the way Claude would.
    let loot = searu(&dir).args(["loot", "--reveal"]).output().unwrap();
    let findings = searu(&dir).arg("findings").output().unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        confirm.status.success(),
        "confirm run failed: {}",
        String::from_utf8_lossy(&confirm.stderr)
    );
    assert!(
        exfil.status.success(),
        "exfil run failed: {}",
        String::from_utf8_lossy(&exfil.stderr)
    );
    let loot = String::from_utf8_lossy(&loot.stdout);
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        loot.contains(SECRET),
        "loot did not capture the secret; loot was:\n{loot}"
    );
    assert!(
        findings.contains("T1190"),
        "no T1190 finding recorded; findings were:\n{findings}"
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
    panic!("the CWE-78 target never bound port {HOST_PORT}");
}
