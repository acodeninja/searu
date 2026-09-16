//! Live dalfox run against the CWE-22 lab (not an XSS app): the image builds, dalfox runs end-to-end
//! and records no false XSS finding. The positive-parse path is covered by the wrapper unit test
//! against dalfox's real JSON. Ignored by default: needs the Docker daemon and network, and builds the
//! dalfox image. Run with `cargo test -p searu --test dalfox_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-22:main";
const CONTAINER: &str = "searu-dalfox-it";
const HOST_PORT: u16 = 5085;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5085 },
        { "type": "ip", "value": "127.0.0.1", "port": 5085 }
    ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the dalfox image"]
fn dalfox_runs_clean_on_a_non_xss_app() {
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
    let target = format!("http://localhost:{HOST_PORT}/?q=test");

    let scan = searu(&dir)
        .args(["run", "dalfox", "--technique", "T1595", "--target", &target])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "dalfox"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "dalfox run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.trim().is_empty(),
        "dalfox recorded a false XSS on the non-XSS app; findings were:\n{findings}"
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
