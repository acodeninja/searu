//! Live crlfuzz run against the OWASP Juice Shop lab (which has no CRLF flaw): the image builds, crlfuzz
//! fuzzes an endpoint end-to-end and records no false finding. The positive-parse path is covered by the
//! wrapper unit test against crlfuzz's real `[VLN]` output. Ignored by default: needs the Docker daemon
//! and network, and builds the crlfuzz image. Run with `cargo test -p searu --test crlfuzz_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-crlfuzz-it";
const HOST_PORT: u16 = 5092;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "url", "value": "http://localhost:5092", "port": 5092 },
        { "type": "ip", "value": "127.0.0.1", "port": 5092 }
    ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the crlfuzz image"]
fn crlfuzz_runs_clean_on_a_non_crlf_app() {
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
            &format!("{HOST_PORT}:3000"),
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
    let target = format!("http://localhost:{HOST_PORT}/redirect?to=x");

    let scan = searu(&dir)
        .args([
            "run",
            "crlfuzz",
            "--technique",
            "T1595",
            "--target",
            &target,
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "crlfuzz"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "crlfuzz run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.trim().is_empty(),
        "crlfuzz recorded a false CRLF finding on a non-CRLF app; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}

fn wait_for_port() {
    for _ in 0..90 {
        if TcpStream::connect(("127.0.0.1", HOST_PORT)).is_ok() {
            std::thread::sleep(Duration::from_secs(2));
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    panic!("the Juice Shop lab never bound port {HOST_PORT}");
}
