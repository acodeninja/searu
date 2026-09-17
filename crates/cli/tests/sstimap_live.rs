//! Live sstimap run against the OWASP Juice Shop lab (no SSTI): the image builds, sstimap tests a
//! parameter end-to-end and records no false finding. The positive-parse path is covered by the wrapper
//! unit test against SSTImap's real detection output. Ignored by default: needs the Docker daemon and
//! network, and builds the sstimap image. Run with `cargo test -p searu --test sstimap_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-sstimap-it";
const HOST_PORT: u16 = 5093;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "url", "value": "http://localhost:5093", "port": 5093 },
        { "type": "ip", "value": "127.0.0.1", "port": 5093 }
    ] },
    "allowed_techniques": ["T1190"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the sstimap image"]
fn sstimap_runs_clean_on_a_non_ssti_app() {
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
    let target = format!("http://localhost:{HOST_PORT}/rest/products/search?q=test");

    let scan = searu(&dir)
        .args([
            "run",
            "sstimap",
            "--technique",
            "T1190",
            "--target",
            &target,
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "sstimap"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "sstimap run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.trim().is_empty(),
        "sstimap recorded a false SSTI on a non-SSTI app; findings were:\n{findings}"
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
