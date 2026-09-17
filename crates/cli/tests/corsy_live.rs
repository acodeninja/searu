//! Live corsy run against the OWASP Juice Shop lab: the image builds, corsy probes the CORS policy and
//! records the wildcard misconfiguration (Juice Shop serves `Access-Control-Allow-Origin: *`). Ignored
//! by default: needs the Docker daemon and network, and builds the corsy image. Run with
//! `cargo test -p searu --test corsy_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-corsy-it";
const HOST_PORT: u16 = 5091;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "url", "value": "http://localhost:5091", "port": 5091 },
        { "type": "ip", "value": "127.0.0.1", "port": 5091 }
    ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the corsy image"]
fn corsy_flags_the_juice_shop_wildcard() {
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
    let target = format!("http://localhost:{HOST_PORT}");

    let scan = searu(&dir)
        .args(["run", "corsy", "--technique", "T1595", "--target", &target])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "corsy"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "corsy run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1595") && findings.contains("CORS misconfiguration"),
        "no CORS finding recorded for the Juice Shop wildcard; findings were:\n{findings}"
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
