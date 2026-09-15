//! Live whatweb fingerprint of the CWE-78 lab (Express/Node): the recorded observations name the
//! stack (X-Powered-By: Express). Ignored by default: needs the Docker daemon and network, and
//! builds the whatweb image. Run with `cargo test -p searu --test whatweb_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-78:main";
const CONTAINER: &str = "searu-whatweb-it";
const HOST_PORT: u16 = 5079;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5079 },
        { "type": "ip", "value": "127.0.0.1", "port": 5079 }
    ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the whatweb image"]
fn fingerprints_the_live_cwe78_stack() {
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
    let target = format!("http://localhost:{HOST_PORT}");

    let scan = searu(&dir)
        .args([
            "run",
            "whatweb",
            "--technique",
            "T1595",
            "--target",
            &target,
        ])
        .output()
        .unwrap();
    let observations = searu(&dir).arg("observations").output().unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "whatweb run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let observations = String::from_utf8_lossy(&observations.stdout);
    assert!(
        observations.contains("Express"),
        "whatweb did not fingerprint the Express stack; observations were:\n{observations}"
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
    panic!("the CWE-78 lab never bound port {HOST_PORT}");
}
