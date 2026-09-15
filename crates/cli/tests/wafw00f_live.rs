//! Live wafw00f run against the CWE-78 lab (no WAF): the image builds, the tool runs, and the parser
//! records no false `waf` observation. Ignored by default: needs the Docker daemon and network, and
//! builds the wafw00f image. Run with `cargo test -p searu --test wafw00f_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-78:main";
const CONTAINER: &str = "searu-wafw00f-it";
const HOST_PORT: u16 = 5080;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5080 },
        { "type": "ip", "value": "127.0.0.1", "port": 5080 }
    ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the wafw00f image"]
fn wafw00f_reports_no_waf_on_the_bare_lab() {
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
            "wafw00f",
            "--technique",
            "T1595",
            "--target",
            &target,
        ])
        .output()
        .unwrap();
    let observations = searu(&dir)
        .args(["observations", "--kind", "waf"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "wafw00f run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let waf = String::from_utf8_lossy(&observations.stdout);
    assert!(
        waf.trim().is_empty(),
        "wafw00f recorded a WAF on the bare lab; observations were:\n{waf}"
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
