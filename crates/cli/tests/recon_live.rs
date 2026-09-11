//! Live black-box recon against the CWE-89 and CWE-22 labs: with only a URL, httpx + katana should
//! discover the login form and the download parameter, recorded as observations. Ignored by default:
//! needs the Docker daemon and network, and builds the httpx/katana images. Run with
//! `cargo test -p searu --test recon_live -- --ignored`. Both labs use port 5000, so this is one
//! sequential test.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const CONTAINER: &str = "searu-recon-it";
const HOST_PORT: u16 = 5000;

const RECON_ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5000 },
        { "type": "ip", "value": "127.0.0.1", "port": 5000 }
    ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the httpx/katana images"]
fn recon_maps_both_labs_black_box() {
    let cwe89 = recon("ghcr.io/ere-be-dragons/cwe-89:main");
    assert!(
        cwe89.contains("/login"),
        "cwe-89 recon did not discover /login; observations:\n{cwe89}"
    );

    let cwe22 = recon("ghcr.io/ere-be-dragons/cwe-22:main");
    assert!(
        cwe22.contains("/download"),
        "cwe-22 recon did not discover /download; observations:\n{cwe22}"
    );
    assert!(
        cwe22.contains("file"),
        "cwe-22 recon did not discover the file parameter; observations:\n{cwe22}"
    );
}

/// Bring up `image`, run httpx + katana against it black-box, and return `searu observations` output.
fn recon(image: &str) -> String {
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
            image,
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
    std::fs::write(pentest.join("rules-of-engagement.json"), RECON_ROE).unwrap();
    let target = format!("http://localhost:{HOST_PORT}");

    for tool in ["httpx", "katana"] {
        let _ = searu(&dir)
            .args(["run", tool, "--technique", "T1595", "--target", &target])
            .output()
            .unwrap();
    }
    let observations = searu(&dir).arg("observations").output().unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    String::from_utf8_lossy(&observations.stdout).into_owned()
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
    panic!("the lab never bound port {HOST_PORT}");
}
