//! Live end-to-end path-traversal run against the CWE-22 lab, playing Claude's loop: point ffuf at
//! the download parameter recon surfaced, fuzz it with a SecLists LFI list searu fetches once, and
//! read the recorded finding. Ignored by default: it needs the Docker daemon and network, builds the
//! ffuf image, and downloads a wordlist. Run with `cargo test -p searu --test lfi_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-22:main";
const CONTAINER: &str = "searu-cwe22-it";
const HOST_PORT: u16 = 5022;

const LAB_ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5022 },
        { "type": "ip", "value": "127.0.0.1", "port": 5022 }
    ] },
    "allowed_techniques": ["T1595", "T1190", "T1083"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the ffuf image and downloads a wordlist"]
fn runs_ffuf_against_the_live_cwe22_download() {
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
    std::fs::write(pentest.join("rules-of-engagement.json"), LAB_ROE).unwrap();
    let target = format!("http://localhost:{HOST_PORT}/download?file=FUZZ");

    let exploit = searu(&dir)
        .args([
            "run",
            "ffuf",
            "--technique",
            "T1190",
            "--target",
            &target,
            "--",
            "-w",
            "seclists:Fuzzing/LFI/LFI-Jhaddix.txt",
            "-mc",
            "200",
        ])
        .output()
        .unwrap();

    let findings = searu(&dir).arg("findings").output().unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        exploit.status.success(),
        "ffuf run failed: {}",
        String::from_utf8_lossy(&exploit.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1190") && findings.contains("Path traversal"),
        "no confirmed path-traversal finding recorded; findings were:\n{findings}"
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
    panic!("the CWE-22 target never bound port {HOST_PORT}");
}
