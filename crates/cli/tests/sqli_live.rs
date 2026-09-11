//! Live end-to-end SQL-injection run against the CWE-89 lab, playing Claude's loop: point sqlmap at
//! the login form recon surfaced, confirm the injection, and read the recorded finding plus the
//! fingerprinted DBMS. Ignored by default: it needs the Docker daemon and network, and builds the
//! sqlmap image from its embedded Dockerfile. Run with `cargo test -p searu --test sqli_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "ghcr.io/ere-be-dragons/cwe-89:main";
const CONTAINER: &str = "searu-cwe89-it";
const HOST_PORT: u16 = 5089;

const LAB_ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 5089 },
        { "type": "ip", "value": "127.0.0.1", "port": 5089 }
    ] },
    "allowed_techniques": ["T1190"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds and runs the sqlmap image"]
fn runs_sqlmap_against_the_live_cwe89_login() {
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
    let target = format!("http://localhost:{HOST_PORT}/login");

    let exploit = searu(&dir)
        .args([
            "run",
            "sqlmap",
            "--technique",
            "T1190",
            "--target",
            &target,
            "--",
            "--data",
            "username=a&password=x",
            "-p",
            "username",
            "--prefix",
            "'",
            "--suffix",
            "/*",
            "--ignore-redirects",
            "--not-string",
            "login",
            "--level",
            "3",
            "--risk",
            "3",
            "--technique=B",
        ])
        .output()
        .unwrap();

    let findings = searu(&dir).arg("findings").output().unwrap();
    let observations = searu(&dir).arg("observations").output().unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        exploit.status.success(),
        "sqlmap run failed: {}",
        String::from_utf8_lossy(&exploit.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    let observations = String::from_utf8_lossy(&observations.stdout);
    assert!(
        findings.contains("T1190") && findings.contains("SQL injection"),
        "no confirmed SQL-injection finding recorded; findings were:\n{findings}"
    );
    assert!(
        observations.contains("back-end DBMS"),
        "sqlmap did not fingerprint the back-end DBMS; observations were:\n{observations}"
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
    panic!("the CWE-89 target never bound port {HOST_PORT}");
}
