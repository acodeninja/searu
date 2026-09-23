//! Live file download against a real Juice Shop: fetch retrieves the exposed KeePass database from
//! /ftp into the run's output directory, recorded as a download observation. Ignored by default: needs
//! the Docker daemon and network, builds the fetch image and pulls Juice Shop. Run with
//! `cargo test -p searu --test fetch_live -- --ignored`.

use assert_cmd::Command;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-fetch-it";
const HOST_PORT: u16 = 3044;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 3044 },
        { "type": "ip", "value": "127.0.0.1", "port": 3044 }
    ] },
    "allowed_techniques": ["T1083"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the fetch image and pulls Juice Shop"]
fn fetch_downloads_the_exposed_keepass_db() {
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
        "docker run: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    wait_for_ready();

    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "fetch",
            "--technique",
            "T1083",
            "--target",
            &format!("http://localhost:{HOST_PORT}/ftp/incident-support.kdbx"),
        ])
        .output()
        .unwrap();
    let observations = searu(&dir)
        .args(["observations", "--kind", "download"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "fetch run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let observations = String::from_utf8_lossy(&observations.stdout);
    assert!(
        observations.contains("incident-support.kdbx"),
        "fetch did not download the KeePass db; observations were:\n{observations}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}

fn wait_for_ready() {
    for _ in 0..120 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", HOST_PORT)) {
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            if stream
                .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .is_ok()
            {
                let mut response = String::new();
                let _ = stream.read_to_string(&mut response);
                if response.contains(" 200") {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    panic!("Juice Shop never became ready on port {HOST_PORT}");
}
