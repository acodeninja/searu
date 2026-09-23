//! Live benchmark scoring against a real OWASP Juice Shop: reading its score board reports how many
//! challenges are solved, by category. Decoupled from the engine — this only reads ground truth.
//! Ignored by default: needs the Docker daemon and network, builds the curl image and pulls Juice Shop.
//! Run with `cargo test -p searu --test benchmark_live -- --ignored`.

use assert_cmd::Command;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-benchmark-it";
const HOST_PORT: u16 = 3045;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "url", "value": "http://localhost:3045" },
        { "type": "domain", "value": "host.docker.internal", "port": 3045 }
    ] }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the curl image and pulls Juice Shop"]
fn benchmark_scores_the_juice_shop_board() {
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

    let score = searu(&dir)
        .args([
            "benchmark",
            "score",
            "--target",
            &format!("http://localhost:{HOST_PORT}"),
        ])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        score.status.success(),
        "benchmark score failed: {}",
        String::from_utf8_lossy(&score.stderr)
    );
    let summary = String::from_utf8_lossy(&score.stderr);
    assert!(
        summary.contains("solved"),
        "no score summary; stderr was:\n{summary}"
    );
    let categories = String::from_utf8_lossy(&score.stdout);
    assert!(
        categories.contains("Injection"),
        "no per-category score; stdout was:\n{categories}"
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
