//! Live browser-driven crawl against a real OWASP Juice Shop: rendering the SPA and following its
//! client-side routes recovers the API endpoint behind the search box and the score-board route — the
//! surface a blind scanner never sees. Ignored by default: needs the Docker daemon and network, builds
//! the browser (Playwright) image and pulls Juice Shop. Run with
//! `cargo test -p searu --test browser_live -- --ignored`.

use assert_cmd::Command;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-browser-it";
const HOST_PORT: u16 = 3042;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 3042 },
        { "type": "ip", "value": "127.0.0.1", "port": 3042 }
    ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the Playwright image and pulls Juice Shop"]
fn browser_maps_the_spa_surface() {
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
    wait_for_ready();

    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let target = format!("http://localhost:{HOST_PORT}");

    let scan = searu(&dir)
        .args([
            "run",
            "browser",
            "--technique",
            "T1595",
            "--target",
            &target,
        ])
        .output()
        .unwrap();
    let endpoints = searu(&dir)
        .args(["observations", "--kind", "endpoint"])
        .output()
        .unwrap();
    let routes = searu(&dir)
        .args(["observations", "--kind", "route"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "browser run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let endpoints = String::from_utf8_lossy(&endpoints.stdout);
    assert!(
        endpoints.contains("/rest/products/search"),
        "browser did not find the search API; endpoints were:\n{endpoints}"
    );
    let routes = String::from_utf8_lossy(&routes.stdout);
    assert!(
        routes.contains("/#/contact"),
        "browser did not follow the SPA's client-side routes; routes were:\n{routes}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}

fn wait_for_ready() {
    for _ in 0..120 {
        if http_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();
    panic!("Juice Shop never became ready on port {HOST_PORT}");
}

fn http_ok() -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", HOST_PORT)) else {
        return false;
    };
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    if stream
        .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
}
