//! Live broken-access-control check against a real Juice Shop: logged in as one user, requesting
//! another basket by id is served (a should-deny request that returns 200), which authz records as a
//! confirmed finding. Ignored by default: needs the Docker daemon and network, builds the authz image
//! and pulls Juice Shop. Run with `cargo test -p searu --test authz_live -- --ignored`.

use assert_cmd::Command;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-authz-it";
const HOST_PORT: u16 = 3043;

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "domain", "value": "localhost", "port": 3043 },
        { "type": "ip", "value": "127.0.0.1", "port": 3043 }
    ] },
    "allowed_techniques": ["T1190"],
    "authorisation": { "exploitation_authorised_by": { "name": "T", "email": "t@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the authz image and pulls Juice Shop"]
fn authz_finds_the_basket_idor() {
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

    let token = login().expect("logging in as the default admin should yield a token");

    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "authz",
            "--technique",
            "T1190",
            "--target",
            &format!("http://localhost:{HOST_PORT}/rest/basket/2"),
            "--",
            "--should-deny",
            "--header",
            &format!("Authorization: Bearer {token}"),
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "authz"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "authz run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("Broken access control"),
        "authz did not flag the basket IDOR; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}

fn login() -> Option<String> {
    let body = br#"{"email":"admin@juice-sh.op","password":"admin123"}"#;
    let mut stream = TcpStream::connect(("127.0.0.1", HOST_PORT)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let request = format!(
        "POST /rest/user/login HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).ok()?;
    stream.write_all(body).ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let marker = "\"token\":\"";
    let start = response.find(marker)? + marker.len();
    let rest = &response[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
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
