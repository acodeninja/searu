//! Live hydra run against the OWASP Juice Shop lab: the image builds, hydra brute-forces the REST login
//! and cracks the well-known `admin@juice-sh.op` / `admin123` pair, recording a weak-credentials finding
//! and the credential as loot. Ignored by default: needs the Docker daemon and network, and builds the
//! hydra image. Run with `cargo test -p searu --test hydra_live -- --ignored`.

use assert_cmd::Command;
use std::net::TcpStream;
use std::process::Command as Process;
use std::time::Duration;

const IMAGE: &str = "bkimminich/juice-shop:v20.2.0";
const CONTAINER: &str = "searu-hydra-it";
const HOST_PORT: u16 = 5095;

// hydra http-post-form spec: JSON body (colons escaped `\:`), the content-type header, then the
// fail-string condition last.
const FORM_SPEC: &str = "/rest/user/login:{\"email\"\\:\"^USER^\",\"password\"\\:\"^PASS^\"}:H=Content-Type\\: application/json:Invalid email or password";

const ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "localhost" } ] },
    "allowed_techniques": ["T1110"],
    "authorisation": { "exploitation_authorised_by": { "name": "Lab Operator", "email": "operator@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the hydra image"]
fn hydra_cracks_the_juice_shop_admin_login() {
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

    let scan = searu(&dir)
        .args([
            "run",
            "hydra",
            "--technique",
            "T1110",
            "--target",
            "localhost",
            "--",
            "-s",
            &HOST_PORT.to_string(),
            "-l",
            "admin@juice-sh.op",
            "-p",
            "admin123",
            "http-post-form",
            FORM_SPEC,
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "hydra"])
        .output()
        .unwrap();

    let _ = Process::new("docker")
        .args(["rm", "-f", CONTAINER])
        .output();

    assert!(
        scan.status.success(),
        "hydra run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1110") && findings.contains("Weak credentials"),
        "hydra did not record the cracked Juice Shop credential; findings were:\n{findings}"
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
