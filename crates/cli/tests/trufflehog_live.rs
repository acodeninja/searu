//! Live trufflehog run against a source tree carrying a throwaway private key: the image builds,
//! trufflehog scans the read-only `/src` mount and records a credential finding tagged T1593.003. The
//! key is generated at test time (via an openssl container) so no secret is committed to the repo.
//! Ignored by default: needs the Docker daemon and builds the trufflehog image. Run with
//! `cargo test -p searu --test trufflehog_live -- --ignored`.

use assert_cmd::Command;
use std::process::Command as Process;

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the trufflehog image"]
fn trufflehog_flags_a_private_key() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();

    let key = Process::new("docker")
        .args(["run", "--rm", "alpine/openssl", "genrsa", "2048"])
        .output()
        .expect("docker run openssl");
    assert!(
        key.status.success(),
        "openssl genrsa failed: {}",
        String::from_utf8_lossy(&key.stderr)
    );
    std::fs::write(code.join("id_rsa"), &key.stdout).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "trufflehog",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "trufflehog"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "trufflehog run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("trufflehog"),
        "no trufflehog finding recorded for the planted key; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
