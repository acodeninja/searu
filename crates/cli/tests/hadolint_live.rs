//! Live hadolint run against a source tree with a fragile Dockerfile: the image builds, hadolint lints
//! the `/src/Dockerfile` mount and records findings tagged T1593.003. Ignored by default: needs the
//! Docker daemon and builds the hadolint image. Run with
//! `cargo test -p searu --test hadolint_live -- --ignored`.

use assert_cmd::Command;

const DOCKERFILE: &str = "FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\nADD https://example.com/app /app\nCMD ./app\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the hadolint image"]
fn hadolint_flags_a_fragile_dockerfile() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("Dockerfile"), DOCKERFILE).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "hadolint",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "hadolint"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "hadolint run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("hadolint"),
        "no hadolint finding recorded for the fragile Dockerfile; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
