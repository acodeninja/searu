//! Live gitleaks run against a source tree carrying a planted secret: the image builds, gitleaks scans
//! the read-only `/src` mount and records a hardcoded-credential finding tagged T1593.003. Ignored by
//! default: needs the Docker daemon and builds the gitleaks image. Run with
//! `cargo test -p searu --test gitleaks_live -- --ignored`.

use assert_cmd::Command;

const LEAKY: &str = "STRIPE_KEY = \"sk_live_ABCDEFGHIJKLMNOPQRSTUVWX\"\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the gitleaks image"]
fn gitleaks_flags_a_planted_secret() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("config.py"), LEAKY).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "gitleaks",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "gitleaks"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "gitleaks run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("gitleaks"),
        "no gitleaks finding recorded for the planted secret; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
