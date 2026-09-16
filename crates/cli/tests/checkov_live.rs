//! Live checkov run against a source tree with an insecure Terraform file: the image builds, checkov
//! scans the read-only `/src` mount and records misconfiguration findings tagged T1593.003. Ignored by
//! default: needs the Docker daemon and builds the checkov image. Run with
//! `cargo test -p searu --test checkov_live -- --ignored`.

use assert_cmd::Command;

const MAIN_TF: &str = "resource \"aws_security_group\" \"open\" {\n  name = \"open\"\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }\n}\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the checkov image"]
fn checkov_flags_an_insecure_terraform_file() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("main.tf"), MAIN_TF).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "checkov",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "checkov"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "checkov run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("checkov"),
        "no checkov finding recorded for the insecure Terraform; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
