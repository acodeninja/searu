//! Live bandit run against a vulnerable Python source tree: the image builds, bandit scans the
//! read-only `/src` mount and records findings tagged T1593.003. Ignored by default: needs the Docker
//! daemon and builds the bandit image. Run with `cargo test -p searu --test bandit_live -- --ignored`.

use assert_cmd::Command;

const VULN_PY: &str =
    "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n\ndef calc(expr):\n    return eval(expr)\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon; builds the bandit image"]
fn bandit_flags_vulnerable_python() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();
    let code = dir.path().join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("vuln.py"), VULN_PY).unwrap();

    let scan = searu(&dir)
        .args([
            "run",
            "bandit",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "bandit"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "bandit run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("bandit"),
        "no bandit finding recorded for the vulnerable Python; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
