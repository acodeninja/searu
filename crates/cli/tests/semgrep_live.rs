//! Live semgrep run against a vulnerable source tree written into the engagement workspace: the image
//! builds, semgrep scans the read-only `/src` mount and records findings tagged T1593.003. Ignored by
//! default: it needs the Docker daemon and network (semgrep fetches its `auto` ruleset) and builds the
//! semgrep image. Run with `cargo test -p searu --test semgrep_live -- --ignored`.

use assert_cmd::Command;

const VULN_PY: &str =
    "import subprocess\n\ndef run(cmd):\n    return subprocess.call(cmd, shell=True)\n\ndef calc(expr):\n    return eval(expr)\n";

const ROE: &str = r#"{
    "scope": { "targets": [] },
    "allowed_techniques": ["T1593.003"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the semgrep image"]
fn semgrep_flags_a_vulnerable_source_tree() {
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
            "semgrep",
            "--technique",
            "T1593.003",
            "--target",
            "src:code",
        ])
        .output()
        .unwrap();
    let findings = searu(&dir)
        .args(["findings", "--tool", "semgrep"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "semgrep run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let findings = String::from_utf8_lossy(&findings.stdout);
    assert!(
        findings.contains("T1593.003") && findings.contains("semgrep"),
        "no semgrep finding recorded for the vulnerable source; findings were:\n{findings}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
