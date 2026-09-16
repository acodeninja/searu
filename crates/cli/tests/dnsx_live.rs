//! Live dnsx run resolving a well-known host: the image builds, dnsx resolves the target (fed on stdin
//! by the runner) and records DNS observations. `one.one.one.one` resolves to Cloudflare's stable
//! 1.1.1.1 / 1.0.0.1, so the assertion is deterministic. Ignored by default: needs the Docker daemon and
//! network, and builds the dnsx image. Run with `cargo test -p searu --test dnsx_live -- --ignored`.

use assert_cmd::Command;

const HOST: &str = "one.one.one.one";

const ROE: &str = r#"{
    "scope": { "targets": [ { "type": "domain", "value": "one.one.one.one" } ] },
    "allowed_techniques": ["T1595"]
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the dnsx image"]
fn dnsx_resolves_a_known_host() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let scan = searu(&dir)
        .args(["run", "dnsx", "--technique", "T1595", "--target", HOST])
        .output()
        .unwrap();
    let observations = searu(&dir)
        .args(["observations", "--kind", "dns"])
        .output()
        .unwrap();

    assert!(
        scan.status.success(),
        "dnsx run failed: {}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let observations = String::from_utf8_lossy(&observations.stdout);
    assert!(
        observations.contains("1.1.1.1"),
        "dnsx did not resolve {HOST} to its known address; observations were:\n{observations}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
