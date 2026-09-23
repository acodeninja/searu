//! Live JWT forging: jwt_tool turns a captured token into alg:none forgeries, recorded as forged-jwt
//! loot with a CWE-347 finding. The forging is offline, so no lab server is needed — only the Docker
//! daemon to build and run the jwt image. Ignored by default; run with
//! `cargo test -p searu --test jwt_live -- --ignored`.

use assert_cmd::Command;

// A structurally valid sample token (the jwt.io HS256 example); jwt_tool rewrites its header to forge
// unsigned variants regardless of the original signature.
const SAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

const ROE: &str = r#"{
    "scope": { "targets": [
        { "type": "url", "value": "http://localhost:3000" },
        { "type": "domain", "value": "host.docker.internal", "port": 3000 }
    ] },
    "allowed_techniques": ["T1606.001"],
    "authorisation": { "exploitation_authorised_by": { "name": "T", "email": "t@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the jwt_tool image"]
fn jwt_forges_an_unsigned_token() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let run = searu(&dir)
        .args([
            "run",
            "jwt",
            "--technique",
            "T1606.001",
            "--target",
            "http://localhost:3000",
            "--",
            SAMPLE,
            "-X",
            "a",
            "-b",
        ])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "jwt run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let loot = searu(&dir)
        .args(["loot", "--category", "forged-jwt"])
        .output()
        .unwrap();
    let loot = String::from_utf8_lossy(&loot.stdout);
    assert!(
        loot.contains("forged-jwt"),
        "jwt did not record a forged token; loot was:\n{loot}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
