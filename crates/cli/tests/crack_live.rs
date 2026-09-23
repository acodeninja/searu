//! Live hash cracking: crack recovers the plaintext behind a captured MD5 with a SecLists wordlist.
//! Cracking is offline, so no lab server is needed — only the Docker daemon to build the john image and
//! network to fetch the wordlist. Ignored by default; run with
//! `cargo test -p searu --test crack_live -- --ignored`.

use assert_cmd::Command;

// md5("admin123"), the hash a Juice Shop SQL dump yields for the default admin.
const HASH: &str = "0192023a7bbd73250516f069df18b500";

const ROE: &str = r#"{
    "scope": { "targets": [ { "type": "url", "value": "http://localhost:3000" } ] },
    "allowed_techniques": ["T1110.002"],
    "authorisation": { "exploitation_authorised_by": { "name": "T", "email": "t@example.com" } }
}"#;

#[test]
#[ignore = "requires the docker daemon and network; builds the john image and fetches a wordlist"]
fn crack_recovers_a_plaintext_password() {
    let dir = tempfile::tempdir().unwrap();
    let pentest = dir.path().join("pentest");
    std::fs::create_dir_all(&pentest).unwrap();
    std::fs::write(pentest.join("rules-of-engagement.json"), ROE).unwrap();

    let run = searu(&dir)
        .args([
            "run",
            "crack",
            "--technique",
            "T1110.002",
            "--target",
            "http://localhost:3000",
            "--",
            "--hash",
            HASH,
            "--format",
            "raw-md5",
            "--wordlist",
            "seclists:Passwords/Common-Credentials/Pwdb_top-10000.txt",
        ])
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "crack run failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let loot = searu(&dir)
        .args(["loot", "--category", "password", "--reveal"])
        .output()
        .unwrap();
    let loot = String::from_utf8_lossy(&loot.stdout);
    assert!(
        loot.contains("admin123"),
        "crack did not recover the password; loot was:\n{loot}"
    );
}

fn searu(dir: &tempfile::TempDir) -> Command {
    let mut command = Command::cargo_bin("searu").unwrap();
    command.current_dir(dir);
    command
}
