use std::collections::BTreeSet;
use std::path::PathBuf;

fn sections_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../skills/searu/sections")
}

#[test]
fn manifest_lists_exactly_the_section_files() {
    let dir = sections_dir();
    let manifest = std::fs::read_to_string(dir.join("manifest.json"))
        .expect("skills/searu/sections/manifest.json is readable");
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest).expect("manifest.json is valid JSON");
    let entries = manifest["sections"]
        .as_array()
        .expect("manifest has a `sections` array");

    let mut listed = BTreeSet::new();
    for entry in entries {
        for field in ["id", "file", "title", "trigger"] {
            let value = entry[field]
                .as_str()
                .unwrap_or_else(|| panic!("section entry is missing a string `{field}`"));
            assert!(!value.is_empty(), "section entry has an empty `{field}`");
        }
        listed.insert(entry["file"].as_str().unwrap().to_string());
    }

    let mut present = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("sections dir is readable") {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.ends_with(".md") {
            present.insert(name);
        }
    }

    assert_eq!(
        listed, present,
        "manifest.json and the section .md files must match one-to-one"
    );
}
