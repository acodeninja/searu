use std::collections::BTreeSet;
use std::path::PathBuf;

use searu_domain::tools::ToolRegistry;
use searu_tool_registry::Registry;

fn specialists_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../skills/searu/specialists")
}

fn model_of(body: &str) -> Option<String> {
    let mut lines = body.lines();
    if lines.next().map(str::trim) != Some("---") {
        return None;
    }
    for line in lines {
        let line = line.trim();
        if line == "---" {
            break;
        }
        if let Some(value) = line.strip_prefix("model:") {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[test]
fn specialists_match_the_registry_bindings_one_to_one() {
    let mut expected = BTreeSet::new();
    for tool in Registry.all() {
        for technique in tool.techniques() {
            expected.insert(format!("{technique}-{}.md", tool.name()));
        }
    }

    let dir = specialists_dir();
    let mut present = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("specialists dir is readable") {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name.ends_with(".md") {
            present.insert(name);
        }
    }

    assert_eq!(
        expected, present,
        "every (tool x technique) binding needs a specialists/<technique>-<tool>.md, and vice versa"
    );
}

#[test]
fn every_specialist_names_a_valid_model() {
    let dir = specialists_dir();
    for entry in std::fs::read_dir(&dir).expect("specialists dir is readable") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("specialist is readable");
        let model = model_of(&body)
            .unwrap_or_else(|| panic!("{} has no `model:` frontmatter", path.display()));
        assert!(
            ["haiku", "sonnet", "opus"].contains(&model.as_str()),
            "{} names an unknown model `{model}`",
            path.display()
        );
    }
}
