//! Reads a benchmark target's progress API through a pinned `curl` container, so searu keeps no
//! host-side HTTP dependency (the same discipline as the wordlist provider). Today it speaks the OWASP
//! Juice Shop score-board shape (`GET /api/Challenges/` → `{ "data": [ { key, name, category,
//! difficulty, solved } ] }`); the parsing is pure and unit-tested against that shape.

use searu_domain::benchmark::Challenge;
use searu_domain::ports::{BenchmarkError, ScoreboardProvider};
use std::process::Command;

const CURL_IMAGE: &str = "curlimages/curl:8.22.0";

pub struct DockerScoreboard {
    pub curl_image: String,
}

impl Default for DockerScoreboard {
    fn default() -> Self {
        Self {
            curl_image: CURL_IMAGE.to_string(),
        }
    }
}

/// Rewrite a host-local target so `curl` *inside a container* can reach it on the host.
fn reachable(target: &str) -> String {
    target
        .replace("127.0.0.1", "host.docker.internal")
        .replace("localhost", "host.docker.internal")
}

impl ScoreboardProvider for DockerScoreboard {
    fn challenges(&self, target: &str) -> Result<Vec<Challenge>, BenchmarkError> {
        let base = reachable(target);
        let url = format!("{}/api/Challenges/", base.trim_end_matches('/'));
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--add-host",
                "host.docker.internal:host-gateway",
                &self.curl_image,
                "-sSfL",
                &url,
            ])
            .output()
            .map_err(|e| BenchmarkError::Fetch(e.to_string()))?;
        if !output.status.success() {
            return Err(BenchmarkError::Fetch(format!(
                "curl failed for {url}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        parse_challenges(&String::from_utf8_lossy(&output.stdout))
    }
}

pub fn parse_challenges(body: &str) -> Result<Vec<Challenge>, BenchmarkError> {
    let document: serde_json::Value =
        serde_json::from_str(body).map_err(|e| BenchmarkError::Parse(e.to_string()))?;
    let data = document["data"]
        .as_array()
        .ok_or_else(|| BenchmarkError::Parse("no `data` array in the response".to_string()))?;
    let mut challenges = Vec::with_capacity(data.len());
    for entry in data {
        let (Some(key), Some(name), Some(category)) = (
            entry["key"].as_str(),
            entry["name"].as_str(),
            entry["category"].as_str(),
        ) else {
            continue;
        };
        challenges.push(Challenge {
            key: key.to_string(),
            name: name.to_string(),
            category: category.to_string(),
            difficulty: entry["difficulty"].as_u64().unwrap_or(0) as u32,
            solved: entry["solved"].as_bool().unwrap_or(false),
        });
    }
    Ok(challenges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_juice_shop_challenge_shape() {
        let body = r#"{"status":"success","data":[
            {"key":"a","name":"Alpha","category":"Injection","difficulty":2,"solved":true},
            {"key":"b","name":"Bravo","category":"XSS","difficulty":1,"solved":false}
        ]}"#;
        let challenges = parse_challenges(body).unwrap();
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].key, "a");
        assert_eq!(challenges[0].category, "Injection");
        assert!(challenges[0].solved);
        assert!(!challenges[1].solved);
    }

    #[test]
    fn a_response_without_a_data_array_is_a_parse_error() {
        assert!(parse_challenges("{\"status\":\"error\"}").is_err());
        assert!(parse_challenges("not json").is_err());
    }

    #[test]
    fn rewrites_a_host_local_target_for_the_container() {
        assert_eq!(
            reachable("http://localhost:3000"),
            "http://host.docker.internal:3000"
        );
    }
}
