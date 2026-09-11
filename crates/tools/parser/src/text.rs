//! Text-output helpers: decode the HTML entities a web target reflects, and scan plaintext for
//! secrets a tool has surfaced (env-style `NAME=VALUE` and connection-string URLs).

use regex::Regex;
use std::sync::OnceLock;

pub fn html_unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            if let Some(decoded) = decode_entity(&after[..semi]) {
                out.push(decoded);
                rest = &after[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let code = if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                u32::from_str_radix(hex, 16).ok()?
            } else {
                entity.strip_prefix('#')?.parse::<u32>().ok()?
            };
            char::from_u32(code)
        }
    }
}

/// Scan text for secrets, returning `(category, value)` pairs. Matches env-style assignments whose
/// name looks sensitive (e.g. `DATABASE_URL`, `*_PASSWORD`, `*_TOKEN`, `*_SECRET`, `*_KEY`) and
/// database/broker connection-string URLs. Deliberately conservative; extend as tools surface more.
pub fn secrets(text: &str) -> Vec<(String, String)> {
    let mut found: Vec<(String, String)> = Vec::new();

    for caps in env_re().captures_iter(text) {
        let name = &caps[1];
        if is_secret_name(name) {
            let category = name.to_ascii_lowercase().replace('_', "-");
            push_unique(&mut found, category, caps[2].to_string());
        }
    }

    for caps in url_re().captures_iter(text) {
        let value = caps[1].to_string();
        let category = match &caps[2] {
            "postgres" | "postgresql" | "mysql" | "mongodb" => "database-url",
            other => other,
        }
        .to_string();
        push_unique(&mut found, category, value);
    }

    found
}

fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.contains("DATABASE_URL")
        || upper.contains("PASSWORD")
        || upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("API_KEY")
        || upper.contains("APIKEY")
        || upper.ends_with("_KEY")
        || upper == "KEY"
}

fn push_unique(found: &mut Vec<(String, String)>, category: String, value: String) {
    if !found.iter().any(|(c, v)| *c == category && *v == value) {
        found.push((category, value));
    }
}

fn env_re() -> &'static Regex {
    // Assignments may sit mid-line (a tool can dump `env` space-separated), so anchor on a preceding
    // start-or-whitespace rather than the line start.
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=(\S+)").expect("valid regex"))
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"((postgres|postgresql|mysql|mongodb|redis|amqp)://\S+)").expect("valid regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unescapes_html_entities() {
        assert_eq!(html_unescape("a&amp;b&lt;c&gt;d&#x3D;e"), "a&b<c>d=e");
        assert!(html_unescape("DATABASE_URL&#x3D;testing").contains("DATABASE_URL=testing"));
    }

    #[test]
    fn scans_env_style_secrets() {
        let text = "PATH=/usr/bin\nDATABASE_URL=testing\nHOME=/root\nAPP_TOKEN=abc123";
        let secrets = secrets(text);
        assert!(secrets.contains(&("database-url".to_string(), "testing".to_string())));
        assert!(secrets.contains(&("app-token".to_string(), "abc123".to_string())));
        assert!(!secrets.iter().any(|(c, _)| c == "path"));
    }

    #[test]
    fn scans_secrets_from_a_space_separated_env_dump() {
        // How commix prints an `env` result: one line, space-separated, with a log prefix.
        let text = "[info] 'env' execution output: DATABASE_URL=testing npm_package_name=@ere-be-dragons/cwe-78 HOME=/app";
        let secrets = secrets(text);
        assert!(secrets.contains(&("database-url".to_string(), "testing".to_string())));
        assert!(!secrets.iter().any(|(c, _)| c == "npm-package-name"));
    }

    #[test]
    fn scans_connection_string_urls() {
        let text = "DATABASE_URL=postgres://application:s3cr3t@db:5432/main";
        let secrets = secrets(text);
        assert!(
            secrets
                .iter()
                .any(|(c, v)| c == "database-url"
                    && v == "postgres://application:s3cr3t@db:5432/main")
        );
    }
}
