//! Shared helpers tool crates use to normalise tool output into findings/loot: a stable fingerprint
//! for the two-store join, and text helpers (HTML unescape + a small secret scanner). This is the
//! tool-*output* parser — distinct from the eventual client `report` deliverable.

pub mod text;

use sha2::{Digest, Sha256};

/// The first 12 hex characters of the SHA-256 of a value — the fingerprint that joins a finding to
/// the loot store without the finding ever holding the plaintext.
pub fn fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_the_first_twelve_hex_of_sha256() {
        assert_eq!(fingerprint("abc"), "ba7816bf8f01");
    }
}
