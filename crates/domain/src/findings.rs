//! Findings and loot: two stores joined by a fingerprint. A finding records the fingerprint of any
//! secret it references, never the value; the plaintext lives only in the loot store.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    NeedsReview,
    Confirmed,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NeedsReview => "needs-review",
            Self::Confirmed => "confirmed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub tool: String,
    pub target: String,
    pub title: String,
    pub severity: Severity,
    pub status: Status,
    pub attack_technique: Vec<String>,
    pub cwe: Vec<u32>,
    pub evidence: String,
    pub loot_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Loot {
    pub fingerprint: String,
    pub category: String,
    pub value: String,
}
