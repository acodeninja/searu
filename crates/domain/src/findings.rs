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

/// An observation is recon intel — a discovered fact about the target (an endpoint, a form field, the
/// tech stack, a server banner) that Claude reads to decide what to run next. Not a vulnerability
/// (finding) and not a secret (loot).
#[derive(Debug, Clone)]
pub struct Observation {
    pub kind: String,
    pub value: String,
    pub detail: Option<String>,
}

/// The run-context attribution stamped onto every stored record: which tool and technique produced it,
/// and the host/service/network it concerns. The host/service are `None` until the asset model resolves
/// them; the network defaults to the public internet.
#[derive(Debug, Clone)]
pub struct RecordContext {
    pub tool: String,
    pub technique: String,
    pub host: Option<String>,
    pub network: String,
    pub service: Option<String>,
}

impl Default for RecordContext {
    fn default() -> Self {
        Self {
            tool: String::new(),
            technique: String::new(),
            host: None,
            network: "internet".to_string(),
            service: None,
        }
    }
}

/// A finding as stored: the finding plus its attribution and first/last-seen timestamps (stamped by the
/// store on emit, so the domain stays clock-free).
#[derive(Debug, Clone)]
pub struct StoredFinding {
    pub finding: Finding,
    pub host: Option<String>,
    pub network: String,
    pub service: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// Loot as stored, with the tool/host that surfaced it and first/last-seen timestamps.
#[derive(Debug, Clone)]
pub struct StoredLoot {
    pub loot: Loot,
    pub tool: String,
    pub host: Option<String>,
    pub network: String,
    pub service: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
}

/// An observation as stored, with the tool/technique that produced it, its host/service/network and
/// first/last-seen timestamps.
#[derive(Debug, Clone)]
pub struct StoredObservation {
    pub observation: Observation,
    pub tool: String,
    pub technique: String,
    pub host: Option<String>,
    pub network: String,
    pub service: Option<String>,
    pub first_seen: u64,
    pub last_seen: u64,
}
