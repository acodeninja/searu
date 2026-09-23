//! Attack-surface coverage: the discipline that makes an assessment exhaustive rather than
//! opportunistic. Every discovered surface item (an endpoint, a parameter, a form, a route) is crossed
//! with the technique classes that could apply to it, and each pairing is scored untried / attempted /
//! succeeded from what searu has already run and found. The gaps — applicable pairings still untried —
//! are the work list; a class with no automated tool yet (IDOR, open redirect) still shows as an
//! applicable gap, so the report names what only a human or a not-yet-built tool can reach.
//!
//! This module is pure: the caller projects the stored records into `SurfaceItem`s and `Signal`s and
//! reads back a matrix, exactly as the host graph is projected from records elsewhere.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Endpoint,
    Param,
    Form,
    Route,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Endpoint => "endpoint",
            ItemKind::Param => "param",
            ItemKind::Form => "form",
            ItemKind::Route => "route",
        }
    }

    pub fn parse(kind: &str) -> Option<ItemKind> {
        match kind {
            "endpoint" => Some(ItemKind::Endpoint),
            "param" => Some(ItemKind::Param),
            "form" => Some(ItemKind::Form),
            "route" => Some(ItemKind::Route),
            _ => None,
        }
    }
}

/// One element of the discovered attack surface. For a parameter, `value` is its name and `endpoint` is
/// the path it belongs to; for the rest, `value` is the path/route and `endpoint` is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceItem {
    pub kind: ItemKind,
    pub value: String,
    pub endpoint: Option<String>,
}

impl SurfaceItem {
    /// A stable identifier for the item, unique across kinds.
    pub fn id(&self) -> String {
        match (&self.kind, &self.endpoint) {
            (ItemKind::Param, Some(endpoint)) => format!("param {} @ {endpoint}", self.value),
            _ => format!("{} {}", self.kind.as_str(), self.value),
        }
    }
}

/// A run signal: a tool touched a target described by `reference` (the target plus its args, for an
/// attempt; the target plus evidence, for a success). Coverage matches an item against the reference
/// text — rewarding runs scoped to a specific item.
#[derive(Debug, Clone)]
pub struct Signal {
    pub tool: String,
    pub reference: String,
}

/// A class of weakness, defined by the tools that exercise it and the item kinds it can apply to. A
/// class with no tools is one searu cannot yet automate — it still applies, so its gaps are reported.
pub struct TechniqueClass {
    pub id: &'static str,
    pub label: &'static str,
    pub tools: &'static [&'static str],
    pub applies: &'static [ItemKind],
}

impl TechniqueClass {
    pub fn automated(&self) -> bool {
        !self.tools.is_empty()
    }

    fn applies_to(&self, kind: ItemKind) -> bool {
        self.applies.contains(&kind)
    }

    fn owns(&self, tool: &str) -> bool {
        // `contains` cannot typecheck a `&str` against `&'static str` elements.
        #[allow(clippy::manual_contains)]
        self.tools.iter().any(|t| *t == tool)
    }
}

pub static CLASSES: &[TechniqueClass] = &[
    TechniqueClass {
        id: "sqli",
        label: "SQL injection",
        tools: &["sqlmap", "ghauri"],
        applies: &[ItemKind::Param],
    },
    TechniqueClass {
        id: "xss",
        label: "cross-site scripting",
        tools: &["dalfox"],
        applies: &[ItemKind::Param],
    },
    TechniqueClass {
        id: "cmdi",
        label: "OS command injection",
        tools: &["commix"],
        applies: &[ItemKind::Param],
    },
    TechniqueClass {
        id: "traversal",
        label: "path traversal / LFI",
        tools: &["dotdotpwn"],
        applies: &[ItemKind::Param],
    },
    TechniqueClass {
        id: "ssti",
        label: "server-side template injection",
        tools: &["sstimap"],
        applies: &[ItemKind::Param],
    },
    TechniqueClass {
        id: "crlf",
        label: "CRLF injection",
        tools: &["crlfuzz"],
        applies: &[ItemKind::Param],
    },
    TechniqueClass {
        id: "upload",
        label: "unrestricted file upload",
        tools: &["fuxploider"],
        applies: &[ItemKind::Form],
    },
    TechniqueClass {
        id: "brute-force",
        label: "credential brute force",
        tools: &["hydra"],
        applies: &[ItemKind::Form],
    },
    TechniqueClass {
        id: "cors",
        label: "CORS misconfiguration",
        tools: &["corsy"],
        applies: &[ItemKind::Endpoint],
    },
    TechniqueClass {
        id: "known-vuln",
        label: "known CVE / misconfiguration",
        tools: &["nuclei", "nikto"],
        applies: &[ItemKind::Endpoint, ItemKind::Route],
    },
    TechniqueClass {
        id: "content-discovery",
        label: "hidden content discovery",
        tools: &["ffuf", "feroxbuster", "gobuster"],
        applies: &[ItemKind::Route],
    },
    TechniqueClass {
        id: "access-control",
        label: "broken access control / IDOR",
        tools: &[],
        applies: &[ItemKind::Endpoint, ItemKind::Param],
    },
    TechniqueClass {
        id: "auth",
        label: "broken authentication / token forgery",
        tools: &[],
        applies: &[ItemKind::Endpoint, ItemKind::Form],
    },
    TechniqueClass {
        id: "redirect-ssrf",
        label: "open redirect / SSRF",
        tools: &[],
        applies: &[ItemKind::Param],
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageState {
    Untried,
    Attempted,
    Succeeded,
}

impl CoverageState {
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageState::Untried => "untried",
            CoverageState::Attempted => "attempted",
            CoverageState::Succeeded => "succeeded",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoverageCell {
    pub item: SurfaceItem,
    pub class_id: &'static str,
    pub class_label: &'static str,
    pub automated: bool,
    pub state: CoverageState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoverageSummary {
    pub total: usize,
    pub untried: usize,
    pub attempted: usize,
    pub succeeded: usize,
    pub untried_no_tool: usize,
}

impl CoverageSummary {
    /// Fraction of applicable pairings that have at least been attempted, 0–100.
    pub fn attempted_pct(&self) -> u32 {
        if self.total == 0 {
            return 0;
        }
        (((self.attempted + self.succeeded) as f64 / self.total as f64) * 100.0).round() as u32
    }
}

fn references(reference: &str, item: &SurfaceItem) -> bool {
    match item.kind {
        ItemKind::Param => {
            let endpoint_ok = item
                .endpoint
                .as_deref()
                .map(|e| reference.contains(e))
                .unwrap_or(true);
            endpoint_ok && reference.contains(&item.value)
        }
        _ => reference.contains(&item.value),
    }
}

fn state_for(
    class: &TechniqueClass,
    item: &SurfaceItem,
    attempts: &[Signal],
    successes: &[Signal],
) -> CoverageState {
    let matches = |signals: &[Signal]| {
        signals
            .iter()
            .any(|s| class.owns(&s.tool) && references(&s.reference, item))
    };
    if matches(successes) {
        CoverageState::Succeeded
    } else if matches(attempts) {
        CoverageState::Attempted
    } else {
        CoverageState::Untried
    }
}

/// Cross every surface item with the classes that apply to it and score each pairing.
pub fn project(
    items: &[SurfaceItem],
    attempts: &[Signal],
    successes: &[Signal],
) -> Vec<CoverageCell> {
    let mut cells = Vec::new();
    for item in items {
        for class in CLASSES {
            if !class.applies_to(item.kind) {
                continue;
            }
            cells.push(CoverageCell {
                item: item.clone(),
                class_id: class.id,
                class_label: class.label,
                automated: class.automated(),
                state: state_for(class, item, attempts, successes),
            });
        }
    }
    cells
}

pub fn summarise(cells: &[CoverageCell]) -> CoverageSummary {
    let mut summary = CoverageSummary {
        total: cells.len(),
        ..Default::default()
    };
    for cell in cells {
        match cell.state {
            CoverageState::Untried => {
                summary.untried += 1;
                if !cell.automated {
                    summary.untried_no_tool += 1;
                }
            }
            CoverageState::Attempted => summary.attempted += 1,
            CoverageState::Succeeded => summary.succeeded += 1,
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(name: &str, endpoint: &str) -> SurfaceItem {
        SurfaceItem {
            kind: ItemKind::Param,
            value: name.to_string(),
            endpoint: Some(endpoint.to_string()),
        }
    }

    #[test]
    fn a_param_is_crossed_with_every_param_class() {
        let items = [param("q", "/rest/products/search")];
        let cells = project(&items, &[], &[]);
        assert!(cells.iter().any(|c| c.class_id == "sqli"));
        assert!(cells.iter().any(|c| c.class_id == "xss"));
        assert!(cells.iter().any(|c| c.class_id == "access-control"));
        assert!(cells.iter().all(|c| c.state == CoverageState::Untried));
    }

    #[test]
    fn a_confirmed_finding_marks_the_pairing_succeeded() {
        let items = [param("q", "/rest/products/search")];
        let successes = [Signal {
            tool: "sqlmap".to_string(),
            reference: "http://h/rest/products/search?q=test injectable".to_string(),
        }];
        let cells = project(&items, &[], &successes);
        let sqli = cells.iter().find(|c| c.class_id == "sqli").unwrap();
        assert_eq!(sqli.state, CoverageState::Succeeded);
        // A different class on the same item is still untried.
        let xss = cells.iter().find(|c| c.class_id == "xss").unwrap();
        assert_eq!(xss.state, CoverageState::Untried);
    }

    #[test]
    fn a_run_that_did_not_find_is_attempted_not_succeeded() {
        let items = [param("q", "/rest/products/search")];
        let attempts = [Signal {
            tool: "dalfox".to_string(),
            reference: "http://h/rest/products/search?q=FUZZ".to_string(),
        }];
        let cells = project(&items, &attempts, &[]);
        let xss = cells.iter().find(|c| c.class_id == "xss").unwrap();
        assert_eq!(xss.state, CoverageState::Attempted);
    }

    #[test]
    fn a_run_scoped_to_another_endpoint_does_not_credit_this_param() {
        let items = [param("q", "/rest/products/search")];
        let attempts = [Signal {
            tool: "sqlmap".to_string(),
            reference: "http://h/rest/user/login q".to_string(),
        }];
        let cells = project(&items, &attempts, &[]);
        let sqli = cells.iter().find(|c| c.class_id == "sqli").unwrap();
        assert_eq!(sqli.state, CoverageState::Untried);
    }

    #[test]
    fn the_summary_counts_states_and_flags_gaps_with_no_tool() {
        let items = [param("q", "/rest/products/search")];
        let successes = [Signal {
            tool: "sqlmap".to_string(),
            reference: "http://h/rest/products/search?q=x".to_string(),
        }];
        let cells = project(&items, &[], &successes);
        let summary = summarise(&cells);
        assert_eq!(summary.succeeded, 1);
        assert!(summary.untried_no_tool >= 1); // access-control/redirect-ssrf have no tool yet
        assert!(summary.attempted_pct() < 100);
    }
}
