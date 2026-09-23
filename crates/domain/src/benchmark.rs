//! Benchmark scoring: a *decoupled* measurement of how much of a benchmark target (a lab with a public
//! answer key, such as OWASP Juice Shop's score board) an engagement has actually broken. Nothing here
//! is a runtime dependency of the engine — searu attacks identically whether or not this is ever run;
//! it exists so the exhaustive engine can be measured and its climb tracked against ground truth.

/// One benchmark challenge as reported by the target's own progress API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub key: String,
    pub name: String,
    pub category: String,
    pub difficulty: u32,
    pub solved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryScore {
    pub category: String,
    pub solved: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Score {
    pub solved: usize,
    pub total: usize,
    pub by_category: Vec<CategoryScore>,
}

impl Score {
    /// Percentage of challenges solved, 0–100.
    pub fn pct(&self) -> u32 {
        if self.total == 0 {
            return 0;
        }
        ((self.solved as f64 / self.total as f64) * 100.0).round() as u32
    }

    /// Change in solved count since a previous score (positive = progress).
    pub fn delta_from(&self, previous: Option<&Score>) -> i64 {
        self.solved as i64 - previous.map(|p| p.solved as i64).unwrap_or(0)
    }
}

/// Tally the challenges into an overall and per-category score. Categories are ordered by name so the
/// report is stable across runs.
pub fn score(challenges: &[Challenge]) -> Score {
    let mut categories: Vec<CategoryScore> = Vec::new();
    for challenge in challenges {
        let entry = match categories
            .iter_mut()
            .find(|c| c.category == challenge.category)
        {
            Some(entry) => entry,
            None => {
                categories.push(CategoryScore {
                    category: challenge.category.clone(),
                    solved: 0,
                    total: 0,
                });
                categories.last_mut().expect("just pushed")
            }
        };
        entry.total += 1;
        if challenge.solved {
            entry.solved += 1;
        }
    }
    categories.sort_by(|a, b| a.category.cmp(&b.category));
    Score {
        solved: challenges.iter().filter(|c| c.solved).count(),
        total: challenges.len(),
        by_category: categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(key: &str, category: &str, solved: bool) -> Challenge {
        Challenge {
            key: key.to_string(),
            name: key.to_string(),
            category: category.to_string(),
            difficulty: 1,
            solved,
        }
    }

    #[test]
    fn scores_overall_and_by_category() {
        let challenges = [
            challenge("a", "Injection", true),
            challenge("b", "Injection", false),
            challenge("c", "XSS", true),
        ];
        let score = score(&challenges);
        assert_eq!(score.solved, 2);
        assert_eq!(score.total, 3);
        assert_eq!(score.pct(), 67);
        assert_eq!(score.by_category.len(), 2);
        // Sorted by category name: Injection before XSS.
        assert_eq!(score.by_category[0].category, "Injection");
        assert_eq!(score.by_category[0].solved, 1);
        assert_eq!(score.by_category[0].total, 2);
        assert_eq!(score.by_category[1].category, "XSS");
        assert_eq!(score.by_category[1].solved, 1);
    }

    #[test]
    fn an_empty_board_is_zero_not_a_division_by_zero() {
        let score = score(&[]);
        assert_eq!(score.total, 0);
        assert_eq!(score.pct(), 0);
    }

    #[test]
    fn delta_measures_progress_since_a_previous_run() {
        let previous = Score {
            solved: 3,
            total: 100,
            by_category: vec![],
        };
        let current = Score {
            solved: 8,
            total: 100,
            by_category: vec![],
        };
        assert_eq!(current.delta_from(Some(&previous)), 5);
        assert_eq!(current.delta_from(None), 8);
    }
}
