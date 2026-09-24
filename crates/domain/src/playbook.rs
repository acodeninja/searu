//! Technology-playbook recognition: map the stack a target was fingerprinted as (the `tech`/`server`
//! observations) to the playbooks that hold transferable techniques for it. Pure — the caller supplies
//! the detected technology strings and the slugs of the playbooks that exist on disk, and reads back
//! which ones apply and which detected technologies have no playbook yet.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaybookMatch {
    pub slug: String,
    pub tech: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Recognition {
    pub matched: Vec<PlaybookMatch>,
    pub gaps: Vec<String>,
}

/// Reduce a fingerprint value to a playbook slug: lower-case and keep the leading identifier, dropping a
/// version or path suffix — `PHP/8.1.2` -> `php`, `Angular 15.0` -> `angular`, `nginx/1.18.0` -> `nginx`.
pub fn slug_for(tech: &str) -> String {
    tech.trim()
        .to_ascii_lowercase()
        .split(['/', ' ', ',', ';', '('])
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}

/// Cross the detected technologies with the available playbook slugs. `matched` is deduplicated by slug
/// (keeping the first technology that named it); `gaps` are the detected slugs with no playbook yet.
pub fn recognise(techs: &[String], available: &[String]) -> Recognition {
    let mut matched: Vec<PlaybookMatch> = Vec::new();
    let mut gaps: Vec<String> = Vec::new();
    for tech in techs {
        let slug = slug_for(tech);
        if slug.is_empty() {
            continue;
        }
        if available.iter().any(|a| a.eq_ignore_ascii_case(&slug)) {
            if !matched.iter().any(|m| m.slug == slug) {
                matched.push(PlaybookMatch {
                    slug,
                    tech: tech.trim().to_string(),
                });
            }
        } else if !gaps.contains(&slug) {
            gaps.push(slug);
        }
    }
    Recognition { matched, gaps }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slugs(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_bare_technology_matches_its_playbook() {
        let got = recognise(&slugs(&["Angular"]), &slugs(&["angular", "php"]));
        assert_eq!(
            got.matched,
            vec![PlaybookMatch {
                slug: "angular".into(),
                tech: "Angular".into()
            }]
        );
        assert!(got.gaps.is_empty());
    }

    #[test]
    fn a_version_suffixed_technology_still_matches() {
        assert_eq!(slug_for("PHP/8.1.2"), "php");
        assert_eq!(slug_for("Angular 15.0"), "angular");
        assert_eq!(slug_for("nginx/1.18.0"), "nginx");
        let got = recognise(&slugs(&["PHP/8.1.2"]), &slugs(&["php"]));
        assert_eq!(got.matched.len(), 1);
        assert_eq!(got.matched[0].slug, "php");
    }

    #[test]
    fn matching_is_case_insensitive() {
        let got = recognise(&slugs(&["WordPress"]), &slugs(&["WORDPRESS"]));
        assert_eq!(got.matched.len(), 1);
        assert_eq!(got.matched[0].slug, "wordpress");
    }

    #[test]
    fn several_technologies_each_resolve() {
        let got = recognise(
            &slugs(&["Angular", "Express", "PHP"]),
            &slugs(&["angular", "express", "wordpress"]),
        );
        let matched: Vec<&str> = got.matched.iter().map(|m| m.slug.as_str()).collect();
        assert_eq!(matched, vec!["angular", "express"]);
        assert_eq!(got.gaps, vec!["php".to_string()]);
    }

    #[test]
    fn a_repeated_technology_is_reported_once() {
        let got = recognise(&slugs(&["Angular", "Angular 15"]), &slugs(&["angular"]));
        assert_eq!(got.matched.len(), 1);
    }

    #[test]
    fn an_unknown_technology_is_a_gap_not_a_match() {
        let got = recognise(&slugs(&["Svelte"]), &slugs(&["angular"]));
        assert!(got.matched.is_empty());
        assert_eq!(got.gaps, vec!["svelte".to_string()]);
    }
}
