//! Reports: human-readable and machine-readable output.

use crate::audit::{StalenessReport, Verdicted};
use crate::VERSION;
use serde::Serialize;

/// A removal candidate as rendered.
#[derive(Debug, Clone, Serialize)]
pub struct Candidate {
    /// Repository.
    pub repo: String,
    /// Flag name.
    pub name: String,
    /// Lifecycle category.
    pub kind: String,
    /// Accountable party.
    pub owner: String,
    /// External issue reference.
    pub ticket: String,
    /// Days since creation.
    pub age_days: u64,
    /// Evidence that fired.
    pub signals: Vec<String>,
    /// Code references, when the source provided them.
    pub code_refs: Vec<String>,
}

impl Candidate {
    fn from(v: &Verdicted) -> Self {
        Self {
            repo: v.record.repo.clone(),
            name: v.record.name.clone(),
            kind: v.record.kind.clone(),
            owner: v.record.owner.clone(),
            ticket: v.record.ticket.clone(),
            age_days: v.record.age.as_secs() / 86_400,
            signals: v.signals.clone(),
            code_refs: v.record.code_refs.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonReport<'a> {
    tool: &'static str,
    version: &'static str,
    source: &'a str,
    summary: std::collections::BTreeMap<&'static str, usize>,
    total: usize,
    removal_candidates: Vec<Candidate>,
    aging: Vec<Candidate>,
}

/// Renders the report as JSON for CI consumption.
#[must_use]
pub fn render_json(report: &StalenessReport) -> String {
    let json = JsonReport {
        tool: "flaglab",
        version: VERSION,
        source: &report.source,
        summary: report.summary(),
        total: report.verdicts.len(),
        removal_candidates: report.candidates().iter().map(|v| Candidate::from(v)).collect(),
        aging: report.aging().iter().map(|v| Candidate::from(v)).collect(),
    };
    serde_json::to_string_pretty(&json).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

/// Renders the report as Markdown, for a PR comment or an issue body.
///
/// The evidence column is mandatory: a removal candidate without its
/// signals is just a suggestion, and suggestions do not get reviewed.
#[must_use]
pub fn render_markdown(report: &StalenessReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "## flaglab {} — flag staleness audit\n\nSource: `{}`\n\n",
        VERSION, report.source
    ));

    let summary = report.summary();
    out.push_str("| verdict | count |\n| --- | --- |\n");
    for (k, v) in &summary {
        out.push_str(&format!("| {k} | {v} |\n"));
    }

    let candidates = report.candidates();
    out.push_str(&format!(
        "\n### Removal candidates ({})\n\n",
        candidates.len()
    ));
    if candidates.is_empty() {
        out.push_str("None. Nothing to clean up.\n");
    } else {
        out.push_str("| repo | flag | kind | owner | age (days) | evidence |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for c in candidates.iter().map(|v| Candidate::from(v)) {
            out.push_str(&format!(
                "| {} | `{}` | {} | {} | {} | {} |\n",
                c.repo,
                c.name,
                c.kind,
                if c.owner.is_empty() { "-" } else { &c.owner },
                c.age_days,
                c.signals.join(", ")
            ));
            for r in &c.code_refs {
                out.push_str(&format!("| | ↳ `{r}` | | | | |\n"));
            }
        }
        out.push_str(
            "\nThese are candidates, not instructions. Remove the flag from code, deploy, \
             then archive the flag — the order matters, because a flag deleted before its \
             callers are removed breaks evaluation for everyone still rolling it out.\n",
        );
    }

    let aging = report.aging();
    if !aging.is_empty() {
        out.push_str(&format!("\n### Aging ({})\n\n", aging.len()));
        out.push_str("| repo | flag | age (days) |\n| --- | --- | --- |\n");
        for c in aging.iter().map(|v| Candidate::from(v)) {
            out.push_str(&format!("| {} | `{}` | {} |\n", c.repo, c.name, c.age_days));
        }
        out.push_str("\nPast the halfway point of their deadline. Review before they become candidates.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::audit::{FlagRecord, Verdicted};
    use flag_kit::{FlagKind, Staleness};
    use std::time::Duration;

    fn v(name: &str, kind: FlagKind, age_days: u64, staleness: Staleness, sigs: &[&str]) -> Verdicted {
        Verdicted {
            record: FlagRecord {
                repo: "app".into(),
                name: name.into(),
                kind: kind.as_str().into(),
                owner: "team".into(),
                ticket: String::new(),
                enabled: true,
                percentage: 100,
                age: Duration::from_secs(age_days * 86_400),
                last_changed: Some(Duration::from_secs(age_days * 86_400)),
                last_evaluated: Some(Duration::from_secs(86_400)),
                evaluation_tracked: true,
                code_refs: vec!["src/main.rs:42".into()],
            },
            staleness,
            signals: sigs.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    fn report() -> StalenessReport {
        StalenessReport {
            source: "civitforge".into(),
            verdicts: vec![
                v("old_flag", FlagKind::Release, 400, Staleness::Stale, &["aged_past_deadline"]),
                v("halfway", FlagKind::Release, 16, Staleness::Aging, &[]),
                v("perm", FlagKind::Permission, 5000, Staleness::Permanent, &[]),
            ],
        }
    }

    #[test]
    fn markdown_always_shows_evidence() {
        let md = render_markdown(&report());
        assert!(md.contains("aged_past_deadline"), "evidence column required");
        assert!(md.contains("src/main.rs:42"), "code refs must be surfaced");
        assert!(md.contains("| permanent | 1 |"));
        assert!(!md.contains("`perm`"), "permanent flags are not candidates");
    }

    #[test]
    fn markdown_says_so_when_clean() {
        let report = StalenessReport {
            source: "s".into(),
            verdicts: vec![v("a", FlagKind::Release, 1, Staleness::Fresh, &[])],
        };
        assert!(render_markdown(&report).contains("Nothing to clean up"));
    }

    #[test]
    fn json_carries_counts_and_candidates() {
        let built = report();
        let json: serde_json::Value = serde_json::from_str(&render_json(&built)).unwrap();
        assert_eq!(json["total"], 3);
        assert_eq!(json["removal_candidates"].as_array().unwrap().len(), 1);
        assert_eq!(json["aging"].as_array().unwrap().len(), 1);
        assert_eq!(json["summary"]["permanent"], 1);
        assert_eq!(json["tool"], "flaglab");
    }

    #[test]
    fn removal_ordering_is_preserved_in_output() {
        let ordered = StalenessReport {
            source: "s".into(),
            verdicts: vec![
                v("older_single", FlagKind::Release, 400, Staleness::Stale, &["aged_past_deadline"]),
                v(
                    "younger_double",
                    FlagKind::Release,
                    60,
                    Staleness::Stale,
                    &["aged_past_deadline", "fully_rolled_out"],
                ),
            ],
        };
        let json: serde_json::Value = serde_json::from_str(&render_json(&ordered)).unwrap();
        let first = &json["removal_candidates"][0]["name"];
        assert_eq!(first, "younger_double");
    }
}