//! Flag sources: where flag records come from.

use crate::audit::{FlagRecord, FlaglabError};

/// A source of flag records.
///
/// Object-safe so a caller can mix a CivitForge export with local files in
/// one [`crate::audit::Lab`] without generics leaking into the CLI.
pub trait FlagSource {
    /// Human-readable name, used in reports and errors.
    fn name(&self) -> &str;

    /// Loads every record this source knows about.
    ///
    /// # Errors
    /// Returns [`FlaglabError`] when the underlying system is unreachable or
    /// malformed. Implementations must not return partial results.
    fn load(&self) -> Result<Vec<FlagRecord>, FlaglabError>;
}

/// Reads newline-delimited JSON records, as emitted by
/// `GET /api/v1/admin/feature-flags/stale` or `flaglab export`.
///
/// JSONL rather than a JSON array so a large estate can be streamed and a
/// truncated export still yields the records that were written.
#[derive(Debug, Clone)]
pub struct JsonlSource {
    name: String,
    body: String,
}

impl JsonlSource {
    /// Wraps an in-memory JSONL document.
    #[must_use]
    pub fn new(name: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            body: body.into(),
        }
    }
}

impl JsonlSource {
    /// Builds a source from in-memory records.
    ///
    /// Used to fold code-discovered references into an audit without a
    /// serialization round trip through a temp file.
    #[must_use]
    pub fn from_records(records: &[FlagRecord]) -> Self {
        let mut body = String::new();
        for r in records {
            let line = serde_json::json!({
                "repo": r.repo,
                "name": r.name,
                "kind": r.kind,
                "owner": r.owner,
                "ticket": r.ticket,
                "enabled": r.enabled,
                "percentage": r.percentage,
                "age_days": r.age.as_secs() / 86_400,
                "last_changed_age_days": r.last_changed.map(|d| d.as_secs() / 86_400),
                "last_evaluated_age_days": r.last_evaluated.map(|d| d.as_secs() / 86_400),
                "evaluation_tracked": r.evaluation_tracked,
                "code_refs": r.code_refs,
            });
            body.push_str(&line.to_string());
            body.push('\n');
        }
        Self::new("records", body)
    }
}

/// The on-disk shape of one JSONL record.
///
/// Ages arrive as day counts because that is what the policy consumes, and
/// because "31 days" survives a JSON round trip in a way that
/// `"31 days ago"` does not.
#[derive(Debug, serde::Deserialize)]
struct Record {
    repo: String,
    name: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    ticket: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    percentage: i64,
    #[serde(default)]
    age_days: i64,
    #[serde(default)]
    last_changed_age_days: Option<i64>,
    #[serde(default)]
    last_evaluated_age_days: Option<i64>,
    /// Absent in older exports, where every record came from a flag system
    /// and therefore had telemetry.
    #[serde(default = "default_tracked")]
    evaluation_tracked: bool,
    #[serde(default)]
    code_refs: Vec<String>,
}

fn default_tracked() -> bool {
    true
}

impl FlagSource for JsonlSource {
    fn name(&self) -> &str {
        &self.name
    }

    fn load(&self) -> Result<Vec<FlagRecord>, FlaglabError> {
        let mut out = Vec::new();
        for (idx, line) in self.body.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let r: Record = serde_json::from_str(line).map_err(|e| FlaglabError::Parse {
                source: format!("{}:{}", self.name, idx + 1),
                message: e.to_string(),
            })?;
            out.push(FlagRecord {
                repo: r.repo,
                name: r.name,
                kind: r.kind,
                owner: r.owner,
                ticket: r.ticket,
                enabled: r.enabled,
                percentage: r.percentage.clamp(0, 100) as u8,
                age: std::time::Duration::from_secs((r.age_days.max(0) as u64) * 86_400),
                last_changed: r
                    .last_changed_age_days
                    .map(|d| std::time::Duration::from_secs((d.max(0) as u64) * 86_400)),
                last_evaluated: r
                    .last_evaluated_age_days
                    .map(|d| std::time::Duration::from_secs((d.max(0) as u64) * 86_400)),
                evaluation_tracked: r.evaluation_tracked,
                code_refs: r.code_refs,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const SAMPLE: &str = r#"{"repo":"app","name":"a_flag","kind":"release","owner":"team","enabled":true,"percentage":100,"age_days":40,"last_changed_age_days":35,"last_evaluated_age_days":1}
# a comment line

{"repo":"app","name":"b_flag","kind":"permission","percentage":0,"age_days":9000}
"#;

    #[test]
    fn parses_records_and_skips_blanks_and_comments() {
        let src = JsonlSource::new("test", SAMPLE);
        let recs = src.load().unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].name, "a_flag");
        assert_eq!(recs[1].kind, "permission");
    }

    #[test]
    fn percentage_is_clamped_on_read() {
        let src = JsonlSource::new(
            "test",
            r#"{"repo":"a","name":"x","percentage":900,"age_days":1}"#,
        );
        assert_eq!(src.load().unwrap()[0].percentage, 100);
    }

    #[test]
    fn negative_ages_do_not_wrap() {
        let src = JsonlSource::new("test", r#"{"repo":"a","name":"x","age_days":-5}"#);
        let r = &src.load().unwrap()[0];
        assert_eq!(r.age.as_secs(), 0);
        assert!(r.last_changed.is_none());
    }

    #[test]
    fn malformed_line_names_the_line() {
        let src = JsonlSource::new(
            "feed",
            "{\"repo\":\"a\",\"name\":\"ok\"}\nthis is not json",
        );
        let err = src.load().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("feed:2"), "error must locate the line: {msg}");
    }
}