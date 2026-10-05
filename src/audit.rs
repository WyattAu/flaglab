//! Records and the staleness verdict.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use flag_kit::{FlagFacts, FlagKind, FlagPolicy, Staleness};

/// Errors this crate can produce.
#[derive(Debug)]
pub enum FlaglabError {
    /// A flag record could not be parsed.
    Parse {
        /// Source that produced the record.
        source: String,
        /// Underlying message.
        message: String,
    },
    /// The flag system could not be read.
    Source(String),
    /// Filesystem or VCS failure while walking repositories.
    Discovery(String),
}

impl fmt::Display for FlaglabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse { source, message } => write!(f, "parse error in {source}: {message}"),
            Self::Source(m) => write!(f, "flag source error: {m}"),
            Self::Discovery(m) => write!(f, "discovery error: {m}"),
        }
    }
}

impl std::error::Error for FlaglabError {}

/// One flag as the audit sees it.
///
/// Deliberately not a flag-kit `Flag`: the kit's shape has no room for
/// owner, ticket, or evaluation evidence, all of which decide staleness.
/// The verdict is computed by the kit; the evidence comes from here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagRecord {
    /// Repository the flag was found in.
    pub repo: String,
    /// Flag name.
    pub name: String,
    /// Lifecycle category; unknown names fall back to `Release`.
    pub kind: String,
    /// Accountable party.
    pub owner: String,
    /// External issue reference.
    pub ticket: String,
    /// Global on/off.
    pub enabled: bool,
    /// Rollout percentage `0..=100`.
    pub percentage: u8,
    /// Age since creation.
    pub age: Duration,
    /// Age since the last change, when known.
    pub last_changed: Option<Duration>,
    /// Age since the last evaluation, when ever evaluated.
    pub last_evaluated: Option<Duration>,
    /// Files and line numbers referencing this flag, when known.
    pub code_refs: Vec<String>,
}

impl FlagRecord {
    /// Parsed lifecycle kind, defaulting to `Release` for legacy records.
    ///
    /// Defaulting rather than failing keeps an old export usable; the
    /// conservative outcome is a short deadline, not a silent exemption.
    #[must_use]
    pub fn flag_kind(&self) -> FlagKind {
        FlagKind::parse(&self.kind).unwrap_or_default()
    }

    fn facts(&self) -> FlagFacts {
        FlagFacts {
            kind: self.flag_kind(),
            age_days: self.age.as_secs() / 86_400,
            last_changed_age_days: self.last_changed.map(|d| (d.as_secs() / 86_400) as u32),
            percentage: self.percentage,
            last_evaluated_age_days: self
                .last_evaluated
                .map(|d| (d.as_secs() / 86_400) as u32),
        }
    }
}

/// One flag plus the verdict and its evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdicted {
    /// The record as found.
    pub record: FlagRecord,
    /// The verdict.
    pub staleness: Staleness,
    /// Individual signals, so the report can explain itself.
    pub signals: Vec<String>,
}

impl Verdicted {
    /// Whether this is a removal candidate.
    #[must_use]
    pub fn is_removal_candidate(&self) -> bool {
        self.staleness.is_stale()
    }
}

/// The audit result for one flag system.
#[derive(Debug, Clone, Default)]
pub struct StalenessReport {
    /// Where the records came from.
    pub source: String,
    /// Every flag with its verdict.
    pub verdicts: Vec<Verdicted>,
}

impl StalenessReport {
    /// Removal candidates, worst evidence first.
    ///
    /// "Worst" means most signals then oldest: a flag that is both past its
    /// deadline *and* fully rolled out is a safer removal than one that is
    /// only past its deadline.
    #[must_use]
    pub fn candidates(&self) -> Vec<&Verdicted> {
        let mut out: Vec<&Verdicted> = self.verdicts.iter().filter(|v| v.is_removal_candidate()).collect();
        out.sort_by(|a, b| {
            b.signals
                .len()
                .cmp(&a.signals.len())
                .then(b.record.age.cmp(&a.record.age))
                .then(a.record.name.cmp(&b.record.name))
        });
        out
    }

    /// Counts per verdict, for the summary line.
    #[must_use]
    pub fn summary(&self) -> BTreeMap<&'static str, usize> {
        let mut m: BTreeMap<&'static str, usize> = BTreeMap::new();
        for v in &self.verdicts {
            *m.entry(v.staleness.as_str()).or_insert(0) += 1;
        }
        m
    }

    /// Flags that are aging: worth reviewing before they become candidates.
    #[must_use]
    pub fn aging(&self) -> Vec<&Verdicted> {
        self.verdicts
            .iter()
            .filter(|v| v.staleness == Staleness::Aging)
            .collect()
    }
}

/// A run over one or more flag systems.
#[derive(Debug, Default)]
pub struct Lab {
    policy: FlagPolicy,
    sources: Vec<Box<dyn crate::source::FlagSource>>,
}

impl Lab {
    /// A lab with the kit's default policy and no sources.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: FlagPolicy::default(),
            sources: Vec::new(),
        }
    }

    /// A lab using age-only policy, for flag sets without rollout metadata.
    #[must_use]
    pub fn age_only() -> Self {
        Self {
            policy: FlagPolicy::age_only(),
            sources: Vec::new(),
        }
    }

    /// Replaces the policy.
    #[must_use]
    pub fn with_policy(mut self, policy: FlagPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Adds a flag source.
    #[must_use]
    pub fn with_source(mut self, source: Box<dyn crate::source::FlagSource>) -> Self {
        self.sources.push(source);
        self
    }

    /// Audits every registered source and concatenates the verdicts.
    ///
    /// # Errors
    /// Returns the first source failure; partial audits are not reported as
    /// complete, because a half-audited estate looks exactly like a clean
    /// one in the summary counts.
    pub fn audit(&self) -> Result<Vec<Verdicted>, FlaglabError> {
        let mut out = Vec::new();
        for source in &self.sources {
            let records = source.load().map_err(FlaglabError::Source)?;
            for record in records {
                let c = self.policy.classify(record.facts());
                out.push(Verdicted {
                    signals: c.signals.iter().map(|s| s.as_str().to_string()).collect(),
                    staleness: c.staleness,
                    record,
                });
            }
        }
        out.sort_by(|a, b| a.record.repo.cmp(&b.record.repo).then(a.record.name.cmp(&b.record.name)));
        Ok(out)
    }

    /// Audits and wraps the result.
    ///
    /// # Errors
    /// Propagates [`Lab::audit`] failures.
    pub fn report(&self, source_name: &str) -> Result<StalenessReport, FlaglabError> {
        Ok(StalenessReport {
            source: source_name.to_string(),
            verdicts: self.audit()?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn record(name: &str, kind: FlagKind, age_days: u64, percentage: u8) -> FlagRecord {
        FlagRecord {
            repo: "app".into(),
            name: name.into(),
            kind: kind.as_str().into(),
            owner: "team".into(),
            ticket: "T-1".into(),
            enabled: true,
            percentage,
            age: Duration::from_secs(age_days * 86_400),
            last_changed: Some(Duration::from_secs(age_days * 86_400)),
            last_evaluated: Some(Duration::from_secs(86_400)),
            code_refs: Vec::new(),
        }
    }

    #[test]
    fn unknown_kind_defaults_to_release_not_exemption() {
        let mut r = record("mystery_flag", FlagKind::Release, 400, 10);
        r.kind = "who_knows".into();
        assert_eq!(r.flag_kind(), FlagKind::Release);
        let c = FlagPolicy::default().classify(r.facts());
        assert_eq!(c.staleness, Staleness::Stale);
    }

    #[test]
    fn permission_gates_are_never_candidates() {
        let r = record("perm_gate", FlagKind::Permission, 3650, 100);
        let c = FlagPolicy::default().classify(r.facts());
        assert_eq!(c.staleness, Staleness::Permanent);
        assert!(!c.is_stale());
    }

    #[test]
    fn fully_rolled_out_beats_age_in_candidate_ordering() {
        let lab = Lab::new();
        let verdicts = vec![
            Verdicted {
                // older, but only one signal
                record: record("old_partial", FlagKind::Release, 400, 50),
                staleness: Staleness::Stale,
                signals: vec!["aged_past_deadline".into()],
            },
            Verdicted {
                // younger, but two independent signals
                record: record("done_full", FlagKind::Release, 60, 100),
                staleness: Staleness::Stale,
                signals: vec!["aged_past_deadline".into(), "fully_rolled_out".into()],
            },
        ];
        let report = StalenessReport {
            source: "t".into(),
            verdicts,
        };
        let names: Vec<&str> = report
            .candidates()
            .iter()
            .map(|v| v.record.name.as_str())
            .collect();
        assert_eq!(names, vec!["done_full", "old_partial"]);
        let _ = lab;
    }

    #[test]
    fn summary_counts_every_verdict() {
        let report = StalenessReport {
            source: "t".into(),
            verdicts: vec![
                Verdicted {
                    record: record("a", FlagKind::Release, 1, 10),
                    staleness: Staleness::Fresh,
                    signals: vec![],
                },
                Verdicted {
                    record: record("b", FlagKind::Permission, 9000, 0),
                    staleness: Staleness::Permanent,
                    signals: vec![],
                },
                Verdicted {
                    record: record("c", FlagKind::Release, 40, 100),
                    staleness: Staleness::Stale,
                    signals: vec!["fully_rolled_out".into()],
                },
            ],
        };
        let s = report.summary();
        assert_eq!(s.get("fresh"), Some(&1));
        assert_eq!(s.get("permanent"), Some(&1));
        assert_eq!(s.get("stale"), Some(&1));
    }

    #[test]
    fn aging_is_reported_before_removal() {
        let report = StalenessReport {
            source: "t".into(),
            verdicts: vec![Verdicted {
                record: record("halfway", FlagKind::Release, 16, 10),
                staleness: Staleness::Aging,
                signals: vec![],
            }],
        };
        assert_eq!(report.aging().len(), 1);
        assert!(report.candidates().is_empty());
    }
}