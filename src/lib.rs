//! flaglab — audit feature flags across many repositories and emit
//! reviewable removal candidates.
//!
//! # Why this exists
//!
//! Uber's Piranha removes flag-gated dead code, and it is good at it: AST
//! analysis plus partial program evaluation, taking a flag key and the
//! branch to keep. But Piranha's input is "this flag is stale", and
//! according to Uber's own write-up that input comes from a scheduled job
//! that queries the flag management system. Nobody ships that job well,
//! and the research is blunt about why: a CMU study of feature-flag
//! practice found removal of obsolete flags to be *the* unsolved problem,
//! and 80% of flag removals touch more than one file.
//!
//! So the missing piece is not the refactoring engine. It is an honest
//! staleness verdict, computed the same way in CI and in a review, over
//! every repository rather than one.
//!
//! # What this does *not* do
//!
//! It does not delete code. It produces candidates with the evidence
//! attached, because an automated refactor driven by an unverified verdict
//! is worse than no automation at all: it removes working paths and blames
//! the flag.
//!
//! # Design
//!
//! The verdict itself comes from `flag_kit::FlagPolicy` — the same code
//! CivitForge's `/api/v1/admin/feature-flags/stale` uses. One policy, two
//! consumers, so a disagreement between CI and production review is
//! impossible by construction.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod audit;
pub mod cli;
pub mod discovery;
pub mod report;
pub mod source;

pub use audit::{FlagRecord, FlaglabError, Lab, StalenessReport};
pub use discovery::{Discovered, discover};
pub use report::{Candidate, render_markdown, render_json};
pub use source::{FlagSource, JsonlSource};

/// Estate-wide library version, for provenance in reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");