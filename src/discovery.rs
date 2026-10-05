//! Repository discovery: find flags in code and VCS history.
//!
//! Code references are the other half of the problem. Datadog's guidance is
//! blunt that surfacing a stale flag is only half the job: "removing a flag
//! safely still means finding every reference to it in your codebase". A
//! tool that reports staleness without references produces work someone has
//! to redo by hand.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::audit::{FlagRecord, FlaglabError};

/// Flag patterns recognised in source.
///
/// Deliberately a fixed table rather than a regex engine: a false positive
/// costs a human a look, but a runtime dependency for matching `if
/// enabled(` would cost every consumer a dependency. `regex` is available
/// through the estate's `validkit/regex` feature when a kit needs more.
const FLAG_PATTERNS: &[(&str, &str)] = &[
    ("flag_kit::FlagName::new(", "flag-kit"),
    ("FlagName::new(", "flag-kit"),
    ("flags.is_enabled(", "generic"),
    ("feature_flag(", "generic"),
    ("is_feature_enabled(", "generic"),
];

/// Directories never scanned: generated or vendored trees full of copies
/// of the source we actually care about.
const SKIP_DIRS: &[&str] = &["target", "node_modules", "dist", "build", "vendor", "coverage"];

/// One flag found in a repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// Repository name.
    pub repo: String,
    /// Flag name.
    pub name: String,
    /// `path:line` references.
    pub references: Vec<String>,
}

impl Discovered {
    /// How many distinct sites reference this flag.
    #[must_use]
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }
}

/// Scans a directory tree for flag references.
///
/// `max_depth` bounds the walk: monorepos contain `target/` and vendored
/// trees that would otherwise dominate the scan without adding evidence.
#[derive(Debug, Clone)]
pub struct Discovery {
    max_depth: usize,
    include_hidden: bool,
}

impl Default for Discovery {
    fn default() -> Self {
        Self {
            max_depth: 8,
            include_hidden: false,
        }
    }
}

/// Result of scanning a repository.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Flags found, sorted by name.
    pub flags: Vec<Discovered>,
    /// Files read.
    pub files_scanned: usize,
}

impl ScanResult {
    /// The flag with the most call sites, which is usually the most
    /// expensive removal and therefore the one to schedule first.
    #[must_use]
    pub fn most_referenced(&self) -> Option<&Discovered> {
        self.flags.iter().max_by_key(|d| d.reference_count())
    }
}

impl Discovery {
    /// A scanner with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the walk depth limit.
    #[must_use]
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Includes dot-directories such as `.github`.
    #[must_use]
    pub fn with_hidden(mut self, include: bool) -> Self {
        self.include_hidden = include;
        self
    }

    /// Walks `root`, returning flags and how many files were read.
    ///
    /// # Errors
    /// Returns [`FlaglabError::Discovery`] when the root is unreadable.
    pub fn scan(&self, repo: &str, root: &Path) -> Result<ScanResult, FlaglabError> {
        if !root.is_dir() {
            return Err(FlaglabError::Discovery(format!(
                "{} is not a directory",
                root.display()
            )));
        }
        let mut found: Vec<Discovered> = Vec::new();
        let mut files = 0usize;
        self.walk(repo, root, 0, &mut found, &mut files)?;
        found.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ScanResult {
            flags: found,
            files_scanned: files,
        })
    }

    fn walk(
        &self,
        repo: &str,
        dir: &Path,
        depth: usize,
        found: &mut Vec<Discovered>,
        files: &mut usize,
    ) -> Result<(), FlaglabError> {
        if depth > self.max_depth {
            return Ok(());
        }
        let entries = std::fs::read_dir(dir)
            .map_err(|e| FlaglabError::Discovery(format!("{}: {e}", dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|e| FlaglabError::Discovery(e.to_string()))?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') && !self.include_hidden {
                continue;
            }
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            if path.is_dir() {
                self.walk(repo, &path, depth + 1, found, files)?;
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            if !matches!(ext.as_str(), "rs" | "toml" | "ts" | "tsx" | "js" | "json") {
                continue;
            }
            *files += 1;
            let body = match std::fs::read_to_string(&path) {
                Ok(b) => b,
                // A binary or permission-denied file is not an audit failure.
                Err(_) => continue,
            };
            self.inspect(repo, &path, &body, found);
        }
        Ok(())
    }

    fn inspect(&self, repo: &str, path: &Path, body: &str, found: &mut Vec<Discovered>) {
        for (idx, line) in body.lines().enumerate() {
            for (pattern, _) in FLAG_PATTERNS {
                let Some(start) = line.find(pattern) else {
                    continue;
                };
                let rest = &line[start + pattern.len()..];
                let Some(name) = extract_quoted(rest) else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                let reference = format!("{}:{}", path.display(), idx + 1);
                match found.iter_mut().find(|d| d.name == name) {
                    Some(existing) => existing.references.push(reference),
                    None => found.push(Discovered {
                        repo: repo.to_string(),
                        name,
                        references: vec![reference],
                    }),
                }
                // One reference per line: a line that mentions the same flag
                // twice is still one edit site.
                break;
            }
        }
    }

    /// Converts discovered references into flag records with zero ages.
    ///
    /// Zero ages mean "age unknown", which the policy treats as fresh rather
    /// than stale: code references prove a flag exists, never that it is
    /// finished. A code-only audit can therefore find *phantom* flags
    /// (referenced in code, unknown to the flag system) but must not claim
    /// anything is stale.
    #[must_use]
    pub fn to_records(&self, scan: &ScanResult) -> Vec<FlagRecord> {
        scan.flags
            .iter()
            .map(|d| FlagRecord {
                repo: d.repo.clone(),
                name: d.name.clone(),
                kind: String::new(),
                owner: String::new(),
                ticket: String::new(),
                enabled: true,
                percentage: 0,
                age: Duration::ZERO,
                last_changed: None,
                last_evaluated: None,
                // A code scan sees references, not evaluations.
                evaluation_tracked: false,
                code_refs: d.references.clone(),
            })
            .collect()
    }
}

/// Extracts the string literal that must begin `s`.
///
/// The patterns end at the opening parenthesis, so the opening quote is the
/// very next byte: skipping to the first quote anywhere would find the
/// *closing* quote and read past the end of the name.
fn extract_quoted(s: &str) -> Option<String> {
    let rest = s.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Convenience: scan a path and return records.
#[must_use]
pub fn discover(repo: &str, root: &Path) -> Vec<FlagRecord> {
    match Discovery::new().scan(repo, root) {
        Ok(scan) => Discovery::new().to_records(&scan),
        // An unreadable root yields no records; the caller auditing a known
        // flag list still wants its output.
        Err(_) => Vec::new(),
    }
}

/// Default scan depth, exposed for callers that want to log it.
pub const DEFAULT_MAX_DEPTH: usize = 8;

/// Placeholder path helper so callers can build a root without importing
/// `PathBuf` themselves.
#[must_use]
pub fn root_of(path: impl Into<PathBuf>) -> PathBuf {
    path.into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::fs;

    /// Unique per call: tests share one process, so a PID-keyed directory
    /// would let parallel tests delete each other's fixtures.
    fn tmp() -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!(
            "flaglab-disc-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn finds_flag_references_with_line_numbers() {
        let d = tmp();
        fs::write(
            d.join("main.rs"),
            "let a = FlagName::new(\"my_flag\").unwrap();\nlet b = flag_kit::FlagName::new(\"my_flag\").unwrap();\n",
        )
        .unwrap();
        let scan = Discovery::new().scan("app", &d).unwrap();
        assert_eq!(scan.flags.len(), 1);
        assert_eq!(scan.flags[0].name, "my_flag");
        assert_eq!(scan.flags[0].reference_count(), 2);
        assert!(scan.flags[0].references[0].ends_with("main.rs:1"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn one_line_mentioning_a_flag_is_one_reference() {
        let d = tmp();
        fs::write(d.join("a.rs"), "check(FlagName::new(\"x\"), FlagName::new(\"x\"))\n").unwrap();
        let scan = Discovery::new().scan("app", &d).unwrap();
        assert_eq!(scan.flags[0].reference_count(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn skips_hidden_and_build_directories() {
        let d = tmp();
        fs::create_dir_all(d.join(".git")).unwrap();
        fs::create_dir_all(d.join("target")).unwrap();
        fs::write(d.join(".git/cfg.rs"), "FlagName::new(\"hidden_flag\")\n").unwrap();
        fs::write(d.join("target/gen.rs"), "FlagName::new(\"gen_flag\")\n").unwrap();
        fs::write(d.join("ok.rs"), "FlagName::new(\"real_flag\")\n").unwrap();
        let scan = Discovery::new().scan("app", &d).unwrap();
        let names: Vec<&str> = scan.flags.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["real_flag"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn most_referenced_surfaces_the_costliest_removal() {
        let d = tmp();
        fs::write(
            d.join("a.rs"),
            "FlagName::new(\"one_flag\")\nFlagName::new(\"two_flag\")\nFlagName::new(\"two_flag\")\n",
        )
        .unwrap();
        let scan = Discovery::new().scan("app", &d).unwrap();
        assert_eq!(scan.most_referenced().unwrap().name, "two_flag");
        fs::remove_dir_all(&d).unwrap();
    }

    /// Code references prove existence, not staleness. A code-only audit
    /// must never report a removal candidate.
    #[test]
    fn code_only_records_are_never_stale() {
        let d = tmp();
        fs::write(d.join("a.rs"), "FlagName::new(\"ancient_flag\")\n").unwrap();
        let scan = Discovery::new().scan("app", &d).unwrap();
        let records = Discovery::new().to_records(&scan);
        let lab = crate::audit::Lab::new();
        let verdicts = lab
            .with_source(Box::new(crate::source::JsonlSource::from_records(&records)))
            .audit()
            .unwrap();
        assert!(verdicts.iter().all(|v| !v.is_removal_candidate()));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn missing_root_is_an_error_not_a_panic() {
        assert!(Discovery::new().scan("app", Path::new("/nonexistent/xyz")).is_err());
    }
}