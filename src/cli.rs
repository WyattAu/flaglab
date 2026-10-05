//! Command-line interface.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::audit::{FlaglabError, Lab};
use crate::discovery::Discovery;
use crate::report::{render_json, render_markdown};
use crate::source::JsonlSource;
use crate::VERSION;

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Markdown for humans and PR comments.
    Markdown,
    /// JSON for CI.
    Json,
}

/// Parsed arguments.
#[derive(Debug, Clone)]
pub struct Args {
    /// Flag records as JSONL, from a file or stdin.
    pub input: Option<PathBuf>,
    /// Repositories to scan for code references.
    pub scan: Vec<PathBuf>,
    /// Output format.
    pub format: Format,
    /// Use age-only policy, for sources without rollout metadata.
    pub age_only: bool,
    /// Exit non-zero when any removal candidate exists, for CI gating.
    pub fail_on_candidates: bool,
    /// Print help.
    pub help: bool,
    /// Print version.
    pub version: bool,
}

impl Default for Args {
    fn default() -> Self {
        Self {
            input: None,
            scan: Vec::new(),
            format: Format::Markdown,
            age_only: false,
            fail_on_candidates: false,
            help: false,
            version: false,
        }
    }
}

const USAGE: &str = "\
flaglab — audit feature flags and emit reviewable removal candidates

USAGE:
    flaglab [OPTIONS] [--input <FILE>] [--scan <DIR>...]

OPTIONS:
    -i, --input <FILE>     Flag records as JSONL ('-' for stdin)
    -s, --scan <DIR>       Scan a repository for flag code references
        --json             Emit JSON instead of Markdown
        --age-only         Use age-only policy (no rollout signals)
        --fail-on-stale    Exit 2 when removal candidates exist (CI gate)
    -h, --help             Print this help
    -V, --version          Print version

EXAMPLES:
    # Audit a CivitForge export
    flaglab -i flags.jsonl

    # Gate CI on cleanup debt
    flaglab -i flags.jsonl --json --fail-on-stale

    # Find flags referenced in code but missing from the flag system
    flaglab -s ./crates --scan ./apps
";

/// Parses arguments, ignoring the program name.
///
/// # Errors
/// Returns a message for an unknown flag or a missing option value.
pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Args, String> {
    let mut out = Args::default();
    let mut it = args.into_iter().peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => out.help = true,
            "-V" | "--version" => out.version = true,
            "--json" => out.format = Format::Json,
            "--age-only" => out.age_only = true,
            "--fail-on-stale" => out.fail_on_candidates = true,
            "-i" | "--input" => {
                out.input = Some(PathBuf::from(
                    it.next().ok_or("--input requires a FILE")?,
                ))
            }
            "-s" | "--scan" => out.scan.push(PathBuf::from(
                it.next().ok_or("--scan requires a DIR")?,
            )),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(out)
}

fn read_input(path: &Option<PathBuf>) -> Result<String, FlaglabError> {
    match path {
        None => Ok(String::new()),
        Some(p) if p.as_os_str() == "-" => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| FlaglabError::Source(format!("stdin: {e}")))?;
            Ok(s)
        }
        Some(p) => std::fs::read_to_string(p)
            .map_err(|e| FlaglabError::Source(format!("{}: {e}", p.display()))),
    }
}

/// Runs the CLI and returns a process exit code.
///
/// Exit codes are meaningful for CI: `0` clean, `1` failure, `2` candidates
/// found with `--fail-on-stale`.
pub fn run(args: Args) -> ExitCode {
    if args.help {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    if args.version {
        println!("flaglab {VERSION}");
        return ExitCode::SUCCESS;
    }

    let body = match read_input(&args.input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("flaglab: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut lab = if args.age_only {
        Lab::age_only()
    } else {
        Lab::new()
    };
    lab = lab.with_source(Box::new(JsonlSource::new(
        args.input
            .as_ref()
            .map_or_else(|| "<none>".into(), |p| p.display().to_string()),
        body,
    )));

    // Code references are merged in so the report can show where a flag is
    // used, and so a code-only flag appears at all (as fresh, never stale).
    for dir in &args.scan {
        let repo = dir
            .file_name()
            .map_or_else(|| dir.display().to_string(), |n| n.to_string_lossy().to_string());
        let discovery = Discovery::new();
        match discovery.scan(&repo, dir) {
            Ok(scan) => {
                let records = discovery.to_records(&scan);
                if !records.is_empty() {
                    lab = lab.with_source(Box::new(JsonlSource::from_records(&records)));
                }
            }
            Err(e) => {
                eprintln!("flaglab: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let source_name = args
        .input
        .as_ref()
        .map_or_else(|| "<scan>".into(), |p| p.display().to_string());
    let report = match lab.report(&source_name) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("flaglab: {e}");
            return ExitCode::FAILURE;
        }
    };

    print!(
        "{}",
        match args.format {
            Format::Json => render_json(&report),
            Format::Markdown => render_markdown(&report),
        }
    );

    if args.fail_on_candidates && !report.candidates().is_empty() {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parses_flags_and_options() {
        let a = parse(v(&["-i", "f.jsonl", "--json", "--fail-on-stale", "-s", "repo"])).unwrap();
        assert_eq!(a.input, Some(PathBuf::from("f.jsonl")));
        assert_eq!(a.format, Format::Json);
        assert!(a.fail_on_candidates);
        assert_eq!(a.scan, vec![PathBuf::from("repo")]);
    }

    #[test]
    fn multiple_scan_dirs_accumulate() {
        let a = parse(v(&["-s", "a", "-s", "b"])).unwrap();
        assert_eq!(a.scan.len(), 2);
    }

    #[test]
    fn rejects_unknown_and_incomplete_flags() {
        assert!(parse(v(&["--nope"])).is_err());
        assert!(parse(v(&["--input"])).is_err());
        assert!(parse(v(&["--scan"])).is_err());
    }

    #[test]
    fn defaults_are_conservative() {
        let a = parse(Vec::new()).unwrap();
        assert_eq!(a.format, Format::Markdown);
        assert!(!a.fail_on_candidates, "must not gate CI unless asked");
        assert!(!a.age_only);
    }
}