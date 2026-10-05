//! `flaglab` binary entry point.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args = match flaglab::cli::parse(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("flaglab: {e}");
            eprintln!("try `flaglab --help`");
            return ExitCode::FAILURE;
        }
    };
    flaglab::cli::run(args)
}
