use std::process::ExitCode;

use clap::Parser;
use git_simple_encrypt::{Cli, run};
use log::LevelFilter;

fn main() -> ExitCode {
    log_init();
    // Print the Display message, not the Debug dump a `Result` return from
    // `main` would produce — the variants carry carefully worded,
    // user-facing text (`Error: PathInsideGitDir("/tmp/...")` helps nobody).
    if let Err(e) = run(Cli::parse()) {
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[inline]
pub fn log_init() {
    #[cfg(not(debug_assertions))]
    log_init_with_default_level(LevelFilter::Info);
    #[cfg(debug_assertions)]
    log_init_with_default_level(LevelFilter::Debug);
}

#[inline]
pub fn log_init_with_default_level(level: LevelFilter) {
    _ = pretty_env_logger::formatted_builder()
        .filter_level(level)
        .format_timestamp_millis()
        .parse_default_env()
        .try_init();
}
