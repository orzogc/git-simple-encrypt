#![warn(clippy::nursery, clippy::cargo, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::multiple_crate_versions)]

pub mod config;
pub mod crypt;
mod error;
pub mod repo;
pub mod salt_cache;
pub mod utils;

#[cfg(feature = "bin")]
mod cli;

#[cfg(feature = "bin")]
pub use crate::cli::{Cli, SetField, SubCommand};
#[cfg(feature = "bin")]
use crate::crypt::{decrypt_repo, encrypt_repo};
#[cfg(feature = "bin")]
use crate::repo::Repo;
pub use crate::{
    crypt::{BatchSummary, FileHeader},
    error::{Error, Result},
};

/// Dispatch a parsed CLI invocation.
///
/// Only available with the `bin` feature (default for the `git-se` binary).
#[cfg(feature = "bin")]
pub fn run(cli: Cli) -> Result<()> {
    if !cli.repo.is_absolute() {
        return Err(Error::RepoPathNotAbsolute(cli.repo.clone()));
    }
    let mut repo = Repo::open(&cli.repo)?;
    match cli.command {
        SubCommand::Encrypt {
            paths,
            allow_password_change,
        } => run_encrypt(&repo, &paths, allow_password_change)?,
        SubCommand::Decrypt { paths } => {
            let password = crate::utils::get_password("Please input your key: ")?;
            decrypt_repo(
                &repo,
                &paths,
                crate::crypt::Password::new(password.as_bytes()),
            )?;
        }
        SubCommand::Add { paths } => repo.conf.add_paths_to_crypt_list(&paths)?,
        SubCommand::Set { field } => field.set(&mut repo)?,
        SubCommand::Pwd => repo.change_password_interactive()?,
        SubCommand::Check { paths, staged } => repo.check(&paths, staged)?,
        SubCommand::Install => repo.install_hook()?,
    }
    Ok(())
}

/// Run the encrypt command: prompt for the password, verify it against
/// committed encrypted files, and handle mismatches interactively.
///
/// Non-interactive stdin never gets a menu: a mismatch surfaces as
/// [`Error::PasswordChanged`], whose message points at
/// `--allow-password-change`.
#[cfg(feature = "bin")]
fn run_encrypt(repo: &Repo, paths: &[std::path::PathBuf], allow_change: bool) -> Result<()> {
    use std::io::IsTerminal as _;

    use crate::{crypt::HeadPasswordCheck, utils::resolve_target_files};

    // Resolve early so an empty list errors before any prompt.
    let targets = resolve_target_files(paths, &repo.conf.crypt_list, repo.path())?;
    if targets.is_empty() {
        return Err(Error::NoFile("encrypt"));
    }

    let mut allow_change = allow_change;
    let mut password = crate::utils::get_password("Please input your key: ")?;
    for attempt in 1..=3 {
        if allow_change {
            break;
        }
        // Candidates come from the HEAD tree via the whole crypt list, so the
        // CLI pre-check and `encrypt_repo`'s own check can never disagree.
        match crate::crypt::verify_password_against_head(
            repo,
            crate::crypt::Password::new(password.as_bytes()),
        ) {
            HeadPasswordCheck::Match => break,
            HeadPasswordCheck::Unverifiable => {
                // No anchor: this encryption *establishes* the password, so a
                // typo would be unrecoverable — confirm it (unless it came
                // from the environment, or we cannot ask).
                if std::io::stdin().is_terminal() && !crate::utils::password_from_env() {
                    let confirm = crate::utils::prompt_password("Please confirm your key: ")?;
                    if confirm.as_str() != password.as_str() {
                        return Err(Error::PasswordMismatch);
                    }
                }
                break;
            }
            HeadPasswordCheck::Mismatch => {
                if !std::io::stdin().is_terminal() {
                    break; // encrypt_repo re-checks and returns PasswordChanged
                }
                let still_encrypted = targets
                    .iter()
                    .filter(|f| crate::utils::is_file_encrypted(f).unwrap_or(false))
                    .count();
                eprintln!(
                    "WARNING: the entered password differs from the password used for \
                     committed encrypted files."
                );
                if still_encrypted > 0 {
                    eprintln!(
                        "  {still_encrypted} target files are still encrypted with the previous \
                         password and will NOT be migrated."
                    );
                }
                eprintln!(
                    "  Continuing encrypts plaintext files with the NEW password; their \
                     ciphertext (and git history) will change."
                );
                let choice = crate::utils::prompt_line(
                    "Choose: [r]e-enter password / [n] use new password / [a]bort (default): ",
                )?;
                match choice.to_ascii_lowercase().as_str() {
                    "r" => {
                        if attempt == 3 {
                            return Err(Error::Other("too many password attempts".to_string()));
                        }
                        password = crate::utils::prompt_password("Please input your key: ")?;
                    }
                    "n" => allow_change = true,
                    _ => return Err(Error::Aborted),
                }
            }
        }
    }
    encrypt_repo(
        repo,
        paths,
        crate::crypt::Password::new(password.as_bytes()),
        allow_change,
    )
}
