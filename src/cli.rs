use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use config_file2::Storable;
use log::{debug, info};

use crate::{
    error::{Error, Result},
    repo::Repo,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None, after_help = r#"Examples:
git-se add file.txt  mydir  # Add files/folders to the encryption list
git-se e                    # Encrypt all files in the list (prompts for the password)
git-se d                    # Decrypt all files in the list (prompts for the password)
git-se e xxx.txt dir1 ...   # Encrypt specific files
git-se d xxx.txt dir1 ...   # Decrypt specific files
git-se p                    # Change the master password (decrypt all, then re-encrypt)
git-se i                    # Install a pre-commit hook to check encryption before committing

The password is never stored. Set GIT_SE_PASSWORD to skip the prompt in scripts.
"#)]
pub struct Cli {
    /// Encrypt, Decrypt and Add
    #[command(subcommand)]
    pub command: SubCommand,
    /// Repository path, allow both relative and absolute path.
    #[arg(short, long, global = true)]
    #[clap(value_parser = repo_path_parser, default_value = ".")]
    pub repo: PathBuf,
}

fn repo_path_parser(path: &str) -> Result<PathBuf, String> {
    match path_absolutize::Absolutize::absolutize(Path::new(path)) {
        Ok(p) => Ok(p.into_owned()),
        Err(e) => Err(e.to_string()),
    }
}

#[derive(Subcommand, Debug)]
pub enum SubCommand {
    /// Encrypt all files in the crypt list, or only the given paths.
    #[clap(alias("e"))]
    Encrypt {
        /// The files or folders to be encrypted.
        paths: Vec<PathBuf>,
        /// Allow encrypting with a password that differs from the one used
        /// for the committed encrypted files. Every encrypted file in the
        /// crypt list must still authenticate under the given password, so
        /// this cannot create a mixed-password repository (use `git-se p` to
        /// migrate). Without this flag, a mismatch is an error when
        /// non-interactive, or asked about interactively.
        #[arg(long, default_value_t = false)]
        allow_password_change: bool,
    },
    /// Decrypt all files in the crypt list, or only the given paths.
    #[clap(alias("d"))]
    Decrypt {
        /// The files or folders to be decrypted.
        paths: Vec<PathBuf>,
    },
    /// Mark files or folders as need-to-be-crypted.
    Add {
        /// The files or folders to add to the crypt list.
        #[arg(required = true, num_args = 1..)]
        paths: Vec<PathBuf>,
    },
    /// Set config items.
    Set {
        #[clap(subcommand)]
        field: SetField,
    },
    /// Change the master password: decrypt everything with the old password,
    /// then re-encrypt with a new one.
    #[clap(alias("p"))]
    Pwd,
    /// Check if all files in the crypt list are encrypted.
    #[clap(alias("c"))]
    Check {
        /// The files or folders to check. If empty, checks all files in the
        /// crypt list.
        paths: Vec<PathBuf>,
        /// Only check files staged for commit (used by pre-commit hook).
        #[arg(long, default_value_t = false)]
        staged: bool,
    },
    /// Install a pre-commit hook to check encryption before committing.
    #[clap(alias("i"))]
    Install,
}

#[derive(Debug, Subcommand)]
pub enum SetField {
    /// Set zstd compression level
    ZstdLevel {
        #[clap(value_parser = validate_zstd_level)]
        value: u8,
    },
    /// Set zstd compression enable or not
    EnableZstd {
        /// `true`, `false`, `1` or `0`.
        //
        // `action` must be explicit: clap's derive infers `SetTrue` from the
        // `bool` field type, which is invalid for a positional and made the
        // whole subcommand unusable (panic in debug, "0 values required" in
        // release, and omitting the value silently stored `false`).
        #[clap(value_parser = validate_bool, action = clap::ArgAction::Set)]
        value: bool,
    },
}

impl SetField {
    /// Apply the field update to the given repo's config.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying git command or the config file write
    /// fails.
    pub fn set(&self, repo: &mut Repo) -> Result<()> {
        match self {
            Self::EnableZstd { value } => {
                repo.conf.use_zstd = *value;
                info!("zstd compression enabled: {value}");
            }
            Self::ZstdLevel { value } => {
                repo.conf.zstd_level = *value;
                info!("zstd compression level set to {value}");
            }
        }
        debug!("store config to {}", repo.conf.config_path.display());
        repo.conf.save().map_err(|e| Error::Config(e.to_string()))?;
        Ok(())
    }
}

fn validate_zstd_level(value: &str) -> Result<u8, String> {
    let value = value
        .parse::<u8>()
        .map_err(|_| "value should be a number")?;
    if (1..=22_u8).contains(&value) {
        Ok(value)
    } else {
        Err("value should be 1-22".to_string())
    }
}

fn validate_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err("value should be `true`, `false`, `1` or `0`".into()),
    }
}

#[cfg(test)]
mod tests {
    use assert2::assert;

    use super::*;

    #[test]
    fn repo_path_parser_resolves_relative() {
        // "." should absolutize to the current working directory.
        let parsed = repo_path_parser(".").unwrap();
        assert!(parsed.is_absolute());
    }

    /// Regression (M-03): the global `--repo` flag must work together with
    /// subcommands (a bogus `args_conflicts_with_subcommands` used to reject
    /// this).
    #[test]
    fn repo_flag_works_with_subcommand() {
        let cli = Cli::try_parse_from(["git-se", "-r", "/tmp/some-repo", "encrypt"]).unwrap();
        assert!(matches!(cli.command, SubCommand::Encrypt { .. }));
        assert!(cli.repo.is_absolute());

        let cli = Cli::try_parse_from(["git-se", "check", "--staged", "--repo", "/tmp/x"]).unwrap();
        assert!(matches!(
            cli.command,
            SubCommand::Check { staged: true, .. }
        ));
    }

    /// Regression: the `bool` positional needs an explicit `ArgAction::Set`.
    /// Without it clap infers `SetTrue`, which panicked in debug builds,
    /// rejected both `true` and `false` in release, and silently stored
    /// `false` when the value was omitted.
    #[test]
    fn set_enable_zstd_parses_boolean_values() {
        for (input, expected) in [("true", true), ("1", true), ("false", false), ("0", false)] {
            let cli = Cli::try_parse_from(["git-se", "set", "enable-zstd", input])
                .unwrap_or_else(|e| panic!("`set enable-zstd {input}` must parse: {e}"));
            let SubCommand::Set {
                field: SetField::EnableZstd { value },
            } = cli.command
            else {
                panic!("expected `set enable-zstd`");
            };
            assert_eq!(value, expected, "for input {input:?}");
        }

        // Omitting the value must be an error, not a silent `false`.
        assert!(Cli::try_parse_from(["git-se", "set", "enable-zstd"]).is_err());
        assert!(Cli::try_parse_from(["git-se", "set", "enable-zstd", "yes"]).is_err());
    }

    /// `git-se add` with no paths used to succeed and rewrite the config,
    /// although the README documents `<PATHS>...` as required.
    #[test]
    fn add_requires_at_least_one_path() {
        assert!(Cli::try_parse_from(["git-se", "add"]).is_err());
        assert!(Cli::try_parse_from(["git-se", "add", "f.txt"]).is_ok());
    }

    #[test]
    fn set_zstd_level_rejects_out_of_range() {
        assert!(Cli::try_parse_from(["git-se", "set", "zstd-level", "15"]).is_ok());
        assert!(Cli::try_parse_from(["git-se", "set", "zstd-level", "0"]).is_err());
        assert!(Cli::try_parse_from(["git-se", "set", "zstd-level", "23"]).is_err());
    }
}
