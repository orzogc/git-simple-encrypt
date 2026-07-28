use std::path::{Path, PathBuf};

use config_file2::Storable;
#[cfg(windows)]
use fuck_backslash::FuckBackslash;
use log::{debug, info};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, Result},
    utils::style::Colorize,
};

pub const CONFIG_FILE_NAME: &str = concat!(env!("CARGO_CRATE_NAME"), ".toml");

#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// **absolute path** of the repo. This config item will not be ser/de from
    /// file; instead, it will be set by cli param.
    #[serde(skip)]
    pub repo_path: PathBuf,
    /// config file path
    #[serde(skip)]
    pub(crate) config_path: PathBuf,
    /// whether to use zstd
    pub use_zstd: bool,
    /// zstd compression level (1-22).
    pub zstd_level: u8,
    /// list of files (patterns) to encrypt
    pub crypt_list: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repo_path: PathBuf::from("."),
            config_path: PathBuf::from(CONFIG_FILE_NAME),
            use_zstd: true,
            zstd_level: 15,
            crypt_list: vec![],
        }
    }
}

impl Storable for Config {
    fn path(&self) -> impl AsRef<Path> {
        &self.config_path
    }
}

/// Just the crypt list, for parsing a config that is not on disk.
///
/// Deliberately not [`Config`]: the staged copy of the config may predate
/// fields this version requires, and a parse failure there would silently
/// weaken the staged-mode policy.
#[derive(Debug, Deserialize)]
struct CryptListOnly {
    #[serde(default)]
    crypt_list: Vec<String>,
}

impl Config {
    /// Extract the crypt list from raw config-file contents.
    ///
    /// Used by `check --staged` to read the policy out of the **index** copy
    /// of the config rather than the working-tree copy (H-01).
    pub fn parse_crypt_list(text: &str) -> Result<Vec<String>> {
        toml::from_str::<CryptListOnly>(text)
            .map(|c| c.crypt_list)
            .map_err(|e| Error::Config(e.to_string()))
    }

    /// The path must be absolute.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self::default().with_repo_path(path)
    }
    /// The path must be absolute.
    #[must_use]
    pub fn with_repo_path(mut self, path: impl AsRef<Path>) -> Self {
        let path = path.as_ref();
        self.repo_path = path.to_path_buf();
        self.config_path = path.join(CONFIG_FILE_NAME);
        self
    }

    /// Add one path to crypt list.
    ///
    /// `path` may be either relative or absolute (it will be resolved against
    /// `repo_path`). Returns an error if the path does not exist, escapes the
    /// repository (via `../` or an intermediate symlink), or points at git
    /// internals / this tool's own config file.
    pub fn add_one_path_to_crypt_list(&mut self, path: impl AsRef<Path>) -> Result<()> {
        debug!("adding path to crypt list: {}", path.as_ref().display());
        let canonical_repo =
            dunce::canonicalize(&self.repo_path).unwrap_or_else(|_| self.repo_path.clone());
        // Shared validation: lexical escape, symlink escape, protected paths.
        // Returns the canonical repo-relative path.
        let rel =
            crate::utils::validate_target_root(path.as_ref(), &self.repo_path, &canonical_repo)?;
        // Windows only: there a backslash IS the separator, and the config
        // should record `/` for cross-platform readability. On Unix it is an
        // ordinary filename byte, and rewriting it silently stored an entry
        // for a path that does not exist.
        #[cfg(windows)]
        let rel = rel.fuck_backslash();

        // `add .` resolves to an empty relative path; store it as ".".
        let rel = if rel.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            rel
        };
        // The config is TOML, which cannot round-trip arbitrary bytes. A lossy
        // conversion used to succeed here and write a path containing U+FFFD,
        // which then failed every later operation with "does not exist".
        let entry = rel
            .to_str()
            .ok_or_else(|| Error::NonUtf8Path(rel.clone()))?
            .to_owned();
        if self.crypt_list.contains(&entry) {
            debug!("already in encrypt list: {entry}");
            return Ok(());
        }
        info!("Add to encrypt list: {}", entry.as_str().green());
        self.crypt_list.push(entry);
        Ok(())
    }

    /// Add the given paths to the encrypt list. This function will be called
    /// seldomly, so it's not a performance issue.
    pub fn add_paths_to_crypt_list(&mut self, paths: &[impl AsRef<Path>]) -> Result<()> {
        for x in paths {
            self.add_one_path_to_crypt_list(x.as_ref())?;
        }
        debug!("store config to {}", self.config_path.display());
        self.save().map_err(|e| Error::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{assert, fs};

    use config_file2::LoadConfigFile;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_add_one_file_to_crypt_list() -> crate::Result<()> {
        let temp_dir = TempDir::new()?.keep();
        let file_path = temp_dir.join("test.toml");
        let mut config = Config::load_or_default(file_path)
            .map_err(|e| Error::Config(e.to_string()))?
            .with_repo_path(&*temp_dir);

        let path_to_add = temp_dir.join("testdir");
        fs::create_dir(&path_to_add)?;
        config.add_one_path_to_crypt_list(path_to_add.as_os_str().to_string_lossy().as_ref())?;
        println!("{:?}", config.crypt_list.first().unwrap());
        assert!(
            config
                .repo_path
                .join(config.crypt_list.first().unwrap())
                .is_dir(),
            "needs to be dir: {}",
            config.crypt_list.first().unwrap()
        );
        Ok(())
    }
}
