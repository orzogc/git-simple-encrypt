use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context as _, Ok};
use colored::Colorize;
use git_simple_encrypt::{
    Cli, FileHeader, SubCommand,
    crypt::{Password, decrypt_repo, encrypt_repo},
    repo::Repo,
};
use rand::prelude::*;
use tap::Tap;
use tempfile::TempDir;

const PASSWORD: &str = "12345678910987654321";
const PASSWORD2: &str = "a-completely-different-password";
const CONFIG: &str = "git_simple_encrypt.toml";

fn bench_init() -> TempDir {
    let pwd = TempDir::new().unwrap();

    // Initialize a new repository
    exec("git init", pwd.path()).unwrap();
    // Repo-local identity: CI containers have no global git config, and a
    // commit that fails for lack of one fails SILENTLY where its status is
    // unchecked, leaving HEAD somewhere the test did not expect.
    exec("git config user.email test@example.com", pwd.path()).unwrap();
    exec("git config user.name test", pwd.path()).unwrap();

    pwd
}

fn test_init() -> TempDir {
    _ = pretty_env_logger::try_init();
    bench_init()
}

fn exec(cmd: &str, pwd: impl AsRef<Path>) -> std::io::Result<Output> {
    let mut temp = cmd.split_whitespace();
    let mut command = Command::new(temp.next().unwrap());
    command.args(temp).current_dir(pwd.as_ref()).output()
}

/// Run a git command with an argument slice (handles non-ASCII filenames and
/// commit flags, unlike [`exec`]).
fn git_args(args: &[&str], pwd: &Path) -> Output {
    Command::new("git")
        .args(args)
        .current_dir(pwd)
        .output()
        .unwrap()
}

/// Stage everything and commit (identity via `-c` so no global config needed).
fn git_commit_all(pwd: &Path) {
    git_args(&["add", "-A"], pwd);
    let out = git_args(
        &[
            "-c",
            "user.email=t@example.com",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "commit",
        ],
        pwd,
    );
    assert!(out.status.success(), "git commit failed: {out:?}");
}

fn run(cmd: SubCommand, pwd: impl Into<PathBuf>) -> anyhow::Result<()> {
    let pwd = pwd.into();
    git_simple_encrypt::run(Cli {
        command: cmd,
        repo: pwd,
    })?;
    Ok(())
}

fn open(pwd: &Path) -> Repo {
    Repo::open(pwd).unwrap()
}

fn encrypt_all(pwd: &Path) -> git_simple_encrypt::Result<()> {
    encrypt_repo(&open(pwd), &[], Password::new(PASSWORD.as_bytes()), false)
}

fn decrypt_all(pwd: &Path) -> git_simple_encrypt::Result<()> {
    decrypt_repo(&open(pwd), &[], Password::new(PASSWORD.as_bytes()))
}

fn encrypt_some(pwd: &Path, paths: &[PathBuf]) -> git_simple_encrypt::Result<()> {
    encrypt_repo(&open(pwd), paths, Password::new(PASSWORD.as_bytes()), false)
}

fn decrypt_some(pwd: &Path, paths: &[PathBuf]) -> git_simple_encrypt::Result<()> {
    decrypt_repo(&open(pwd), paths, Password::new(PASSWORD.as_bytes()))
}

trait PathExt {
    fn is_encrypted(&self) -> bool;
    fn is_compressed(&self) -> bool;
    fn is_not_encrypted(&self) -> bool {
        !self.is_encrypted()
    }
}

impl<T> PathExt for T
where
    T: AsRef<Path>,
{
    fn is_encrypted(&self) -> bool {
        let mut f = fs::File::open(self.as_ref()).unwrap();
        FileHeader::read_from(&mut f).is_ok()
    }

    /// Check if the file is both encrypted and compressed.
    fn is_compressed(&self) -> bool {
        let mut f = fs::File::open(self.as_ref()).unwrap();
        FileHeader::read_from(&mut f).unwrap().is_compressed()
    }
}

// ============ region Tests ============

#[test]
fn test_basic() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    // Create a new file and stage it for commit
    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("t2.txt"), "6".repeat(100))?;
    std::fs::write(temp_dir.join("t3.txt"), "do not crypt")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;
    assert!(temp_dir.join("t1.txt").is_file());
    assert!(temp_dir.join("t2.txt").is_file());

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "t2.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt (added files)
    encrypt_all(temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    dbg!(std::fs::read_to_string(temp_dir.join("git_simple_encrypt.toml")).unwrap());
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("t2.txt").is_compressed());
    assert!(temp_dir.join("t3.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    // Decrypt
    decrypt_all(temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test decrypt result
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    assert!(temp_dir.join("t1.txt").is_not_encrypted());
    assert!(temp_dir.join("t2.txt").is_not_encrypted());
    assert!(temp_dir.join("t3.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_not_encrypted());
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t3.txt"))?,
        "do not crypt"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t4.txt"))?,
        "dir test"
    );
    Ok(())
}

#[test]
fn test_encrypt_multiple_times() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt multiple times
    encrypt_all(temp_dir)?;
    encrypt_all(temp_dir)?;
    encrypt_all(temp_dir)?;

    // Test
    temp_dir.read_dir()?.for_each(|x| println!("{:?}", x));
    temp_dir
        .join("dir")
        .read_dir()?
        .for_each(|x| println!("{:?}", x));
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    // Decrypt
    decrypt_all(temp_dir)?;
    println!("{}", "After Decrypt".green());

    // Test

    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").is_not_encrypted());
    assert!(temp_dir.join("dir/t4.txt").is_not_encrypted());
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t4.txt"))?,
        "dir test"
    );

    Ok(())
}

#[test]
#[ignore = "This test takes too long to run, and it's not necessary to run it every time. You can run it manually if you want."]
fn test_many_files() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let dir = temp_dir.join("dir");
    std::fs::create_dir(&dir)?;
    let files = (1..2000)
        .map(|i| {
            dir.join(format!("file{}.txt", i))
                .tap(|f| std::fs::write(f, "Hello").unwrap())
        })
        .collect::<Vec<PathBuf>>();

    // Add file
    run(
        SubCommand::Add {
            paths: vec!["dir".into()],
        },
        temp_dir,
    )?;

    // Encrypt
    encrypt_all(temp_dir)?;
    // Decrypt
    decrypt_all(temp_dir)?;

    // Test
    for _ in 1..10 {
        let file_name = files.choose(&mut rand::rng()).unwrap();
        println!("Testing file: {}", file_name.display());
        assert_eq!(std::fs::read_to_string(file_name)?, "Hello");
    }

    Ok(())
}

#[test]
fn test_large_file_encrypt_decrypt() -> anyhow::Result<()> {
    const FILE_SIZE: usize = 5 * 1024 * 1024; // 5 MB
    let pwd = test_init();
    let temp_dir = pwd.path();

    let mut rng = rand::rngs::SmallRng::from_seed([42; 32]);
    let original_data: Vec<u8> = (0..FILE_SIZE).map(|_| rng.random::<u8>()).collect();

    let file_path = temp_dir.join("large.bin");
    std::fs::write(&file_path, &original_data)?;

    run(
        SubCommand::Add {
            paths: vec![file_path.clone()],
        },
        temp_dir,
    )?;
    encrypt_all(temp_dir)?;

    assert!(file_path.is_encrypted());
    decrypt_all(temp_dir)?;

    let decrypted_data = std::fs::read(&file_path)?;
    assert_eq!(decrypted_data, original_data);
    assert!(file_path.is_not_encrypted());

    Ok(())
}

#[test]
fn test_partial_decrypt() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("dir/t4.txt"), "dir test")?;

    // Add file
    run(
        SubCommand::Add {
            paths: ["t1.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt
    encrypt_all(temp_dir)?;

    // Partial decrypt
    decrypt_some(temp_dir, &["dir".into()])?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("dir/t4.txt").exists());

    // Reencrypt
    encrypt_all(temp_dir)?;

    // Partial decrypt
    decrypt_some(temp_dir, &["t1.txt".into()])?;

    // Test
    for entry in temp_dir.read_dir()? {
        println!("{:?}", entry?);
    }
    assert!(temp_dir.join("t1.txt").exists());
    assert!(temp_dir.join("dir/t4.txt").is_encrypted());

    Ok(())
}

#[test]
fn test_tampered_encrypted_file_fails_aad() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let file_path = temp_dir.join("secret.txt");
    let original_content = b"Hello, this is a secret message that must be authenticated!";
    std::fs::write(&file_path, original_content)?;

    run(
        SubCommand::Add {
            paths: vec![file_path.clone()],
        },
        temp_dir,
    )?;
    encrypt_all(temp_dir)?;

    assert!(file_path.is_encrypted());
    let mut encrypted_data = std::fs::read(&file_path)?;
    assert!(!encrypted_data.is_empty());

    // 篡改：翻转中间的一个字节
    let mid = encrypted_data.len() / 2;
    encrypted_data[mid] ^= 0xFF;

    // 写回篡改后的数据
    std::fs::write(&file_path, &encrypted_data)?;

    // 尝试解密，应该失败（AAD 校验不通过）
    let decrypt_result = decrypt_all(temp_dir);
    dbg!(&decrypt_result);
    assert!(decrypt_result.is_err());
    // 可选：验证文件仍然处于加密状态（因为解密失败，文件未被修改）
    assert!(file_path.is_encrypted());

    // 另一种篡改方式：截断文件末尾 10 个字节
    let mut encrypted_data2 = std::fs::read(&file_path)?;
    encrypted_data2.truncate(encrypted_data2.len().saturating_sub(10));
    std::fs::write(&file_path, &encrypted_data2)?;

    let decrypt_result2 = decrypt_all(temp_dir);
    dbg!(&decrypt_result);
    assert!(decrypt_result2.is_err());

    Ok(())
}

#[test]
fn test_deterministic_reencryption() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("dir"))?;
    std::fs::write(temp_dir.join("t1.txt"), "Hello, world!")?;
    std::fs::write(temp_dir.join("t2.txt"), "6".repeat(100))?;
    std::fs::write(temp_dir.join("dir/t3.txt"), "nested file")?;

    // Add files
    run(
        SubCommand::Add {
            paths: ["t1.txt", "t2.txt", "dir"].map(PathBuf::from).to_vec(),
        },
        temp_dir,
    )?;

    // ---- First encrypt ----
    encrypt_all(temp_dir)?;
    assert!(temp_dir.join("t1.txt").is_encrypted());
    assert!(temp_dir.join("t2.txt").is_compressed());
    assert!(temp_dir.join("dir/t3.txt").is_encrypted());

    let enc1_t1 = std::fs::read(temp_dir.join("t1.txt"))?;
    let enc1_t2 = std::fs::read(temp_dir.join("t2.txt"))?;
    let enc1_t3 = std::fs::read(temp_dir.join("dir/t3.txt"))?;

    // ---- Decrypt ----
    decrypt_all(temp_dir)?;
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t3.txt"))?,
        "nested file"
    );

    // ---- Re-encrypt (should produce identical ciphertext) ----
    encrypt_all(temp_dir)?;

    let enc2_t1 = std::fs::read(temp_dir.join("t1.txt"))?;
    let enc2_t2 = std::fs::read(temp_dir.join("t2.txt"))?;
    let enc2_t3 = std::fs::read(temp_dir.join("dir/t3.txt"))?;

    assert_eq!(
        enc1_t1, enc2_t1,
        "t1.txt: decrypt→encrypt must produce identical ciphertext"
    );
    assert_eq!(
        enc1_t2, enc2_t2,
        "t2.txt: decrypt→encrypt must produce identical ciphertext"
    );
    assert_eq!(
        enc1_t3, enc2_t3,
        "dir/t3.txt: decrypt→encrypt must produce identical ciphertext"
    );

    // Verify the files still decrypt correctly
    decrypt_all(temp_dir)?;
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t1.txt"))?,
        "Hello, world!"
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("t2.txt"))?,
        "6".repeat(100)
    );
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("dir/t3.txt"))?,
        "nested file"
    );

    Ok(())
}

#[test]
fn test_deterministic_reencryption_multiple_cycles() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::write(temp_dir.join("data.txt"), "persistent data")?;

    run(
        SubCommand::Add {
            paths: vec!["data.txt".into()],
        },
        temp_dir,
    )?;

    // Encrypt and capture ciphertext from 3 decrypt→encrypt cycles
    encrypt_all(temp_dir)?;
    let reference = std::fs::read(temp_dir.join("data.txt"))?;

    for cycle in 1..=3 {
        decrypt_all(temp_dir)?;
        assert_eq!(
            std::fs::read_to_string(temp_dir.join("data.txt"))?,
            "persistent data",
            "Data corrupted at cycle {cycle}"
        );

        encrypt_all(temp_dir)?;
        let ciphertext = std::fs::read(temp_dir.join("data.txt"))?;
        assert_eq!(ciphertext, reference, "Ciphertext changed at cycle {cycle}");
    }

    Ok(())
}

/// Regression: a staged plaintext file whose name needs git quoting
/// (non-ASCII here) must NOT slip past `check --staged`. Previously the
/// line-based parsing of `git diff --name-only` produced a garbage path that
/// was silently filtered out, letting the plaintext be committed.
#[test]
fn test_check_staged_non_ascii_filename() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let name = "密码.txt";
    std::fs::write(temp_dir.join(name), "PLAINTEXT SECRET")?;

    run(
        SubCommand::Add {
            paths: vec![name.into()],
        },
        temp_dir,
    )?;
    git_args(&["add", "--", name], temp_dir);

    let result = run(
        SubCommand::Check {
            paths: vec![],
            staged: true,
        },
        temp_dir,
    );
    assert!(
        result.is_err(),
        "staged plaintext file with non-ASCII name must fail the check"
    );
    Ok(())
}

/// Regression: ignore rules must not hide files that are explicitly in the
/// crypt list. Previously a `.gitignore`/`*.pem` rule silently excluded
/// `secrets/a.pem` from both encryption and `check`, while git would still
/// commit it (e.g. via `.ignore`, which git does not read).
#[test]
fn test_gitignore_does_not_hide_listed_files() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("secrets"))?;
    std::fs::write(temp_dir.join("secrets/a.pem"), "KEY A")?;
    std::fs::write(temp_dir.join("secrets/b.txt"), "B")?;
    std::fs::write(temp_dir.join(".gitignore"), "*.pem\n")?;

    run(
        SubCommand::Add {
            paths: vec!["secrets".into()],
        },
        temp_dir,
    )?;
    encrypt_all(temp_dir)?;

    assert!(temp_dir.join("secrets/a.pem").is_encrypted());
    assert!(temp_dir.join("secrets/b.txt").is_encrypted());

    run(
        SubCommand::Check {
            paths: vec![],
            staged: false,
        },
        temp_dir,
    )?;
    Ok(())
}

/// `git-se add` must refuse paths escaping the repo, git internals, and the
/// tool's own config file.
#[test]
fn test_add_rejects_escape_and_protected_paths() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    // A file OUTSIDE the repo must never enter the crypt list.
    let outside = temp_dir.parent().unwrap().join("git-se-outside-test.txt");
    std::fs::write(&outside, "do not touch")?;

    let result = run(
        SubCommand::Add {
            paths: vec!["../git-se-outside-test.txt".into()],
        },
        temp_dir,
    );
    let err = result.unwrap_err();
    let err = err.downcast::<git_simple_encrypt::Error>()?;
    assert!(
        matches!(err, git_simple_encrypt::Error::PathEscapesRepo(_)),
        "expected PathEscapesRepo, got {err:?}"
    );

    // A successful add so the config file exists on disk for the check below.
    std::fs::write(temp_dir.join("dummy.txt"), "x")?;
    run(
        SubCommand::Add {
            paths: vec!["dummy.txt".into()],
        },
        temp_dir,
    )?;

    for protected in [".git", ".git/config", "git_simple_encrypt.toml"] {
        let result = run(
            SubCommand::Add {
                paths: vec![protected.into()],
            },
            temp_dir,
        );
        let err = result.unwrap_err();
        let err = err.downcast::<git_simple_encrypt::Error>()?;
        assert!(
            matches!(err, git_simple_encrypt::Error::ProtectedPath(_)),
            "expected ProtectedPath for {protected}, got {err:?}"
        );
    }

    let _ = std::fs::remove_file(&outside);
    Ok(())
}

/// Encrypting with an explicit escaping path must also be refused (the
/// escape check is not limited to `add`).
#[test]
fn test_encrypt_rejects_explicit_escaping_path() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let err = encrypt_some(temp_dir, &["../outside.txt".into()]).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PathEscapesRepo(_)),
        "expected PathEscapesRepo, got {err:?}"
    );
    Ok(())
}

/// Adding the repo root (".") must encrypt regular files but never touch
/// `.git` internals or the config file itself.
#[test]
fn test_add_repo_root_excludes_git_and_config() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::write(temp_dir.join("plain.txt"), "encrypt me")?;
    run(
        SubCommand::Add {
            paths: vec![".".into()],
        },
        temp_dir,
    )?;
    encrypt_all(temp_dir)?;

    assert!(temp_dir.join("plain.txt").is_encrypted());
    assert!(
        temp_dir.join(".git/config").is_not_encrypted(),
        ".git internals must never be encrypted"
    );
    assert!(
        temp_dir.join("git_simple_encrypt.toml").is_not_encrypted(),
        "the config file must never be encrypted"
    );
    assert!(
        temp_dir.join(".git/HEAD").is_not_encrypted(),
        ".git/HEAD must stay intact"
    );

    // And everything still decrypts.
    decrypt_all(temp_dir)?;
    assert_eq!(
        std::fs::read_to_string(temp_dir.join("plain.txt"))?,
        "encrypt me"
    );
    Ok(())
}

/// Regression (H-02): an explicit path must never encrypt git internals,
/// even when named directly on the command line.
#[test]
fn test_encrypt_rejects_explicit_git_config() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    for protected in [".git", ".git/config", "git_simple_encrypt.toml"] {
        let err = encrypt_some(temp_dir, &[protected.into()]).unwrap_err();
        assert!(
            matches!(
                err,
                git_simple_encrypt::Error::ProtectedPath(_)
                    | git_simple_encrypt::Error::NoFile(_)
                    | git_simple_encrypt::Error::PathNotExist(_)
            ),
            "{protected} must not be encryptable, got {err:?}"
        );
    }
    // The repo's git config must be untouched.
    let head = std::fs::read(temp_dir.join(".git/config"))?;
    assert_eq!(&head[..5], b"[core");
    Ok(())
}

/// Regression (H-03): an intermediate symlink must not let encryption escape
/// the repository boundary.
#[cfg(unix)]
#[test]
fn test_encrypt_rejects_intermediate_symlink_escape() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    let outside = TempDir::new()?;
    let outside_file = outside.path().join("secret.txt");
    std::fs::write(&outside_file, "OUTSIDE")?;
    std::os::unix::fs::symlink(outside.path(), temp_dir.join("link"))?;

    // Via encrypt with an explicit path...
    let err = encrypt_some(temp_dir, &["link/secret.txt".into()]).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PathEscapesRepo(_)),
        "expected PathEscapesRepo, got {err:?}"
    );
    // ...and via add.
    let result = run(
        SubCommand::Add {
            paths: vec!["link/secret.txt".into()],
        },
        temp_dir,
    );
    let err = result
        .unwrap_err()
        .downcast::<git_simple_encrypt::Error>()?;
    assert!(
        matches!(err, git_simple_encrypt::Error::PathEscapesRepo(_)),
        "expected PathEscapesRepo from add, got {err:?}"
    );

    assert_eq!(std::fs::read_to_string(&outside_file)?, "OUTSIDE");
    Ok(())
}

/// Overlapping crypt-list entries must not process the same file twice.
#[test]
fn test_resolve_target_files_dedup() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::create_dir(temp_dir.join("d"))?;
    std::fs::write(temp_dir.join("d/f.txt"), "x")?;

    let files = git_simple_encrypt::utils::resolve_target_files(
        &[],
        &["d".to_owned(), "d/f.txt".to_owned()],
        temp_dir,
        &git_simple_encrypt::utils::ProtectedDirs::default(),
    )?;
    assert_eq!(files.len(), 1, "overlapping entries must be deduplicated");
    Ok(())
}

#[test]
fn test_check_staged() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::write(temp_dir.join("encrypted.txt"), "already encrypted")?;
    std::fs::write(temp_dir.join("unencrypted.txt"), "not yet encrypted")?;
    std::fs::write(temp_dir.join("plain.txt"), "not in crypt list")?;

    run(
        SubCommand::Add {
            paths: ["encrypted.txt", "unencrypted.txt"]
                .map(PathBuf::from)
                .to_vec(),
        },
        temp_dir,
    )?;

    // Encrypt only encrypted.txt, leave unencrypted.txt as-is
    encrypt_some(temp_dir, &["encrypted.txt".into()])?;
    assert!(temp_dir.join("encrypted.txt").is_encrypted());
    assert!(temp_dir.join("unencrypted.txt").is_not_encrypted());

    // Case 1: stage only the encrypted file → should pass
    exec("git add encrypted.txt", temp_dir).context("git add encrypted.txt")?;
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_ok(),
        "encrypted staged file should pass check"
    );

    // Case 2: also stage the unencrypted file (in crypt list) → should fail
    exec("git add unencrypted.txt", temp_dir).context("git add unencrypted.txt")?;
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_err(),
        "unencrypted staged file (in crypt list) should fail check"
    );

    // Clear index
    exec("git rm --cached encrypted.txt unencrypted.txt", temp_dir).context("git rm --cached")?;

    // Case 3: stage a file not in crypt list → should pass (nothing to check)
    exec("git add plain.txt", temp_dir).context("git add plain.txt")?;
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_ok(),
        "staged file not in crypt list should pass check"
    );

    // Clear index
    exec("git rm --cached plain.txt", temp_dir).context("git rm --cached")?;

    // Case 4: nothing staged → should pass
    assert!(
        run(
            SubCommand::Check {
                paths: vec![],
                staged: true
            },
            temp_dir
        )
        .is_ok(),
        "nothing staged should pass check"
    );

    Ok(())
}

// ============ region Password handling (zero-persistence) ============

/// The HEAD-based consistency check: no anchor on first encrypt, silent pass
/// on match, hard error on mismatch, explicit flag to change password.
#[test]
fn test_head_password_verification_flow() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::write(temp_dir.join("f.txt"), "secret")?;
    run(
        SubCommand::Add {
            paths: vec!["f.txt".into()],
        },
        temp_dir,
    )?;

    // 1. No HEAD yet → Unverifiable → encrypt proceeds without any anchor.
    encrypt_all(temp_dir)?;
    assert!(temp_dir.join("f.txt").is_encrypted());

    // Commit the encrypted file so HEAD holds an anchor.
    git_commit_all(temp_dir);

    // 2. Same password passes the HEAD check without complaint.
    decrypt_all(temp_dir)?;
    encrypt_all(temp_dir)?;

    // 3. A different password is rejected...
    decrypt_all(temp_dir)?;
    let err = encrypt_repo(
        &open(temp_dir),
        &[],
        Password::new(PASSWORD2.as_bytes()),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PasswordChanged(_)),
        "expected PasswordChanged, got {err:?}"
    );

    // 4. ...unless explicitly allowed: an intentional password change.
    encrypt_repo(
        &open(temp_dir),
        &[],
        Password::new(PASSWORD2.as_bytes()),
        true,
    )?;
    decrypt_repo(&open(temp_dir), &[], Password::new(PASSWORD2.as_bytes()))?;
    assert_eq!(std::fs::read_to_string(temp_dir.join("f.txt"))?, "secret");
    Ok(())
}

/// Regression (H-06): encrypting only a NEW (never committed) file must not
/// bypass the HEAD password anchor — candidates come from the whole crypt
/// list, not just this run's targets.
#[test]
fn test_partial_encrypt_new_file_cannot_bypass_anchor() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    // Encrypt and commit an anchor file with the correct password.
    std::fs::write(temp_dir.join("anchor.txt"), "anchor")?;
    run(
        SubCommand::Add {
            paths: vec!["anchor.txt".into()],
        },
        temp_dir,
    )?;
    encrypt_all(temp_dir)?;
    git_commit_all(temp_dir);

    // Add a new file and try to encrypt ONLY it with a WRONG password.
    std::fs::write(temp_dir.join("new.txt"), "newfile")?;
    run(
        SubCommand::Add {
            paths: vec!["new.txt".into()],
        },
        temp_dir,
    )?;
    let err = encrypt_repo(
        &open(temp_dir),
        &["new.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PasswordChanged(_)),
        "expected PasswordChanged, got {err:?}"
    );
    assert!(
        temp_dir.join("new.txt").is_not_encrypted(),
        "the new file must not be encrypted with the wrong password"
    );
    Ok(())
}

/// A wrong password must fail fast in the decrypt pre-check, before any file
/// is written.
#[test]
fn test_decrypt_wrong_password_precheck() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::write(temp_dir.join("f.txt"), "secret")?;
    run(
        SubCommand::Add {
            paths: vec!["f.txt".into()],
        },
        temp_dir,
    )?;
    encrypt_all(temp_dir)?;

    let err = decrypt_repo(&open(temp_dir), &[], Password::new(PASSWORD2.as_bytes())).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PasswordCheckFailed(_)),
        "expected PasswordCheckFailed, got {err:?}"
    );
    assert!(
        temp_dir.join("f.txt").is_encrypted(),
        "failed pre-check must leave the file untouched"
    );
    Ok(())
}

/// Empty passwords are rejected before any work happens.
#[test]
fn test_empty_password_rejected() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    std::fs::write(temp_dir.join("f.txt"), "x")?;
    run(
        SubCommand::Add {
            paths: vec!["f.txt".into()],
        },
        temp_dir,
    )?;

    let err = encrypt_repo(&open(temp_dir), &[], Password::new(b""), false).unwrap_err();
    assert!(matches!(err, git_simple_encrypt::Error::EmptyKey));
    let err = decrypt_repo(&open(temp_dir), &[], Password::new(b"")).unwrap_err();
    assert!(matches!(err, git_simple_encrypt::Error::EmptyKey));
    Ok(())
}

/// A password stored in `.git/config` by an older version is scrubbed when
/// the repo is opened.
#[test]
fn test_legacy_key_is_scrubbed_on_open() -> anyhow::Result<()> {
    let pwd = test_init();
    let temp_dir = pwd.path();

    git_args(
        &["config", "--local", "git-simple-encrypt.key", "hunter2"],
        temp_dir,
    );
    let out = git_args(
        &["config", "--local", "--get", "git-simple-encrypt.key"],
        temp_dir,
    );
    assert!(out.status.success(), "setup: legacy key should exist");

    // Opening the repo triggers the one-time migration.
    _ = open(temp_dir);

    let out = git_args(
        &["config", "--local", "--get", "git-simple-encrypt.key"],
        temp_dir,
    );
    assert!(
        !out.status.success(),
        "legacy key should have been scrubbed on open"
    );
    Ok(())
}

/// Regression (H-06): the HEAD password anchor must come from the HEAD tree,
/// not from a working-tree walk. With the committed ciphertext deleted from
/// disk, encrypting a *new* file with the wrong password used to succeed —
/// leaving a file only the wrong password could open.
#[test]
fn test_head_anchor_survives_deleted_worktree_file() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::create_dir(root.join("secrets"))?;
    fs::write(root.join("secrets/old.txt"), "OLD_SECRET")?;
    run(
        SubCommand::Add {
            paths: vec!["secrets".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);

    // The only committed anchor disappears from the working tree; a brand-new
    // file takes its place.
    fs::remove_file(root.join("secrets/old.txt"))?;
    fs::write(root.join("secrets/new.txt"), "NEW_SECRET")?;

    let wrong = encrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()), false);
    assert!(
        wrong.is_err(),
        "a wrong password must be rejected even when the anchor is only in HEAD"
    );
    assert!(
        root.join("secrets/new.txt").is_not_encrypted(),
        "the rejected run must not have written anything"
    );

    // The right password still works, and round-trips.
    encrypt_all(root)?;
    assert!(root.join("secrets/new.txt").is_encrypted());
    decrypt_all(root)?;
    assert_eq!(
        fs::read_to_string(root.join("secrets/new.txt"))?,
        "NEW_SECRET"
    );
    Ok(())
}

/// Regression (H-05): one failing file must abort the whole run. Previously
/// each file committed independently, so a corrupt file left the rest of the
/// repo decrypted — encrypted and plaintext files side by side.
#[test]
fn test_partial_failure_leaves_repo_untouched() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("a.txt"), "AAA")?;
    fs::write(root.join("b.txt"), "BBB")?;
    run(
        SubCommand::Add {
            paths: vec!["a.txt".into(), "b.txt".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);

    // Truncate a.txt mid-chunk so only that file fails to decrypt.
    let good = fs::read(root.join("a.txt"))?;
    fs::write(root.join("a.txt"), &good[..good.len() - 8])?;

    assert!(decrypt_all(root).is_err(), "the run must fail as a whole");
    assert!(
        root.join("b.txt").is_encrypted(),
        "an unrelated file must not have been decrypted by the failed run"
    );

    // Restoring the damaged file lets the same command succeed unchanged.
    fs::write(root.join("a.txt"), &good)?;
    decrypt_all(root)?;
    assert_eq!(fs::read_to_string(root.join("a.txt"))?, "AAA");
    assert_eq!(fs::read_to_string(root.join("b.txt"))?, "BBB");
    Ok(())
}

/// Regression (H-05): a password change is one transaction. If any file fails
/// to re-encrypt, every file must stay readable with the OLD password —
/// never left decrypted, never a mix of old and new.
#[test]
fn test_password_change_is_all_or_nothing() -> anyhow::Result<()> {
    use git_simple_encrypt::crypt::change_password;

    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("a.txt"), "AAA")?;
    fs::write(root.join("b.txt"), "SECRET_B")?;
    run(
        SubCommand::Add {
            paths: vec!["a.txt".into(), "b.txt".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);

    // Corrupt b.txt's last tag so its re-encryption fails after a.txt's
    // succeeded — exactly the window the two-phase commit has to cover.
    let mut damaged = fs::read(root.join("b.txt"))?;
    let last = damaged.len() - 5;
    damaged[last] ^= 0xFF;
    fs::write(root.join("b.txt"), &damaged)?;

    let result = change_password(
        &open(root),
        Password::new(PASSWORD.as_bytes()),
        Password::new(PASSWORD2.as_bytes()),
    );
    assert!(result.is_err(), "the password change must fail as a whole");

    // a.txt must NOT have been re-encrypted: still the old password, and
    // certainly not plaintext.
    assert!(root.join("a.txt").is_encrypted());
    decrypt_some(root, &["a.txt".into()])?;
    assert_eq!(fs::read_to_string(root.join("a.txt"))?, "AAA");
    Ok(())
}

/// Regression: an absolute path inside the repo is a valid explicit target.
/// It used to panic in debug builds (`debug_assert!(is_relative())`) while
/// working fine in release.
#[test]
fn test_absolute_explicit_path_is_accepted() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("f.txt"), "hello")?;

    let absolute = root.canonicalize()?.join("f.txt");
    encrypt_some(root, std::slice::from_ref(&absolute))?;
    assert!(root.join("f.txt").is_encrypted());

    decrypt_some(root, std::slice::from_ref(&absolute))?;
    assert_eq!(fs::read_to_string(root.join("f.txt"))?, "hello");
    Ok(())
}

/// Regression: a non-UTF-8 path cannot survive a TOML round-trip, so `add`
/// must reject it instead of storing a lossy `U+FFFD` name that no later
/// command can resolve.
#[cfg(unix)]
#[test]
fn test_add_rejects_non_utf8_path() -> anyhow::Result<()> {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

    let pwd = test_init();
    let root = pwd.path();
    let name = PathBuf::from(OsStr::from_bytes(b"bad\xff\xfename.txt"));

    // APFS and HFS+ reject filenames that are not valid UTF-8 (EILSEQ), so on
    // macOS this input cannot be created in the first place and there is
    // nothing to assert.
    if fs::write(root.join(&name), "SECRET").is_err() {
        eprintln!("skipped: this filesystem does not accept non-UTF-8 filenames");
        return Ok(());
    }

    let mut repo = open(root);
    let err = repo
        .conf
        .add_one_path_to_crypt_list(&name, &repo.protected())
        .unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::NonUtf8Path(_)),
        "expected NonUtf8Path, got {err:?}"
    );
    assert!(repo.conf.crypt_list.is_empty());
    Ok(())
}

/// Regression: ambient `GIT_DIR` / `GIT_WORK_TREE` must not redirect git-se
/// at another repository. It used to let this repo's staged plaintext pass
/// and installed the hook into the foreign repo.
#[test]
fn test_git_env_vars_cannot_redirect_the_repo() -> anyhow::Result<()> {
    let target = test_init();
    let decoy = bench_init();
    let root = target.path();

    // The config is written directly rather than via `run(SubCommand::Add)`:
    // opening the repo in-process would hold the repository lock for the rest
    // of the test binary's lifetime, and the real binary spawned below would
    // then (correctly) fail with `RepoLocked`.
    fs::write(root.join("secret.txt"), "PLAINTEXT_SECRET")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"secret.txt\"]\n",
    )?;
    git_args(&["add", "-A"], root);

    // Drive the real binary so the vars are set only for the child. Mutating
    // them in-process would leak into every other test running in parallel.
    let git_se = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_git-se"))
            .args(args)
            .arg("--repo")
            .arg(root)
            .env("GIT_DIR", decoy.path().join(".git"))
            .env("GIT_WORK_TREE", decoy.path())
            .output()
            .unwrap()
    };

    let staged = git_se(&["check", "--staged"]);
    assert!(
        !staged.status.success(),
        "staged plaintext must still be caught with GIT_DIR pointing elsewhere: {staged:?}"
    );

    let hook = git_se(&["install"]);
    assert!(hook.status.success(), "install failed: {hook:?}");
    assert!(
        root.join(".git/hooks/pre-commit").exists(),
        "the hook must land in the repo git-se was pointed at"
    );
    assert!(
        !decoy.path().join(".git/hooks/pre-commit").exists(),
        "the hook must not land in the repo named by GIT_DIR"
    );
    Ok(())
}

/// Regression: `Repo::open` resolves the root through git plumbing, which
/// reports the *physical* path (on macOS `/var` is a symlink to
/// `/private/var`). An explicit absolute target spelled the way the caller
/// knows the repo — through the symlink — must not look like an escape.
#[cfg(unix)]
#[test]
fn test_absolute_target_through_symlinked_repo_root() -> anyhow::Result<()> {
    let real = test_init();
    let link_parent = TempDir::new()?;
    let link = link_parent.path().join("repo-link");
    std::os::unix::fs::symlink(real.path(), &link)?;
    fs::write(real.path().join("f.txt"), "hello")?;

    // Built from the symlinked root, while Repo::open resolves to the real one.
    let via_link = link.join("f.txt");
    encrypt_some(&link, std::slice::from_ref(&via_link))?;
    assert!(real.path().join("f.txt").is_encrypted());

    decrypt_some(&link, std::slice::from_ref(&via_link))?;
    assert_eq!(fs::read_to_string(real.path().join("f.txt"))?, "hello");
    Ok(())
}

/// The lexical guard deliberately skips absolute entries, so prove the
/// canonical check alone still rejects them — both an ordinary outside path
/// and one that only reaches outside after symlink resolution.
#[cfg(unix)]
#[test]
fn test_absolute_target_outside_repo_is_rejected() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    let outside = TempDir::new()?;
    let victim = outside.path().join("victim.txt");
    fs::write(&victim, "OUTSIDE")?;

    let err = encrypt_some(root, std::slice::from_ref(&victim)).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PathEscapesRepo(_)),
        "an absolute path outside the repo must be rejected, got {err:?}"
    );

    // Absolute, inside the repo lexically, but escaping through a symlink.
    std::os::unix::fs::symlink(outside.path(), root.join("link"))?;
    let via_link = root.join("link").join("victim.txt");
    let err = encrypt_some(root, std::slice::from_ref(&via_link)).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PathEscapesRepo(_)),
        "an absolute path escaping via a symlink must be rejected, got {err:?}"
    );

    // ...and `add` must refuse both as well.
    let mut repo = open(root);
    for path in [&victim, &via_link] {
        let err = repo
            .conf
            .add_one_path_to_crypt_list(path, &repo.protected())
            .unwrap_err();
        assert!(
            matches!(err, git_simple_encrypt::Error::PathEscapesRepo(_)),
            "add must reject {}, got {err:?}",
            path.display()
        );
    }

    assert_eq!(fs::read_to_string(&victim)?, "OUTSIDE");
    Ok(())
}

/// Regression: widening the crypt list brings already-committed files into
/// scope without modifying them. A diff-based staged check cannot see those,
/// so the whole index must be enumerated.
#[test]
fn test_staged_check_sees_files_the_new_policy_covers() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("secret.txt"), "PLAINTEXT_SECRET")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = []\n",
    )?;
    git_commit_all(root);

    // Only the config changes; secret.txt is neither modified nor re-staged.
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"secret.txt\"]\n",
    )?;
    git_args(&["add", CONFIG], root);

    let err = open(root).check(&[], true).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::FilesNotEncrypted(1, 1)),
        "expected the newly-covered plaintext to be caught, got {err:?}"
    );
    Ok(())
}

/// Regression: a staged config that does not parse must block the commit.
/// Silently falling back to the working-tree list let a corrupt staged policy
/// wave plaintext through.
#[test]
fn test_staged_check_fails_closed_on_unparsable_config() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("secret.txt"), "PLAINTEXT_SECRET")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"secret.txt\"]\n",
    )?;
    git_args(&["add", "-A"], root);
    fs::write(root.join(CONFIG), "crypt_list = [ not valid toml\n")?;
    git_args(&["add", CONFIG], root);
    // Working tree back to an empty list, deliberately not staged.
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = []\n",
    )?;

    let err = open(root).check(&[], true).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::Config(_)),
        "an unparsable staged config must be a hard error, got {err:?}"
    );
    Ok(())
}

/// Regression: crypt-list entries are normalized, so `./x`, `x` and `x/` all
/// denote the same target for the staged check as for encryption.
#[test]
fn test_staged_check_normalizes_crypt_list_entries() -> anyhow::Result<()> {
    for spelling in ["./secret.txt", "secret.txt"] {
        let pwd = test_init();
        let root = pwd.path();
        fs::write(root.join("secret.txt"), "PLAINTEXT_SECRET")?;
        fs::write(
            root.join(CONFIG),
            format!("use_zstd = true\nzstd_level = 15\ncrypt_list = [{spelling:?}]\n"),
        )?;
        git_args(&["add", "-A"], root);

        let err = open(root).check(&[], true).unwrap_err();
        assert!(
            matches!(err, git_simple_encrypt::Error::FilesNotEncrypted(1, 1)),
            "entry {spelling:?} must match secret.txt, got {err:?}"
        );
    }
    Ok(())
}

/// Regression (H-06): the HEAD anchors are chosen by the policy committed in
/// HEAD. Narrowing the crypt list locally, without committing it, used to hide
/// every anchor and let a wrong password through.
#[test]
fn test_head_anchor_uses_committed_policy() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::create_dir(root.join("secrets"))?;
    fs::write(root.join("secrets/old.txt"), "OLD")?;
    run(
        SubCommand::Add {
            paths: vec!["secrets".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);

    // Local, uncommitted narrowing of the policy.
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"new.txt\"]\n",
    )?;
    fs::write(root.join("new.txt"), "NEW")?;

    let err =
        encrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()), false).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::PasswordChanged(_)),
        "the committed policy must still supply anchors, got {err:?}"
    );
    assert!(root.join("new.txt").is_not_encrypted());
    Ok(())
}

/// Regression: a nested repository's internals are as fatal to encrypt as the
/// outer repository's. `validate_repo_relative` checks every component now,
/// not just the first.
#[test]
fn test_nested_git_dir_is_protected() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::create_dir(root.join("inner"))?;
    exec("git init", root.join("inner"))?;

    let mut repo = open(root);
    let err = repo
        .conf
        .add_one_path_to_crypt_list("inner/.git/config", &repo.protected())
        .unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::ProtectedPath(_)),
        "expected ProtectedPath for a nested .git, got {err:?}"
    );
    Ok(())
}

/// Regression: a file already encrypted under a *different* password must be
/// reported rather than silently skipped by encrypt.
#[test]
fn test_encrypt_rejects_foreign_ciphertext() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("s.txt"), "SECRET")?;
    run(
        SubCommand::Add {
            paths: vec!["s.txt".into()],
        },
        root,
    )?;
    // Encrypted with PASSWORD2...
    encrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()), false)?;

    // ...then encrypted again with PASSWORD: the format probe says "already
    // encrypted", but the AEAD check says it is not ours.
    let err = encrypt_all(root).unwrap_err();
    assert!(
        format!("{err}").contains("not with this password"),
        "expected a foreign-ciphertext error, got {err:?}"
    );

    // With the flag, per-file authentication still applies (B-02): the wrong
    // password fails even with it...
    assert!(
        encrypt_repo(&open(root), &[], Password::new(PASSWORD.as_bytes()), true).is_err(),
        "--allow-password-change must not skip per-file authentication"
    );
    // ...while the file's OWN password still skips it cleanly.
    encrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()), true)?;
    Ok(())
}

/// Regression: `git-se p` must encrypt a listed file that is currently
/// plaintext, not skip it and report success.
#[test]
fn test_change_password_encrypts_plaintext_members() -> anyhow::Result<()> {
    use git_simple_encrypt::crypt::change_password;

    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("a.txt"), "AAA")?;
    fs::write(root.join("b.txt"), "BBB")?;
    run(
        SubCommand::Add {
            paths: vec!["a.txt".into(), "b.txt".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);
    // a.txt is left decrypted, as a half-finished session would.
    decrypt_some(root, &["a.txt".into()])?;
    assert!(root.join("a.txt").is_not_encrypted());

    change_password(
        &open(root),
        Password::new(PASSWORD.as_bytes()),
        Password::new(PASSWORD2.as_bytes()),
    )?;

    assert!(
        root.join("a.txt").is_encrypted(),
        "plaintext member must be encrypted"
    );
    assert!(root.join("b.txt").is_encrypted());
    decrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()))?;
    assert_eq!(fs::read_to_string(root.join("a.txt"))?, "AAA");
    assert_eq!(fs::read_to_string(root.join("b.txt"))?, "BBB");
    Ok(())
}

/// Regression: `install` must write where git actually looks for hooks.
#[test]
fn test_install_honors_core_hooks_path() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    git_args(&["config", "core.hooksPath", "custom-hooks"], root);

    open(root).install_hook()?;
    assert!(
        root.join("custom-hooks/pre-commit").exists(),
        "the hook must land where core.hooksPath points"
    );
    assert!(
        !root.join(".git/hooks/pre-commit").exists(),
        "and not in the default location git would ignore"
    );
    Ok(())
}

// ============ region: 2026-07 audit regression tests ============

/// Regression (A-01): a crypt-list entry that is not a plain repo-relative
/// path (`d/../x`, absolute) is a hard error in EVERY mode. It used to be
/// encrypted by `e` yet treated as "no policy" by `check --staged`, and it
/// hid the HEAD password anchors.
#[test]
fn test_non_relative_crypt_entry_rejected_everywhere() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::create_dir(root.join("d"))?;
    fs::write(root.join("secret.txt"), "PLAIN")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"d/../secret.txt\"]\n",
    )?;
    git_args(&["add", "-A"], root);

    assert!(
        matches!(encrypt_all(root), Err(git_simple_encrypt::Error::Config(_))),
        "encrypt must reject the entry"
    );
    assert!(
        matches!(
            open(root).check(&[], false),
            Err(git_simple_encrypt::Error::Config(_))
        ),
        "check must reject the entry"
    );
    assert!(
        matches!(
            open(root).check(&[], true),
            Err(git_simple_encrypt::Error::Config(_))
        ),
        "check --staged must fail closed on the entry, not see an empty policy"
    );
    Ok(())
}

/// Regression (A-01): the same entry must not strip the HEAD password
/// anchors either — a wrong password used to sail through because the
/// anchor-selecting policy silently dropped it.
#[test]
fn test_non_relative_crypt_entry_cannot_hide_head_anchor() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::create_dir(root.join("secrets"))?;
    fs::create_dir(root.join("d"))?;
    fs::write(root.join("secrets/old.txt"), "OLD")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"d/../secrets\"]\n",
    )?;
    encrypt_some(root, &["secrets/old.txt".into()])?;
    git_commit_all(root);

    // The anchor leaves the working tree (still committed); a new plaintext
    // file appears. Any encrypt must now fail on the config error — with
    // EITHER password — instead of accepting a wrong one.
    fs::remove_file(root.join("secrets/old.txt"))?;
    fs::write(root.join("secrets/new.txt"), "NEW")?;
    let result = encrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()), false);
    assert!(
        matches!(result, Err(git_simple_encrypt::Error::Config(_))),
        "the HEAD policy must fail closed on the bad entry, got {result:?}"
    );
    assert_eq!(fs::read_to_string(root.join("secrets/new.txt"))?, "NEW");
    Ok(())
}

/// Regression (A-04/A-14): the startup sweep must leave user files alone,
/// however they are named — including names that match OLDER versions'
/// shapes, which cannot be told apart from user files — and only collect
/// files that have git-se's current full generated name shape AND are old
/// enough.
#[test]
fn test_sweep_only_removes_old_generated_names() -> anyhow::Result<()> {
    use std::time::{Duration, SystemTime};

    let pwd = test_init();
    let root = pwd.path();
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = []\n",
    )?;

    // User files that merely share the prefix, plus files matching previous
    // versions' shapes — all indistinguishable from user files, all must
    // survive even when old.
    fs::write(root.join(".git-se-tmp.notes"), "USER1")?;
    fs::write(root.join(".git-se-bak.data"), "USER2")?;
    fs::create_dir(root.join("sub"))?;
    fs::write(root.join("sub/.git-se-tmp.keep"), "USER3")?;
    fs::write(root.join(".git-se-tmp.ABC123"), "LEGACY_TMP")?;
    fs::write(root.join(".git-se-bak.2024"), "LEGACY_DIGITS")?;
    fs::write(root.join(".git-se-bak.01234567.0"), "LEGACY_HEX8")?;
    // Current generated shapes, fresh: not old enough to collect.
    fs::write(root.join(".git-se-tmp.a1b2c3d4e5f6g7h8"), "FRESH_TMP")?;
    // Current generated shapes AND old: collected.
    fs::write(root.join(".git-se-tmp.x9y8z7w6v5u4t3s2"), "OLD_TMP")?;
    fs::write(
        root.join(".git-se-bak.0123456789abcdef0123456789abcdef.0"),
        "OLD_BAK",
    )?;
    let old_time =
        std::fs::FileTimes::new().set_modified(SystemTime::now() - Duration::from_secs(2 * 3600));
    for name in [
        ".git-se-tmp.ABC123",
        ".git-se-bak.2024",
        ".git-se-bak.01234567.0",
        ".git-se-tmp.x9y8z7w6v5u4t3s2",
        ".git-se-bak.0123456789abcdef0123456789abcdef.0",
    ] {
        std::fs::File::options()
            .write(true)
            .open(root.join(name))?
            .set_times(old_time)?;
    }

    open(root); // any command sweeps at startup

    assert_eq!(fs::read_to_string(root.join(".git-se-tmp.notes"))?, "USER1");
    assert_eq!(fs::read_to_string(root.join(".git-se-bak.data"))?, "USER2");
    assert_eq!(
        fs::read_to_string(root.join("sub/.git-se-tmp.keep"))?,
        "USER3"
    );
    assert_eq!(
        fs::read_to_string(root.join(".git-se-tmp.ABC123"))?,
        "LEGACY_TMP"
    );
    assert_eq!(
        fs::read_to_string(root.join(".git-se-bak.2024"))?,
        "LEGACY_DIGITS"
    );
    assert_eq!(
        fs::read_to_string(root.join(".git-se-bak.01234567.0"))?,
        "LEGACY_HEX8"
    );
    assert!(
        root.join(".git-se-tmp.a1b2c3d4e5f6g7h8").exists(),
        "a fresh generated-shape file must survive the age check"
    );
    assert!(
        !root.join(".git-se-tmp.x9y8z7w6v5u4t3s2").exists(),
        "an old generated-shape temp must be collected"
    );
    assert!(
        !root
            .join(".git-se-bak.0123456789abcdef0123456789abcdef.0")
            .exists(),
        "an old generated-shape backup must be collected"
    );
    Ok(())
}

/// Regression (A-05): without a working `git` binary the repository must
/// refuse to open — the path-shape fallbacks used to let
/// `--allow-password-change` encrypt a detached git dir's refs.
#[test]
fn test_repo_refuses_to_open_without_git_binary() -> anyhow::Result<()> {
    let meta = TempDir::new()?;
    let wt = TempDir::new()?;
    let out = Command::new("git")
        .args([
            "init",
            "--separate-git-dir",
            meta.path().to_str().unwrap(),
            wt.path().to_str().unwrap(),
        ])
        .output()?;
    assert!(out.status.success(), "git init failed: {out:?}");
    fs::write(wt.path().join("seed.txt"), "seed")?;
    git_commit_all(wt.path());

    // The detached git dir has no `.git` anywhere in its path.
    let refs_dir = meta.path().join("refs");
    let mut refs_before: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    let mut stack = vec![refs_dir.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                refs_before.push((path.clone(), fs::read(&path)?));
            }
        }
    }
    assert!(!refs_before.is_empty(), "expected real refs to protect");

    let output = Command::new(env!("CARGO_BIN_EXE_git-se"))
        .args([
            "--repo",
            refs_dir.to_str().unwrap(),
            "encrypt",
            "--allow-password-change",
        ])
        .env_clear()
        .env("PATH", "/nonexistent")
        .env("GIT_SE_PASSWORD", PASSWORD)
        .output()?;
    assert!(
        !output.status.success(),
        "git-se must refuse to run without a git binary: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("git-se requires a working git binary"),
        "expected the GitUnavailable message, got: {stderr}"
    );
    for (path, content) in refs_before {
        assert_eq!(
            fs::read(&path)?,
            content,
            "the git ref {} must be untouched",
            path.display()
        );
    }
    Ok(())
}

/// Regression (A-06): plaintext appended after a multi-chunk ciphertext must
/// be reported by `git-se e`, not skipped — the first chunk authenticates
/// either way, so the check now decrypts the whole file.
#[test]
fn test_encrypt_reports_appended_plaintext_multi_chunk() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    // Incompressible content, comfortably over one chunk even after zstd.
    let mut data = vec![0u8; 70_000];
    rand::rng().fill_bytes(&mut data);
    fs::write(root.join("big.bin"), &data)?;
    run(
        SubCommand::Add {
            paths: vec!["big.bin".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    assert!(root.join("big.bin").is_encrypted());

    let mut tampered = fs::read(root.join("big.bin"))?;
    tampered.extend_from_slice(b"PLAINTEXT_SECRET");
    fs::write(root.join("big.bin"), &tampered)?;

    let result = encrypt_all(root);
    match &result {
        Err(git_simple_encrypt::Error::BatchFile { source, .. })
            if matches!(**source, git_simple_encrypt::Error::ForeignCiphertext(_)) => {}
        other => panic!("the tampered file must be reported, not skipped: {other:?}"),
    }
    assert!(
        root.join("big.bin").is_encrypted(),
        "the reported file must not have been rewritten"
    );
    Ok(())
}

/// Regression (A-07a): a real anchor must be found no matter how many
/// plaintext blobs sort ahead of it — the scan used to give up after 256
/// candidates, hiding the anchor and waving a wrong password through.
#[test]
fn test_head_anchor_found_behind_many_plaintext_blobs() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    // 260 blobs just large enough to be candidates, all sorting before the
    // anchor, all plaintext.
    for i in 0..260 {
        fs::write(root.join(format!("f{i:03}.txt")), vec![0u8; 104])?;
    }
    fs::write(root.join("zzz_anchor.txt"), "ANCHOR")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\".\"]\n",
    )?;
    encrypt_some(root, &["zzz_anchor.txt".into()])?;
    git_commit_all(root);

    fs::write(root.join("new.txt"), "NEW")?;
    let result = encrypt_repo(
        &open(root),
        &["new.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        false,
    );
    assert!(
        matches!(result, Err(git_simple_encrypt::Error::PasswordChanged(_))),
        "the anchor behind 260 plaintext blobs must still veto the wrong password, got {result:?}"
    );
    assert_eq!(fs::read_to_string(root.join("new.txt"))?, "NEW");
    Ok(())
}

/// Regression (A-07b): "HEAD has no config" is ordinary, but "HEAD has a
/// config that cannot be read" must be a hard error. A gitlink at the
/// config's path makes `cat-file blob` fail while `ls-tree` still lists it.
#[test]
fn test_head_config_unreadable_fails_closed() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("zzz.txt"), "ANCHOR")?;
    run(
        SubCommand::Add {
            paths: vec!["zzz.txt".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);
    let head_sha = String::from_utf8(git_args(&["rev-parse", "HEAD"], root).stdout)?
        .trim()
        .to_string();

    // Replace the committed config with a gitlink: present in the tree,
    // unreadable as a blob.
    let out = git_args(
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{head_sha},{CONFIG}"),
        ],
        root,
    );
    assert!(out.status.success(), "update-index failed: {out:?}");
    let out = git_args(&["commit", "-qm", "gitlink-config"], root);
    assert!(out.status.success(), "gitlink commit failed: {out:?}");

    fs::write(root.join("new.txt"), "NEW")?;
    let result = encrypt_repo(
        &open(root),
        &["new.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        false,
    );
    assert!(
        matches!(result, Err(git_simple_encrypt::Error::Config(_))),
        "an unreadable HEAD config must fail closed, got {result:?}"
    );
    assert_eq!(fs::read_to_string(root.join("new.txt"))?, "NEW");
    Ok(())
}

/// Regression (A-08): `git-se pwd` on a list that is entirely plaintext must
/// encrypt those files with the new password, not report "nothing to do"
/// and leave them in the clear. Driven through the real binary so the
/// password prompts read from a pipe; no GIT_SE_PASSWORD is set, which also
/// proves the pointless OLD-password prompt is gone.
#[test]
fn test_pwd_encrypts_all_plaintext_list() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("f.txt"), "PLAIN")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"f.txt\"]\n",
    )?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_git-se"))
        .args(["--repo", root.to_str().unwrap(), "pwd"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    use std::io::Write as _;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"new-password\nnew-password\n")?;
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "pwd must succeed on an all-plaintext list: {output:?}"
    );
    assert!(
        root.join("f.txt").is_encrypted(),
        "the listed plaintext must have been encrypted with the new password"
    );

    // ... and it must be the NEW password the file answers to.
    decrypt_repo(&open(root), &[], Password::new(b"new-password"))?;
    assert_eq!(fs::read_to_string(root.join("f.txt"))?, "PLAIN");
    Ok(())
}

/// Regression (A-09): the config file gets the same symlink protection as a
/// target file. A config symlinked into `.git` used to be read happily.
#[cfg(unix)]
#[test]
fn test_config_symlink_is_rejected() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(
        root.join(".git/policy.toml"),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = []\n",
    )?;
    std::os::unix::fs::symlink(".git/policy.toml", root.join(CONFIG))?;

    let result = Repo::open(root);
    assert!(
        matches!(result, Err(git_simple_encrypt::Error::SymlinkedTarget(_))),
        "a symlinked config must be rejected, got {result:?}"
    );
    Ok(())
}

/// Regression (A-03d): a second git-se process fails fast instead of
/// interfering with the first one's transaction files.
#[test]
fn test_second_process_fails_fast_on_repo_lock() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = []\n",
    )?;

    let _repo = open(root); // holds the lock for the rest of this process
    let output = Command::new(env!("CARGO_BIN_EXE_git-se"))
        .args(["--repo", root.to_str().unwrap(), "check"])
        .output()?;
    assert!(
        !output.status.success(),
        "the second process must fail, got: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("another git-se process is running"),
        "expected the RepoLocked message, got: {stderr}"
    );
    Ok(())
}

/// Regression (A-10): the staged-check policy is the UNION of the staged and
/// the working-tree config — a deliberate fail-closed: a file covered by
/// either is checked. Documenting the semantics so a future "strictly
/// index-only" simplification does not silently re-open the gap.
#[test]
fn test_staged_policy_is_union_by_design() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("a.txt"), "PLAIN")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = []\n",
    )?;
    git_args(&["add", "-A"], root);
    // The staged config demands nothing; the working tree (unstaged) covers a.txt.
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"a.txt\"]\n",
    )?;

    let err = open(root).check(&[], true).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::FilesNotEncrypted(1, 1)),
        "the working-tree half of the union must still demand encryption, got {err:?}"
    );
    Ok(())
}

// ============ region: 2026-07 second-round audit regression tests ============

/// Regression (B-01): a large blob sorting before a small one must not shift
/// the small blob's recorded size. The batched probe used to zip the filtered
/// small list with the unfiltered size list, so the anchor got the large
/// blob's `total_len`, failed the framing check, and a wrong password sailed
/// through.
#[test]
fn test_head_anchor_not_misized_by_large_blob() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    // > SMALL_BLOB_LIMIT (64 KiB) so it takes the large path in the probe,
    // and sized so the WRONG size fails framing (65640: body % chunk == 0).
    fs::write(root.join("aaa_large.txt"), vec![0u8; 65640])?;
    fs::write(root.join("zzz_anchor.txt"), "ANCHOR")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\".\"]\n",
    )?;
    encrypt_some(root, &["zzz_anchor.txt".into()])?;
    git_commit_all(root);

    fs::write(root.join("new.txt"), "NEW")?;
    let result = encrypt_repo(
        &open(root),
        &["new.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        false,
    );
    assert!(
        matches!(result, Err(git_simple_encrypt::Error::PasswordChanged(_))),
        "the small anchor behind the large blob must still veto the wrong password, got {result:?}"
    );
    assert_eq!(fs::read_to_string(root.join("new.txt"))?, "NEW");
    Ok(())
}

/// Regression (B-01, staged variant): the same size mix-up made a small
/// ENCRYPTED staged file look unencrypted (its framing checked against a
/// large neighbor's size), wrongly blocking the commit.
#[test]
fn test_staged_check_small_blob_after_large_blob() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    // Incompressible, so the encrypted form stays above the large-blob limit.
    let mut big = vec![0u8; 70_000];
    rand::rng().fill_bytes(&mut big);
    fs::write(root.join("aaa_big.bin"), &big)?;
    fs::write(root.join("zzz_small.txt"), "small secret")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\".\"]\n",
    )?;
    encrypt_all(root)?;
    assert!(root.join("aaa_big.bin").is_encrypted());
    assert!(root.join("zzz_small.txt").is_encrypted());
    git_args(&["add", "-A"], root);

    open(root).check(&[], true).map_err(|e| {
        anyhow::anyhow!("two properly encrypted staged files must pass the check: {e}")
    })?;
    Ok(())
}

/// Regression (B-02): `--allow-password-change` skips ONLY the HEAD anchor
/// check. An already-encrypted target that does not authenticate with the
/// given password — tampered with, or encrypted under another password — is
/// an error even with the flag, never a silent skip.
#[test]
fn test_allow_password_change_still_authenticates_targets() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    let mut data = vec![0u8; 70_000];
    rand::rng().fill_bytes(&mut data);
    fs::write(root.join("big.bin"), &data)?;
    run(
        SubCommand::Add {
            paths: vec!["big.bin".into()],
        },
        root,
    )?;
    encrypt_all(root)?;

    // Tamper: plaintext appended after a full leading chunk.
    let mut tampered = fs::read(root.join("big.bin"))?;
    tampered.extend_from_slice(b"PLAINTEXT_SECRET");
    fs::write(root.join("big.bin"), &tampered)?;

    let result = encrypt_repo(&open(root), &[], Password::new(PASSWORD.as_bytes()), true);
    assert!(
        result.is_err(),
        "a tampered file must be reported even with --allow-password-change"
    );

    // Restore, then re-encrypt under a DIFFERENT password: the file is now
    // foreign to the original password, flag or not.
    fs::write(root.join("big.bin"), &data)?;
    encrypt_repo(&open(root), &[], Password::new(PASSWORD.as_bytes()), true)?;
    let result = encrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()), true);
    assert!(
        result.is_err(),
        "a file encrypted under another password must not be silently skipped"
    );
    Ok(())
}

/// Regression (B-06): a HEAD that cannot be resolved although commits exist
/// (a corrupt or repointed ref) must fail closed — only a genuinely fresh
/// repository is "nothing to verify against".
#[test]
fn test_broken_head_fails_closed() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("a.txt"), "A")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\".\"]\n",
    )?;
    encrypt_some(root, &["a.txt".into()])?;
    git_commit_all(root);

    // Point HEAD at a ref that does not exist: commits remain reachable via
    // refs, but HEAD no longer resolves.
    fs::write(root.join(".git/HEAD"), "ref: refs/heads/bogus\n")?;

    fs::write(root.join("new.txt"), "NEW")?;
    let result = encrypt_repo(
        &open(root),
        &["new.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        false,
    );
    assert!(
        matches!(result, Err(git_simple_encrypt::Error::Git(_))),
        "a broken HEAD must fail closed, got {result:?}"
    );
    assert_eq!(fs::read_to_string(root.join("new.txt"))?, "NEW");
    Ok(())
}

/// Regression (B-07): "any single success is proof the password was used
/// before" — a matching anchor must be found behind ANY number of
/// non-matching ones; the attempt count is no longer capped.
#[test]
fn test_matching_anchor_behind_many_others() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    for i in 0..=8 {
        fs::write(root.join(format!("f{i}.txt")), vec![0u8; 104])?;
    }
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\".\"]\n",
    )?;
    // f0..f7 with password A, f8 with password B — both before any commit,
    // so neither run has anchors to check against.
    let eight: Vec<PathBuf> = (0..8).map(|i| format!("f{i}.txt").into()).collect();
    encrypt_repo(&open(root), &eight, Password::new(b"password-A"), false)?;
    encrypt_repo(
        &open(root),
        &["f8.txt".into()],
        Password::new(b"password-B"),
        false,
    )?;
    git_commit_all(root);

    fs::write(root.join("new.txt"), "NEW")?;
    // Password B matches only f8 — the NINTH anchor. It must still match.
    encrypt_repo(
        &open(root),
        &["new.txt".into()],
        Password::new(b"password-B"),
        false,
    )?;
    assert!(root.join("new.txt").is_encrypted());

    // And a password matching NO anchor must still be rejected.
    fs::write(root.join("new2.txt"), "NEW2")?;
    let result = encrypt_repo(
        &open(root),
        &["new2.txt".into()],
        Password::new(b"password-C"),
        false,
    );
    assert!(
        matches!(result, Err(git_simple_encrypt::Error::PasswordChanged(_))),
        "a password with no matching anchor must be rejected, got {result:?}"
    );
    Ok(())
}

// ============ region: 2026-07 seventh-round audit regression tests ============

/// Regression (2026-07 audit): an UNREADABLE old-password ciphertext must
/// not slip past the single-password scope check. The probe used to fold
/// read errors into "not encrypted, skip", so `--allow-password-change`
/// recreated the mixed-password state the check exists to prevent.
#[cfg(unix)]
#[test]
fn test_allow_password_change_fails_on_unreadable_ciphertext() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("a.txt"), "AAA")?;
    fs::write(root.join("b.txt"), "BBB")?;
    run(
        SubCommand::Add {
            paths: vec!["a.txt".into(), "b.txt".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);

    decrypt_some(root, &["b.txt".into()])?;
    // The old-password ciphertext becomes unreadable.
    fs::set_permissions(root.join("a.txt"), fs::Permissions::from_mode(0o000))?;

    let err = encrypt_repo(
        &open(root),
        &["b.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        true,
    )
    .unwrap_err();
    assert!(
        !matches!(err, git_simple_encrypt::Error::BatchFile { .. }),
        "the scope check itself must fail (before any per-file work), got {err:?}"
    );
    // Nothing was written: b.txt is still plaintext, a.txt untouched.
    assert!(root.join("b.txt").is_not_encrypted());
    fs::set_permissions(root.join("a.txt"), fs::Permissions::from_mode(0o600))?;
    decrypt_some(root, &["a.txt".into()])?;
    assert_eq!(fs::read_to_string(root.join("a.txt"))?, "AAA");
    Ok(())
}

/// Regression (2026-07 audit): a NESTED repository whose real git dir lives
/// inside the worktree under a non-`.git` name (via a `.git` pointer file)
/// must be protected exactly like the outer one: whole-repo encryption
/// prunes it, and explicit targets into it are rejected.
#[test]
fn test_nested_separate_git_dir_is_protected() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();

    // inner/ is a nested repo with .git a POINTER FILE to inner/meta.
    let inner = root.join("inner");
    let out = Command::new("git")
        .arg("init")
        .arg("--separate-git-dir")
        .arg(inner.join("meta"))
        .arg(&inner)
        .output()?;
    assert!(out.status.success(), "git init failed: {out:?}");
    assert!(
        fs::metadata(inner.join(".git"))?.is_file(),
        "setup: the nested .git must be a pointer file"
    );
    fs::write(inner.join("file.txt"), "nested content")?;

    // Whole-repo encryption must prune the nested git dir but still process
    // the nested worktree's ordinary files.
    fs::write(root.join("plain.txt"), "outer content")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\".\"]\n",
    )?;
    encrypt_all(root)?;
    assert!(root.join("plain.txt").is_encrypted());
    assert!(
        inner.join("file.txt").is_encrypted(),
        "nested worktree content stays in scope"
    );
    assert!(
        !fs::read(inner.join("meta/HEAD"))?.starts_with(b"GITSE"),
        "the nested git dir must never be encrypted"
    );

    // Explicit targets into the nested git dir are rejected too.
    for protected in ["inner/meta", "inner/meta/HEAD"] {
        let err = encrypt_some(root, &[protected.into()]).unwrap_err();
        assert!(
            matches!(
                err,
                git_simple_encrypt::Error::ProtectedPath(_) | git_simple_encrypt::Error::NoFile(_)
            ),
            "{protected} must not be encryptable, got {err:?}"
        );
    }

    // Both repositories still work.
    let out = git_args(&["rev-parse", "--is-inside-work-tree"], root);
    assert!(
        out.status.success(),
        "outer repo must stay healthy: {out:?}"
    );
    let out = git_args(&["rev-parse", "--is-inside-work-tree"], &inner);
    assert!(
        out.status.success(),
        "inner repo must stay healthy: {out:?}"
    );
    Ok(())
}

// ============ region: 2026-07 sixth-round audit regression tests ============

/// Regression (2026-07 audit): `--allow-password-change` must not be able to
/// leave the repository in a mixed-password state. It used to authenticate
/// only THIS run's targets, so re-encrypting a decrypted subset under a new
/// password succeeded while the rest still answered to the old one — a
/// state `git-se p` cannot repair. The flag now verifies every encrypted
/// file in the whole crypt list against the given password.
#[test]
fn test_allow_password_change_cannot_create_mixed_passwords() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(root.join("a.txt"), "AAA")?;
    fs::write(root.join("b.txt"), "BBB")?;
    run(
        SubCommand::Add {
            paths: vec!["a.txt".into(), "b.txt".into()],
        },
        root,
    )?;
    encrypt_all(root)?;
    git_commit_all(root);

    // Decrypt only b.txt, then re-encrypt it under a NEW password with the
    // flag: the scope check must refuse — a.txt still answers to the old one.
    decrypt_some(root, &["b.txt".into()])?;
    let err = encrypt_repo(
        &open(root),
        &["b.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        true,
    )
    .unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::ForeignCiphertext(_)),
        "expected ForeignCiphertext for the old-password a.txt, got {err:?}"
    );
    // Nothing was written: b.txt is still plaintext, a.txt still old-password.
    assert!(root.join("b.txt").is_not_encrypted());
    decrypt_some(root, &["a.txt".into()])?;
    assert_eq!(fs::read_to_string(root.join("a.txt"))?, "AAA");

    // With EVERYTHING plaintext the flag remains the supported way to
    // establish a new password, and it still works.
    encrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()), true)?;
    decrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()))?;
    assert_eq!(fs::read_to_string(root.join("a.txt"))?, "AAA");
    assert_eq!(fs::read_to_string(root.join("b.txt"))?, "BBB");

    // Staged migration keeps working: already-migrated files authenticate
    // under the SAME password, so each batch's scope check passes.
    encrypt_repo(
        &open(root),
        &["a.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        true,
    )?;
    encrypt_repo(
        &open(root),
        &["b.txt".into()],
        Password::new(PASSWORD2.as_bytes()),
        true,
    )?;
    decrypt_repo(&open(root), &[], Password::new(PASSWORD2.as_bytes()))?;
    assert_eq!(fs::read_to_string(root.join("a.txt"))?, "AAA");
    assert_eq!(fs::read_to_string(root.join("b.txt"))?, "BBB");
    Ok(())
}

/// Regression (2026-07 audit): a `--separate-git-dir` layout places the REAL
/// git dir inside the worktree under an arbitrary name. It must be as
/// untouchable as `.git`: `add` rejects it, a crypt list pointing into it is
/// refused, and whole-repo encryption prunes it.
#[test]
fn test_separate_git_dir_inside_worktree_is_protected() -> anyhow::Result<()> {
    let outer = TempDir::new()?;
    let root = outer.path().join("repo");
    let out = Command::new("git")
        .arg("init")
        .arg("--separate-git-dir")
        .arg(root.join("meta"))
        .arg(&root)
        .output()?;
    assert!(out.status.success(), "git init failed: {out:?}");
    git_args(&["config", "user.email", "t@example.com"], &root);
    git_args(&["config", "user.name", "t"], &root);

    // Sanity: the resolved git dir really is inside the (resolved) worktree.
    // Compare against `repo.path()`, not a locally canonicalized `root`:
    // both sides were dunce-canonicalized inside `Repo::open`, so the
    // comparison is flavor-safe on Windows (std's `canonicalize` yields a
    // `\\?\`-prefixed verbatim path there, which never `starts_with` a
    // dunce path) and on macOS (/var -> /private/var).
    let mut repo = open(&root);
    assert!(
        repo.git_dir().starts_with(repo.path()),
        "setup: the git dir must be inside the worktree: {} not under {}",
        repo.git_dir().display(),
        repo.path().display()
    );

    // `add` must refuse git internals under their real (non-`.git`) name —
    // including the lock file, whose replacement would silently void the
    // repo mutex.
    for protected in ["meta/HEAD", "meta/git-se.lock"] {
        let err = repo
            .conf
            .add_one_path_to_crypt_list(protected, &repo.protected())
            .unwrap_err();
        assert!(
            matches!(err, git_simple_encrypt::Error::ProtectedPath(_)),
            "expected ProtectedPath for {protected}, got {err:?}"
        );
    }

    // A crypt-list entry covering the git dir must fail target resolution.
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\"meta\"]\n",
    )?;
    let err = encrypt_all(&root).unwrap_err();
    assert!(
        matches!(err, git_simple_encrypt::Error::ProtectedPath(_)),
        "expected ProtectedPath for crypt_list = [\"meta\"], got {err:?}"
    );
    assert!(
        !fs::read(root.join("meta/HEAD"))?.starts_with(b"GITSE"),
        "git's HEAD must never be encrypted"
    );

    // Whole-repo encryption must succeed while pruning the git dir.
    fs::write(root.join("plain.txt"), "encrypt me")?;
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = [\".\"]\n",
    )?;
    encrypt_all(&root)?;
    assert!(root.join("plain.txt").is_encrypted());
    assert!(
        !fs::read(root.join("meta/HEAD"))?.starts_with(b"GITSE"),
        "whole-repo encryption must prune the git dir"
    );

    // The repository still works.
    let out = git_args(&["rev-parse", "--is-inside-work-tree"], &root);
    assert!(out.status.success(), "the repo must stay healthy: {out:?}");
    Ok(())
}

/// Regression (B-08): the repo lock is released when the last `Repo` handle
/// drops — a library host must not block other git-se processes until it
/// exits.
#[test]
fn test_repo_lock_released_on_drop() -> anyhow::Result<()> {
    let pwd = test_init();
    let root = pwd.path();
    fs::write(
        root.join(CONFIG),
        "use_zstd = true\nzstd_level = 15\ncrypt_list = []\n",
    )?;

    let git_se_check = || {
        Command::new(env!("CARGO_BIN_EXE_git-se"))
            .args(["--repo", root.to_str().unwrap(), "check"])
            .output()
            .unwrap()
    };

    let repo = open(root);
    let clone = repo.clone();
    assert!(
        !git_se_check().status.success(),
        "a live Repo must block a second process"
    );
    drop(repo);
    assert!(
        !git_se_check().status.success(),
        "a surviving clone must keep the lock held"
    );
    drop(clone);
    // No handles left: the lock is gone. (`check` still exits non-zero here
    // because the crypt list is empty — but with NoFile, not RepoLocked.)
    let output = git_se_check();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("another git-se process is running"),
        "the lock must be released after the last handle drops: {stderr}"
    );
    Ok(())
}
