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

fn bench_init() -> TempDir {
    let pwd = TempDir::new().unwrap();

    // Initialize a new repository
    exec("git init", pwd.path()).unwrap();

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
    let err = repo.conf.add_one_path_to_crypt_list(&name).unwrap_err();
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

    fs::write(root.join("secret.txt"), "PLAINTEXT_SECRET")?;
    run(
        SubCommand::Add {
            paths: vec!["secret.txt".into()],
        },
        root,
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
