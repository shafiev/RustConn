//! `SSH_ASKPASS` helper for delivering stored account passwords to OpenSSH.
//!
//! The helper is a small POSIX `sh` script that holds no secret: it only names
//! an environment variable whose value is the *path* of an owner-only secret
//! file. OpenSSH runs the script, the script checks the prompt, and prints the
//! file only for an account-password prompt. The password therefore never
//! appears in `argv` or in `/proc/<pid>/environ`.
//!
//! This module owns:
//!
//! * the prompt-aware helper script and its per-process cache ([`helper_script`]),
//! * the owner-only secret files ([`create_secret_file`]),
//! * the per-child environment for one SSH launch ([`child_env`]).
//!
//! # Where an askpass secret may live
//!
//! Every askpass secret file is placed by one resolver, `secret_dir`:
//! [`crate::secret_file_dir`] (`$XDG_RUNTIME_DIR` on Linux, `$TMPDIR` on macOS)
//! and, only when that declines (a Linux session without a runtime directory,
//! such as `su`, a container or `cron`), the system temp directory. In the temp
//! directory a file is only ever created under a random UUID name, atomically
//! (`O_EXCL`), with mode 0600, so a password can still be delivered there. A
//! missing runtime directory never disables askpass.
//!
//! Key passphrases are out of scope on purpose: the helper refuses every
//! `*passphrase*` prompt, and no passphrase is stored or fetched here.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Environment variable carrying the target account password to the outer
/// OpenSSH process. Nested proxy hops explicitly clear it before starting SSH.
pub const TARGET_PASSWORD_ENV: &str = "_RC_TGT_PW_FILE";

/// File-name prefix of the secret files written by [`create_secret_file`].
const SECRET_FILE_PREFIX: &str = "rustconn-askpass-secret-";

/// Which credential an askpass helper releases.
///
/// A closed set rather than a free-form env var name, so a caller can never
/// turn an arbitrary string into a file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AskpassSlot {
    /// Target account password; env `_RC_TGT_PW_FILE`, script
    /// `rustconn-target-askpass.sh`.
    Target,
    /// Bastion `n` of the jump chain (issue #203). The env var is named by
    /// [`jump_host_pw_env_name`](crate::ssh_tunnel::jump_host_pw_env_name); the
    /// script is `rustconn-jh-askpass.sh` for `n = 0` or
    /// `rustconn-jh-askpass-{n}.sh` for deeper hops.
    JumpHost(usize),
}

impl AskpassSlot {
    /// Name of the env var the helper reads its secret-file path from.
    ///
    /// Index 0 keeps the legacy single-bastion name `_RC_JH_PW_FILE`; deeper
    /// hops use `_RC_JH_PW_FILE_1`, `_RC_JH_PW_FILE_2`, and so on.
    #[must_use]
    pub fn env_var_name(self) -> String {
        match self {
            Self::Target => TARGET_PASSWORD_ENV.to_string(),
            Self::JumpHost(index) => crate::ssh_tunnel::jump_host_pw_env_name(index),
        }
    }
}

/// Failure to create an askpass helper or its secret file.
///
/// Never carries a secret: the wrapped I/O errors describe a path and an OS
/// condition, not file contents.
#[derive(Debug, thiserror::Error)]
pub enum AskpassError {
    /// The helper script could not be written.
    #[error("Failed to write askpass helper script: {0}")]
    WriteScript(#[source] std::io::Error),
    /// The helper script could not be made executable.
    #[error("Failed to set askpass helper script permissions: {0}")]
    ScriptPermissions(#[source] std::io::Error),
    /// The secret file could not be created (including an already existing path).
    #[error("Failed to create askpass secret file: {0}")]
    CreateSecretFile(#[source] std::io::Error),
    /// Writing the password into the secret file failed; the file was removed.
    #[error("Failed to write askpass secret file: {0}")]
    WriteSecretFile(#[source] std::io::Error),
    /// The in-process helper cache lock was poisoned by a panicking thread.
    #[error("Askpass helper cache is unavailable")]
    CachePoisoned,
}

/// Builds a helper that releases a credential only for an account-password prompt.
///
/// The matcher mirrors [`crate::looks_like_password_prompt`]
/// (the terminal-watcher matcher): the shell `case` is **exclusion-first, then a broad
/// positive match**. It lowercases the prompt, rejects the prompts that must never receive
/// the account password — host-key confirmation, private-key passphrases, OTP/verification
/// challenges, and password-*change* prompts (`old`/`current`/`new`/`retype`/`confirm`/
/// `verify`/`repeat`, incl. uk/ru) — and only then accepts any account-password prompt.
///
/// Unlike the old `*"'s password:"*`-only glob, the positive branch accepts the
/// server-/PAM-defined keyboard-interactive forms (`Password:`, ESXi's
/// `(root@host) Password:`, localized `пароль:`/`passwort:`/`密码：`/`パスワード:` …),
/// which is why issue #364 (ESXi via a jump host) was failing.
///
/// POSIX `sh` note: `tr '[:upper:]' '[:lower:]'` folds **ASCII only**, so the ASCII
/// branches match against the folded copy `$lc`, while non-ASCII suffixes match against
/// the **raw** `$prompt`. To stay case-insensitive without Unicode folding, the localized
/// suffixes that have an uppercase first letter are matched by their first-letter-agnostic
/// tail (e.g. `*ароль:` catches both `Пароль:` and `пароль:`); CJK/Kana suffixes are
/// caseless and matched whole.
///
/// Re-invocation: the helper **reads** the secret file (`exec 3<` + `cat`) and
/// must NOT delete it. OpenSSH counts `NumberOfPasswordPrompts` per *method*, so a
/// server offering both `keyboard-interactive` and `password` runs this script
/// **twice** against the same `$secret_file` path (the env-var name is fixed; only
/// the path's value is per-connection). An in-script `rm -f` after the first read
/// left the second invocation with no file → an empty password → `Permission
/// denied` (issue
/// [#382](https://github.com/totoshko88/RustConn/issues/382), a regression from
/// the keyboard-interactive support added in #364). Cleanup is owned elsewhere:
/// every secret-file path is registered in the cleanup list returned by
/// [`child_env`] and removed by the GUI's `watch_child_exit` when the ssh child
/// exits, and the file lives in a user-private tmpfs dir (`$XDG_RUNTIME_DIR`, mode
/// 0600) — never world-writable `/tmp` — so the in-script delete bought no extra
/// security.
#[must_use]
pub fn script_contents(slot: AskpassSlot) -> String {
    let env_var_name = slot.env_var_name();
    format!(
        "#!/bin/sh\n\
         prompt=\"${{1-}}\"\n\
         lc=$(printf '%s' \"$prompt\" | tr '[:upper:]' '[:lower:]')\n\
         case \"$lc\" in\n\
         \x20\x20# Not the account password — stay silent (passphrase, host-key, OTP, change).\n\
         \x20\x20*passphrase*|*\"verification code\"*|*\"(current)\"*|\\\n\
         \x20\x20*\"old password\"*|*\"current password\"*|*\"new password\"*|\\\n\
         \x20\x20*\"retype password\"*|*\"retype new password\"*|*\"confirm password\"*|\\\n\
         \x20\x20*\"verify password\"*|*\"repeat password\"*)\n\
         \x20\x20\x20\x20exit 1 ;;\n\
         esac\n\
         case \"$prompt\" in\n\
         \x20\x20# Localized password-change prompts (non-ASCII, matched raw, first-letter-agnostic).\n\
         \x20\x20*\"тарий пароль\"*|*\"тарый пароль\"*|*\"овий пароль\"*|*\"овый пароль\"*)\n\
         \x20\x20\x20\x20exit 1 ;;\n\
         esac\n\
         case \"$lc\" in\n\
         \x20\x20# OpenSSH `password` auth + ASCII PAM/keyboard-interactive account prompts.\n\
         \x20\x20*\"'s password:\"*|*\"password:\"|*\"password: \"|*\"pass:\"|*\"pass: \"|\\\n\
         \x20\x20*\"passwort:\"|*\"passwort: \"|*\"kennwort:\"|*\"kennwort: \"|\\\n\
         \x20\x20*\"mot de passe:\"|*\"mot de passe :\")\n\
         \x20\x20\x20\x20_rc_emit=1 ;;\n\
         \x20\x20*) _rc_emit=0 ;;\n\
         esac\n\
         if [ \"$_rc_emit\" = 0 ]; then\n\
         \x20\x20case \"$prompt\" in\n\
         \x20\x20\x20\x20# Non-ASCII account prompts, matched raw (first-letter-agnostic where cased).\n\
         \x20\x20\x20\x20*\"ontraseña:\"|*\"enha:\"|*\"ароль:\"|*\"ароль: \"|*\"asło:\"|*\"eslo:\"|\\\n\
         \x20\x20\x20\x20*\"achtwoord:\"|*\"ösenord:\"|*\"dgangskode:\"|\\\n\
         \x20\x20\x20\x20*\"密码:\"|*\"密码：\"|*\"密碼:\"|*\"密碼：\"|\\\n\
         \x20\x20\x20\x20*\"パスワード:\"|*\"パスワード：\"|*\"비밀번호:\"|*\"비밀번호：\")\n\
         \x20\x20\x20\x20\x20\x20_rc_emit=1 ;;\n\
         \x20\x20esac\n\
         fi\n\
         [ \"$_rc_emit\" = 1 ] || exit 1\n\
         secret_file=\"${{{env_var_name}}}\"\n\
         [ -n \"$secret_file\" ] || exit 1\n\
         exec 3<\"$secret_file\" || exit 1\n\
         cat <&3\n"
    )
}

/// Returns the path of the cached prompt-aware helper for `slot`, writing it on
/// first use.
///
/// The script holds no secret — only the env var name — so it is safe to keep
/// for the process lifetime and share across sessions. The password is written
/// directly from a [`SecretString`] to a randomized mode-0600 file by
/// [`create_secret_file`]; the env carries only its path, and the helper opens
/// and reads it. It deliberately does not unlink the file (that would break a
/// second, keyboard-interactive invocation — see [`script_contents`], issue
/// #382); cleanup is the caller's job, using the paths from [`child_env`].
///
/// The script itself is placed by the shared resolver (`$XDG_RUNTIME_DIR` on
/// Linux, `$TMPDIR` on macOS; mode 0700) under a stable per-slot name so a
/// reconnect reuses it, avoiding `/tmp` symlink races on a fixed filename.
/// Only when the resolver declines does it fall back to a randomized
/// `temp_dir()` path. Created once and cached per slot. For multi-hop (issue
/// #203), each deeper hop gets its own script reading `_RC_JH_PW_FILE_1`,
/// `_RC_JH_PW_FILE_2`, and so on.
///
/// # Errors
///
/// Returns [`AskpassError::WriteScript`] or [`AskpassError::ScriptPermissions`]
/// if the script cannot be written or made executable (both are also logged at
/// error level), and [`AskpassError::CachePoisoned`] if the cache lock is
/// poisoned.
pub fn helper_script(slot: AskpassSlot) -> Result<PathBuf, AskpassError> {
    static SCRIPTS: OnceLock<Mutex<HashMap<AskpassSlot, PathBuf>>> = OnceLock::new();
    let cache = SCRIPTS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().map_err(|_| AskpassError::CachePoisoned)?;

    if let Some(path) = map.get(&slot) {
        return Ok(path.clone());
    }

    // Shared resolver: `$XDG_RUNTIME_DIR` on Linux, `$TMPDIR` on macOS. When a
    // user-private directory exists the script gets a stable per-slot name so a
    // reconnect reuses it; only when the resolver declines (a Linux box with no
    // runtime dir) do we fall back to a randomized `temp_dir()` path to avoid a
    // fixed name in world-writable `/tmp`.
    let path = script_path_in(crate::secret_file_dir().as_deref(), slot);
    write_script(&path, &script_contents(slot))?;

    map.insert(slot, path.clone());
    drop(map);
    Ok(path)
}

/// Writes `password` to a fresh owner-only secret file and returns its path.
///
/// The file is `rustconn-askpass-secret-<uuid>` in the shared secret directory,
/// created with `create_new` (`O_EXCL`) and mode 0600 set at open time. The
/// caller owns the path and must remove it when the SSH child exits. The
/// password reaches the helper through this file, never through `argv` or the
/// process environment.
///
/// # Errors
///
/// Returns [`AskpassError::CreateSecretFile`] if the file cannot be created
/// (including a pre-existing path) and [`AskpassError::WriteSecretFile`] if
/// writing fails, in which case the file is removed first.
pub fn create_secret_file(password: &SecretString) -> Result<PathBuf, AskpassError> {
    create_prefixed_secret_file(SECRET_FILE_PREFIX, password)
}

/// Builds the per-child askpass environment for one SSH launch.
///
/// Returns the `NAME=value` entries to apply to the child, and the secret files
/// to remove when the child exits. Entries come in a fixed order: one
/// `<hop env>=<path>` per bastion password, then — if `target_password` is
/// given as `(password, helper script)` — `_RC_TGT_PW_FILE=<path>`,
/// `SSH_ASKPASS=<script>` and `SSH_ASKPASS_REQUIRE=force`. A secret file that
/// cannot be created is logged and skipped.
///
/// Concurrency invariant (why this cannot race between simultaneous sessions):
/// the environment is returned as a plain `Vec` and applied only to the one
/// child process spawned for this connection (through the GUI's
/// `build_child_env` → the VTE spawn's env vector). Nothing here touches the
/// *process-global* environment — there is deliberately no
/// `std::env::set_var`, which Rust 2024 forbids anyway. Although the variable
/// *names* are fixed (`_RC_TGT_PW_FILE`, `_RC_JH_PW_FILE`), their *values* are
/// freshly randomised secret-file paths from [`create_secret_file`], so two
/// connections opened at the same time each carry their own file in their own
/// child environment and cannot read each other's password. Keep it that way:
/// never promote these to a global set.
#[must_use]
pub fn child_env(
    jump_host_passwords: &[(AskpassSlot, SecretString)],
    target_password: Option<(&SecretString, &Path)>,
) -> (Vec<Zeroizing<String>>, Vec<PathBuf>) {
    let mut env = Vec::with_capacity(jump_host_passwords.len() + 3);
    let mut cleanup_paths = Vec::with_capacity(jump_host_passwords.len() + 1);
    for (slot, password) in jump_host_passwords {
        match create_secret_file(password) {
            Ok(path) => {
                env.push(Zeroizing::new(format!(
                    "{}={}",
                    slot.env_var_name(),
                    path.display()
                )));
                cleanup_paths.push(path);
            }
            Err(error) => {
                tracing::error!(%error, "Failed to create jump host askpass secret file");
            }
        }
    }
    if let Some((password, script)) = target_password {
        match create_secret_file(password) {
            Ok(path) => {
                env.push(Zeroizing::new(format!(
                    "{TARGET_PASSWORD_ENV}={}",
                    path.display()
                )));
                cleanup_paths.push(path);
                env.push(Zeroizing::new(format!("SSH_ASKPASS={}", script.display())));
                env.push(Zeroizing::new("SSH_ASKPASS_REQUIRE=force".to_string()));
            }
            Err(error) => {
                tracing::error!(%error, "Failed to create target askpass secret file");
            }
        }
    }
    (env, cleanup_paths)
}

/// Directory every askpass secret file is created in.
///
/// The one fallback policy for all askpass secrets: the shared resolver
/// ([`crate::secret_file_dir`]: `$XDG_RUNTIME_DIR` on Linux, `$TMPDIR` on
/// macOS), and only when it declines — a Linux box with no runtime dir, unusual —
/// the weaker `temp_dir()`, so a password can still be delivered rather than
/// dropped. Files there are random-named, `O_EXCL`, mode 0600.
fn secret_dir() -> PathBuf {
    crate::secret_file_dir().unwrap_or_else(std::env::temp_dir)
}

/// Picks the helper script path: a stable per-slot name inside `dir`, or a
/// randomized `temp_dir()` name when there is no private directory.
fn script_path_in(dir: Option<&Path>, slot: AskpassSlot) -> PathBuf {
    match dir {
        Some(dir) => match slot {
            AskpassSlot::Target => dir.join("rustconn-target-askpass.sh"),
            AskpassSlot::JumpHost(0) => dir.join("rustconn-jh-askpass.sh"),
            // Unique file per hop index: rustconn-jh-askpass-1.sh, etc.
            AskpassSlot::JumpHost(index) => dir.join(format!("rustconn-jh-askpass-{index}.sh")),
        },
        None => std::env::temp_dir().join(format!("rc-askpass-{}.sh", Uuid::new_v4())),
    }
}

/// Writes the helper script and makes it executable (mode 0700).
///
/// Overwrites an existing file at `path`: the stable per-slot name is reused
/// after an application restart.
fn write_script(path: &Path, contents: &str) -> Result<(), AskpassError> {
    if let Err(e) = std::fs::write(path, contents.as_bytes()) {
        tracing::error!(error = %e, "Failed to create SSH askpass script");
        return Err(AskpassError::WriteScript(e));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
            tracing::error!(error = %e, "Failed to chmod SSH askpass script");
            return Err(AskpassError::ScriptPermissions(e));
        }
    }

    Ok(())
}

/// Opens `path` for writing, failing if it already exists (`O_EXCL`), with mode
/// 0600 set at open time on Unix. A symlink at `path` is not followed.
fn open_new_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Creates `<dir>/<prefix><uuid>` with the password inside; see
/// [`create_secret_file`].
fn create_secret_file_in(
    dir: &Path,
    prefix: &str,
    password: &SecretString,
) -> Result<PathBuf, AskpassError> {
    let path = dir.join(format!("{prefix}{}", Uuid::new_v4()));
    let mut file = open_new_owner_only(&path).map_err(AskpassError::CreateSecretFile)?;
    if let Err(error) = file.write_all(password.expose_secret().as_bytes()) {
        drop(file);
        let _ = std::fs::remove_file(&path);
        return Err(AskpassError::WriteSecretFile(error));
    }
    drop(file);
    Ok(path)
}

/// Like [`create_secret_file`] with a caller-chosen file-name prefix, for the
/// SSH tunnel's secret files (`rc-tun-secret-`).
pub(crate) fn create_prefixed_secret_file(
    prefix: &str,
    password: &SecretString,
) -> Result<PathBuf, AskpassError> {
    create_secret_file_in(&secret_dir(), prefix, password)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// SHA-256 of the helper script as shipped in 0.23.21 (`rustconn` crate,
    /// `askpass_script_contents`), captured before the move.
    const GOLDEN_TARGET: &str = "b054fa0a1da0ec5a59cbcc2a6a34d2a6962a8150e44d3416110d3277b704a248";
    const GOLDEN_JUMP_HOST_0: &str =
        "9acb167be044ba83a99ab8a00a01cb3ad005014ea8a9185b1052c85123ac5b4b";
    const GOLDEN_JUMP_HOST_1: &str =
        "7c3ffd6fb39d73f5d75c1851378c8da7851327b5a7ab5f41a1e540e6de3573a7";

    fn sha256_hex(text: &str) -> String {
        hex::encode(ring::digest::digest(&ring::digest::SHA256, text.as_bytes()).as_ref())
    }

    fn run_askpass_script(prompt: &str) -> (std::process::Output, PathBuf) {
        let secret_path =
            std::env::temp_dir().join(format!("rustconn-askpass-test-secret-{}", Uuid::new_v4()));
        std::fs::write(&secret_path, b"test-account-password")
            .expect("test secret file must be writable");
        let output = std::process::Command::new("sh")
            .args([
                "-c",
                &script_contents(AskpassSlot::Target),
                "rustconn-askpass-test",
                prompt,
            ])
            .env(TARGET_PASSWORD_ENV, &secret_path)
            .output()
            .expect("test askpass script must run");
        (output, secret_path)
    }

    #[test]
    fn script_bytes_are_unchanged_from_the_gui_helper() {
        for (slot, golden) in [
            (AskpassSlot::Target, GOLDEN_TARGET),
            (AskpassSlot::JumpHost(0), GOLDEN_JUMP_HOST_0),
            (AskpassSlot::JumpHost(1), GOLDEN_JUMP_HOST_1),
        ] {
            assert_eq!(
                sha256_hex(&script_contents(slot)),
                golden,
                "helper script bytes changed for {slot:?}"
            );
        }

        let target = script_contents(AskpassSlot::Target);
        assert!(target.starts_with("#!/bin/sh\n"));
        assert!(target.contains("secret_file=\"${_RC_TGT_PW_FILE}\""));
        assert!(target.contains("*passphrase*"));
        assert!(
            script_contents(AskpassSlot::JumpHost(0)).contains("secret_file=\"${_RC_JH_PW_FILE}\"")
        );
        assert!(
            script_contents(AskpassSlot::JumpHost(1))
                .contains("secret_file=\"${_RC_JH_PW_FILE_1}\"")
        );
    }

    #[test]
    fn slot_env_var_names() {
        assert_eq!(AskpassSlot::Target.env_var_name(), "_RC_TGT_PW_FILE");
        assert_eq!(AskpassSlot::JumpHost(0).env_var_name(), "_RC_JH_PW_FILE");
        assert_eq!(AskpassSlot::JumpHost(2).env_var_name(), "_RC_JH_PW_FILE_2");
    }

    #[test]
    fn script_path_uses_stable_names_in_a_private_dir() {
        let dir = Path::new("/run/user/1000");
        assert_eq!(
            script_path_in(Some(dir), AskpassSlot::Target),
            dir.join("rustconn-target-askpass.sh")
        );
        assert_eq!(
            script_path_in(Some(dir), AskpassSlot::JumpHost(0)),
            dir.join("rustconn-jh-askpass.sh")
        );
        assert_eq!(
            script_path_in(Some(dir), AskpassSlot::JumpHost(1)),
            dir.join("rustconn-jh-askpass-1.sh")
        );
    }

    #[test]
    fn script_path_without_a_private_dir_is_random_in_temp_dir() {
        let first = script_path_in(None, AskpassSlot::Target);
        let second = script_path_in(None, AskpassSlot::Target);
        assert_eq!(first.parent(), Some(std::env::temp_dir().as_path()));
        let name = first
            .file_name()
            .and_then(|n| n.to_str())
            .expect("script name must be UTF-8");
        assert!(
            name.starts_with("rc-askpass-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("sh"))
        );
        assert_ne!(first, second, "fallback names must be random");
    }

    #[test]
    fn script_is_written_with_mode_0700_and_can_be_rewritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("helper.sh");
        let body = script_contents(AskpassSlot::Target);

        write_script(&path, &body).expect("first write");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read"), body);

        // A stable name is reused after an application restart.
        write_script(&path, &body).expect("rewrite over an existing file");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn helper_script_is_cached_per_slot_and_executable() {
        let first = helper_script(AskpassSlot::Target).expect("helper must be created");
        let again = helper_script(AskpassSlot::Target).expect("helper must be cached");
        assert_eq!(first, again);
        assert_eq!(
            std::fs::metadata(&first)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read_to_string(&first).expect("read"),
            script_contents(AskpassSlot::Target)
        );
    }

    #[test]
    fn askpass_secret_file_is_owner_only_and_not_an_environment_value() {
        let secret = SecretString::new("file-only-secret".to_string().into());
        let path = create_secret_file(&secret).expect("secret file must be created");
        let metadata = std::fs::metadata(&path).expect("secret file metadata must exist");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read(&path).expect("secret file must be readable"),
            b"file-only-secret"
        );
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("secret name must be UTF-8");
        assert!(name.starts_with(SECRET_FILE_PREFIX));
        std::fs::remove_file(path).expect("test secret file must be removed");
    }

    #[test]
    fn secret_file_in_a_dir_has_exact_content_prefix_and_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let secret = SecretString::from("exact-bytes ");
        let path = create_secret_file_in(dir.path(), "probe-", &secret).expect("create");
        assert_eq!(path.parent(), Some(dir.path()));
        assert!(
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("probe-"))
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(std::fs::read(&path).expect("read"), b"exact-bytes ");
    }

    #[test]
    fn secret_file_creation_refuses_an_existing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("occupied");
        std::fs::write(&path, b"original").expect("seed");

        let error = open_new_owner_only(&path).expect_err("must not open an existing file");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).expect("read"), b"original");
    }

    #[test]
    fn secret_file_creation_does_not_follow_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("victim");
        std::fs::write(&target, b"victim-content").expect("seed");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        assert!(open_new_owner_only(&link).is_err());
        assert_eq!(std::fs::read(&target).expect("read"), b"victim-content");
    }

    #[test]
    fn child_env_carries_paths_in_order_and_never_a_password() {
        let jump_pw = SecretString::from("jump-secret-value");
        let target_pw = SecretString::from("target-secret-value");
        let script = Path::new("/run/user/1000/rustconn-target-askpass.sh");

        let (env, cleanup) = child_env(
            &[(AskpassSlot::JumpHost(0), jump_pw)],
            Some((&target_pw, script)),
        );

        assert_eq!(cleanup.len(), 2);
        let expected = [
            format!("_RC_JH_PW_FILE={}", cleanup[0].display()),
            format!("_RC_TGT_PW_FILE={}", cleanup[1].display()),
            format!("SSH_ASKPASS={}", script.display()),
            "SSH_ASKPASS_REQUIRE=force".to_string(),
        ];
        let actual: Vec<&str> = env.iter().map(|entry| entry.as_str()).collect();
        assert_eq!(actual, expected);

        for (path, password) in [
            (&cleanup[0], "jump-secret-value"),
            (&cleanup[1], "target-secret-value"),
        ] {
            assert_eq!(
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(std::fs::read(path).expect("read"), password.as_bytes());
        }
        let rendered = format!("{env:?}");
        assert!(!rendered.contains("jump-secret-value"));
        assert!(!rendered.contains("target-secret-value"));

        for path in cleanup {
            std::fs::remove_file(path).expect("cleanup");
        }

        let (env, cleanup) = child_env(&[], None);
        assert!(env.is_empty() && cleanup.is_empty());
    }

    #[test]
    fn errors_and_slots_do_not_leak_the_password() {
        let missing = Path::new("/nonexistent-rustconn-askpass-dir");
        let secret = SecretString::from("hunter2-leak-probe");
        let error = create_secret_file_in(missing, "probe-", &secret)
            .expect_err("a missing directory must fail");

        assert!(matches!(error, AskpassError::CreateSecretFile(_)));
        assert!(!format!("{error}").contains("hunter2-leak-probe"));
        assert!(!format!("{error:?}").contains("hunter2-leak-probe"));
        assert_eq!(format!("{:?}", AskpassSlot::JumpHost(3)), "JumpHost(3)");
    }

    #[test]
    fn askpass_helper_releases_password_only_for_account_prompt() {
        // Every account-password prompt the helper must answer: OpenSSH's own
        // `password` auth, PAM/keyboard-interactive forms (ESXi, generic PAM,
        // Dropbear), and the localized variants mirrored from the Rust matcher.
        // Issue #364: ESXi authenticates via keyboard-interactive, so its prompt
        // is `(root@host) Password:` — the old `'s password:`-only glob missed it.
        for accepted_prompt in [
            "alice@example.com's password: ",
            "Password: ",
            "Password:",
            "(root@esxi.example.com) Password: ", // ESXi via jump host (#364)
            "root@192.0.2.10's password:",
            "Пароль: ",
            "Passwort:",
            "密码：",
        ] {
            let (accepted, accepted_secret_path) = run_askpass_script(accepted_prompt);
            assert!(
                accepted.status.success(),
                "should accept account prompt: {accepted_prompt:?}"
            );
            assert_eq!(
                accepted.stdout, b"test-account-password",
                "wrong output for: {accepted_prompt:?}"
            );
            // The helper must READ, never delete: OpenSSH re-invokes it per
            // auth method (keyboard-interactive + password), so the file has to
            // survive the first read (issue #382). Cleanup is owned by the
            // caller, not by the script.
            assert!(
                accepted_secret_path.exists(),
                "secret file must survive a read for: {accepted_prompt:?}"
            );
            assert_eq!(
                std::fs::read(&accepted_secret_path).expect("secret file must still be readable"),
                b"test-account-password",
                "secret content must be intact after a read for: {accepted_prompt:?}"
            );
            std::fs::remove_file(&accepted_secret_path)
                .expect("test secret file must be removed by the test");
        }

        // Prompts that must NEVER receive the account password: key passphrase,
        // host-key confirmation, OTP/verification, password-change (any stage),
        // and sudo (sudo asks for the *local* password, not the SSH account).
        for rejected_prompt in [
            "Enter passphrase for key '/home/alice/.ssh/id_ed25519': ",
            "Enter passphrase for /home/alice/.ssh/id_ed25519: ",
            "The authenticity of host cannot be established. Continue connecting (yes/no)? ",
            "Verification code: ",
            "Password expired. Enter new password: ",
            "(current) UNIX password: ",
            "Old Password: ",
            "Retype new password: ",
            "Confirm password: ",
            "Старий пароль: ",
            "[sudo] password for alice: ",
            "",
        ] {
            let (rejected, rejected_secret_path) = run_askpass_script(rejected_prompt);
            assert!(
                !rejected.status.success(),
                "must reject prompt: {rejected_prompt:?}"
            );
            assert!(
                rejected.stdout.is_empty(),
                "leaked password for: {rejected_prompt:?}"
            );
            std::fs::remove_file(rejected_secret_path)
                .expect("rejected prompt must leave the test file for owner cleanup");
        }
    }

    /// Regression for issue
    /// [#382](https://github.com/totoshko88/RustConn/issues/382): OpenSSH counts
    /// `NumberOfPasswordPrompts` per *method*, so a server offering both
    /// `keyboard-interactive` and `password` runs the one askpass helper **twice**
    /// against the same secret-file path. The helper must emit the password on
    /// every invocation; the old in-script `rm -f` consumed the file on the first
    /// read, so the second produced an empty password and `Permission denied`.
    ///
    /// Checked for the target env var and jump-hop env vars, since all share
    /// `script_contents` — a fix to one must hold for the others.
    #[test]
    fn askpass_helper_survives_repeated_invocations() {
        for slot in [
            AskpassSlot::Target,
            AskpassSlot::JumpHost(0),
            AskpassSlot::JumpHost(1),
        ] {
            let env_var = slot.env_var_name();
            let secret_path =
                std::env::temp_dir().join(format!("rustconn-askpass-reinvoke-{}", Uuid::new_v4()));
            std::fs::write(&secret_path, b"persistent-secret")
                .expect("test secret file must be writable");
            let script = script_contents(slot);

            // Two invocations with the SAME env/path, as OpenSSH does for a
            // keyboard-interactive + password server.
            for round in 1..=2 {
                let output = std::process::Command::new("sh")
                    .args(["-c", &script, "rustconn-askpass-test", "Password: "])
                    .env(&env_var, &secret_path)
                    .output()
                    .expect("test askpass script must run");
                assert!(
                    output.status.success(),
                    "invocation {round} failed for {env_var}"
                );
                assert_eq!(
                    output.stdout, b"persistent-secret",
                    "invocation {round} emitted the wrong password for {env_var}"
                );
                assert!(
                    secret_path.exists(),
                    "secret file deleted after invocation {round} for {env_var} (#382)"
                );
            }

            std::fs::remove_file(&secret_path).expect("test secret file must be removed");
        }
    }
}
