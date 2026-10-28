//! Bitwarden `bw` spawn-count and argv-safety harness (W0).
//!
//! The 0.24 performance release drives the number of `bw` child processes per
//! vault operation down (target: one spawn per store, plus a fallback). This
//! harness measures that directly: it puts a fake `bw` on the backend's
//! resolved command path, runs real [`BitwardenBackend`] operations against it,
//! and reads back how many times the fake was spawned and what argv each spawn
//! received.
//!
//! It also pins the 0.23.21 security fix (issue, embedded-RDP-era): the item
//! JSON for `create item` / `edit item` carries the plaintext password and must
//! reach `bw` over stdin, never as a base64 argument visible in
//! `/proc/<pid>/cmdline`. The harness fails if any recorded argv contains the
//! base64-encoded item.
//!
//! Marked `#[ignore]` because it spawns a real child process and sets the
//! process-global `bw` command path (via [`set_bw_cmd`]), which would interfere
//! with any other Bitwarden test running in the same binary. Run it explicitly:
//!
//! ```bash
//! cargo test -p rustconn-core --test bitwarden_spawn_counter -- --ignored
//! ```

#![allow(
    clippy::unwrap_used,
    reason = "a test harness uses unwrap/expect for brevity"
)]

use std::fs;
use std::io::Read as _;
use std::path::PathBuf;

use rustconn_core::models::Credentials;
use rustconn_core::secret::{BitwardenBackend, SecretBackend as _, set_bw_cmd};
use secrecy::SecretString;

/// A fake `bw` binary plus the files it records its calls into.
struct FakeBw {
    dir: tempfile::TempDir,
}

impl FakeBw {
    /// Writes an executable shell `bw` stub into a fresh temp dir.
    ///
    /// The stub records one line per spawn into `calls.log` (its full argv) and
    /// answers the subcommands the backend actually issues with the minimal
    /// valid JSON each one parses. It derives the record path from its own
    /// location (`$0`), because [`BitwardenBackend::build_command`] passes the
    /// child only `PATH` and `BW_SESSION`, so a record path cannot be handed to
    /// it through the environment.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let bw = dir.path().join("bw");

        // The stub strips the leading `--nointeraction` the backend always
        // prepends, then dispatches on the verb. `create`/`edit` read and
        // discard stdin so the write side never blocks on a full pipe.
        let script = r#"#!/bin/sh
here="$(dirname "$0")"
# Record the whole argv, one field per line, terminated by a blank line.
for a in "$@"; do printf '%s\n' "$a" >> "$here/calls.log"; done
printf '\n' >> "$here/calls.log"

# Drop the leading --nointeraction the backend always adds.
if [ "$1" = "--nointeraction" ]; then shift; fi

case "$1 $2" in
  "--version "*) echo "2025.1.0" ;;
  "status "*) echo '{"status":"unlocked","userEmail":"t@e","lastSync":null}' ;;
  "sync "*) echo "Syncing complete." ;;
  "list folders") echo '[{"id":"f1","name":"RustConn"}]' ;;
  "list items") echo '[]' ;;
  "get template"*) echo '{"type":1,"name":"","login":{"username":"","password":""}}' ;;
  "create item") cat >/dev/null 2>&1; echo '{"id":"new-id"}' ;;
  "edit item") cat >/dev/null 2>&1; echo '{"id":"edit-id"}' ;;
  *) echo '{}' ;;
esac
exit 0
"#;
        fs::write(&bw, script).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = fs::metadata(&bw).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&bw, perms).unwrap();
        }

        Self { dir }
    }

    fn bw_path(&self) -> PathBuf {
        self.dir.path().join("bw")
    }

    fn calls_log(&self) -> PathBuf {
        self.dir.path().join("calls.log")
    }

    /// The argv of every spawn so far: each inner `Vec` is one invocation's
    /// fields (the stub records them before stripping `--nointeraction`).
    fn recorded_spawns(&self) -> Vec<Vec<String>> {
        let path = self.calls_log();
        if !path.exists() {
            return Vec::new();
        }
        let mut contents = String::new();
        fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        contents
            .split("\n\n")
            .map(str::trim)
            .filter(|block| !block.is_empty())
            .map(|block| block.lines().map(str::to_owned).collect())
            .collect()
    }
}

fn point_backend_at(fake: &FakeBw) {
    set_bw_cmd(fake.bw_path().to_str().unwrap());
}

/// Blocks on a future on a fresh current-thread runtime — the backend's async
/// API from a sync test.
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

#[test]
#[ignore = "spawns a real fake-bw child and sets the process-global bw path; run with --ignored"]
fn store_never_puts_the_item_on_the_command_line() {
    let fake = FakeBw::new();
    point_backend_at(&fake);

    let backend = BitwardenBackend::with_session(SecretString::from("fake-session".to_string()));
    let creds = Credentials::with_password("alice", "s3cr3t-p@ss");

    block_on(backend.store("conn-id-123", &creds)).unwrap();

    let spawns = fake.recorded_spawns();
    assert!(
        !spawns.is_empty(),
        "store should have spawned bw at least once"
    );

    // The item JSON holds the plaintext password; it must travel over stdin, so
    // no spawn's argv may carry a long base64 blob. The password itself must
    // never appear in any field either.
    for argv in &spawns {
        for field in argv {
            assert!(
                !field.contains("s3cr3t-p@ss"),
                "plaintext password leaked into bw argv: {argv:?}"
            );
            let looks_base64 = field.len() > 40
                && field
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
            assert!(
                !looks_base64,
                "a base64 item blob reached bw argv (should be stdin): {field}"
            );
        }
    }
}

#[test]
#[ignore = "spawns a real fake-bw child and sets the process-global bw path; run with --ignored"]
fn a_store_spawns_a_bounded_number_of_bw_processes() {
    let fake = FakeBw::new();
    point_backend_at(&fake);

    let backend = BitwardenBackend::with_session(SecretString::from("fake-session".to_string()));
    let creds = Credentials::with_password("bob", "another-pass");

    block_on(backend.store("conn-id-456", &creds)).unwrap();

    let count = fake.recorded_spawns().len();
    // This is a regression ceiling, not a target: the W2 serve work drives this
    // toward 1. A store today issues a small, bounded set of calls (template,
    // folder/item lookups, create); fail loudly if it balloons.
    assert!(
        (1..=8).contains(&count),
        "store spawned {count} bw processes; expected a small bounded number (1..=8)"
    );
}

#[test]
#[ignore = "spawns a real fake-bw child and sets the process-global bw path; run with --ignored"]
fn the_stub_records_argv_without_a_leading_nointeraction_being_lost() {
    // Guards the harness itself: the backend prepends --nointeraction, and the
    // stub records the raw argv, so the first field of a data call is that flag.
    let fake = FakeBw::new();
    point_backend_at(&fake);

    let backend = BitwardenBackend::with_session(SecretString::from("fake-session".to_string()));
    let _ = block_on(backend.retrieve("conn-id-789"));

    let spawns = fake.recorded_spawns();
    assert!(!spawns.is_empty(), "retrieve should have spawned bw");
    assert!(
        spawns
            .iter()
            .all(|argv| argv.first().is_some_and(|f| f == "--nointeraction")),
        "every bw spawn should start with --nointeraction: {spawns:?}"
    );
}
