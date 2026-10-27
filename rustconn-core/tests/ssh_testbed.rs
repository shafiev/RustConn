//! Live-sshd integration tests against the containerized testbed (K0, W3).
//!
//! These exercise the SSH primitives that unit tests cannot reach because they
//! need a real server answering on a real socket: the pre-connect port check
//! ([`check_port`]/[`check_port_async`]), the ControlMaster socket detection
//! that drives the P4 fast path ([`control_socket_present`] and its lifecycle),
//! and the interactive keepalive applied to a live stream
//! ([`set_interactive_keepalive`]).
//!
//! Every test here is `#[ignore]`: it depends on a server started out of band by
//! `scripts/sshd-testbed.sh`, which is not part of the build and never runs in
//! the default `cargo test`. The runner starts a profile, sources the printed
//! env, then runs with `-- --ignored`:
//!
//! ```bash
//! scripts/sshd-testbed.sh up password
//! source target/sshd-testbed.env
//! cargo test -p rustconn-core --test ssh_testbed -- --ignored
//! scripts/sshd-testbed.sh down
//! ```
//!
//! The key-setup tests at the bottom (K2, `rustconn_core::ssh_key_setup`) each
//! name the profile they need and skip under any other: the happy path,
//! passphrase and repeat deploy (`strictmodes`), a server that ignores keys
//! (`password`), an unknown host key beating a custom `StrictHostKeyChecking=no`
//! (`unknown-hostkey`), a changed host key, a wrong password, a `ForceCommand`
//! that swallows the installer (`forcecommand`) and a two-factor server
//! (`key-otp`). Not covered: a `StrictModes` refusal caused by loose
//! permissions, because the testbed does not loosen the key directory.
//!
//! A test skips itself (passes, with an eprintln) when `RUSTCONN_SSHD_*` is
//! absent, so running `--ignored` without a live testbed does not fail the
//! suite — it reports that the testbed was not up. The tests read the server's
//! address from the environment and never hard-code a loopback `ssh` target in
//! their source; where a real `ssh` client is spawned (ForceCommand, unknown
//! host key) the argv is built from the env at run time.

#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    reason = "a test harness uses unwrap/expect for brevity and eprintln for skip notes"
)]

use std::net::{IpAddr, SocketAddr};

use rustconn_core::PortCheckResult;

/// The testbed coordinates, read from the env `scripts/sshd-testbed.sh` writes.
struct Testbed {
    host: String,
    port: u16,
    user: String,
    profile: String,
    /// `RUSTCONN_SSHD_PASS`; wrap in a `SecretString` before it goes anywhere.
    password: Option<String>,
}

impl Testbed {
    /// Reads the testbed env, or `None` when no testbed is up. A `None` means
    /// the test should skip itself rather than fail.
    fn from_env() -> Option<Self> {
        let host = std::env::var("RUSTCONN_SSHD_HOST").ok()?;
        let port = std::env::var("RUSTCONN_SSHD_PORT").ok()?.parse().ok()?;
        let user = std::env::var("RUSTCONN_SSHD_USER").ok()?;
        let profile = std::env::var("RUSTCONN_SSHD_PROFILE").unwrap_or_default();
        let password = std::env::var("RUSTCONN_SSHD_PASS").ok();
        Some(Self {
            host,
            port,
            user,
            profile,
            password,
        })
    }

    fn socket_addr(&self) -> SocketAddr {
        let ip: IpAddr = self.host.parse().expect("testbed host is an IP");
        SocketAddr::new(ip, self.port)
    }
}

/// Skips (returns) with a visible note when no testbed is configured. A macro,
/// not a helper, so the early `return` lands in the test body.
macro_rules! testbed_or_skip {
    () => {
        match Testbed::from_env() {
            Some(tb) => tb,
            None => {
                eprintln!(
                    "ssh_testbed: no RUSTCONN_SSHD_* in env — start \
                     scripts/sshd-testbed.sh and source its env; skipping"
                );
                return;
            }
        }
    };
}

/// The pre-connect port check sees the live sshd as open.
///
/// This is the synchronous `check_port` the SSH connect path runs before a
/// session; against a real listening sshd it must report the port reachable.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh — run with -- --ignored"]
fn port_check_sees_the_live_sshd() {
    let tb = testbed_or_skip!();
    let result = rustconn_core::check_port(&tb.host, tb.port, 5);
    assert!(
        matches!(result, Ok(PortCheckResult::Open)),
        "check_port should see the testbed sshd at {}:{} as open, got {result:?}",
        tb.host,
        tb.port
    );
}

/// The async port check agrees with the sync one against the live server.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh — run with -- --ignored"]
fn async_port_check_sees_the_live_sshd() {
    let tb = testbed_or_skip!();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = rt.block_on(rustconn_core::check_port_async(&tb.host, tb.port, 5));
    assert!(
        matches!(result, Ok(PortCheckResult::Open)),
        "check_port_async should see the testbed sshd as open, got {result:?}"
    );
}

/// A port the testbed does not listen on reads as closed.
///
/// Guards against a `check_port` that reports every host reachable: the testbed
/// binds one port, and the port one below it is almost always free.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh — run with -- --ignored"]
fn port_check_reports_a_closed_port() {
    let tb = testbed_or_skip!();
    let closed_port = tb.port.checked_sub(1).unwrap_or(tb.port + 1);
    let result = rustconn_core::check_port(&tb.host, closed_port, 2);
    // A reachable IP with nothing listening gives `Err(Unreachable)`; the one
    // thing it must not be is `Ok(Open)`.
    assert!(
        !matches!(result, Ok(PortCheckResult::Open)),
        "a port the testbed does not listen on ({closed_port}) must not read as open, got {result:?}"
    );
}

/// `set_interactive_keepalive` applies cleanly to a live connection to the sshd.
///
/// The keepalive is what keeps a long interactive session from parking forever
/// on a half-open socket (see error-resolution.md). Here it only has to apply
/// without error to a real connected stream; the kernel-level behaviour is not
/// observable from a test.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh — run with -- --ignored"]
fn interactive_keepalive_applies_to_a_live_stream() {
    let tb = testbed_or_skip!();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let stream = tokio::net::TcpStream::connect(tb.socket_addr())
            .await
            .expect("connect to the live testbed sshd");
        // Must not panic or error; applied to the same kind of stream the
        // connect path uses.
        rustconn_core::connection::set_interactive_keepalive(&stream, "ssh");
    });
}

/// With no ControlMaster socket for the testbed host, the P4 fast path does not
/// fire — `control_socket_present` reports absence.
///
/// This pins the negative half of the P4 optimisation (W1): a host with no live
/// master must still take the normal port-check path. The positive half (an
/// actual multiplexed master) needs a real `ssh -M` session and is left to the
/// manual ForceCommand/ssh profiles below.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh — run with -- --ignored"]
fn control_socket_absent_for_a_fresh_host() {
    let tb = testbed_or_skip!();
    assert!(
        !rustconn_core::control_socket_present(&tb.host, tb.port),
        "no ControlMaster socket should exist for a freshly started testbed host"
    );
}

/// The ForceCommand profile makes the server answer with a fixed sentinel.
///
/// This is the shape the key-deploy script relies on (plan W3 K0/K4): a server
/// that intercepts the command. The test spawns the system `ssh` with the
/// testbed address built from the env at run time (never a hard-coded loopback
/// target in source). Only meaningful under the `forcecommand` profile; other
/// profiles skip.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh forcecommand — run with -- --ignored"]
fn forcecommand_profile_returns_the_sentinel() {
    let tb = testbed_or_skip!();
    if tb.profile != "forcecommand" {
        eprintln!(
            "ssh_testbed: profile is '{}', not 'forcecommand' — skipping",
            tb.profile
        );
        return;
    }
    // Built from the env, so the source carries no literal ssh-to-loopback argv.
    let target = format!("{}@{}", tb.user, tb.host);
    let output = std::process::Command::new("ssh")
        .args([
            "-p",
            &tb.port.to_string(),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "BatchMode=no",
            &target,
            "true",
        ])
        .output()
        .expect("spawn ssh against the testbed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("RUSTCONN_FORCECOMMAND_SENTINEL"),
        "ForceCommand should echo the sentinel; got stdout={stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// Key setup (K2): rustconn_core::ssh_key_setup against the live testbed
// ---------------------------------------------------------------------------

use std::path::{Path, PathBuf};

use rustconn_core::ssh_key_setup::{
    DeployCredentials, DeployOutcome, KeyAlgorithm, KeySetupError, KeygenRequest, PublicKeyLine,
    RunControl, SshTarget, VerifyOutcome, default_key_comment, ensure_key_setup_dir, generate_key,
    run_deploy, run_verify,
};
use secrecy::SecretString;

/// Skips unless the running profile is `$profile`.
macro_rules! profile_or_skip {
    ($tb:expr, $profile:expr) => {
        if $tb.profile != $profile {
            eprintln!(
                "ssh_testbed: profile is '{}', this test needs '{}' — skipping",
                $tb.profile, $profile
            );
            return;
        }
    };
}

/// A scratch directory with a key directory and a `known_hosts` file.
struct KeyEnv {
    _tmp: tempfile::TempDir,
    key_dir: PathBuf,
    known_hosts: PathBuf,
}

impl KeyEnv {
    /// `known_hosts` holds the server's real ed25519 host key (from
    /// `ssh-keyscan`), so `StrictHostKeyChecking=yes` can succeed.
    fn trusting(tb: &Testbed) -> Self {
        let env = Self::empty();
        let scan = std::process::Command::new("ssh-keyscan")
            .args(["-t", "ed25519", "-p", &tb.port.to_string(), &tb.host])
            .output()
            .expect("run ssh-keyscan");
        assert!(
            !scan.stdout.is_empty(),
            "ssh-keyscan returned no host key: {}",
            String::from_utf8_lossy(&scan.stderr)
        );
        std::fs::write(&env.known_hosts, &scan.stdout).unwrap();
        env
    }

    /// An empty `known_hosts`: every host key is unknown.
    fn empty() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let key_dir = tmp.path().join("rustconn");
        ensure_key_setup_dir(&key_dir).unwrap();
        let known_hosts = tmp.path().join("known_hosts");
        std::fs::write(&known_hosts, b"").unwrap();
        Self {
            _tmp: tmp,
            key_dir,
            known_hosts,
        }
    }

    fn target(&self, tb: &Testbed, session_args: &[&str]) -> SshTarget {
        SshTarget {
            host: tb.host.clone(),
            port: tb.port,
            username: Some(tb.user.clone()),
            session_args: session_args.iter().map(|s| (*s).to_owned()).collect(),
            known_hosts_file: Some(self.known_hosts.clone()),
        }
    }

    fn new_key(&self, name: &str, passphrase: Option<&str>) -> (PathBuf, PublicKeyLine) {
        let request = KeygenRequest {
            private_key_path: self.key_dir.join(name),
            algorithm: KeyAlgorithm::Ed25519,
            comment: default_key_comment(),
            passphrase: passphrase.map(SecretString::from),
        };
        let key = generate_key(&request, &RunControl::default()).expect("generate a key");
        (key.private_key_path, key.public_key)
    }
}

fn credentials(tb: &Testbed) -> DeployCredentials {
    DeployCredentials {
        password: tb.password.clone().map(SecretString::from),
        jump_host_passwords: Vec::new(),
    }
}

fn deploy(
    tb: &Testbed,
    env: &KeyEnv,
    session_args: &[&str],
    key: &PublicKeyLine,
) -> Result<DeployOutcome, KeySetupError> {
    run_deploy(
        &env.target(tb, session_args),
        key,
        &credentials(tb),
        &RunControl::default(),
    )
}

fn verify(
    tb: &Testbed,
    env: &KeyEnv,
    private: &Path,
    key: &PublicKeyLine,
    passphrase: Option<&str>,
) -> Result<VerifyOutcome, KeySetupError> {
    let passphrase = passphrase.map(SecretString::from);
    run_verify(
        &env.target(tb, &[]),
        private,
        key,
        passphrase.as_ref(),
        &[],
        &RunControl::default(),
    )
}

/// Generate, deploy, deploy again, verify. Also pins the `-v` line format that
/// verification reads (`Server accepts key: … SHA256:…`), which the design
/// notes had not been checked against a real server.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh strictmodes — run with -- --ignored"]
fn key_setup_happy_path() {
    let tb = testbed_or_skip!();
    profile_or_skip!(tb, "strictmodes");
    let env = KeyEnv::trusting(&tb);
    let (private, key) = env.new_key("happy-12345678_ed25519", None);

    assert!(matches!(
        deploy(&tb, &env, &[], &key),
        Ok(DeployOutcome::Installed)
    ));
    assert!(matches!(
        deploy(&tb, &env, &[], &key),
        Ok(DeployOutcome::AlreadyPresent)
    ));
    assert!(matches!(
        verify(&tb, &env, &private, &key, None),
        Ok(VerifyOutcome::Accepted)
    ));
}

#[test]
#[ignore = "needs scripts/sshd-testbed.sh strictmodes — run with -- --ignored"]
fn key_setup_passphrase_verify() {
    let tb = testbed_or_skip!();
    profile_or_skip!(tb, "strictmodes");
    let env = KeyEnv::trusting(&tb);
    let (private, key) = env.new_key("pass-12345678_ed25519", Some("correct horse battery"));
    assert!(deploy(&tb, &env, &[], &key).is_ok());

    assert!(matches!(
        verify(&tb, &env, &private, &key, Some("correct horse battery")),
        Ok(VerifyOutcome::Accepted)
    ));
    let wrong = verify(&tb, &env, &private, &key, Some("not the passphrase"));
    assert!(
        matches!(wrong, Err(KeySetupError::WrongPassphrase)),
        "{wrong:?}"
    );
}

/// The key lands in `authorized_keys`, but a server with `PubkeyAuthentication
/// no` never accepts it: the case where the caller keeps the key and says so.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh password — run with -- --ignored"]
fn key_setup_verify_rejected_when_pubkey_disabled() {
    let tb = testbed_or_skip!();
    profile_or_skip!(tb, "password");
    let env = KeyEnv::trusting(&tb);
    let (private, key) = env.new_key("nopk-12345678_ed25519", None);
    assert!(matches!(
        deploy(&tb, &env, &[], &key),
        Ok(DeployOutcome::Installed)
    ));
    assert!(matches!(
        verify(&tb, &env, &private, &key, None),
        Err(KeySetupError::KeyNotAccepted)
    ));
}

/// A custom `StrictHostKeyChecking=no` must not let an unknown host key through.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh unknown-hostkey — run with -- --ignored"]
fn key_setup_unknown_host_key_even_with_custom_no() {
    let tb = testbed_or_skip!();
    profile_or_skip!(tb, "unknown-hostkey");
    let env = KeyEnv::empty();
    let (_, key) = env.new_key("hk-12345678_ed25519", None);
    let result = deploy(&tb, &env, &["-o", "StrictHostKeyChecking=no"], &key);
    assert!(
        matches!(result, Err(KeySetupError::HostKeyUnknown)),
        "{result:?}"
    );
    let known = std::fs::read_to_string(&env.known_hosts).unwrap();
    assert!(known.is_empty(), "the host key must not have been recorded");
}

/// `known_hosts` names a different key for this address: refuse, and say it changed.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh — run with -- --ignored"]
fn key_setup_changed_host_key() {
    let tb = testbed_or_skip!();
    let env = KeyEnv::empty();
    let (_, other_host_key) = env.new_key("elsewhere-12345678_ed25519", None);
    std::fs::write(
        &env.known_hosts,
        format!("[{}]:{} {}\n", tb.host, tb.port, other_host_key.as_str()),
    )
    .unwrap();
    let (_, key) = env.new_key("chg-12345678_ed25519", None);
    let result = deploy(&tb, &env, &[], &key);
    assert!(
        matches!(result, Err(KeySetupError::HostKeyChanged)),
        "{result:?}"
    );
}

#[test]
#[ignore = "needs scripts/sshd-testbed.sh password — run with -- --ignored"]
fn key_setup_wrong_password() {
    let tb = testbed_or_skip!();
    profile_or_skip!(tb, "password");
    let env = KeyEnv::trusting(&tb);
    let (_, key) = env.new_key("pw-12345678_ed25519", None);
    let wrong = DeployCredentials {
        password: Some(SecretString::from("definitely-not-the-password")),
        jump_host_passwords: Vec::new(),
    };
    let result = run_deploy(&env.target(&tb, &[]), &key, &wrong, &RunControl::default());
    match result {
        Err(KeySetupError::AuthFailed { server_methods }) => {
            assert!(
                server_methods.iter().any(|m| m == "password"),
                "{server_methods:?}"
            );
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

/// A `ForceCommand` answers instead of the installer: the login works, the
/// sentinel never appears.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh forcecommand — run with -- --ignored"]
fn key_setup_forcecommand_has_no_sentinel() {
    let tb = testbed_or_skip!();
    profile_or_skip!(tb, "forcecommand");
    let env = KeyEnv::trusting(&tb);
    let (_, key) = env.new_key("fc-12345678_ed25519", None);
    let result = deploy(&tb, &env, &[], &key);
    assert!(
        matches!(result, Err(KeySetupError::NoSentinel { .. })),
        "{result:?}"
    );
}

/// A two-factor server does not take the password alone: no `password` among
/// the methods it lists.
#[test]
#[ignore = "needs scripts/sshd-testbed.sh key-otp — run with -- --ignored"]
fn key_setup_key_otp_rejects_password_deploy() {
    let tb = testbed_or_skip!();
    profile_or_skip!(tb, "key-otp");
    let env = KeyEnv::trusting(&tb);
    let (_, key) = env.new_key("otp-12345678_ed25519", None);
    match deploy(&tb, &env, &[], &key) {
        Err(KeySetupError::AuthFailed { server_methods }) => {
            assert!(
                !server_methods.iter().any(|m| m == "password"),
                "{server_methods:?}"
            );
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}
