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
}

impl Testbed {
    /// Reads the testbed env, or `None` when no testbed is up. A `None` means
    /// the test should skip itself rather than fail.
    fn from_env() -> Option<Self> {
        let host = std::env::var("RUSTCONN_SSHD_HOST").ok()?;
        let port = std::env::var("RUSTCONN_SSHD_PORT").ok()?.parse().ok()?;
        let user = std::env::var("RUSTCONN_SSHD_USER").ok()?;
        let profile = std::env::var("RUSTCONN_SSHD_PROFILE").unwrap_or_default();
        Some(Self {
            host,
            port,
            user,
            profile,
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
