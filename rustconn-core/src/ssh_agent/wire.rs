//! Native ssh-agent wire protocol — the read half (A1).
//!
//! Speaks the ssh-agent protocol directly over the `SSH_AUTH_SOCK` Unix socket
//! instead of spawning `ssh-add -l` and a per-key `ssh-keygen`. On an SSH
//! connect with N agent identities that shell-out path cost N+1 processes and
//! about (1+N)×5 ms on the GTK main thread (issue, A1); this answers in one
//! round trip with no process at all.
//!
//! Scope is deliberately the READ half — [`request_identities`] and the SHA256
//! fingerprint it computes with `ring`. Adding and removing keys still go
//! through `ssh-add` in [`super::SshAgentManager`]: adding an *encrypted* key
//! needs a passphrase-decrypt that belongs with the `ssh-key` crate (A2), and
//! until that lands the existing askpass path stays.
//!
//! # Protocol
//!
//! Framing is `uint32 length` then `byte type` then the message body
//! (draft-miller-ssh-agent). The client sends `SSH_AGENTC_REQUEST_IDENTITIES`
//! (11) with an empty body; the agent answers `SSH_AGENT_IDENTITIES_ANSWER`
//! (12): `uint32 nkeys`, then for each key a `string` key blob and a `string`
//! comment. A `string` is a `uint32` length followed by that many bytes. All
//! integers are big-endian.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use super::{AgentError, AgentKey, AgentResult};

/// `SSH_AGENTC_REQUEST_IDENTITIES`.
const REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER`.
const IDENTITIES_ANSWER: u8 = 12;

/// How long one agent round trip may take.
///
/// The agent is a local Unix socket, so a well-behaved one answers in under a
/// millisecond; this only bounds a wedged or launchd-throttled agent so the
/// caller (often the GTK thread) never parks on it. Matches the spirit of the
/// `ssh-add` timeout the shell-out path already used.
const AGENT_IO_TIMEOUT: Duration = Duration::from_secs(3);

/// A reply larger than this is treated as a broken or hostile agent and
/// refused rather than allocated.
///
/// A real agent holds a handful of keys at a few hundred bytes each; 1 MiB is
/// orders of magnitude above any legitimate reply and still cheap to reject.
const MAX_REPLY_BYTES: u32 = 1024 * 1024;

/// Reads the identities an agent at `socket_path` holds, over the native
/// protocol, computing each key's SHA256 fingerprint in-process.
///
/// Returns the keys in agent order. `AgentKey::bits` is `0` here: the wire
/// format does not carry it and deriving it means parsing every algorithm's
/// blob, which no connect-path decision needs — identities are matched by
/// fingerprint. `key_type` is read from the blob's leading algorithm string.
///
/// # Errors
///
/// Returns [`AgentError::Io`] if the socket cannot be reached or the exchange
/// times out, and [`AgentError::ParseError`] if the reply is not a well-formed
/// `SSH_AGENT_IDENTITIES_ANSWER`.
pub(super) fn request_identities(socket_path: &str) -> AgentResult<Vec<AgentKey>> {
    let mut stream = UnixStream::connect(Path::new(socket_path))?;
    stream.set_read_timeout(Some(AGENT_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(AGENT_IO_TIMEOUT))?;

    // Request: length (1 for the type byte) + type, empty body.
    let mut request = Vec::with_capacity(5);
    request.extend_from_slice(&1u32.to_be_bytes());
    request.push(REQUEST_IDENTITIES);
    stream.write_all(&request)?;
    stream.flush()?;

    // Reply: uint32 length, then that many bytes (type + body).
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let reply_len = u32::from_be_bytes(len_buf);
    if reply_len == 0 || reply_len > MAX_REPLY_BYTES {
        return Err(AgentError::ParseError(format!(
            "agent reply length {reply_len} out of range"
        )));
    }
    let mut body = vec![0u8; reply_len as usize];
    stream.read_exact(&mut body)?;

    parse_identities_answer(&body)
}

/// Parses the body of an `SSH_AGENT_IDENTITIES_ANSWER` (type byte + payload).
///
/// Split from the I/O so it can be tested against captured bytes without a live
/// agent.
fn parse_identities_answer(body: &[u8]) -> AgentResult<Vec<AgentKey>> {
    let mut reader = Reader::new(body);

    let msg_type = reader.u8()?;
    if msg_type != IDENTITIES_ANSWER {
        return Err(AgentError::ParseError(format!(
            "expected IDENTITIES_ANSWER ({IDENTITIES_ANSWER}), got message type {msg_type}"
        )));
    }

    let nkeys = reader.u32()?;
    // A sane agent holds few keys; bound the count against a truncated length
    // field claiming millions and driving a huge pre-allocation.
    if nkeys > 4096 {
        return Err(AgentError::ParseError(format!(
            "agent reports {nkeys} keys, which is implausible"
        )));
    }

    let mut keys = Vec::with_capacity(nkeys as usize);
    for _ in 0..nkeys {
        let blob = reader.string()?;
        let comment = reader.string()?;
        keys.push(AgentKey {
            fingerprint: sha256_fingerprint(blob),
            bits: 0,
            key_type: key_type_from_blob(blob),
            comment: String::from_utf8_lossy(comment).into_owned(),
        });
    }

    Ok(keys)
}

/// The OpenSSH `SHA256:<base64>` fingerprint of a public-key blob.
///
/// OpenSSH hashes the raw blob with SHA-256 and prints the digest as standard
/// base64 with the padding `=` stripped. `ring` does the hash in-process, which
/// is the whole point of A1: no `ssh-keygen -lf -` per key.
fn sha256_fingerprint(blob: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, blob);
    // Standard base64 without padding, as OpenSSH prints a SHA256 fingerprint.
    // `data-encoding` is already the project's base64 (see bitwarden.rs).
    let b64 = data_encoding::BASE64_NOPAD.encode(digest.as_ref());
    format!("SHA256:{b64}")
}

/// The leading algorithm string of a public-key blob (`ssh-ed25519`,
/// `ssh-rsa`, `ecdsa-sha2-nistp256`, …), uppercased to a short type the UI
/// already shows (`ED25519`, `RSA`, `ECDSA`).
///
/// Returns `"UNKNOWN"` when the blob does not start with a readable algorithm
/// string; a connect decision never keys on this, so a best-effort label is
/// enough.
fn key_type_from_blob(blob: &[u8]) -> String {
    let mut reader = Reader::new(blob);
    let Ok(algo) = reader.string() else {
        return "UNKNOWN".to_string();
    };
    let algo = String::from_utf8_lossy(algo);
    match algo.as_ref() {
        "ssh-ed25519" => "ED25519".to_string(),
        "ssh-rsa" => "RSA".to_string(),
        "ssh-dss" => "DSA".to_string(),
        a if a.starts_with("ecdsa-sha2-") => "ECDSA".to_string(),
        a if a.starts_with("sk-ssh-ed25519") => "ED25519-SK".to_string(),
        a if a.starts_with("sk-ecdsa-sha2-") => "ECDSA-SK".to_string(),
        other => other.to_uppercase(),
    }
}

/// A bounds-checked cursor over the reply bytes.
///
/// Every read is length-checked and returns [`AgentError::ParseError`] on a
/// short buffer rather than panicking (M-PANIC-ON-BUG: a malformed reply is a
/// recoverable condition, not a bug in this program).
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> AgentResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            AgentError::ParseError("length overflow reading agent reply".to_string())
        })?;
        if end > self.buf.len() {
            return Err(AgentError::ParseError(
                "agent reply ended mid-field".to_string(),
            ));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> AgentResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> AgentResult<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// An SSH `string`: a `uint32` length then that many bytes.
    fn string(&mut self) -> AgentResult<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an SSH `string` (uint32 length + bytes).
    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + bytes.len());
        #[expect(clippy::cast_possible_truncation, reason = "test inputs are tiny")]
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// A minimal valid ed25519 key blob: algorithm string + 32-byte pubkey.
    fn ed25519_blob() -> Vec<u8> {
        let mut blob = ssh_string(b"ssh-ed25519");
        blob.extend(ssh_string(&[7u8; 32]));
        blob
    }

    /// An IDENTITIES_ANSWER body for the given (blob, comment) pairs.
    fn answer_body(keys: &[(Vec<u8>, &str)]) -> Vec<u8> {
        let mut body = vec![IDENTITIES_ANSWER];
        #[expect(clippy::cast_possible_truncation, reason = "test inputs are tiny")]
        body.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for (blob, comment) in keys {
            body.extend(ssh_string(blob));
            body.extend(ssh_string(comment.as_bytes()));
        }
        body
    }

    #[test]
    fn empty_agent_parses_to_no_keys() {
        let body = answer_body(&[]);
        let keys = parse_identities_answer(&body).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn one_ed25519_key_round_trips() {
        let body = answer_body(&[(ed25519_blob(), "user@host")]);
        let keys = parse_identities_answer(&body).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "ED25519");
        assert_eq!(keys[0].comment, "user@host");
        assert!(keys[0].fingerprint.starts_with("SHA256:"));
        // No padding in an OpenSSH SHA256 fingerprint.
        assert!(!keys[0].fingerprint.contains('='));
    }

    #[test]
    fn fingerprint_matches_known_vector() {
        // SHA256 of the 11 bytes b"hello world", base64 no-pad, is a fixed
        // value — this pins the encoding (standard base64, padding stripped,
        // SHA256: prefix) against drift.
        let fp = sha256_fingerprint(b"hello world");
        assert_eq!(fp, "SHA256:uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek");
    }

    #[test]
    fn rsa_and_ecdsa_types_are_recognised() {
        let rsa = ssh_string(b"ssh-rsa");
        assert_eq!(key_type_from_blob(&rsa), "RSA");
        let ecdsa = ssh_string(b"ecdsa-sha2-nistp256");
        assert_eq!(key_type_from_blob(&ecdsa), "ECDSA");
    }

    #[test]
    fn wrong_message_type_is_a_parse_error() {
        // A SUCCESS (6) where an IDENTITIES_ANSWER was expected.
        let body = vec![6u8, 0, 0, 0, 0];
        assert!(matches!(
            parse_identities_answer(&body),
            Err(AgentError::ParseError(_))
        ));
    }

    #[test]
    fn truncated_reply_is_a_parse_error_not_a_panic() {
        // Claims one key, then ends immediately.
        let mut body = vec![IDENTITIES_ANSWER];
        body.extend_from_slice(&1u32.to_be_bytes());
        assert!(matches!(
            parse_identities_answer(&body),
            Err(AgentError::ParseError(_))
        ));
    }

    #[test]
    fn implausible_key_count_is_refused() {
        let mut body = vec![IDENTITIES_ANSWER];
        body.extend_from_slice(&5000u32.to_be_bytes());
        assert!(matches!(
            parse_identities_answer(&body),
            Err(AgentError::ParseError(_))
        ));
    }
}
