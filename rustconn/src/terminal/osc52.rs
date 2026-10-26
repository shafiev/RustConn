//! OSC 52 — clipboard offers from the remote side.
//!
//! libvte parses OSC 52 (`ESC ] 52 ; …`) and then does nothing with it: through
//! 0.84 the `XTERM_SET_XSELECTION` handler is a no-op, so a yank in a remote
//! Neovim — or in tmux with `set-clipboard external` — puts the text nowhere.
//! GNOME Terminal and xfce4-terminal inherit the same hole, so this is a VTE
//! limitation and not a RustConn bug. VTE's 4 KiB `VTE_SEQ_STRING_MAX_CAPACITY`
//! is a second ceiling on the way: an OSC string longer than that is dropped
//! before any handler would see it.
//!
//! [`Osc52Filter`] does what VTE will not. It lifts clipboard offers out of the
//! PTY byte stream on the way to `Terminal::feed`, hands the text to the system
//! clipboard, and passes every other byte through untouched.
//!
//! The filter must never disagree with VTE about what a byte means: anything it
//! holds back that VTE would draw is a bug (a prompt that does not show), and
//! anything VTE treats as OSC 52 that the filter misses is a hole (a remote
//! clipboard write). VTE decodes the stream as UTF-8 before parsing it, so the
//! 8-bit C1 controls are accepted here only in that form — `c2 9d` for `OSC`,
//! `c2 9c` for `ST` — and a bare `0x9d`/`0x9c` is just a continuation byte, as
//! in `❯` (`e2 9d af`). `CAN`, `SUB` and the other C1 controls abandon an open
//! string, as they do in VTE, and only what VTE would also wait for (an open
//! string, a lone `ESC` or `c2`) is held at the end of a chunk.
//!
//! Two rules keep that from becoming a remote-controlled write primitive:
//!
//! * **Opt-in.** [`set_enabled`] mirrors `TerminalSettings::allow_osc52_clipboard`
//!   and starts out off, the way [`super::safe_paste`] does for its own flag. A
//!   host that can write the clipboard can aim a pastejacking payload at the
//!   next terminal the user pastes into, so it is the user's call, per install.
//! * **Write-only, one selection.** A `?` payload is a *query* — the terminal is
//!   being asked to send its clipboard back to the application. Answering it
//!   would stream local clipboard contents to a remote, so the sequence is
//!   dropped unanswered and the application falls back to its own timeout. The
//!   `p` (primary) and `s` (select) selections are passed through rather than
//!   half-supported: they are real, and writing them from a remote was not asked
//!   for.
//!
//! ponytail: only the `c` selection and only `ST`/`BEL`-terminated strings are
//! recognised — no DCS tmux passthrough (`ESC P tmux ; …`), which `allow-passthrough
//! on` wraps sequences in. `set-clipboard external`, the documented route, writes
//! OSC 52 straight to the outer tty and needs none of that. Add a DCS state to
//! [`State`] if a real user turns out to need the wrapper.

use std::cell::Cell;
use std::mem;

use gtk4::glib;
use gtk4::prelude::*;
use vte4::Terminal;
use zeroize::Zeroizing;

thread_local! {
    /// Whether an OSC 52 clipboard offer is honoured. Mirrors
    /// `TerminalSettings::allow_osc52_clipboard`; read once per completed
    /// sequence, so a change in Preferences applies to sessions that are already
    /// open. GTK is single-threaded, so a thread-local is the whole-process
    /// value here — the same reasoning as [`super::safe_paste`].
    static ENABLED: Cell<bool> = const { Cell::new(false) };
}

/// Records whether OSC 52 clipboard offers are honoured.
///
/// Called from `configure_terminal_with_settings`, which the settings dialog
/// re-runs on save, so the flag tracks the setting without threading it into
/// every call site.
pub fn set_enabled(enabled: bool) {
    ENABLED.with(|flag| flag.set(enabled));
}

/// Whether an OSC 52 clipboard offer is honoured.
fn enabled() -> bool {
    ENABLED.with(Cell::get)
}

/// Puts a decoded OSC 52 payload on the system clipboard.
///
/// Takes the terminal's own display, the way every other clipboard write in this
/// module does, and must be called on the GTK main thread — which the caller is,
/// because the only path here is the one `deliver_output_to` runs.
///
/// ponytail: silent, like copy-on-select — a remote yank is not worth a toast,
/// and the paste that follows is the user's own.
pub fn offer_to_clipboard(terminal: &Terminal, text: &str) {
    terminal.display().clipboard().set_text(text);
}

/// Longest OSC string body [`Osc52Filter`] will hold, in bytes.
///
/// The remote is the untrusted side of this boundary, so this bounds how much
/// of a stream it can make us buffer: a string that outgrows it is discarded up
/// to its terminator, which is what VTE does with anything past its own 4 KiB
/// limit. 1 MiB sits far enough above that to keep every sequence VTE would
/// have accepted working here — and above tmux's 100 kB `set-clipboard-limit` —
/// while still capping a hostile sender.
const MAX_OSC_BODY: usize = 1024 * 1024;

/// `ESC` — an introducer on its own, and the first byte of the 7-bit `ST`.
const ESC: u8 = 0x1b;
/// `]` — what turns `ESC` into a 7-bit OSC introducer.
const INTRODUCER_7BIT: u8 = b']';
/// `\` — the second byte of the 7-bit `ST` terminator.
const TERMINATOR_7BIT: u8 = b'\\';
/// First byte of the UTF-8 encoding of every C1 control, `U+0080`–`U+009F`
/// (`c2 80`–`c2 9f`).
///
/// VTE decodes the PTY stream as UTF-8 *before* its parser sees it
/// (`Terminal::process_incoming_utf8` → `Parser::feed`), so a C1 control exists
/// only as these two bytes. A bare `0x9d` or `0x9c` is a continuation byte
/// (`❯` is `e2 9d af`, `➜` is `e2 9e 9c`) or, on its own, `U+FFFD` — never a
/// control. `c2` always starts a new character, so one byte of lookahead after
/// it is all the decoding the filter needs.
const C1_LEAD: u8 = 0xc2;
/// Second byte of C1 `OSC` (`c2 9d`), the 8-bit introducer.
const C1_OSC: u8 = 0x9d;
/// Second byte of C1 `ST` (`c2 9c`), the 8-bit terminator.
const C1_ST: u8 = 0x9c;
/// `CAN` — VTE abandons the string in progress on it.
const CAN: u8 = 0x18;
/// `SUB` — likewise.
const SUB: u8 = 0x1a;
/// `BEL` — xterm accepts it as an OSC terminator and most `printf` recipes use it.
const BEL: u8 = 0x07;

/// Whether VTE leaves its parser state alone on `byte` while an `ESC` is open:
/// every C0 control but `ESC`, `CAN` and `SUB` is executed on the spot, and
/// `DEL` is ignored (`Parser::feed` and the `ESC` state of `feed_to_state`). So
/// `ESC BEL ] 52 …` still opens an OSC string in VTE, and must in the filter.
const fn is_transparent_in_escape(byte: u8) -> bool {
    matches!(byte, 0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f)
}

/// Whether VTE drops `byte` from the body of an OSC string: C0 controls other
/// than `BEL`, `ESC`, `CAN` and `SUB` are `action_nop` in `OSC_STRING`, and `DEL`
/// is ignored in every state. The filter keeps them in `pending`, so a string
/// passes on untouched, but classifies the body without them, as VTE does —
/// `ESC ] 5 NUL 2 ; c ; … BEL` is OSC 52 to VTE.
const fn is_ignored_in_osc_body(byte: u8) -> bool {
    matches!(byte, 0x00..=0x06 | 0x08..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f)
}

/// Where [`Osc52Filter`] is in the stream.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Between sequences. Bytes go straight to the output.
    #[default]
    Ground,
    /// Saw `ESC`. The next byte decides whether an OSC string starts here;
    /// anything else means this `ESC` opened a different sequence.
    Escape,
    /// Saw `c2`, the first half of a possible C1 control. `9d` makes it the
    /// 8-bit OSC introducer; anything else means it was an ordinary character.
    C1Lead,
    /// Inside an OSC string, collecting its body.
    Osc,
    /// Inside an OSC string, just saw `ESC` — which is *not* in `pending` yet:
    /// `\` ends the string, and anything else abandoned it and begins a new
    /// escape sequence.
    OscEscape,
    /// Inside an OSC string, just saw `c2` — not in `pending` yet either. `9c`
    /// ends the string, `9d` restarts it, the other C1 controls abandon it, and
    /// anything else makes `c2` an ordinary character of the body.
    OscC1Lead,
}

/// Removes OSC 52 clipboard offers from one PTY output stream.
///
/// A PTY read is bounded by `READ_CHUNK` (8 KiB), which is smaller than a large
/// yank, so a sequence routinely arrives in pieces and the filter has to hold
/// state between chunks. One filter therefore belongs to one stream, and lives
/// as long as the reader does.
///
/// Bytes are never dropped unless they belong to a recognised OSC 52 clipboard
/// offer or to an OSC string the stream ended in the middle of while offers are
/// honoured ([`finish`](Self::finish)), and they keep their order with one
/// exception: a C0 control that arrives while an `ESC` is held goes out ahead
/// of it, which VTE cannot tell apart.
#[derive(Debug, Default)]
pub struct Osc52Filter {
    state: State,
    /// What the filter holds back from the output: the string in progress,
    /// introducer included, or the lone `ESC` / `c2` held by [`State::Escape`] /
    /// [`State::C1Lead`]. The lookahead byte of [`State::OscEscape`] and
    /// [`State::OscC1Lead`] is not in it until it is classified.
    pending: Vec<u8>,
    /// Set once `pending` outgrew [`MAX_OSC_BODY`]: the rest of the string is
    /// discarded rather than buffered.
    oversized: bool,
    /// Where the filtered bytes land. Owned by the filter and reused, so the
    /// common case — nothing removed — costs no allocation per chunk.
    out: Vec<u8>,
}

impl Osc52Filter {
    /// Feeds one chunk of PTY output through the filter.
    ///
    /// Returns the bytes to hand to VTE, which is `chunk` itself in borrowed
    /// form whenever nothing was removed. A clipboard offer is passed to `sink`
    /// instead of the output.
    ///
    /// The result borrows the filter, so it stays valid until the next call.
    pub fn push<'a>(&'a mut self, chunk: &[u8], sink: &mut dyn FnMut(&str)) -> &'a [u8] {
        self.out.clear();
        for &byte in chunk {
            self.step(byte, sink);
        }
        &self.out
    }

    /// Releases whatever the stream ended in the middle of.
    ///
    /// A lone `ESC` or `c2` is handed over, so the filter never swallows the
    /// tail of a session. An OSC string still open is *dropped* while offers are
    /// honoured: VTE never dispatches an unterminated string, but fed the
    /// fragment it would sit in its string state, and the next `BEL` or `ST` fed
    /// to the same widget (a local message, a reconnect) would complete it
    /// behind the filter's back. With the setting off the fragment is released
    /// as it came, like every other byte. An unterminated string carries no
    /// payload to trust, so `sink` is not involved.
    ///
    /// The result borrows the filter, as [`push`](Self::push)'s does.
    pub fn finish(&mut self) -> &[u8] {
        self.out.clear();
        let open_string = matches!(self.state, State::Osc | State::OscEscape | State::OscC1Lead);
        if open_string && enabled() {
            self.pending.clear();
        } else {
            self.out.append(&mut self.pending);
            // The lookahead byte of an open string is not in `pending`, so it
            // follows it.
            match self.state {
                State::OscEscape => self.out.push(ESC),
                State::OscC1Lead => self.out.push(C1_LEAD),
                State::Ground | State::Escape | State::C1Lead | State::Osc => {}
            }
        }
        self.state = State::Ground;
        self.oversized = false;
        &self.out
    }

    /// Classifies one byte and either passes it on or collects it.
    fn step(&mut self, byte: u8, sink: &mut dyn FnMut(&str)) {
        match self.state {
            State::Ground => match byte {
                ESC => {
                    self.pending.push(byte);
                    self.state = State::Escape;
                }
                C1_LEAD => {
                    self.pending.push(byte);
                    self.state = State::C1Lead;
                }
                _ => self.out.push(byte),
            },
            State::C1Lead => {
                if byte == C1_OSC {
                    self.pending.push(byte);
                    self.state = State::Osc;
                } else {
                    // An ordinary character (or another C1 control, which this
                    // filter has no use for). Classify this byte again, because
                    // `c2 c2 9d` and `c2 ESC ]` each hold a sequence of their own.
                    self.out.append(&mut self.pending);
                    self.state = State::Ground;
                    self.step(byte, sink);
                }
            }
            State::Escape => {
                if byte == INTRODUCER_7BIT {
                    self.pending.push(byte);
                    self.state = State::Osc;
                } else if is_transparent_in_escape(byte) {
                    // VTE runs this control (or ignores `DEL`) and stays in its
                    // `ESC` state, so the filter stays too, with the `ESC` still
                    // held. The control goes out ahead of that `ESC`: executing
                    // it does not depend on the `ESC`, and holding it back would
                    // let a run of controls grow `pending` without a bound.
                    self.out.push(byte);
                } else {
                    // Not an OSC string — this `ESC` opened a CSI, a charset
                    // selector, a keypad mode or something else. Hand the held
                    // `ESC` over and classify this byte again from the ground,
                    // because `ESC ESC ]` is two sequences and not one.
                    self.out.append(&mut self.pending);
                    self.state = State::Ground;
                    self.step(byte, sink);
                }
            }
            State::Osc => match byte {
                BEL => {
                    // The terminator joins `pending`, so that `body_of` sees the
                    // same framing whichever of the three ended the string.
                    self.push_body(byte);
                    self.finish_sequence(sink);
                }
                ESC => self.state = State::OscEscape,
                C1_LEAD => self.state = State::OscC1Lead,
                CAN | SUB => {
                    // VTE drops the string on either and carries on from the
                    // ground, so the fragment and this byte both go to VTE.
                    self.abandon();
                    self.out.push(byte);
                }
                _ => self.push_body(byte),
            },
            State::OscEscape => {
                if byte == TERMINATOR_7BIT {
                    self.push_body(ESC);
                    self.push_body(byte);
                    self.finish_sequence(sink);
                } else {
                    // The string was abandoned mid-flight. Pass on what was
                    // collected — leaving an unterminated OSC in the stream
                    // would make VTE swallow every byte after it as body — and
                    // treat the `ESC` as the start of the next sequence, with
                    // this byte as its second half (VTE's `ST_ESC` does the same).
                    self.abandon();
                    self.pending.push(ESC);
                    self.state = State::Escape;
                    self.step(byte, sink);
                }
            }
            State::OscC1Lead => match byte {
                C1_ST => {
                    self.push_body(C1_LEAD);
                    self.push_body(byte);
                    self.finish_sequence(sink);
                }
                C1_OSC => {
                    // A new OSC replaces the one in progress.
                    self.abandon();
                    self.pending.extend_from_slice(&[C1_LEAD, byte]);
                    self.state = State::Osc;
                }
                0x80..=0x9f => {
                    // Any other C1 control ends the string; both bytes go on.
                    self.abandon();
                    self.out.extend_from_slice(&[C1_LEAD, byte]);
                }
                _ => {
                    // `c2 a0`–`c2 bf` is a printable character, and anything
                    // else leaves `c2` as a malformed prefix that VTE shows as
                    // `U+FFFD` while it reads this byte afresh.
                    self.push_body(C1_LEAD);
                    self.state = State::Osc;
                    self.step(byte, sink);
                }
            },
        }
    }

    /// Gives up on the string in `pending`: what was collected goes on to VTE
    /// as it is, and the filter is back on the ground.
    fn abandon(&mut self) {
        self.out.append(&mut self.pending);
        self.oversized = false;
        self.state = State::Ground;
    }

    /// Collects one body byte, and gives up on a string that outgrew the cap.
    fn push_body(&mut self, byte: u8) {
        if self.pending.len() >= MAX_OSC_BODY {
            self.oversized = true;
            return;
        }
        self.pending.push(byte);
    }

    /// Ends the sequence in `pending`: offers it as a clipboard write, or passes
    /// it through for VTE to deal with.
    fn finish_sequence(&mut self, sink: &mut dyn FnMut(&str)) {
        let oversized = self.oversized;
        let sequence = mem::take(&mut self.pending);
        self.state = State::Ground;
        self.oversized = false;

        // Over-long: discard it rather than emit the fragment, exactly as VTE
        // does past its own limit, and let the next sequence start clean.
        if oversized {
            return;
        }

        // Disabled: byte-for-byte what the stream looked like before this filter
        // existed, which is what VTE — and RustConn — do with the sequence today.
        if !enabled() {
            self.out.extend_from_slice(&sequence);
            return;
        }

        match parse(&sequence) {
            Parsed::Write(text) => sink(&text),
            Parsed::Query => {
                // Deliberately unanswered. A reply would be the local clipboard's
                // contents travelling to the remote, which is the one direction
                // this feature must never open.
                tracing::debug!("dropped OSC 52 clipboard query; reads are not served");
            }
            Parsed::Other => self.out.extend_from_slice(&sequence),
        }
    }
}

/// What a completed OSC string turned out to be.
enum Parsed {
    /// A clipboard write for the `CLIPBOARD` selection, decoded.
    ///
    /// `Zeroizing` because the payload is session output that may be a secret
    /// the user yanked on the remote — the same reasoning as the
    /// `Zeroizing<Vec<u8>>` chunks it arrived in.
    Write(Zeroizing<String>),
    /// A `?` payload: a request for the clipboard's contents.
    Query,
    /// Another OSC, another selection, or something malformed.
    Other,
}

/// Classifies a completed OSC string.
///
/// Every failure mode is `Other`, which means "pass it on" — an unrecognised
/// string is far more likely to be something VTE handles (a title, a colour, a
/// `OSC 133` shell-integration mark) than something worth guessing at.
fn parse(sequence: &[u8]) -> Parsed {
    let Some(body) = body_of(sequence) else {
        return Parsed::Other;
    };
    // Classify the body VTE sees: it ignores some controls inside a string, so
    // `5<NUL>2;c;…` is OSC 52 to it. The copy is wiped on drop because the
    // payload may be a secret the user yanked.
    let cleaned;
    let body = if body.iter().any(|&byte| is_ignored_in_osc_body(byte)) {
        cleaned = Zeroizing::new(
            body.iter()
                .copied()
                .filter(|&byte| !is_ignored_in_osc_body(byte))
                .collect::<Vec<u8>>(),
        );
        cleaned.as_slice()
    } else {
        body
    };

    let mut parts = body.splitn(3, |&byte| byte == b';');
    if parts.next() != Some(b"52".as_slice()) {
        return Parsed::Other;
    }
    // `c` is CLIPBOARD. `p` (primary) and `s` (select) are real xterm
    // selections, but writing them from a remote is not this feature.
    if parts.next() != Some(b"c".as_slice()) {
        return Parsed::Other;
    }

    let Some(payload) = parts.next() else {
        return Parsed::Other;
    };
    if payload == b"?" {
        return Parsed::Query;
    }

    // An empty payload is xterm's way of saying "the selection is now empty",
    // which a remote may as well be allowed to do.
    let Ok(encoded) = std::str::from_utf8(payload) else {
        return Parsed::Other;
    };
    // GLib's decoder stops at the first byte outside the alphabet rather than
    // reporting it, which is acceptable here: the payload is not a trust
    // boundary (the opt-in is), and a remote can send any well-formed base64 it
    // likes regardless. What does matter is that what comes out is text — a
    // clipboard is asked for text, and raw bytes have no business in one.
    //
    // The decoded bytes may be a secret the user yanked, so they are wrapped in
    // `Zeroizing` the instant they land in Rust — before the `String` is built —
    // so the intermediate buffer is wiped on drop rather than left in the heap.
    // (`glib::base64_decode` copies out of its own GLib allocation, which this
    // cannot wipe; swapping in a pure-Rust decoder would close that last gap but
    // is not worth a new dependency for a buffer freed microseconds later.)
    let decoded = Zeroizing::new(glib::base64_decode(encoded));
    match std::str::from_utf8(&decoded) {
        Ok(text) => Parsed::Write(Zeroizing::new(text.to_owned())),
        Err(_) => Parsed::Other,
    }
}

/// Strips the introducer and the terminator off a completed OSC string.
fn body_of(sequence: &[u8]) -> Option<&[u8]> {
    let rest = sequence
        .strip_prefix(&[ESC, INTRODUCER_7BIT])
        .or_else(|| sequence.strip_prefix(&[C1_LEAD, C1_OSC]))?;
    // Both `ST` forms are two bytes, and the filter appends the held first byte
    // together with the second one that completes them.
    rest.strip_suffix(&[ESC, TERMINATOR_7BIT])
        .or_else(|| rest.strip_suffix(&[C1_LEAD, C1_ST]))
        .or_else(|| rest.strip_suffix(&[BEL]))
}

#[cfg(test)]
mod tests {
    use super::{MAX_OSC_BODY, Osc52Filter, Parsed, State, body_of, parse, set_enabled};
    use gtk4::glib;

    /// Encodes `text` the way an application would, so a test can state its
    /// expectation in plain text.
    fn offer(text: &str) -> Vec<u8> {
        let payload = glib::base64_encode(text.as_bytes());
        format!("\x1b]52;c;{payload}\x07").into_bytes()
    }

    /// Runs `bytes` through the filter and returns what VTE would have been fed
    /// plus every clipboard write the filter made, in order.
    fn run(bytes: &[u8]) -> (Vec<u8>, Vec<String>) {
        run_in_chunks(std::iter::once(bytes))
    }

    /// The same, but with the stream cut into the given chunks — which is how a
    /// real PTY read splits a long yank.
    fn run_in_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> (Vec<u8>, Vec<String>) {
        set_enabled(true);
        let mut filter = Osc52Filter::default();
        let mut fed = Vec::new();
        let mut writes = Vec::new();
        for chunk in chunks {
            let mut sink = |text: &str| writes.push(text.to_owned());
            fed.extend_from_slice(filter.push(chunk, &mut sink));
        }
        fed.extend_from_slice(filter.finish());
        (fed, writes)
    }

    #[test]
    fn clipboard_offer_is_lifted_out_of_the_stream() {
        let (fed, writes) = run(&offer("copied on the remote"));
        assert_eq!(writes, ["copied on the remote"]);
        assert!(fed.is_empty(), "VTE must not see the sequence: {fed:?}");
    }

    #[test]
    fn offer_survives_every_possible_chunk_split() {
        let sequence = offer("a payload long enough to cross a chunk boundary for sure");
        // The reference result, fed as one chunk.
        let (fed_whole, writes_whole) = run(&sequence);

        // Every two-way split, which covers an introducer landing on a boundary,
        // the base64 landing on one, and the terminator landing on one.
        for split in 1..sequence.len() {
            let (fed, writes) = run_in_chunks([&sequence[..split], &sequence[split..]]);
            assert_eq!(writes, writes_whole, "writes differ when split at {split}");
            assert_eq!(fed, fed_whole, "output differs when split at {split}");
        }

        // Byte at a time is the worst case a reader can produce.
        let (fed, writes) = run_in_chunks(sequence.chunks(1));
        assert_eq!(writes, writes_whole);
        assert_eq!(fed, fed_whole);
    }

    #[test]
    fn unrelated_output_is_passed_through_byte_for_byte() {
        // A title, an OSC 133 shell-integration mark, a colour, a CSI, a bare
        // ESC and a chunk of plain text — all of which VTE handles today.
        let stream = b"\x1b]0;a title\x07\x1b]133;A\x1b\\hello\x1b[2J\x1b[1;31m\x1b[m world\x1b(B";
        let (fed, writes) = run(stream);
        assert_eq!(fed, stream);
        assert_eq!(writes, Vec::<String>::new());
    }

    #[test]
    fn output_around_a_removed_offer_keeps_its_order() {
        let mut stream = b"before ".to_vec();
        stream.extend_from_slice(&offer("the yank"));
        stream.extend_from_slice(b" after");
        let (fed, writes) = run(&stream);
        assert_eq!(fed, b"before  after");
        assert_eq!(writes, ["the yank"]);
    }

    #[test]
    fn several_offers_in_one_chunk_are_all_handled() {
        let mut stream = offer("first");
        stream.extend_from_slice(&offer("second"));
        stream.extend_from_slice(&offer("third"));
        let (fed, writes) = run(&stream);
        assert_eq!(writes, ["first", "second", "third"]);
        assert_eq!(fed, Vec::<u8>::new());
    }

    #[test]
    fn an_esc_that_starts_something_else_is_not_swallowed() {
        // `ESC [` is a CSI, and the `ESC` before the OSC must survive it.
        let mut stream = b"\x1b[2J".to_vec();
        stream.extend_from_slice(&offer("yank"));
        stream.extend_from_slice(b"\x1b[1;1H");
        let (fed, writes) = run(&stream);
        assert_eq!(fed, b"\x1b[2J\x1b[1;1H");
        assert_eq!(writes, ["yank"]);
    }

    #[test]
    fn a_doubled_escape_starts_a_second_sequence() {
        // `ESC ESC ] 52 …` is a lone `ESC` followed by a perfectly good OSC, the
        // way xterm reads it: the leading byte goes to VTE and the offer is still
        // honoured, rather than one greedy sequence swallowing the pair.
        let mut stream = b"\x1b".to_vec();
        stream.extend_from_slice(&offer("yank"));
        let (fed, writes) = run(&stream);
        assert_eq!(writes, ["yank"]);
        assert_eq!(fed, b"\x1b");
    }

    #[test]
    fn an_abandoned_string_is_handed_over_rather_than_truncated() {
        // A new escape sequence starts before the string is terminated. The
        // fragment goes on to VTE: leaving it there unterminated would make VTE
        // treat the rest of the session as body.
        let payload = glib::base64_encode(b"half");
        let mut stream = format!("\x1b]52;c;{payload}").into_bytes();
        stream.extend_from_slice(b"\x1b[2J");
        let (fed, writes) = run(&stream);
        assert_eq!(writes, Vec::<String>::new());
        // Nothing lost and nothing reordered: the fragment plus the CSI that
        // replaced it comes out as it went in.
        assert_eq!(fed, stream);
    }

    #[test]
    fn a_string_the_stream_ends_inside_is_dropped_by_finish_while_offers_are_honoured() {
        // Fed to VTE, the fragment would leave it in its OSC state, and the next
        // `BEL` it is given (a local message, a reconnect) would complete the
        // offer behind the filter's back. So nothing of it is released — not
        // the lookahead `ESC` / `c2` either.
        let payload = glib::base64_encode(b"cut off");
        let open = format!("\x1b]52;c;{payload}").into_bytes();
        let mut streams = vec![open.clone()];
        for tail in [&b"\x1b"[..], b"\xc2"] {
            streams.push([open.as_slice(), tail].concat());
        }
        streams.push(b"\xc2\x9d52;c;aGVsbG8=".to_vec());
        for stream in streams {
            let (fed, writes) = run(&stream);
            assert!(fed.is_empty(), "{stream:?} leaked an open string: {fed:?}");
            assert!(
                writes.is_empty(),
                "an unterminated payload must not be trusted"
            );
            // The bytes VTE would otherwise see after it are not swallowed.
            let mut after = stream.clone();
            after.extend_from_slice(b"\x18text");
            assert_eq!(run(&after).0, after);
        }
    }

    #[test]
    fn a_string_the_stream_ends_inside_is_released_by_finish_while_the_setting_is_off() {
        let payload = glib::base64_encode(b"cut off");
        let stream = format!("\x1b]52;c;{payload}\x1b").into_bytes();
        set_enabled(false);
        let mut filter = Osc52Filter::default();
        let mut sink = |_: &str| {};
        let mut fed = filter.push(&stream, &mut sink).to_vec();
        fed.extend_from_slice(filter.finish());
        assert_eq!(fed, stream);
    }

    #[test]
    fn controls_ignored_by_vte_do_not_hide_an_offer_in_the_body() {
        // VTE drops NUL, SOH, LF, DEL … inside an OSC string, so each of these
        // is OSC 52 to it and has to be one to the filter.
        let payload = glib::base64_encode(b"hello");
        for noise in ["\x00", "\x01", "\n", "\x17", "\x19", "\x1c", "\x7f"] {
            let streams = [
                format!("\x1b]5{noise}2;c;{payload}\x07"),
                format!("\x1b]52;{noise}c;{payload}\x07"),
                format!("\x1b]52;c;{noise}{payload}{noise}\x07"),
                format!("\x1b]52;c;{payload}{noise}\x1b\\"),
                format!("\u{9d}5{noise}2;c;{payload}\u{9c}"),
            ];
            for stream in streams {
                let (fed, writes) = run(stream.as_bytes());
                assert_eq!(writes, ["hello"], "{stream:?} was not understood");
                assert!(fed.is_empty(), "{stream:?} reached VTE: {fed:?}");
            }
        }
        // A query dressed the same way is still a query, and unanswered.
        let (fed, writes) = run(b"\x1b]5\x002;c;\x01?\x07");
        assert!(writes.is_empty() && fed.is_empty());
        // And with the setting off nothing is altered.
        assert_eq!(
            pushed_once(false, b"\x1b]5\x002;c;aGk=\x07"),
            b"\x1b]5\x002;c;aGk=\x07"
        );
    }

    #[test]
    fn a_control_between_esc_and_the_introducer_does_not_hide_an_offer() {
        // In VTE's ESC state a C0 control is executed and `DEL` ignored without
        // leaving it, so `ESC <control> ]` opens an OSC string. The control goes
        // out; the `ESC` and the offer do not.
        let payload = glib::base64_encode(b"hello");
        for control in ["\x00", "\x07", "\x0a", "\x19", "\x1f", "\x7f"] {
            let stream = format!("\x1b{control}]52;c;{payload}\x07");
            let (fed, writes) = run(stream.as_bytes());
            assert_eq!(writes, ["hello"], "{stream:?} was not understood");
            assert_eq!(fed, control.as_bytes(), "{stream:?}");
            // Several in a row, and in front of an `ST`-terminated offer.
            let stream = format!("\x1b{control}{control}]52;c;{payload}\x1b\\");
            let (fed, writes) = run(stream.as_bytes());
            assert_eq!(writes, ["hello"], "{stream:?} was not understood");
            assert_eq!(fed, [control, control].concat().as_bytes());
        }
        // The same after an abandoned string: `ST_ESC` falls through to `ESC`.
        let mut stream = b"\x1b]0;x\x1b\x01]52;c;".to_vec();
        stream.extend_from_slice(payload.as_bytes());
        stream.push(0x07);
        let (fed, writes) = run(&stream);
        assert_eq!(writes, ["hello"]);
        assert_eq!(fed, b"\x1b]0;x\x01");
    }

    #[test]
    fn a_control_after_esc_that_starts_nothing_keeps_the_sequence_for_vte() {
        // Nothing is removed: the `ESC` is released with whatever follows.
        let (fed, writes) = run(b"\x1b\x07[2Jtext");
        assert_eq!(fed, b"\x07\x1b[2Jtext");
        assert!(writes.is_empty());
        // CAN and SUB end the escape in VTE, so they are not transparent.
        let (fed, _) = run(b"\x1b\x18]52;c;aGk=\x07");
        assert_eq!(fed, b"\x1b\x18]52;c;aGk=\x07");
        let (fed, _) = run(b"\x1b\x1a]52;c;aGk=\x07");
        assert_eq!(fed, b"\x1b\x1a]52;c;aGk=\x07");
    }

    #[test]
    fn an_oversized_string_is_discarded_and_the_next_one_still_works() {
        let mut stream = vec![b'\x1b', b']', b'0', b';'];
        stream.extend(std::iter::repeat_n(b'x', MAX_OSC_BODY + 16));
        stream.push(0x07);
        stream.extend_from_slice(b"visible");
        stream.extend_from_slice(&offer("after the flood"));

        let (fed, writes) = run(&stream);
        assert_eq!(writes, ["after the flood"], "the filter did not recover");
        assert_eq!(fed, b"visible");
    }

    #[test]
    fn a_query_is_never_answered() {
        let (fed, writes) = run(b"\x1b]52;c;?\x07");
        assert!(
            writes.is_empty(),
            "the local clipboard must not be sent out"
        );
        assert_eq!(fed, Vec::<u8>::new());
    }

    #[test]
    fn the_primary_and_select_selections_are_left_alone() {
        let payload = glib::base64_encode(b"yank");
        for selection in ["p", "s", "q0", "0"] {
            let stream = format!("\x1b]52;{selection};{payload}\x07").into_bytes();
            let (fed, writes) = run(&stream);
            assert!(
                writes.is_empty(),
                "selection {selection} must not be written"
            );
            assert_eq!(fed, stream, "selection {selection} must be passed on");
        }
    }

    #[test]
    fn a_payload_that_is_not_text_never_reaches_the_clipboard() {
        // Valid base64 of bytes that are not valid UTF-8.
        let payload = glib::base64_encode(&[0xff, 0xfe, 0xfd]);
        let stream = format!("\x1b]52;c;{payload}\x07").into_bytes();
        let (fed, writes) = run(&stream);
        assert!(writes.is_empty());
        assert_eq!(fed, stream);
    }

    #[test]
    fn an_empty_payload_clears_the_clipboard() {
        let (fed, writes) = run(b"\x1b]52;c;\x07");
        assert_eq!(writes, [""]);
        assert_eq!(fed, Vec::<u8>::new());
    }

    #[test]
    fn nothing_is_removed_while_the_setting_is_off() {
        let sequence = offer("yank");
        set_enabled(false);
        let mut filter = Osc52Filter::default();
        let mut writes = Vec::new();
        let mut sink = |text: &str| writes.push(text.to_owned());
        let fed = filter.push(&sequence, &mut sink).to_vec();
        assert_eq!(fed, sequence, "the sequence must reach VTE untouched");
        assert_eq!(writes, Vec::<String>::new());

        // And an offer split across chunks stays whole on the way to VTE.
        set_enabled(false);
        let mut filter = Osc52Filter::default();
        let mut fed = Vec::new();
        for byte in &sequence {
            let mut sink = |text: &str| writes.push(text.to_owned());
            fed.extend_from_slice(filter.push(std::slice::from_ref(byte), &mut sink));
        }
        assert_eq!(fed, sequence);
        assert_eq!(writes, Vec::<String>::new());
    }

    #[test]
    fn the_setting_is_read_per_sequence_so_it_applies_to_open_sessions() {
        set_enabled(false);
        let mut filter = Osc52Filter::default();
        let mut writes = Vec::new();
        let mut sink = |text: &str| writes.push(text.to_owned());

        // Off: through to VTE.
        let mut fed = filter.push(&offer("first"), &mut sink).to_vec();
        // The user turns it on in Preferences mid-session.
        set_enabled(true);
        fed.extend_from_slice(filter.push(&offer("second"), &mut sink));

        assert_eq!(writes, ["second"]);
        assert_eq!(fed, offer("first"));
    }

    /// Builds `OSC 52 ; c ; <base64 of "hello">` with the framing asked for, as
    /// raw bytes.
    ///
    /// A C1 control in a terminal stream is the UTF-8 encoding of its code point
    /// (`c2 9c` for `ST`, as `"\u{9c}".as_bytes()`), because VTE decodes UTF-8
    /// before it parses. A bare `0x9c` is a continuation byte, not a control.
    fn framed_offer(introducer: &[u8], terminator: &[u8]) -> Vec<u8> {
        let mut sequence = introducer.to_vec();
        sequence.extend_from_slice(b"52;c;");
        sequence.extend_from_slice(glib::base64_encode(b"hello").as_bytes());
        sequence.extend_from_slice(terminator);
        sequence
    }

    /// Every introducer VTE accepts, and every terminator.
    const INTRODUCERS: [&[u8]; 2] = [b"\x1b]", b"\xc2\x9d"];
    const TERMINATORS: [&[u8]; 3] = [b"\x1b\\", b"\x07", b"\xc2\x9c"];

    #[test]
    fn both_terminators_and_both_introducers_are_understood() {
        for introducer in INTRODUCERS {
            for terminator in TERMINATORS {
                let sequence = framed_offer(introducer, terminator);
                let (fed, writes) = run(&sequence);
                assert_eq!(writes, ["hello"], "{sequence:?} was not understood");
                assert!(fed.is_empty(), "{sequence:?} reached VTE: {fed:?}");
            }
        }
    }

    #[test]
    fn a_raw_c1_byte_is_a_utf8_continuation_not_a_control() {
        // A bare 0x9c does not end a string: VTE reads it as part of a character
        // or as U+FFFD. The payload is therefore still open, so nothing is
        // written, and the stream ended inside it. With offers honoured the open
        // string is dropped; with the setting off it all reaches VTE unchanged.
        let mut sequence = b"\x1b]52;c;".to_vec();
        sequence.extend_from_slice(glib::base64_encode(b"hello").as_bytes());
        sequence.push(0x9c);
        sequence.extend_from_slice(b"rest");
        let (fed, writes) = run(&sequence);
        assert!(writes.is_empty(), "a bare 0x9c ended the string");
        assert!(fed.is_empty(), "an open string was released: {fed:?}");
        set_enabled(false);
        let mut filter = Osc52Filter::default();
        let mut sink = |_: &str| {};
        let mut fed = filter.push(&sequence, &mut sink).to_vec();
        fed.extend_from_slice(filter.finish());
        assert_eq!(fed, sequence);

        // Nor does a bare 0x9d introduce one.
        let mut sequence = vec![0x9d];
        sequence.extend_from_slice(b"52;c;aGVsbG8=\x07");
        for enabled in [false, true] {
            assert_eq!(pushed_once(enabled, &sequence), sequence);
        }
        let (fed, writes) = run(&sequence);
        assert!(writes.is_empty(), "a bare 0x9d introduced a string");
        assert_eq!(fed, sequence);
    }

    #[test]
    fn the_utf8_encoded_st_terminates_like_vte() {
        let mut sequence = b"\x1b]52;c;".to_vec();
        sequence.extend_from_slice(glib::base64_encode(b"hello").as_bytes());
        sequence.extend_from_slice("\u{9c}".as_bytes());
        let (fed, writes) = run(&sequence);
        assert_eq!(writes, ["hello"]);
        assert!(fed.is_empty(), "the sequence reached VTE: {fed:?}");
    }

    #[test]
    fn body_of_strips_only_the_framing() {
        assert_eq!(body_of(b"\x1b]0;title\x07"), Some(&b"0;title"[..]));
        assert_eq!(body_of(b"\x1b]0;title\x1b\\"), Some(&b"0;title"[..]));
        assert_eq!(body_of(b"\xc2\x9d0;title\xc2\x9c"), Some(&b"0;title"[..]));
        assert_eq!(body_of(b"\xc2\x9d0;title\x07"), Some(&b"0;title"[..]));
        assert_eq!(body_of(b"\x9d0;title\x9c"), None);
        assert_eq!(body_of(b"\x1b[2J"), None);
        assert_eq!(body_of(b"\x1b]"), None);
    }

    #[test]
    fn an_arrow_glyph_inside_a_title_does_not_end_it_early() {
        // `➜` is e2 9e 9c: its last byte is a continuation byte, not `ST`.
        let mut stream = "\x1b]0;\u{279c} dir\x07".as_bytes().to_vec();
        stream.extend_from_slice(&offer("yank"));
        let (fed, writes) = run(&stream);
        assert_eq!(fed, "\x1b]0;\u{279c} dir\x07".as_bytes());
        assert_eq!(writes, ["yank"]);
    }

    #[test]
    fn a_cyrillic_title_with_0x9c_and_0x9d_bytes_stays_whole() {
        // `ѝ` is d1 9d and `ќ` is d1 9c.
        for introducer in INTRODUCERS {
            for terminator in TERMINATORS {
                let mut stream = introducer.to_vec();
                stream.extend_from_slice("0;\u{45d}\u{45c} сервер".as_bytes());
                stream.extend_from_slice(terminator);
                let (fed, writes) = run(&stream);
                assert_eq!(fed, stream, "the title was altered");
                assert!(writes.is_empty());
            }
        }
    }

    #[test]
    fn can_and_sub_abort_an_osc_string_like_vte() {
        let payload = glib::base64_encode(b"hello");
        for abort in [&b"\x18"[..], b"\x1a", b"\xc2\x9b", b"\xc2\x85", b"\xc2\x9e"] {
            let mut stream = format!("\x1b]52;c;{payload}").into_bytes();
            stream.extend_from_slice(abort);
            stream.extend_from_slice("текст".as_bytes());
            // Everything is released by the one `push`, no `finish` needed.
            assert_eq!(pushed_once(true, &stream), stream, "{abort:?} held bytes");
            let (fed, writes) = run(&stream);
            assert_eq!(fed, stream);
            assert!(writes.is_empty(), "{abort:?} did not abort the string");
        }
    }

    #[test]
    fn a_c1_osc_inside_an_osc_starts_a_new_one() {
        let mut stream = b"\x1b]0;x".to_vec();
        stream.extend_from_slice(b"\xc2\x9d52;c;");
        stream.extend_from_slice(glib::base64_encode(b"hello").as_bytes());
        stream.push(0x07);
        let (fed, writes) = run(&stream);
        assert_eq!(fed, b"\x1b]0;x");
        assert_eq!(writes, ["hello"]);
    }

    #[test]
    fn an_offer_right_after_an_abandoned_string_is_still_honoured() {
        let mut stream = b"\x1b]0;x".to_vec();
        stream.extend_from_slice(&offer("hello"));
        let (fed, writes) = run(&stream);
        assert_eq!(fed, b"\x1b]0;x");
        assert_eq!(writes, ["hello"]);
    }

    #[test]
    fn only_an_incomplete_prefix_is_held_at_a_chunk_end() {
        // Text, a split glyph and a split `❯`: VTE draws what it can, so the
        // filter holds nothing.
        for chunk in [&b"text \xe2"[..], b"text \xe2\x9d", b"text \xd1"] {
            assert_eq!(pushed_once(true, chunk), chunk, "{chunk:?} was held");
        }
        // A lone `c2` or `ESC` is a prefix VTE also waits on.
        for chunk in [&b"text \xc2"[..], b"text \x1b"] {
            assert_eq!(pushed_once(true, chunk), b"text ", "{chunk:?}");
        }
        // And `finish` releases it.
        for held in [&b"\xc2"[..], b"\x1b"] {
            let (fed, writes) = run(held);
            assert_eq!(fed, held);
            assert!(writes.is_empty());
        }
        // A control after the held `ESC` goes out at once; the `ESC` stays.
        assert_eq!(pushed_once(true, b"text \x1b\x07"), b"text \x07");
    }

    #[test]
    fn the_oversized_flag_is_cleared_when_a_string_is_abandoned() {
        let mut stream = b"\x1b]0;".to_vec();
        stream.extend(std::iter::repeat_n(b'x', MAX_OSC_BODY + 16));
        stream.push(0x18);
        stream.extend_from_slice(&offer("after"));
        let (_, writes) = run(&stream);
        assert_eq!(writes, ["after"]);
    }

    /// Streams that exercise every transition of the filter.
    fn corpus() -> Vec<Vec<u8>> {
        let hello = glib::base64_encode(b"hello");
        let mut corpus: Vec<Vec<u8>> = vec![
            "\x1b]0;anton@pop-os: ~\x07\u{256d}\u{2500} anton\r\n\u{2570}\u{276f} "
                .as_bytes()
                .to_vec(),
            "\x1b]0;\u{279c} dir\x07\x1b]0;\u{279c} dir\x1b\\"
                .as_bytes()
                .to_vec(),
            "\x1b]0;\u{45d}\u{45c} сервер\x07\u{255d}\u{f09d}\u{45d}"
                .as_bytes()
                .to_vec(),
            b"\xc2".to_vec(),
            b"\xc2\xc2\x9d0;x\x07".to_vec(),
            b"\xc2\x1b]0;x\x07".to_vec(),
            b"\x1b\x1b]0;x\x07".to_vec(),
            b"\x1b]0;x\x1b[2Jtext".to_vec(),
            b"\x1b]0;x\x18text\x1b]0;y\x1atext".to_vec(),
            b"\x1b]0;x\xc2\x9btext\xc2\xa0nbsp\xc2\x07".to_vec(),
            b"\x1b]0;x\xc2\x9d0;y\xc2\x9c".to_vec(),
            b"\x1b]0;\x9c\x9d\xc2\xc2\x9c".to_vec(),
        ];
        for introducer in INTRODUCERS {
            for terminator in TERMINATORS {
                corpus.push(framed_offer(introducer, terminator));
                let mut around = b"before ".to_vec();
                around.extend_from_slice(&framed_offer(introducer, terminator));
                around.extend_from_slice("\u{276f} after".as_bytes());
                corpus.push(around);
            }
        }
        let mut aborted = b"\x1b]52;c;".to_vec();
        aborted.extend_from_slice(hello.as_bytes());
        aborted.push(0x18);
        aborted.extend_from_slice(&offer("again"));
        corpus.push(aborted);
        corpus
    }

    /// Streams where a C0 control meets a held `ESC` or ignored controls sit in
    /// a string: with the setting off, the control still goes out ahead of the
    /// `ESC`, so these are checked for chunking alone, not for identity.
    fn escape_corpus() -> Vec<Vec<u8>> {
        let hello = glib::base64_encode(b"hello");
        let mut corpus = vec![
            b"\x1b]0;x\x1b\x07tail".to_vec(),
            b"\x1b\x07[2Jtext".to_vec(),
            b"\x1b\x00\x7f\x19\x1f]0;x\x07".to_vec(),
            b"\x1b\x18]0;x\x07\x1b\x1a]0;y\x07".to_vec(),
            b"\x1b\xc2\x9d0;x\x07".to_vec(),
        ];
        for noise in ["\x00", "\x01", "\n", "\x7f"] {
            corpus.push(format!("\x1b]5{noise}2;c;{hello}{noise}\x07").into_bytes());
            corpus.push(format!("\x1b{noise}]52;c;{hello}\x1b\\ after").into_bytes());
            corpus.push(format!("\x1b]0;x\x1b{noise}]52;c;{hello}\x07").into_bytes());
            corpus.push(format!("\u{9d}52;{noise}c;{hello}\u{9c}").into_bytes());
        }
        corpus
    }

    /// Runs `chunks` through one filter, `finish` included.
    fn feed_chunks(enabled: bool, chunks: Vec<&[u8]>) -> (Vec<u8>, Vec<String>) {
        set_enabled(enabled);
        let mut filter = Osc52Filter::default();
        let mut fed = Vec::new();
        let mut writes = Vec::new();
        for chunk in chunks {
            let mut sink = |text: &str| writes.push(text.to_owned());
            fed.extend_from_slice(filter.push(chunk, &mut sink));
        }
        fed.extend_from_slice(filter.finish());
        (fed, writes)
    }

    #[test]
    fn every_split_of_the_corpus_matches_the_whole_feed() {
        let exact = corpus().into_iter().map(|stream| (stream, true));
        let reordering = escape_corpus().into_iter().map(|stream| (stream, false));
        for (stream, exact) in exact.chain(reordering) {
            for enabled in [true, false] {
                let whole = feed_chunks(enabled, vec![&stream]);
                assert_eq!(
                    feed_chunks(enabled, stream.chunks(1).collect()),
                    whole,
                    "byte-at-a-time differs for {stream:?} (enabled = {enabled})"
                );
                for split in 1..stream.len() {
                    assert_eq!(
                        feed_chunks(enabled, vec![&stream[..split], &stream[split..]]),
                        whole,
                        "split at {split} differs for {stream:?} (enabled = {enabled})"
                    );
                }
                if !enabled {
                    assert!(whole.1.is_empty());
                    if exact {
                        assert_eq!(whole.0, stream, "the disabled filter altered {stream:?}");
                    } else {
                        let (mut got, mut want) = (whole.0, stream.clone());
                        got.sort_unstable();
                        want.sort_unstable();
                        assert_eq!(got, want, "the disabled filter lost bytes of {stream:?}");
                    }
                }
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn chunking_never_changes_the_result(
            alphabet in proptest::collection::vec(
                proptest::sample::select(ALPHABET.to_vec()),
                0..64,
            ),
            cuts in proptest::collection::vec(0usize..64, 0..6),
            enabled in proptest::bool::ANY,
        ) {
            let run_with = |chunks: Vec<&[u8]>| feed_chunks(enabled, chunks);
            let whole = run_with(vec![&alphabet]);
            let mut points: Vec<usize> = cuts.iter().map(|cut| cut % (alphabet.len() + 1)).collect();
            points.sort_unstable();
            let mut chunks = Vec::new();
            let mut start = 0;
            for point in points {
                chunks.push(&alphabet[start..point]);
                start = point;
            }
            chunks.push(&alphabet[start..]);
            proptest::prop_assert_eq!(run_with(chunks), whole.clone());
            if !enabled {
                // A control may pass a held `ESC`, so compare the bytes, not
                // their order.
                let (mut got, mut want) = (whole.0, alphabet.clone());
                got.sort_unstable();
                want.sort_unstable();
                proptest::prop_assert_eq!(got, want);
            }
        }

        #[test]
        fn nothing_is_held_back_while_the_filter_is_on_the_ground(
            alphabet in proptest::collection::vec(
                proptest::sample::select(ALPHABET.to_vec()),
                0..64,
            ),
            cuts in proptest::collection::vec(0usize..64, 0..6),
        ) {
            set_enabled(false);
            let mut points: Vec<usize> = cuts.iter().map(|cut| cut % (alphabet.len() + 1)).collect();
            points.sort_unstable();
            let mut filter = Osc52Filter::default();
            let mut sink = |_: &str| {};
            let (mut fed, mut released, mut start) = (0, 0, 0);
            for point in points.into_iter().chain([alphabet.len()]) {
                let chunk = &alphabet[start..point];
                start = point;
                fed += chunk.len();
                released += filter.push(chunk, &mut sink).len();
                // Only an open string, a lone `ESC` or a lone `c2` may be held.
                if filter.state == State::Ground {
                    proptest::prop_assert_eq!(released, fed);
                }
            }
        }
    }

    /// Bytes that make the filter's sequences turn up often in generated input.
    const ALPHABET: [u8; 21] = [
        0x1b, b']', b'\\', 0x07, 0x18, 0x1a, 0xc2, 0x9c, 0x9d, 0x9b, 0xe2, 0xa0, b'5', b'2', b';',
        b'c', b'A', b'=', 0x01, 0x7f, 0x0a,
    ];

    /// What one `push` hands back for `bytes`, with no `finish`, so a held byte
    /// shows up as a short result.
    fn pushed_once(enabled: bool, bytes: &[u8]) -> Vec<u8> {
        set_enabled(enabled);
        let mut filter = Osc52Filter::default();
        let mut sink = |_: &str| {};
        filter.push(bytes, &mut sink).to_vec()
    }

    #[test]
    fn a_prompt_glyph_with_a_0x9d_continuation_passes_through_at_once() {
        // The oh-my-bash `powerline-multiline` prompt: `❯` is e2 9d af, and its
        // 0x9d is a UTF-8 continuation byte, not a C1 OSC introducer.
        let stream =
            "\x1b]0;anton@pop-os: ~\x07\u{256d}\u{2500} anton\r\n\u{2570}\u{276f} ".as_bytes();
        for enabled in [false, true] {
            assert_eq!(
                pushed_once(enabled, stream),
                stream,
                "the prompt line was held back (enabled = {enabled})"
            );
        }
    }

    #[test]
    fn box_drawing_and_nerd_font_glyphs_are_not_held() {
        // ╝ e2 95 9d, ┝ e2 94 9d, U+F09D ef 82 9d, ѝ d1 9d.
        let stream = "a \u{255d} b \u{251d} c \u{f09d} d \u{45d} e".as_bytes();
        for enabled in [false, true] {
            assert_eq!(pushed_once(enabled, stream), stream, "enabled = {enabled}");
        }
    }

    #[test]
    fn parse_classifies_the_three_outcomes() {
        let write = format!("\x1b]52;c;{}\x07", glib::base64_encode(b"text"));
        assert!(matches!(parse(write.as_bytes()), Parsed::Write(_)));
        assert!(matches!(parse(b"\x1b]52;c;?\x07"), Parsed::Query));
        assert!(matches!(parse(b"\x1b]0;title\x07"), Parsed::Other));
        assert!(matches!(parse(b"\x1b]52;c\x07"), Parsed::Other));
        assert!(matches!(parse(b"\x1b]52;c"), Parsed::Other));
    }
}
