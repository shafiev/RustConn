//! Holds PTY output back while the user drags out a mouse selection.
//!
//! VTE drops a selection whenever new output arrives before the drag ends. In
//! `process_incoming` it compares the selected text with the PRIMARY copy it
//! takes on button release, and mid-drag there is no such copy yet, so any
//! output at all deselects. For its own PTY, VTE avoids this by not reading
//! while a selection is in progress (`disconnect_pty_read` in
//! `start_selection`). RustConn owns the PTY and calls `feed`, which bypasses
//! that pause. A remote that redraws on a timer, such as byobu's status clock,
//! would cancel every drag that takes longer than a second.
//!
//! [`SelectionHold`] restores the pause on the relay side. The output loop
//! waits while the primary button is down and VTE is selecting for this press,
//! and resumes on release. A click that VTE reports to a mouse-tracking app
//! (tmux with mouse on, vim) starts no selection and never pauses output, even
//! when an older selection is still on screen: VTE leaves that one alone, so
//! `has_selection` alone cannot tell the two apart. The hold therefore pauses
//! only for a selection that was empty at the press or that VTE replaced after
//! it (`selection-changed`). Nothing is buffered here: while the loop waits,
//! the relay's bounded queue fills and the reader thread blocks, the same
//! backpressure VTE gets.

use std::cell::Cell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{EventControllerFocus, EventControllerLegacy, PropagationPhase, gdk, glib};
use vte4::Terminal;
use vte4::prelude::TerminalExt;

/// Tracks whether a selection drag is in progress on one terminal.
pub(super) struct SelectionHold {
    held: Rc<Cell<bool>>,
    /// The selection on screen belongs to the current press, not to an older one.
    fresh: Rc<Cell<bool>>,
    wake: async_channel::Receiver<()>,
    /// Weak on purpose: the terminal owns its controllers, and the controllers'
    /// closures own the only senders of `wake`. If the hold kept them alive, a
    /// terminal destroyed mid-drag would never close the channel and the
    /// waiter would park for good. Weak, dropping the last reference to the
    /// terminal (GTK removes a widget's controllers when it finalizes, not when
    /// it is disposed) drops the senders and wakes the waiter.
    controllers: Option<(
        glib::WeakRef<EventControllerLegacy>,
        glib::WeakRef<EventControllerFocus>,
    )>,
    selection_changed: Option<glib::SignalHandlerId>,
}

impl SelectionHold {
    /// Starts watching the primary button on `terminal`.
    ///
    /// The controllers only observe: every event is passed on to VTE.
    pub(super) fn attach(terminal: &Terminal) -> Self {
        let (held, wake_tx, wake) = Self::state();
        let fresh = Rc::new(Cell::new(false));

        let buttons = EventControllerLegacy::new();
        buttons.set_propagation_phase(PropagationPhase::Capture);
        let held_on_button = Rc::clone(&held);
        let fresh_on_button = Rc::clone(&fresh);
        let wake_on_button = wake_tx.clone();
        // Weak, so the controller the terminal owns does not own the terminal.
        let terminal_on_button = terminal.downgrade();
        buttons.connect_event(move |_, event| {
            let primary = event
                .downcast_ref::<gdk::ButtonEvent>()
                .is_some_and(|button| button.button() == gdk::BUTTON_PRIMARY);
            if primary {
                match event.event_type() {
                    gdk::EventType::ButtonPress => {
                        // Capture phase: VTE has not handled this press yet, so
                        // this is the selection the press found, not one it made.
                        let had_selection = terminal_on_button
                            .upgrade()
                            .is_some_and(|terminal| terminal.has_selection());
                        press(&held_on_button, &fresh_on_button, had_selection);
                    }
                    gdk::EventType::ButtonRelease => {
                        release(&held_on_button, &wake_on_button);
                    }
                    _ => {}
                }
            }
            glib::Propagation::Proceed
        });

        // A release that never reaches the terminal (the window lost focus mid
        // drag) would otherwise stall the session's output until the next click.
        let focus = EventControllerFocus::new();
        let held_on_leave = Rc::clone(&held);
        focus.connect_leave(move |_| release(&held_on_leave, &wake_tx));

        // VTE emits this synchronously from `deselect_all`, which it runs when a
        // press starts a new selection over an old one.
        let held_on_change = Rc::clone(&held);
        let fresh_on_change = Rc::clone(&fresh);
        let changed_id = terminal.connect_selection_changed(move |_| {
            selection_changed(&held_on_change, &fresh_on_change);
        });

        terminal.add_controller(buttons.clone());
        terminal.add_controller(focus.clone());

        Self {
            held,
            fresh,
            wake,
            controllers: Some((buttons.downgrade(), focus.downgrade())),
            selection_changed: Some(changed_id),
        }
    }

    fn state() -> (
        Rc<Cell<bool>>,
        async_channel::Sender<()>,
        async_channel::Receiver<()>,
    ) {
        // One slot is enough: the waiter re-checks the state after every wake.
        let (wake_tx, wake) = async_channel::bounded(1);
        (Rc::new(Cell::new(false)), wake_tx, wake)
    }

    /// Returns once the primary button is up, the press turns out not to be
    /// selecting, `has_selection` turns false, or the terminal is gone.
    ///
    /// `has_selection` is re-checked after every wake. The caller passes VTE's
    /// own `has_selection` through a weak reference, so a terminal closed mid
    /// drag is not kept alive by its output loop. When the last reference to
    /// the terminal is dropped, GTK finalizes it and removes its controllers,
    /// and with them every sender of the wake channel, which ends the wait; that
    /// is the only wake a destroyed terminal can send.
    #[expect(
        clippy::future_not_send,
        reason = "GTK state; awaited only from glib::spawn_future_local on the main thread"
    )]
    pub(super) async fn wait_while_selecting(&self, has_selection: impl Fn() -> bool) {
        while self.wake.try_recv().is_ok() {}
        while self.held.get() && self.fresh.get() && has_selection() {
            if self.wake.recv().await.is_err() {
                return;
            }
        }
    }

    /// Removes the controllers and the signal handler again, so a reconnect does
    /// not stack them.
    pub(super) fn detach(mut self, terminal: &Terminal) {
        if let Some((buttons, focus)) = self.controllers.take() {
            if let Some(buttons) = buttons.upgrade() {
                terminal.remove_controller(&buttons);
            }
            if let Some(focus) = focus.upgrade() {
                terminal.remove_controller(&focus);
            }
        }
        if let Some(id) = self.selection_changed.take() {
            terminal.disconnect(id);
        }
    }
}

/// A primary press: a selection already on screen is only this drag's if VTE
/// replaces it, which `selection_changed` reports.
// ponytail: a triple-click drag over a word the double-click just selected
// reaches VTE's `start_selection` without `deselect_all`, so no signal arrives
// and that drag is not held (the pre-#391 behaviour). Track the click count
// from the gesture if this turns out to matter.
fn press(held: &Cell<bool>, fresh: &Cell<bool>, had_selection: bool) {
    held.set(true);
    fresh.set(!had_selection);
}

/// VTE changed the selection. While the button is down that is a new selection
/// started by this press; after the release it is the finished drag.
fn selection_changed(held: &Cell<bool>, fresh: &Cell<bool>) {
    if held.get() {
        fresh.set(true);
    }
}

fn release(held: &Cell<bool>, wake: &async_channel::Sender<()>) {
    held.set(false);
    // Full means a wake is already pending, which is all the waiter needs.
    let _ = wake.try_send(());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hold whose button state the test drives, since GDK events cannot be
    /// synthesised without a display.
    fn manual_hold() -> (SelectionHold, async_channel::Sender<()>) {
        let (held, wake_tx, wake) = SelectionHold::state();
        let manual = SelectionHold {
            held,
            fresh: Rc::new(Cell::new(false)),
            wake,
            controllers: None,
            selection_changed: None,
        };
        (manual, wake_tx)
    }

    fn pump(ctx: &glib::MainContext) {
        while ctx.iteration(false) {}
    }

    #[test]
    fn a_click_without_a_selection_does_not_wait() {
        let (hold, _wake_tx) = manual_hold();
        press(&hold.held, &hold.fresh, false);
        glib::MainContext::new().block_on(hold.wait_while_selecting(|| false));
    }

    #[test]
    fn an_old_selection_under_a_forwarded_click_does_not_wait() {
        let (hold, _wake_tx) = manual_hold();
        // VTE forwards the click to the app and leaves the old selection alone,
        // so no `selection-changed` follows the press.
        press(&hold.held, &hold.fresh, true);
        glib::MainContext::new().block_on(hold.wait_while_selecting(|| true));
    }

    #[test]
    fn a_new_selection_over_an_old_one_waits_until_the_release() {
        let ctx = glib::MainContext::new();
        let (hold, wake_tx) = manual_hold();
        press(&hold.held, &hold.fresh, true);
        // VTE ran `deselect_all` for the new drag.
        selection_changed(&hold.held, &hold.fresh);

        let hold = Rc::new(hold);
        let done = Rc::new(Cell::new(false));
        let (hold_task, done_task) = (Rc::clone(&hold), Rc::clone(&done));
        drop(ctx.spawn_local(async move {
            hold_task.wait_while_selecting(|| true).await;
            done_task.set(true);
        }));

        pump(&ctx);
        assert!(!done.get(), "output resumed mid drag");
        release(&hold.held, &wake_tx);
        pump(&ctx);
        assert!(done.get(), "output did not resume on release");
    }

    #[test]
    fn a_selection_change_after_the_release_is_not_a_new_drag() {
        let (hold, wake_tx) = manual_hold();
        press(&hold.held, &hold.fresh, true);
        release(&hold.held, &wake_tx);
        // VTE reports the finished drag on release; it must not arm the next press.
        selection_changed(&hold.held, &hold.fresh);
        assert!(!hold.fresh.get());
    }

    #[test]
    fn a_waiter_wakes_when_the_last_sender_is_dropped() {
        let ctx = glib::MainContext::new();
        let (hold, wake_tx) = manual_hold();
        press(&hold.held, &hold.fresh, false);

        let hold = Rc::new(hold);
        let done = Rc::new(Cell::new(false));
        let (hold_task, done_task) = (Rc::clone(&hold), Rc::clone(&done));
        drop(ctx.spawn_local(async move {
            hold_task.wait_while_selecting(|| true).await;
            done_task.set(true);
        }));

        pump(&ctx);
        assert!(!done.get(), "output resumed mid drag");
        // The terminal was disposed mid drag: its controllers, and with them
        // the senders their closures own, are gone, and no release ever came.
        drop(wake_tx);
        pump(&ctx);
        assert!(done.get(), "a destroyed terminal left the waiter parked");
    }

    #[test]
    fn a_finished_selection_does_not_wait() {
        let (hold, _wake_tx) = manual_hold();
        glib::MainContext::new().block_on(hold.wait_while_selecting(|| true));
    }

    #[test]
    fn a_drag_waits_until_the_release() {
        let ctx = glib::MainContext::new();
        let (hold, wake_tx) = manual_hold();
        press(&hold.held, &hold.fresh, false);
        // A wake left over from an earlier drag must not end this one.
        assert!(wake_tx.try_send(()).is_ok());

        let hold = Rc::new(hold);
        let done = Rc::new(Cell::new(false));
        let (hold_task, done_task) = (Rc::clone(&hold), Rc::clone(&done));
        drop(ctx.spawn_local(async move {
            hold_task.wait_while_selecting(|| true).await;
            done_task.set(true);
        }));

        pump(&ctx);
        assert!(!done.get(), "output resumed mid drag");
        release(&hold.held, &wake_tx);
        pump(&ctx);
        assert!(done.get(), "output did not resume on release");
    }
}
