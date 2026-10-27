//! "Set Up Key Authentication" dialog.
//!
//! This module is widgets and wording only. It never starts a process and never
//! touches the application state: the sequence generate, install, verify lives
//! in `window/key_setup.rs`, which drives [`KeySetupDialog`] through its state
//! methods (`set_resolving`, `set_running`, `show_failure`,
//! `show_second_factor`).
//!
//! The wording for every way key setup can end is in [`failure_view`], a pure
//! function over [`KeySetupError`], so each outcome has a unit test even though
//! the dialog itself cannot be built without a display.

use std::path::Path;

use adw::prelude::*;
use gtk4::prelude::*;
use libadwaita as adw;
use rustconn_core::ssh_key_setup::{DeployStep, KeyAlgorithm, KeySetupError, NetworkFailure};
use secrecy::SecretString;

use crate::i18n::{i18n, i18n_f};

/// Which step of key setup is running, for the status line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySetupStage {
    /// Looking up the stored account password.
    ResolvingPassword,
    /// `ssh-keygen`.
    Generating,
    /// Appending the key to the server's `authorized_keys`.
    Installing,
    /// Signing in with the new key.
    Verifying,
}

/// The status line for a running stage. `host` is `user@host` or `host`.
#[must_use]
pub fn stage_label(stage: KeySetupStage, host: &str) -> String {
    match stage {
        KeySetupStage::ResolvingPassword => i18n("Looking up the stored password…"),
        KeySetupStage::Generating => i18n("Generating key…"),
        KeySetupStage::Installing => i18n_f("Installing the key on {}…", &[host]),
        KeySetupStage::Verifying => i18n("Checking that the key signs in…"),
    }
}

/// What the dialog knows about how the account password was handled, which
/// decides how an authentication failure reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FailureContext {
    /// A password was handed to the install step.
    pub password_sent: bool,
    /// A password was available but the connection's options or proxy route
    /// stopped RustConn from passing it (the same gate as a normal connect).
    pub password_gated_off: bool,
}

/// The one extra thing a failure can ask for besides retrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    /// Nothing else.
    None,
    /// Offer "Connect": open a normal session to accept the host key.
    Connect,
    /// Show the account password row: the user can fix this by typing it.
    AskPassword,
}

/// How one failure is shown: the text and which actions make sense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureView {
    /// Heading, only for outcomes that deserve one.
    pub title: Option<String>,
    /// What happened and what to do.
    pub body: String,
    /// The extra action on offer.
    pub action: FailureAction,
    /// Offer to run the setup again.
    pub retry: bool,
    /// Offer "Delete Generated Key" (when a key exists on disk).
    pub delete_key: bool,
}

impl FailureView {
    /// A failure with just a message and no actions.
    #[must_use]
    pub fn message(body: String) -> Self {
        Self {
            title: None,
            body,
            action: FailureAction::None,
            retry: false,
            delete_key: false,
        }
    }

    /// Also offer to try again.
    #[must_use]
    pub fn retry(mut self) -> Self {
        self.retry = true;
        self
    }

    /// Also offer to delete the generated key.
    #[must_use]
    pub fn with_delete(mut self) -> Self {
        self.delete_key = true;
        self
    }

    fn titled(mut self, title: String) -> Self {
        self.title = Some(title);
        self
    }

    fn with_action(mut self, action: FailureAction) -> Self {
        self.action = action;
        self
    }

    /// Whether "Connect" is offered.
    #[must_use]
    pub fn offers_connect(&self) -> bool {
        self.action == FailureAction::Connect
    }

    /// Whether the account password row should be shown.
    #[must_use]
    pub fn asks_password(&self) -> bool {
        self.action == FailureAction::AskPassword
    }
}

/// The wording and actions for a failed run.
///
/// Exhaustive on purpose: a new [`KeySetupError`] variant in the core fails to
/// compile here instead of reaching the user as a blank message.
#[must_use]
#[expect(
    clippy::too_many_lines,
    reason = "one arm per error variant; splitting would only scatter the wording"
)]
pub fn failure_view(err: &KeySetupError, ctx: &FailureContext) -> FailureView {
    match err {
        KeySetupError::HostKeyUnknown => FailureView::message(i18n(
            "RustConn has not seen this server's host key yet, so nothing was sent. Connect once so the key is recorded, then try again. If the terminal asks about the key, check it before you accept.",
        ))
        .titled(i18n("Unknown Host Key"))
        .with_action(FailureAction::Connect)
        .retry(),
        KeySetupError::HostKeyChanged => FailureView::message(i18n(
            "The server's host key differs from the one on record. Someone may be intercepting the connection. Nothing was sent. Check the key with the server's administrator before connecting.",
        ))
        .titled(i18n("Host Key Changed")),
        KeySetupError::Network(failure) => FailureView::message(network_text(*failure)).retry(),
        KeySetupError::AuthFailed { server_methods } => auth_failed_view(server_methods, *ctx),
        KeySetupError::PasswordExpired => FailureView::message(i18n(
            "The account password has expired. Change it on the server, then try again.",
        ))
        .retry(),
        KeySetupError::WrongPassphrase => {
            FailureView::message(i18n("The passphrase is not correct for this key."))
                .retry()
                .with_delete()
        }
        KeySetupError::KeyNotAccepted => FailureView::message(i18n(
            "The key was installed, but the server does not accept it. Common causes are wrong permissions on the home folder or ~/.ssh (StrictModes), a custom AuthorizedKeysFile, SELinux, or key sign-in being disabled. The key is kept so you can try again after fixing the server.",
        ))
        .retry()
        .with_delete(),
        KeySetupError::NoSentinel { .. } => FailureView::message(i18n(
            "Sign-in worked, but the server did not run the install command. The account may be limited to a fixed command or a restricted shell.",
        ))
        .with_delete(),
        KeySetupError::NoPosixShell => FailureView::message(i18n(
            "The server has no POSIX shell, for example a Windows server. Key setup supports Linux and other Unix-like servers.",
        ))
        .with_delete(),
        KeySetupError::DeployScriptFailed(step) => {
            FailureView::message(deploy_step_text(*step)).retry().with_delete()
        }
        KeySetupError::SshFailed { code: Some(code) } => {
            FailureView::message(i18n_f("ssh exited with code {}.", &[&code.to_string()]))
                .retry()
                .with_delete()
        }
        KeySetupError::SshFailed { code: None } => {
            FailureView::message(i18n("ssh was stopped by a signal."))
                .retry()
                .with_delete()
        }
        KeySetupError::KeygenMissing => FailureView::message(i18n(
            "ssh-keygen was not found. Install the OpenSSH client.",
        )),
        KeySetupError::SshMissing => {
            FailureView::message(i18n("ssh was not found. Install the OpenSSH client."))
        }
        KeySetupError::KeygenFailed { .. } => {
            FailureView::message(i18n("ssh-keygen could not create the key.")).retry()
        }
        KeySetupError::NoHomeDir => {
            FailureView::message(i18n("Your home folder could not be found."))
        }
        KeySetupError::KeyDir { path, .. } => FailureView::message(i18n_f(
            "Could not use the key folder {}.",
            &[&path.display().to_string()],
        ))
        .retry(),
        KeySetupError::KeyFileExists { path } => FailureView::message(i18n_f(
            "A file already exists at {}.",
            &[&path.display().to_string()],
        ))
        .retry(),
        KeySetupError::NoFreeKeyName { dir } => FailureView::message(i18n_f(
            "There is no free key file name in {}. Remove unused keys from it.",
            &[&dir.display().to_string()],
        )),
        KeySetupError::KeyFile { path, .. } => FailureView::message(i18n_f(
            "Could not read the key file {}.",
            &[&path.display().to_string()],
        ))
        .retry(),
        KeySetupError::RefusedToDelete { path } => FailureView::message(i18n_f(
            "{} was not created by RustConn, so it was not deleted.",
            &[&path.display().to_string()],
        )),
        // The reason is for the log; the user can do nothing with it.
        KeySetupError::InvalidPublicKey(_) => {
            FailureView::message(i18n("The generated public key is not valid.")).with_delete()
        }
        KeySetupError::InvalidTarget => FailureView::message(i18n(
            "This host name or user name cannot be used for key setup.",
        )),
        KeySetupError::AskpassSetup => {
            FailureView::message(i18n("Could not prepare the password helper.")).retry()
        }
        KeySetupError::Spawn { program, .. } => {
            FailureView::message(i18n_f("Could not start {}.", &[program])).retry()
        }
        KeySetupError::Timeout => {
            FailureView::message(i18n("The server did not answer in time."))
                .retry()
                .with_delete()
        }
        KeySetupError::Cancelled => FailureView::message(i18n("Cancelled."))
            .retry()
            .with_delete(),
    }
}

fn network_text(failure: NetworkFailure) -> String {
    match failure {
        NetworkFailure::Refused => {
            i18n("Connection refused. Check the host, the port and that the SSH server is running.")
        }
        NetworkFailure::TimedOut => {
            i18n("The connection timed out. Check that the host is reachable.")
        }
        NetworkFailure::Unreachable => {
            i18n("The host is unreachable. Check the network connection.")
        }
        NetworkFailure::UnknownHost => {
            i18n("The host name could not be resolved. Check the host name.")
        }
        NetworkFailure::ClosedByRemote => i18n("The server closed the connection."),
    }
}

fn deploy_step_text(step: DeployStep) -> String {
    match step {
        DeployStep::CreateSshDir => i18n("Could not create ~/.ssh on the server."),
        DeployStep::CreateAuthorizedKeys => {
            i18n("Could not create ~/.ssh/authorized_keys on the server.")
        }
        DeployStep::ReadKey => i18n("The server did not receive the key."),
        DeployStep::AppendKey => i18n(
            "Could not add the key to ~/.ssh/authorized_keys on the server. Check the disk space and file permissions.",
        ),
    }
}

/// Whether a `Permission denied (…)` method list includes a password-like method.
fn offers_password(methods: &[String]) -> bool {
    methods
        .iter()
        .any(|m| m == "password" || m == "keyboard-interactive")
}

/// The four ways an authentication failure reads, told apart by what the server
/// offers and by whether a password went out.
///
/// A server that offers no password method at all is reported as such even when
/// a password was handed over: `ssh` never tried it, so "the password was not
/// accepted" would send the user to retype something that was never the problem.
fn auth_failed_view(methods: &[String], ctx: FailureContext) -> FailureView {
    if methods.is_empty() {
        return FailureView::message(i18n(
            "Too many authentication attempts. Remove unused keys from the SSH agent and try again.",
        ))
        .retry();
    }
    if !offers_password(methods) {
        return FailureView::message(i18n_f(
            "The server does not allow password sign-in (it offers: {}), so the key cannot be installed this way.",
            &[&methods.join(", ")],
        ));
    }
    if ctx.password_sent {
        // The password row opens so a typed password can replace a stale
        // stored one; without it every retry would send the same wrong password.
        return FailureView::message(i18n(
            "The server did not accept the password. Enter the account password and try again.",
        ))
        .with_action(FailureAction::AskPassword)
        .retry();
    }
    if ctx.password_gated_off {
        return FailureView::message(i18n(
            "The server asks for a password, but this connection's options or proxy prevent RustConn from passing the stored one safely.",
        ));
    }
    FailureView::message(i18n(
        "The server asks for a password. Enter the account password and try again.",
    ))
    .with_action(FailureAction::AskPassword)
    .retry()
}

/// The key type for a position in the key type combo row.
#[must_use]
pub fn algorithm_for_index(index: u32) -> KeyAlgorithm {
    match index {
        1 => KeyAlgorithm::Rsa4096,
        _ => KeyAlgorithm::Ed25519,
    }
}

/// The widgets of the dialog. Cloning is cheap: every field is a GObject handle.
#[derive(Clone)]
pub struct KeySetupDialog {
    dialog: adw::Dialog,
    algorithm_row: adw::ComboRow,
    key_row: adw::ActionRow,
    passphrase_group: adw::PreferencesGroup,
    passphrase_row: adw::PasswordEntryRow,
    password_group: adw::PreferencesGroup,
    password_row: adw::PasswordEntryRow,
    status_group: adw::PreferencesGroup,
    spinner: gtk4::Spinner,
    status_title: gtk4::Label,
    status_label: gtk4::Label,
    setup_button: gtk4::Button,
    cancel_button: gtk4::Button,
    stop_button: gtk4::Button,
    connect_button: gtk4::Button,
    delete_button: gtk4::Button,
    use_key_button: gtk4::Button,
    keep_button: gtk4::Button,
}

impl KeySetupDialog {
    /// Builds the dialog. `target` is `user@host` (or `host`).
    #[must_use]
    pub fn new(target: &str) -> Self {
        let intro = adw::PreferencesGroup::builder()
            .description(i18n_f(
                "RustConn creates a key, installs it on {} and checks that it signs in. The stored password is kept.",
                &[target],
            ))
            .build();
        let algorithm_row = adw::ComboRow::builder()
            .title(i18n("Key Type"))
            .model(&gtk4::StringList::new(&[
                &i18n("Ed25519 (Recommended)"),
                &i18n("RSA 4096"),
            ]))
            .build();
        intro.add(&algorithm_row);
        let key_row = adw::ActionRow::builder()
            .title(i18n("Key File"))
            .subtitle_selectable(true)
            .activatable(false)
            .build();
        intro.add(&key_row);
        if rustconn_core::snap::is_snap() {
            let snap_row = adw::ActionRow::builder()
                .title(i18n(
                    "In the snap, the key is kept in the snap's own folder and is deleted when the snap is removed. Without an SSH agent, a key passphrase is asked on every connect.",
                ))
                .title_lines(0)
                .activatable(false)
                .build();
            let icon = gtk4::Image::from_icon_name("dialog-warning-symbolic");
            icon.update_property(&[gtk4::accessible::Property::Label(&i18n("Warning"))]);
            snap_row.add_prefix(&icon);
            intro.add(&snap_row);
        }

        let passphrase_group = adw::PreferencesGroup::builder()
            .description(Self::passphrase_hint(false))
            .build();
        let passphrase_row = adw::PasswordEntryRow::builder()
            .title(i18n("Passphrase (Optional)"))
            .build();
        passphrase_group.add(&passphrase_row);

        let password_group = adw::PreferencesGroup::builder()
            .description(i18n("Used once to install the key. Not saved."))
            .visible(false)
            .build();
        let password_row = adw::PasswordEntryRow::builder()
            .title(i18n("Account Password"))
            .build();
        password_group.add(&password_row);

        let spinner = gtk4::Spinner::new();
        let status_title = gtk4::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .css_classes(["heading"])
            .visible(false)
            .build();
        let status_label = gtk4::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .hexpand(true)
            .selectable(true)
            .build();
        let text_box = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
        text_box.append(&status_title);
        text_box.append(&status_label);
        let status_box = gtk4::Box::new(gtk4::Orientation::Horizontal, 12);
        status_box.set_margin_top(6);
        status_box.set_margin_bottom(6);
        status_box.append(&spinner);
        status_box.append(&text_box);

        let connect_button = gtk4::Button::with_label(&i18n("Connect"));
        let delete_button = gtk4::Button::with_label(&i18n("Delete Generated Key"));
        delete_button.add_css_class("destructive-action");
        let use_key_button = gtk4::Button::with_label(&i18n("Use Key"));
        let keep_button = gtk4::Button::with_label(&i18n("Keep Current Settings"));
        let actions = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
        for button in [
            &connect_button,
            &use_key_button,
            &keep_button,
            &delete_button,
        ] {
            button.set_visible(false);
            actions.append(button);
        }

        let status_group = adw::PreferencesGroup::builder()
            .title(i18n("Status"))
            .visible(false)
            .build();
        let status_content = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
        status_content.append(&status_box);
        status_content.append(&actions);
        status_group.add(&status_content);

        let page = adw::PreferencesPage::new();
        page.add(&intro);
        page.add(&passphrase_group);
        page.add(&password_group);
        page.add(&status_group);

        let setup_button = gtk4::Button::with_label(&i18n("Set Up"));
        setup_button.add_css_class("suggested-action");
        let cancel_button = gtk4::Button::with_label(&i18n("Cancel"));
        // A second button rather than relabelling Cancel while a run is in
        // flight: `connect_clicked` adds handlers, it never replaces them.
        let stop_button = gtk4::Button::with_label(&i18n("Stop"));
        stop_button.set_visible(false);

        let header = adw::HeaderBar::builder()
            .title_widget(&adw::WindowTitle::new(
                &i18n("Set Up Key Authentication"),
                target,
            ))
            .show_end_title_buttons(false)
            .show_start_title_buttons(false)
            .build();
        header.pack_start(&cancel_button);
        header.pack_start(&stop_button);
        header.pack_end(&setup_button);

        let toolbar = adw::ToolbarView::new();
        toolbar.add_top_bar(&header);
        toolbar.set_content(Some(&page));

        let dialog = adw::Dialog::builder()
            .content_width(480)
            .content_height(560)
            .child(&toolbar)
            .build();
        dialog.set_default_widget(Some(&setup_button));

        let this = Self {
            dialog,
            algorithm_row,
            key_row,
            passphrase_group,
            passphrase_row,
            password_group,
            password_row,
            status_group,
            spinner,
            status_title,
            status_label,
            setup_button,
            cancel_button,
            stop_button,
            connect_button,
            delete_button,
            use_key_button,
            keep_button,
        };
        let dialog = this.dialog.clone();
        this.cancel_button.connect_clicked(move |_| {
            dialog.close();
        });
        this
    }

    fn passphrase_hint(reusable: bool) -> String {
        if reusable {
            i18n(
                "A key from an earlier attempt is ready and will be used again. Enter its passphrase if it has one.",
            )
        } else {
            i18n(
                "A passphrase protects the key if someone copies it. Without an SSH agent it is asked on every connect.",
            )
        }
    }

    /// Shows the dialog over `parent`.
    pub fn present(&self, parent: &impl IsA<gtk4::Widget>) {
        self.dialog.present(Some(parent));
    }

    /// Closes the dialog.
    pub fn close(&self) {
        self.dialog.close();
    }

    /// The dialog as a widget, to parent a confirmation to.
    #[must_use]
    pub fn widget(&self) -> &adw::Dialog {
        &self.dialog
    }

    /// The key type chosen in the combo row.
    #[must_use]
    pub fn algorithm(&self) -> KeyAlgorithm {
        algorithm_for_index(self.algorithm_row.selected())
    }

    /// The key passphrase, `None` when the row is empty.
    #[must_use]
    pub fn passphrase(&self) -> Option<SecretString> {
        secret_from_row(&self.passphrase_row)
    }

    /// The account password typed for this run, `None` when the row is empty or
    /// hidden.
    #[must_use]
    pub fn typed_password(&self) -> Option<SecretString> {
        if self.password_group.is_visible() {
            secret_from_row(&self.password_row)
        } else {
            None
        }
    }

    /// Empties both secret rows. Called only when the dialog closes: between
    /// attempts the rows keep their text so Try Again can reuse it.
    pub fn clear_secrets(&self) {
        self.passphrase_row.set_text("");
        self.password_row.set_text("");
    }

    /// Shows where the key will be written; `reusable` marks a pair left over
    /// from an earlier attempt.
    pub fn set_slot_hint(&self, path: Option<&Path>, reusable: bool) {
        self.key_row
            .set_subtitle(&path.map(|p| p.display().to_string()).unwrap_or_default());
        self.passphrase_group
            .set_description(Some(&Self::passphrase_hint(reusable)));
    }

    /// Shows or hides the account password row.
    pub fn set_password_row_visible(&self, visible: bool) {
        self.password_group.set_visible(visible);
    }

    /// Re-reads the key type when the user changes it.
    pub fn connect_algorithm_changed(&self, handler: impl Fn() + 'static) {
        self.algorithm_row
            .connect_selected_notify(move |_| handler());
    }

    /// Runs `handler` when the dialog has closed, however it was closed.
    pub fn connect_closed(&self, handler: impl Fn() + 'static) {
        self.dialog.connect_closed(move |_| handler());
    }

    /// Runs `handler` when Set Up (or Try Again) is pressed.
    pub fn connect_setup(&self, handler: impl Fn() + 'static) {
        self.setup_button.connect_clicked(move |_| handler());
    }

    /// Runs `handler` when Stop is pressed.
    pub fn connect_stop(&self, handler: impl Fn() + 'static) {
        self.stop_button.connect_clicked(move |button| {
            button.set_sensitive(false);
            handler();
        });
    }

    /// Runs `handler` when Connect is pressed.
    pub fn connect_connect(&self, handler: impl Fn() + 'static) {
        self.connect_button.connect_clicked(move |_| handler());
    }

    /// Runs `handler` when Delete Generated Key is pressed.
    pub fn connect_delete_key(&self, handler: impl Fn() + 'static) {
        self.delete_button.connect_clicked(move |_| handler());
    }

    /// Runs `handler` when Use Key is pressed.
    pub fn connect_use_key(&self, handler: impl Fn() + 'static) {
        self.use_key_button.connect_clicked(move |_| handler());
    }

    /// Runs `handler` when Keep Current Settings is pressed.
    pub fn connect_keep(&self, handler: impl Fn() + 'static) {
        self.keep_button.connect_clicked(move |_| handler());
    }

    fn set_inputs_sensitive(&self, sensitive: bool) {
        self.algorithm_row.set_sensitive(sensitive);
        self.passphrase_row.set_sensitive(sensitive);
        self.password_row.set_sensitive(sensitive);
    }

    fn hide_result_buttons(&self) {
        for button in [
            &self.connect_button,
            &self.delete_button,
            &self.use_key_button,
            &self.keep_button,
        ] {
            button.set_visible(false);
        }
    }

    fn show_status(&self, title: Option<&str>, body: &str, busy: bool) {
        self.status_group.set_visible(true);
        self.spinner.set_spinning(busy);
        self.spinner.set_visible(busy);
        self.status_title.set_label(title.unwrap_or_default());
        self.status_title.set_visible(title.is_some());
        self.status_label.set_label(body);
        // A label that changes under the user is silent to a screen reader.
        let priority = if busy {
            gtk4::AccessibleAnnouncementPriority::Low
        } else {
            gtk4::AccessibleAnnouncementPriority::Medium
        };
        self.status_label.announce(body, priority);
    }

    /// The account password lookup is in flight: nothing can be started yet.
    pub fn set_resolving(&self, resolving: bool) {
        if resolving {
            self.show_status(
                None,
                &stage_label(KeySetupStage::ResolvingPassword, ""),
                true,
            );
            self.set_inputs_sensitive(false);
            self.setup_button.set_sensitive(false);
        } else {
            self.status_group.set_visible(false);
            self.spinner.set_spinning(false);
            self.set_inputs_sensitive(true);
            self.setup_button.set_sensitive(true);
        }
    }

    /// A stage is running: inputs lock, Stop replaces Cancel and Set Up.
    pub fn set_running(&self, stage: KeySetupStage, host: &str) {
        self.show_status(None, &stage_label(stage, host), true);
        self.hide_result_buttons();
        self.set_inputs_sensitive(false);
        self.setup_button.set_visible(false);
        self.cancel_button.set_visible(false);
        self.stop_button.set_visible(true);
        self.stop_button.set_sensitive(true);
    }

    fn finish_run(&self) {
        self.set_inputs_sensitive(true);
        self.stop_button.set_visible(false);
        self.cancel_button.set_visible(true);
        self.cancel_button.set_label(&i18n("Close"));
    }

    /// A run ended in failure. `key_on_disk` says whether a generated key
    /// exists, which is what makes "Delete Generated Key" meaningful.
    pub fn show_failure(&self, view: &FailureView, key_on_disk: bool) {
        self.show_status(view.title.as_deref(), &view.body, false);
        self.hide_result_buttons();
        self.finish_run();
        self.setup_button.set_label(&i18n("Try Again"));
        self.setup_button.set_visible(view.retry);
        self.setup_button.set_sensitive(true);
        self.connect_button.set_visible(view.offers_connect());
        self.delete_button
            .set_visible(view.delete_key && key_on_disk);
        if view.asks_password() {
            self.password_group.set_visible(true);
            self.password_row.grab_focus();
        }
    }

    /// The server accepted the key but wants another factor: the user decides.
    pub fn show_second_factor(&self, key_on_disk: bool) {
        self.show_status(
            Some(&i18n("Key Accepted, More Required")),
            &i18n(
                "The server accepted the key but also asks for another factor, such as a one-time code. Use the key for this connection anyway?",
            ),
            false,
        );
        self.hide_result_buttons();
        self.finish_run();
        // One suggested action per dialog: Use Key takes it from Set Up here.
        self.setup_button.set_visible(false);
        self.use_key_button.add_css_class("suggested-action");
        self.use_key_button.set_visible(true);
        self.keep_button.set_visible(true);
        self.delete_button.set_visible(key_on_disk);
    }

    /// The generated key was deleted: only a fresh run is left.
    pub fn show_deleted(&self) {
        self.show_status(None, &i18n("The generated key was deleted."), false);
        self.hide_result_buttons();
        self.finish_run();
        self.setup_button.set_label(&i18n("Set Up"));
        self.setup_button.set_visible(true);
        self.setup_button.set_sensitive(true);
    }
}

fn secret_from_row(row: &adw::PasswordEntryRow) -> Option<SecretString> {
    let text = row.text();
    if text.is_empty() {
        None
    } else {
        Some(SecretString::from(text.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rustconn_core::ssh_key_setup::PublicKeyError;

    use super::*;

    fn ctx() -> FailureContext {
        FailureContext::default()
    }

    fn auth(methods: &[&str]) -> KeySetupError {
        KeySetupError::AuthFailed {
            server_methods: methods.iter().map(|m| (*m).to_string()).collect(),
        }
    }

    #[test]
    fn unknown_host_key_offers_connect_and_retry() {
        let view = failure_view(&KeySetupError::HostKeyUnknown, &ctx());
        assert!(view.offers_connect());
        assert!(view.retry);
        assert!(!view.delete_key);
        assert!(view.title.is_some());
    }

    #[test]
    fn changed_host_key_offers_neither_connect_nor_retry() {
        let view = failure_view(&KeySetupError::HostKeyChanged, &ctx());
        assert!(!view.offers_connect());
        assert!(!view.retry);
        assert!(!view.delete_key);
        assert!(view.title.is_some());
    }

    #[test]
    fn only_the_unknown_host_key_offers_connect() {
        let errors = [
            KeySetupError::HostKeyChanged,
            KeySetupError::PasswordExpired,
            KeySetupError::WrongPassphrase,
            KeySetupError::KeyNotAccepted,
            KeySetupError::Timeout,
            KeySetupError::Cancelled,
            auth(&["password"]),
        ];
        for err in errors {
            assert!(!failure_view(&err, &ctx()).offers_connect(), "{err}");
        }
    }

    #[test]
    fn a_kept_key_can_be_retried_and_deleted() {
        for err in [
            KeySetupError::WrongPassphrase,
            KeySetupError::KeyNotAccepted,
            KeySetupError::Timeout,
            KeySetupError::Cancelled,
        ] {
            let view = failure_view(&err, &ctx());
            assert!(view.retry && view.delete_key, "{err}");
        }
    }

    #[test]
    fn a_refused_delete_offers_nothing() {
        let view = failure_view(
            &KeySetupError::RefusedToDelete {
                path: PathBuf::from("/tmp/other"),
            },
            &ctx(),
        );
        assert!(!view.retry && !view.delete_key && !view.offers_connect());
        assert!(view.body.contains("/tmp/other"));
    }

    #[test]
    fn the_four_password_failures_read_differently() {
        let sent = FailureContext {
            password_sent: true,
            password_gated_off: false,
        };
        let gated = FailureContext {
            password_sent: false,
            password_gated_off: true,
        };
        let methods = ["publickey", "password"];
        let rejected = failure_view(&auth(&methods), &sent);
        let blocked = failure_view(&auth(&methods), &gated);
        let missing = failure_view(&auth(&methods), &ctx());
        let no_password = failure_view(&auth(&["publickey"]), &ctx());
        let too_many = failure_view(&auth(&[]), &ctx());

        let bodies = [
            &rejected.body,
            &blocked.body,
            &missing.body,
            &no_password.body,
            &too_many.body,
        ];
        for (i, a) in bodies.iter().enumerate() {
            for b in &bodies[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // A rejected stored password must be replaceable from the dialog.
        assert!(rejected.retry && rejected.asks_password());
        assert!(!blocked.retry && !blocked.asks_password());
        assert!(missing.retry && missing.asks_password());
        assert!(!no_password.retry);
        assert!(no_password.body.contains("publickey"));
        assert!(too_many.retry && !too_many.asks_password());
    }

    #[test]
    fn keyboard_interactive_counts_as_a_password_method() {
        let view = failure_view(&auth(&["publickey", "keyboard-interactive"]), &ctx());
        assert!(view.asks_password());
    }

    #[test]
    fn a_server_without_password_sign_in_wins_over_a_sent_password() {
        let sent = FailureContext {
            password_sent: true,
            password_gated_off: false,
        };
        let view = failure_view(&auth(&["publickey"]), &sent);
        assert!(!view.retry);
        assert!(view.body.contains("publickey"));
    }

    #[test]
    fn deploy_steps_each_have_their_own_text() {
        let steps = [
            DeployStep::CreateSshDir,
            DeployStep::CreateAuthorizedKeys,
            DeployStep::ReadKey,
            DeployStep::AppendKey,
        ];
        let texts: Vec<String> = steps.iter().map(|s| deploy_step_text(*s)).collect();
        for (i, a) in texts.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &texts[i + 1..] {
                assert_ne!(a, b);
            }
        }
        let view = failure_view(
            &KeySetupError::DeployScriptFailed(DeployStep::AppendKey),
            &ctx(),
        );
        assert!(view.retry && view.delete_key);
    }

    #[test]
    fn network_failures_each_have_their_own_text_and_retry() {
        let all = [
            NetworkFailure::Refused,
            NetworkFailure::TimedOut,
            NetworkFailure::Unreachable,
            NetworkFailure::UnknownHost,
            NetworkFailure::ClosedByRemote,
        ];
        let texts: Vec<String> = all.iter().map(|f| network_text(*f)).collect();
        for (i, a) in texts.iter().enumerate() {
            for b in &texts[i + 1..] {
                assert_ne!(a, b);
            }
        }
        for failure in all {
            assert!(failure_view(&KeySetupError::Network(failure), &ctx()).retry);
        }
    }

    #[test]
    fn ssh_exit_code_is_named_and_a_signal_is_not() {
        let coded = failure_view(&KeySetupError::SshFailed { code: Some(7) }, &ctx());
        assert!(coded.body.contains('7'));
        let signalled = failure_view(&KeySetupError::SshFailed { code: None }, &ctx());
        assert_ne!(coded.body, signalled.body);
    }

    #[test]
    fn no_failure_text_is_empty() {
        let path = PathBuf::from("/k");
        let io = || std::io::Error::other("x");
        let errors = vec![
            KeySetupError::KeygenMissing,
            KeySetupError::SshMissing,
            KeySetupError::NoHomeDir,
            KeySetupError::KeyDir {
                path: path.clone(),
                source: io(),
            },
            KeySetupError::KeyFileExists { path: path.clone() },
            KeySetupError::NoFreeKeyName { dir: path.clone() },
            KeySetupError::KeyFile {
                path: path.clone(),
                source: io(),
            },
            KeySetupError::RefusedToDelete { path },
            KeySetupError::KeygenFailed { code: Some(1) },
            KeySetupError::InvalidPublicKey(PublicKeyError::TooLong),
            KeySetupError::InvalidTarget,
            KeySetupError::AskpassSetup,
            KeySetupError::Spawn {
                program: "ssh",
                source: io(),
            },
            KeySetupError::HostKeyUnknown,
            KeySetupError::HostKeyChanged,
            KeySetupError::PasswordExpired,
            KeySetupError::WrongPassphrase,
            KeySetupError::NoPosixShell,
            KeySetupError::NoSentinel { code: Some(0) },
            KeySetupError::KeyNotAccepted,
            KeySetupError::Timeout,
            KeySetupError::Cancelled,
        ];
        for err in errors {
            assert!(!failure_view(&err, &ctx()).body.is_empty(), "{err}");
        }
    }

    #[test]
    fn path_and_program_names_reach_the_text() {
        let view = failure_view(
            &KeySetupError::KeyDir {
                path: PathBuf::from("/home/u/.ssh/rustconn"),
                source: std::io::Error::other("x"),
            },
            &ctx(),
        );
        assert!(view.body.contains("/home/u/.ssh/rustconn"));
        let view = failure_view(
            &KeySetupError::Spawn {
                program: "ssh-keygen",
                source: std::io::Error::other("x"),
            },
            &ctx(),
        );
        assert!(view.body.contains("ssh-keygen"));
    }

    #[test]
    fn algorithm_index_defaults_to_ed25519() {
        assert_eq!(algorithm_for_index(0), KeyAlgorithm::Ed25519);
        assert_eq!(algorithm_for_index(1), KeyAlgorithm::Rsa4096);
        assert_eq!(algorithm_for_index(2), KeyAlgorithm::Ed25519);
        assert_eq!(algorithm_for_index(u32::MAX), KeyAlgorithm::Ed25519);
    }

    #[test]
    fn stage_labels_are_distinct_and_name_the_host() {
        let stages = [
            KeySetupStage::ResolvingPassword,
            KeySetupStage::Generating,
            KeySetupStage::Installing,
            KeySetupStage::Verifying,
        ];
        let labels: Vec<String> = stages.iter().map(|s| stage_label(*s, "me@box")).collect();
        for (i, a) in labels.iter().enumerate() {
            assert!(!a.is_empty());
            for b in &labels[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert!(stage_label(KeySetupStage::Installing, "me@box").contains("me@box"));
    }
}
