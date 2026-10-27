//! "Set Up Key Authentication…": the part that does the work.
//!
//! The dialog itself (`dialogs/key_setup.rs`) is widgets and wording. This
//! module owns the sequence behind it: look up the stored account password,
//! generate the key, install it, check that it signs in, and then switch the
//! connection to it.
//!
//! Every step that waits on a process runs through
//! [`spawn_blocking_with_callback`], one stage at a time so the status line can
//! follow, and the callbacks run on the GTK thread. No `Ref` or `RefMut` of the
//! application state is held across a stage: the state is borrowed for a read
//! or a write and released before the next stage starts. The work moves between
//! stages inside [`KeySetupRun`], which is `Send` and owns the secrets, so they
//! die with the run.
//!
//! The ssh arguments, the bastion passwords and the account-password gate come
//! from [`build_key_setup_launch`], i.e. from the same code a live session uses.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rustconn_core::ssh_key_setup::{
    self, DEFAULT_TIMEOUT, DeployCredentials, KeyAlgorithm, KeySetupError, KeySlot, KeygenRequest,
    PublicKeyLine, RunControl, SshTarget, VerifyOutcome,
};
use secrecy::{ExposeSecret, SecretString};

use super::protocols::{resolve_globals_with_ask, substitute_variables};
use super::protocols_ssh::build_key_setup_launch;
use super::*;
use crate::dialogs::key_setup::{
    FailureContext, FailureView, KeySetupDialog, KeySetupStage, failure_view,
};
use crate::i18n::{i18n, i18n_f};
use crate::utils::spawn_blocking_with_callback;

/// What the dialog needs from the main window.
pub(super) struct KeySetupContext {
    /// Weak: the window owns the action that owns this context.
    pub(super) window: glib::WeakRef<adw::ApplicationWindow>,
    pub(super) state: SharedAppState,
    pub(super) sidebar: SharedSidebar,
    pub(super) notebook: SharedNotebook,
    pub(super) split_view: SharedSplitView,
    pub(super) monitoring: types::SharedMonitoring,
    pub(super) toast_overlay: SharedToastOverlay,
}

/// What stage 1 hands to the main thread.
struct Generated {
    private_key_path: PathBuf,
    public_key: PublicKeyLine,
    /// `ssh -G`'s answer, only asked for when a password could be sent.
    declares_proxy: Option<bool>,
}

/// Everything stage 1 needs, owned so it can move to the worker thread.
struct GenerateJob {
    connection_name: String,
    connection_id: Uuid,
    algorithm: KeyAlgorithm,
    passphrase: Option<SecretString>,
    control: RunControl,
    host: String,
    port: u16,
    username: Option<String>,
    check_proxy: bool,
}

/// The run as it moves from stage to stage. `Send`, owns its secrets.
struct KeySetupRun {
    target: SshTarget,
    credentials: DeployCredentials,
    private_key_path: PathBuf,
    public_key: PublicKeyLine,
    passphrase: Option<SecretString>,
    control: RunControl,
}

/// One open dialog and what its callbacks share.
///
/// The widgets hold closures that hold this, so the dialog is dropped from here
/// when it closes ([`Controller::release`]); otherwise the cycle would keep
/// every widget alive. A callback that finds no dialog is a callback for a
/// dialog the user already closed, and does nothing.
struct Controller {
    ctx: Rc<KeySetupContext>,
    dialog: RefCell<Option<KeySetupDialog>>,
    connection_id: Uuid,
    connection_name: String,
    /// Substituted host, as a live session would dial it.
    host: String,
    port: u16,
    username: Option<String>,
    /// `user@host`, for display.
    target_label: String,
    /// The account password from the vault. Never the typed one, never saved.
    stored_password: RefCell<Option<SecretString>>,
    /// The cancel flag of the run in flight.
    cancel: RefCell<Option<Arc<AtomicBool>>>,
    /// The private key of this attempt, once it exists on disk.
    key_path: RefCell<Option<PathBuf>>,
    failure_context: Cell<FailureContext>,
    busy: Cell<bool>,
}

impl Controller {
    fn dialog(&self) -> Option<KeySetupDialog> {
        self.dialog.borrow().clone()
    }

    fn request_cancel(&self) {
        if let Some(flag) = self.cancel.borrow().as_ref() {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// The dialog closed: stop any run, empty the secret rows, drop the widgets.
    fn release(&self) {
        self.request_cancel();
        let dialog = self.dialog.borrow_mut().take();
        if let Some(dialog) = dialog {
            dialog.clear_secrets();
        }
        *self.stored_password.borrow_mut() = None;
    }
}

/// Opens the dialog for a connection. Does nothing for a connection that is not SSH.
pub(super) fn open_key_setup_dialog(ctx: Rc<KeySetupContext>, connection_id: Uuid) {
    let Some(window) = ctx.window.upgrade() else {
        return;
    };
    let Ok(state) = ctx.state.try_borrow() else {
        tracing::warn!("Application state busy; key setup dialog not opened");
        return;
    };
    let connection = state.get_connection(connection_id).cloned();
    drop(state);
    let Some(connection) = connection else {
        tracing::debug!(%connection_id, "key setup: connection not found");
        return;
    };
    if !matches!(
        connection.protocol_config,
        rustconn_core::ProtocolConfig::Ssh(_)
    ) {
        tracing::debug!(%connection_id, "key setup: not an SSH connection");
        return;
    }

    let globals = resolve_globals_with_ask(&ctx.state, connection_id);
    let host = substitute_variables(&connection.host, &globals);
    let username = connection
        .username
        .as_ref()
        .map(|u| substitute_variables(u, &globals));
    let target_label = display_target(username.as_deref(), &host);

    let dialog = KeySetupDialog::new(&target_label);
    let controller = Rc::new(Controller {
        ctx,
        dialog: RefCell::new(Some(dialog.clone())),
        connection_id,
        connection_name: connection.name.clone(),
        host,
        port: connection.port,
        username,
        target_label,
        stored_password: RefCell::new(None),
        cancel: RefCell::new(None),
        key_path: RefCell::new(None),
        failure_context: Cell::new(FailureContext::default()),
        busy: Cell::new(false),
    });
    wire(&controller, &dialog);
    refresh_slot_hint(&controller);
    dialog.present(&window);
    look_up_stored_password(&controller);
}

/// `user@host`, or just `host` without a user name.
fn display_target(username: Option<&str>, host: &str) -> String {
    match username {
        Some(user) if !user.is_empty() => format!("{user}@{host}"),
        _ => host.to_string(),
    }
}

fn wire(controller: &Rc<Controller>, dialog: &KeySetupDialog) {
    let c = Rc::clone(controller);
    dialog.connect_setup(move || start_run(&c));
    let c = Rc::clone(controller);
    dialog.connect_stop(move || c.request_cancel());
    let c = Rc::clone(controller);
    dialog.connect_connect(move || connect_session(&c));
    let c = Rc::clone(controller);
    dialog.connect_delete_key(move || confirm_delete(&c));
    let c = Rc::clone(controller);
    dialog.connect_use_key(move || use_key(&c));
    let c = Rc::clone(controller);
    dialog.connect_keep(move || {
        if let Some(dialog) = c.dialog() {
            dialog.close();
        }
    });
    let c = Rc::clone(controller);
    dialog.connect_algorithm_changed(move || refresh_slot_hint(&c));
    let c = Rc::clone(controller);
    dialog.connect_closed(move || c.release());
}

/// Shows where the key will go, and whether a key from an earlier attempt waits there.
///
/// Reads a few files in a local folder and starts no process.
// ponytail: synchronous fs read when the dialog opens and the key type changes;
// fine for a local folder, move it to a worker if this ever points at a network home.
fn refresh_slot_hint(c: &Rc<Controller>) {
    let Some(dialog) = c.dialog() else {
        return;
    };
    let slot = ssh_key_setup::default_key_setup_dir().and_then(|dir| {
        ssh_key_setup::resolve_key_slot(
            &dir,
            &c.connection_name,
            c.connection_id,
            dialog.algorithm(),
        )
    });
    match slot {
        Ok(KeySlot::Fresh(path)) => dialog.set_slot_hint(Some(&path), false),
        Ok(KeySlot::Reusable {
            private_key_path, ..
        }) => dialog.set_slot_hint(Some(&private_key_path), true),
        Err(e) => {
            // No folder yet is the normal first run; the worker creates it.
            tracing::debug!(error = %e, "key setup: no key slot to show");
            dialog.set_slot_hint(None, false);
        }
    }
}

/// Finds the stored account password the way a connect does: the session cache
/// first, then the vault off the GTK thread (`resolve_credentials_gtk` fills
/// the cache). Without one, the dialog asks for it.
fn look_up_stored_password(c: &Rc<Controller>) {
    let Some(dialog) = c.dialog() else {
        return;
    };
    let cached = c
        .ctx
        .state
        .try_borrow()
        .ok()
        .and_then(|s| s.get_cached_credentials(c.connection_id).cloned())
        .map(|credentials| credentials.password)
        .filter(|p| !p.expose_secret().is_empty());
    if let Some(password) = cached {
        *c.stored_password.borrow_mut() = Some(password);
        return;
    }
    let needs_lookup = c
        .ctx
        .state
        .try_borrow()
        .ok()
        .and_then(|s| {
            s.get_connection(c.connection_id)
                .map(|conn| crate::state::password_source_needs_resolution(&conn.password_source))
        })
        .unwrap_or(false);
    if !needs_lookup {
        dialog.set_password_row_visible(true);
        return;
    }

    dialog.set_resolving(true);
    let state = c.ctx.state.clone();
    let connection_id = c.connection_id;
    let c = Rc::clone(c);
    crate::state::resolve_credentials_gtk(&state, connection_id, move |result| {
        use rustconn_core::sync::CredentialResolutionResult;
        let password = match result {
            Ok(CredentialResolutionResult::Resolved(credentials)) => credentials
                .password
                .filter(|p| !p.expose_secret().is_empty()),
            Ok(_) => None,
            Err(e) => {
                tracing::warn!(error = %e, "key setup: password lookup failed");
                None
            }
        };
        let Some(dialog) = c.dialog() else {
            return;
        };
        dialog.set_resolving(false);
        dialog.set_password_row_visible(password.is_none());
        *c.stored_password.borrow_mut() = password;
    });
}

/// Set Up (or Try Again) was pressed: stage 1, generating the key.
fn start_run(c: &Rc<Controller>) {
    if c.busy.get() {
        return;
    }
    let Some(dialog) = c.dialog() else {
        return;
    };
    let password = dialog
        .typed_password()
        .or_else(|| c.stored_password.borrow().clone());
    let passphrase = dialog.passphrase();
    let control = RunControl {
        timeout: DEFAULT_TIMEOUT,
        cancel: Arc::new(AtomicBool::new(false)),
    };
    *c.cancel.borrow_mut() = Some(Arc::clone(&control.cancel));
    c.busy.set(true);
    dialog.set_running(KeySetupStage::Generating, &c.target_label);

    let job = GenerateJob {
        connection_name: c.connection_name.clone(),
        connection_id: c.connection_id,
        algorithm: dialog.algorithm(),
        passphrase: passphrase.clone(),
        control: control.clone(),
        host: c.host.clone(),
        port: c.port,
        username: c.username.clone(),
        check_proxy: password.is_some(),
    };
    let c = Rc::clone(c);
    spawn_blocking_with_callback(
        move || generate(job),
        move |result| on_generated(&c, result, password, passphrase, control),
    );
}

/// Stage 1, off the GTK thread: the folder, the key (or the one from an earlier
/// attempt), and `ssh -G` for the password gate.
fn generate(job: GenerateJob) -> Result<Generated, KeySetupError> {
    let dir = ssh_key_setup::default_key_setup_dir()?;
    ssh_key_setup::ensure_key_setup_dir(&dir)?;
    let (private_key_path, public_key) = match ssh_key_setup::resolve_key_slot(
        &dir,
        &job.connection_name,
        job.connection_id,
        job.algorithm,
    )? {
        KeySlot::Fresh(path) => {
            let key = ssh_key_setup::generate_key(
                &KeygenRequest {
                    private_key_path: path,
                    algorithm: job.algorithm,
                    comment: ssh_key_setup::default_key_comment(),
                    passphrase: job.passphrase,
                },
                &job.control,
            )?;
            (key.private_key_path, key.public_key)
        }
        KeySlot::Reusable {
            private_key_path,
            public_key,
        } => (private_key_path, public_key),
    };
    let declares_proxy = job.check_proxy.then(|| {
        rustconn_core::ssh_tunnel::ssh_config_declares_proxy(
            &job.host,
            job.port,
            job.username.as_deref(),
        )
    });
    Ok(Generated {
        private_key_path,
        public_key,
        declares_proxy,
    })
}

fn on_generated(
    c: &Rc<Controller>,
    result: Result<Generated, KeySetupError>,
    password: Option<SecretString>,
    passphrase: Option<SecretString>,
    control: RunControl,
) {
    if c.dialog().is_none() {
        return;
    }
    let generated = match result {
        Ok(generated) => generated,
        Err(e) => return fail(c, &e, false),
    };
    *c.key_path.borrow_mut() = Some(generated.private_key_path.clone());

    // Built here, on the GTK thread, because it reads the application state;
    // nothing is held across the call and no process is started in it.
    let (connection, groups) = match c.ctx.state.try_borrow() {
        Ok(state) => (
            state.get_connection(c.connection_id).cloned(),
            state.list_groups_owned(),
        ),
        Err(_) => (None, Vec::new()),
    };
    let Some(connection) = connection else {
        tracing::warn!("key setup: connection unavailable after key generation");
        return fail_with(
            c,
            &FailureView::message(i18n("The connection could not be read. Try again."))
                .retry()
                .with_delete(),
        );
    };
    let launch = build_key_setup_launch(
        &connection,
        &c.ctx.state,
        &groups,
        password,
        generated.declares_proxy,
    );
    c.failure_context.set(FailureContext {
        password_sent: launch.password_sent,
        password_gated_off: launch.password_gated_off,
    });
    install(
        c,
        KeySetupRun {
            target: launch.target,
            credentials: launch.credentials,
            private_key_path: generated.private_key_path,
            public_key: generated.public_key,
            passphrase,
            control,
        },
    );
}

/// Stage 2: put the public key into `authorized_keys`.
fn install(c: &Rc<Controller>, run: KeySetupRun) {
    let Some(dialog) = c.dialog() else {
        return;
    };
    dialog.set_running(KeySetupStage::Installing, &c.target_label);
    let c = Rc::clone(c);
    spawn_blocking_with_callback(
        move || {
            let result = ssh_key_setup::run_deploy(
                &run.target,
                &run.public_key,
                &run.credentials,
                &run.control,
            );
            (run, result)
        },
        move |(mut run, result)| {
            if c.dialog().is_none() {
                return;
            }
            match result {
                Ok(outcome) => {
                    tracing::info!(?outcome, "key setup: public key is on the server");
                    // Verification signs in with the new key; the account
                    // password has done its job.
                    run.credentials.password = None;
                    verify(&c, run);
                }
                Err(e) => fail(&c, &e, true),
            }
        },
    );
}

/// Stage 3: sign in with the new key.
fn verify(c: &Rc<Controller>, run: KeySetupRun) {
    let Some(dialog) = c.dialog() else {
        return;
    };
    dialog.set_running(KeySetupStage::Verifying, &c.target_label);
    let c = Rc::clone(c);
    spawn_blocking_with_callback(
        move || {
            ssh_key_setup::run_verify(
                &run.target,
                &run.private_key_path,
                &run.public_key,
                run.passphrase.as_ref(),
                &run.credentials.jump_host_passwords,
                &run.control,
            )
        },
        move |result| {
            let Some(dialog) = c.dialog() else {
                return;
            };
            match result {
                Ok(VerifyOutcome::Accepted) => succeed(&c),
                Ok(VerifyOutcome::AcceptedSecondFactorRequired) => {
                    finish_run(&c);
                    dialog.show_second_factor(true);
                }
                Err(e) => fail(&c, &e, true),
            }
        },
    );
}

fn finish_run(c: &Controller) {
    c.busy.set(false);
    *c.cancel.borrow_mut() = None;
}

fn fail(c: &Rc<Controller>, error: &KeySetupError, key_on_disk: bool) {
    tracing::warn!(error = %error, key_on_disk, "key setup failed");
    let view = failure_view(error, &c.failure_context.get());
    finish_run(c);
    let key_kept = key_on_disk && c.key_path.borrow().is_some();
    if key_kept {
        // The key stays on disk, so the next attempt reuses it: say so.
        refresh_slot_hint(c);
    }
    if let Some(dialog) = c.dialog() {
        dialog.show_failure(&view, key_kept);
    }
}

fn fail_with(c: &Rc<Controller>, view: &FailureView) {
    finish_run(c);
    let key_kept = c.key_path.borrow().is_some();
    if key_kept {
        refresh_slot_hint(c);
    }
    if let Some(dialog) = c.dialog() {
        dialog.show_failure(view, key_kept);
    }
}

/// The key works: switch the connection to it.
fn succeed(c: &Rc<Controller>) {
    finish_run(c);
    let Some(path) = c.key_path.borrow().clone() else {
        return;
    };
    switch_connection_to_key(c, &path);
}

/// Use Key after a second-factor warning.
fn use_key(c: &Rc<Controller>) {
    let Some(path) = c.key_path.borrow().clone() else {
        return;
    };
    switch_connection_to_key(c, &path);
}

/// Saves the connection with key authentication, closes the dialog and offers Undo.
///
/// The connection is read again from the state rather than taken from the
/// snapshot the dialog opened with, so an edit made meanwhile is not overwritten.
/// The password source is left alone: the stored password stays in the vault.
fn switch_connection_to_key(c: &Rc<Controller>, key_path: &Path) {
    let original = match switch_to_key(&c.ctx.state, c.connection_id, key_path) {
        Ok(original) => original,
        Err(message) => {
            tracing::warn!(error = %message, "key setup: could not switch the connection");
            fail_with(
                c,
                &FailureView::message(i18n_f(
                    "The key works, but the connection could not be switched to it: {}",
                    &[&message],
                )),
            );
            return;
        }
    };
    if let Some(dialog) = c.dialog() {
        dialog.close();
    }

    let name = original.name.clone();
    let toast = adw::Toast::new(&i18n_f("'{}' now signs in with a key", &[&name]));
    toast.set_button_label(Some(&i18n("Undo")));
    toast.set_timeout(10);
    let state = c.ctx.state.clone();
    let sidebar = c.ctx.sidebar.clone();
    let overlay = Rc::clone(&c.ctx.toast_overlay);
    toast.connect_button_clicked(move |_| {
        restore_connection(&state, &sidebar, &overlay, &original);
    });
    c.ctx.toast_overlay.widget().add_toast(toast);

    // After the dialog has closed, so the reload does not make it stutter.
    let state = c.ctx.state.clone();
    let sidebar = c.ctx.sidebar.clone();
    glib::idle_add_local_once(move || {
        MainWindow::reload_sidebar_preserving_state(&state, &sidebar);
    });
}

/// Writes the key settings into the stored connection; returns the connection
/// as it was, for Undo.
fn switch_to_key(
    state: &SharedAppState,
    connection_id: Uuid,
    key_path: &Path,
) -> Result<rustconn_core::Connection, String> {
    let mut state = state
        .try_borrow_mut()
        .map_err(|_| i18n("the application is busy"))?;
    let original = state
        .get_connection(connection_id)
        .cloned()
        .ok_or_else(|| i18n("the connection no longer exists"))?;
    let mut modified = original.clone();
    if !apply_key_auth(&mut modified, key_path) {
        return Err(i18n("the connection is not an SSH connection"));
    }
    state.update_connection(connection_id, modified)?;
    Ok(original)
}

/// Undo: puts the connection back as it was before the switch.
///
/// The key stays on the disk and on the server; only the connection's sign-in
/// settings go back.
fn restore_connection(
    state: &SharedAppState,
    sidebar: &SharedSidebar,
    overlay: &SharedToastOverlay,
    original: &rustconn_core::Connection,
) {
    let restored = match state.try_borrow_mut() {
        Ok(mut state) => state.update_connection(original.id, original.clone()),
        Err(_) => Err("the application is busy".to_string()),
    };
    match restored {
        Ok(()) => {
            MainWindow::reload_sidebar_preserving_state(state, sidebar);
            overlay.show_toast(&i18n_f(
                "Restored the previous sign-in settings for '{}'",
                &[&original.name],
            ));
        }
        Err(e) => {
            tracing::warn!(error = %e, "key setup: undo failed");
            overlay.show_error(&i18n(
                "The previous sign-in settings could not be restored.",
            ));
        }
    }
}

/// Points an SSH connection at `key_path`: public key authentication with that
/// file, restricted to it. Mirrors what the connection editor writes for a
/// key file, so the editor shows the result as if the user had picked it.
/// `password_source` is deliberately not touched.
///
/// Returns `false`, changing nothing, for a connection that is not SSH.
fn apply_key_auth(connection: &mut rustconn_core::Connection, key_path: &Path) -> bool {
    use rustconn_core::SshKeySource;
    use rustconn_core::models::SshAuthMethod;

    let rustconn_core::ProtocolConfig::Ssh(config) = &mut connection.protocol_config else {
        return false;
    };
    config.auth_method = SshAuthMethod::PublicKey;
    config.key_source = SshKeySource::File {
        path: key_path.to_path_buf(),
    };
    config.key_path = Some(key_path.to_path_buf());
    config.agent_key_fingerprint = None;
    config.identities_only = true;
    true
}

/// Connect, offered when the host key is not known yet: opens an ordinary
/// session so the key gets recorded.
///
/// An ordinary connect decides whether the terminal asks about the key: when
/// the stored password goes through askpass it adds
/// `StrictHostKeyChecking=accept-new`, so a first-seen key is recorded without
/// a question. The wording does not promise a prompt for that reason.
///
/// The dialog closes first. It is modal, and the host key question is answered
/// in the terminal behind it.
fn connect_session(c: &Rc<Controller>) {
    if let Some(dialog) = c.dialog() {
        dialog.close();
    }
    c.ctx.toast_overlay.show_toast(&i18n(
        "Once the session is open and the host key is recorded, choose Set Up Key Authentication again.",
    ));
    MainWindow::start_connection_with_credential_resolution(
        c.ctx.state.clone(),
        c.ctx.notebook.clone(),
        c.ctx.split_view.clone(),
        c.ctx.sidebar.clone(),
        c.ctx.monitoring.clone(),
        c.connection_id,
        None,
    );
}

/// Delete Generated Key: asks first, then removes the key files.
fn confirm_delete(c: &Rc<Controller>) {
    let Some(dialog) = c.dialog() else {
        return;
    };
    let Some(path) = c.key_path.borrow().clone() else {
        return;
    };
    let alert = adw::AlertDialog::new(
        Some(&i18n("Delete Generated Key?")),
        Some(&i18n(
            "The key files are removed from this computer. If the public key was already installed, it stays in the server's authorized_keys.",
        )),
    );
    alert.add_response("cancel", &i18n("Cancel"));
    alert.add_response("delete", &i18n("Delete"));
    alert.set_response_appearance("delete", adw::ResponseAppearance::Destructive);
    alert.set_default_response(Some("cancel"));
    alert.set_close_response("cancel");
    let c = Rc::clone(c);
    alert.connect_response(None, move |_, response| {
        if response == "delete" {
            delete_key(&c, path.clone());
        }
    });
    alert.present(Some(dialog.widget()));
}

fn delete_key(c: &Rc<Controller>, path: PathBuf) {
    let c = Rc::clone(c);
    spawn_blocking_with_callback(
        move || ssh_key_setup::delete_generated_key(&path),
        move |result| {
            let Some(dialog) = c.dialog() else {
                return;
            };
            match result {
                Ok(()) => {
                    *c.key_path.borrow_mut() = None;
                    refresh_slot_hint(&c);
                    dialog.show_deleted();
                }
                Err(e) => fail(&c, &e, true),
            }
        },
    );
}

#[cfg(test)]
mod tests {
    use rustconn_core::models::{PasswordSource, SshAuthMethod};
    use rustconn_core::{Connection, ProtocolConfig, SshKeySource};

    use super::*;

    fn ssh_config(connection: &Connection) -> &rustconn_core::SshConfig {
        match &connection.protocol_config {
            ProtocolConfig::Ssh(config) => config,
            other => panic!("expected an SSH connection, got {other:?}"),
        }
    }

    #[test]
    fn apply_key_auth_writes_what_the_editor_writes_for_a_key_file() {
        let mut connection = Connection::new_ssh("web".into(), "web.example".into(), 22);
        connection.password_source = PasswordSource::Vault;
        let path = Path::new("/home/u/.ssh/rustconn/web-1234abcd-ed25519");

        assert!(apply_key_auth(&mut connection, path));

        let config = ssh_config(&connection);
        assert_eq!(config.auth_method, SshAuthMethod::PublicKey);
        assert_eq!(
            config.key_source,
            SshKeySource::File {
                path: path.to_path_buf()
            }
        );
        assert_eq!(config.key_path.as_deref(), Some(path));
        assert!(config.identities_only);
        assert_eq!(config.agent_key_fingerprint, None);
        // The stored password stays where it is.
        assert_eq!(connection.password_source, PasswordSource::Vault);
    }

    #[test]
    fn apply_key_auth_replaces_an_agent_key_choice() {
        let mut connection = Connection::new_ssh("web".into(), "web.example".into(), 22);
        if let ProtocolConfig::Ssh(config) = &mut connection.protocol_config {
            config.auth_method = SshAuthMethod::Agent;
            config.key_source = SshKeySource::Agent {
                fingerprint: "SHA256:old".into(),
                comment: "old".into(),
            };
            config.agent_key_fingerprint = Some("SHA256:old".into());
        }
        assert!(apply_key_auth(&mut connection, Path::new("/k/new")));
        let config = ssh_config(&connection);
        assert_eq!(config.auth_method, SshAuthMethod::PublicKey);
        assert_eq!(config.agent_key_fingerprint, None);
        assert!(matches!(config.key_source, SshKeySource::File { .. }));
    }

    #[test]
    fn apply_key_auth_leaves_a_non_ssh_connection_alone() {
        let mut connection = Connection::new_rdp("desk".into(), "desk.example".into(), 3389);
        assert!(!apply_key_auth(&mut connection, Path::new("/k/new")));
        assert!(matches!(connection.protocol_config, ProtocolConfig::Rdp(_)));
    }

    #[test]
    fn display_target_names_the_user_when_there_is_one() {
        assert_eq!(display_target(Some("anton"), "box"), "anton@box");
        assert_eq!(display_target(Some(""), "box"), "box");
        assert_eq!(display_target(None, "box"), "box");
    }
}
