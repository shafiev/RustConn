//! Structured-logging helpers for `RustConn`.
//!
//! Provides the canonical span names used across the core operations
//! (connection, search, import/export, credential resolution, session
//! lifecycle) so log spans are named consistently. The `tracing` subscriber
//! itself is initialised by the application entry point via `tracing_subscriber`
//! (see `rustconn/src/main.rs`).

pub mod perf;

/// Standard span names for `RustConn` operations
pub mod span_names {
    /// Connection establishment span
    pub const CONNECTION_ESTABLISH: &str = "connection.establish";
    /// Connection disconnect span
    pub const CONNECTION_DISCONNECT: &str = "connection.disconnect";
    /// Search execution span
    pub const SEARCH_EXECUTE: &str = "search.execute";
    /// Search cache lookup span
    pub const SEARCH_CACHE_LOOKUP: &str = "search.cache_lookup";
    /// Import operation span
    pub const IMPORT_EXECUTE: &str = "import.execute";
    /// Export operation span
    pub const EXPORT_EXECUTE: &str = "export.execute";
    /// Credential resolution span
    pub const CREDENTIAL_RESOLVE: &str = "credential.resolve";
    /// Credential store span
    pub const CREDENTIAL_STORE: &str = "credential.store";
    /// Configuration load span
    pub const CONFIG_LOAD: &str = "config.load";
    /// Configuration save span
    pub const CONFIG_SAVE: &str = "config.save";
    /// Session start span
    pub const SESSION_START: &str = "session.start";
    /// Session end span
    pub const SESSION_END: &str = "session.end";
}
