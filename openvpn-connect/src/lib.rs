//! Safe, source-built Rust bindings to the OpenVPN 3 client core used by
//! OpenVPN Connect.
//!
//! [`Client::connect`] blocks for the lifetime of a VPN session. Run it on a
//! dedicated thread and use a cloned [`Client`] as the control handle.

#![allow(clippy::doc_markdown)]

mod client;
mod error;
mod external_transport;
mod external_tun;
mod native;
mod types;

#[cfg(feature = "tokio")]
pub mod tokio;

pub use client::Client;
pub use error::{Error, Result};
pub use external_transport::{
    ExternalRemote, ExternalTransport, ExternalTransportConfig, ExternalTransportEndpoint,
    ExternalTransportIo,
};
pub use external_tun::{
    ExternalTun, ExternalTunConfig, ExternalTunInfo, ExternalTunIo, ExternalTunStartConfig,
};
pub use types::{
    AppControlMessage, Capabilities, Config, ConnectionInfo, Credentials, DcoKeyConfig,
    DcoKeyDirection, DcoPeer, DnsAddress, DnsOptions, DnsSecurity, DnsServer, DnsTransport,
    DynamicChallenge, Evaluation, Event, EventHandler, ExternalPkiCertificate,
    ExternalPkiCertificateRequest, ExternalPkiError, ExternalPkiSignRequest, InterfaceStats,
    MergedConfig, RemoteOverride, ServerEntry, SessionToken, Statistic, Status, TransportStats,
    TunBuilder,
};

/// Returns features compiled into the linked native OpenVPN Core artifact.
#[must_use]
pub fn capabilities() -> Capabilities {
    native::capabilities()
}

/// Reads a profile and optionally resolves all referenced files.
#[must_use]
pub fn merge_config_path(path: &str, follow_references: bool) -> MergedConfig {
    native::merge_config_path(path, follow_references)
}

/// Resolves inline references in profile content using OpenVPN Core's merger.
#[must_use]
pub fn merge_config_string(content: &str) -> MergedConfig {
    native::merge_config_string(content)
}

/// Parses and validates a profile without allocating a stateful client.
pub fn evaluate_config(config: &Config) -> Result<Evaluation> {
    config.validate_capabilities()?;
    native::evaluate_static(config)
}

/// Returns the OpenVPN Core platform description.
#[must_use]
pub fn platform() -> String {
    native::platform()
}

/// Returns the OpenVPN Core copyright notice.
#[must_use]
pub fn copyright() -> String {
    native::copyright()
}

/// Returns the maximum accepted profile size in bytes.
#[must_use]
pub fn max_profile_size() -> usize {
    native::max_profile_size()
}

/// Runs the upstream crypto backend self-test.
///
/// OpenVPN Core returns an empty string when no diagnostic was produced.
#[must_use]
pub fn crypto_self_test() -> String {
    native::crypto_self_test()
}

/// Parses an OpenVPN dynamic challenge cookie.
#[must_use]
pub fn parse_dynamic_challenge(cookie: &str) -> Option<DynamicChallenge> {
    native::parse_dynamic_challenge(cookie)
}
