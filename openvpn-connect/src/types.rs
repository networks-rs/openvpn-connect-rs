/// Capabilities compiled into the linked native OpenVPN Core artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Capabilities {
    pub tun_builder: bool,
    pub dco: bool,
    pub dco_tun_builder: bool,
    pub gremlin: bool,
    pub external_tun: bool,
    pub external_transport: bool,
    pub private_tunnel_proxy: bool,
}

/// OpenVPN profile and client-core settings.
#[derive(Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    /// Inline OpenVPN profile content.
    pub content: String,
    /// Additional profile directives represented as key/value pairs.
    pub content_list: Vec<(String, String)>,
    /// Custom key/value pairs sent to the server as peer information.
    pub peer_info: Vec<(String, String)>,
    pub gui_version: String,
    pub sso_methods: String,
    pub app_custom_protocols: String,
    pub hw_addr_override: String,
    pub platform_version: String,
    pub server_override: String,
    pub port_override: String,
    pub proto_override: String,
    pub allow_unused_addr_families: String,
    pub compression_mode: String,
    pub external_pki_alias: String,
    pub private_key_password: String,
    pub tls_version_min_override: String,
    pub tls_cert_profile_override: String,
    pub tls_cipher_list: String,
    pub tls_ciphersuites_list: String,
    pub proxy_host: String,
    pub proxy_port: String,
    pub proxy_username: String,
    pub proxy_password: String,
    /// Enables the platform-provided custom proxy implementation.
    pub alternative_proxy: bool,
    /// Gremlin fault-injection configuration when Core is built with support for it.
    pub gremlin_config: String,
    pub connection_timeout_seconds: i32,
    pub ssl_debug_level: i32,
    pub default_key_direction: i32,
    pub protocol_version_override: i32,
    pub clock_tick_ms: u32,
    pub tun_persist: bool,
    pub google_dns_fallback: bool,
    pub dhcp_search_domains_as_split_domains: bool,
    pub synchronous_dns_lookup: bool,
    pub autologin_sessions: bool,
    pub retry_on_auth_failed: bool,
    pub disable_client_cert: bool,
    pub proxy_allow_cleartext_auth: bool,
    pub dco: bool,
    pub echo: bool,
    pub info: bool,
    pub allow_local_lan_access: bool,
    /// Emulates excluded routes on Android versions without native support.
    pub enable_route_emulation: bool,
    pub wintun: bool,
    pub allow_local_dns_resolvers: bool,
    pub enable_legacy_algorithms: bool,
    pub enable_non_preferred_data_channel_algorithms: bool,
    pub generate_tun_builder_capture_event: bool,
}

impl Config {
    /// Creates a configuration from inline `.ovpn` profile content.
    #[must_use]
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            ..Self::default()
        }
    }

    /// Sets the identity reported to the server as `IV_GUI_VER`.
    #[must_use]
    pub fn with_gui_version(mut self, value: impl Into<String>) -> Self {
        self.gui_version = value.into();
        self
    }

    /// Overrides the profile's remote server.
    #[must_use]
    pub fn with_server_override(mut self, value: impl Into<String>) -> Self {
        self.server_override = value.into();
        self
    }

    /// Overrides the profile's remote port.
    #[must_use]
    pub fn with_port_override(mut self, value: impl Into<String>) -> Self {
        self.port_override = value.into();
        self
    }

    /// Overrides the profile transport (`tcp`, `udp`, or `adaptive`).
    #[must_use]
    pub fn with_protocol_override(mut self, value: impl Into<String>) -> Self {
        self.proto_override = value.into();
        self
    }

    /// Verifies that every requested optional setting is implemented by the
    /// native artifact linked into this process.
    pub fn validate_capabilities(&self) -> crate::Result<()> {
        let capabilities = crate::capabilities();
        if self.dco && !capabilities.dco {
            return Err(crate::Error::UnsupportedCapability {
                capability: "dco",
                detail: "enable the `dco` Cargo feature on Linux or Windows and install the platform DCO dependencies",
            });
        }
        if !self.gremlin_config.is_empty() && !capabilities.gremlin {
            return Err(crate::Error::UnsupportedCapability {
                capability: "gremlin",
                detail: "rebuild OpenVPN Core from source with OPENVPN_GREMLIN",
            });
        }
        if self.alternative_proxy && !capabilities.private_tunnel_proxy {
            return Err(crate::Error::UnsupportedCapability {
                capability: "private-tunnel-proxy",
                detail: "the proprietary Private Tunnel proxy implementation is not present in the open-source OpenVPN 3 source tree",
            });
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            content: String::new(),
            content_list: Vec::new(),
            peer_info: Vec::new(),
            gui_version: String::new(),
            sso_methods: String::new(),
            app_custom_protocols: String::new(),
            hw_addr_override: String::new(),
            platform_version: String::new(),
            server_override: String::new(),
            port_override: String::new(),
            proto_override: String::new(),
            allow_unused_addr_families: String::new(),
            compression_mode: String::new(),
            external_pki_alias: String::new(),
            private_key_password: String::new(),
            tls_version_min_override: String::new(),
            tls_cert_profile_override: String::new(),
            tls_cipher_list: String::new(),
            tls_ciphersuites_list: String::new(),
            proxy_host: String::new(),
            proxy_port: String::new(),
            proxy_username: String::new(),
            proxy_password: String::new(),
            alternative_proxy: false,
            gremlin_config: String::new(),
            connection_timeout_seconds: 0,
            ssl_debug_level: 0,
            default_key_direction: -1,
            protocol_version_override: 0,
            clock_tick_ms: 0,
            tun_persist: false,
            google_dns_fallback: false,
            dhcp_search_domains_as_split_domains: cfg!(any(
                target_os = "windows",
                target_os = "macos",
                target_os = "linux",
                target_os = "ios"
            )),
            synchronous_dns_lookup: false,
            autologin_sessions: true,
            retry_on_auth_failed: false,
            disable_client_cert: false,
            proxy_allow_cleartext_auth: false,
            dco: cfg!(feature = "dco"),
            echo: false,
            info: false,
            allow_local_lan_access: false,
            enable_route_emulation: true,
            wintun: false,
            allow_local_dns_resolvers: false,
            enable_legacy_algorithms: false,
            enable_non_preferred_data_channel_algorithms: false,
            generate_tun_builder_capture_event: false,
        }
    }
}

/// Credentials passed to OpenVPN Core before connecting.
#[derive(Clone, Default)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub http_proxy_username: String,
    pub http_proxy_password: String,
    pub response: String,
    pub dynamic_challenge_cookie: String,
}

impl Credentials {
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            ..Self::default()
        }
    }
}

/// Result of parsing and validating an OpenVPN profile.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Evaluation {
    pub userlocked_username: String,
    pub profile_name: String,
    pub friendly_name: String,
    pub autologin: bool,
    pub external_pki: bool,
    pub vpn_ca: String,
    pub static_challenge: String,
    pub static_challenge_echo: bool,
    pub private_key_password_required: bool,
    pub allow_password_save: bool,
    pub remote_host: String,
    pub remote_port: String,
    pub remote_proto: String,
    pub servers: Vec<ServerEntry>,
    pub windows_driver: String,
    pub dco_compatible: bool,
    pub dco_incompatibility_reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerEntry {
    pub server: String,
    pub friendly_name: String,
}

/// Non-error status returned after a connection session exits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub status: String,
    pub message: String,
}

/// Result of resolving external file references in an OpenVPN profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergedConfig {
    pub status: String,
    pub error_text: String,
    pub basename: String,
    pub profile_content: String,
    pub referenced_paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub error: bool,
    pub fatal: bool,
    pub name: String,
    pub info: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppControlMessage {
    pub protocol: String,
    pub payload: String,
}

/// Replacement for the profile's selected `remote` directive.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RemoteOverride {
    pub host: String,
    pub ip: String,
    pub port: String,
    pub protocol: String,
}

/// A DNS resolver address supplied to [`TunBuilder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAddress {
    pub address: String,
    /// Zero means the default DNS port.
    pub port: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnsSecurity {
    #[default]
    Unset,
    No,
    Yes,
    Optional,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DnsTransport {
    #[default]
    Unset,
    Plain,
    Https,
    Tls,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServer {
    pub priority: i32,
    pub addresses: Vec<DnsAddress>,
    pub resolve_domains: Vec<String>,
    pub security: DnsSecurity,
    pub transport: DnsTransport,
    pub sni: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsOptions {
    pub from_dhcp_options: bool,
    pub search_domains: Vec<String>,
    pub servers: Vec<DnsServer>,
}

/// Peer information passed to a platform DCO implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DcoPeer {
    pub peer_id: u32,
    pub transport_fd: u32,
    pub remote_ip: String,
    pub remote_port: u16,
    pub vpn_ipv4: String,
    pub vpn_ipv6: String,
}

/// One direction of key material supplied to a platform DCO implementation.
///
/// This type deliberately does not implement `Debug` to avoid accidental key logging.
#[derive(Clone, Eq, PartialEq)]
pub struct DcoKeyDirection {
    pub cipher_key: Vec<u8>,
    pub nonce_tail: [u8; 8],
}

/// Complete key update supplied to a platform DCO implementation.
///
/// This type deliberately does not implement `Debug` to avoid accidental key logging.
#[derive(Clone, Eq, PartialEq)]
pub struct DcoKeyConfig {
    pub encrypt: DcoKeyDirection,
    pub decrypt: DcoKeyDirection,
    pub key_id: i32,
    pub remote_peer_id: i32,
    pub cipher_algorithm: u32,
}

/// Platform tunnel construction callbacks used on Android, iOS and OpenHarmony.
///
/// Methods are invoked synchronously by the dedicated Core connection thread.
/// Defaults mirror `openvpn::TunBuilderBase` exactly.
pub trait TunBuilder: Send + Sync + 'static {
    fn new_tunnel(&self) -> bool {
        false
    }

    fn set_layer(&self, _layer: i32) -> bool {
        true
    }

    fn set_remote_address(&self, _address: &str, _ipv6: bool) -> bool {
        false
    }

    fn add_address(
        &self,
        _address: &str,
        _prefix_length: i32,
        _gateway: &str,
        _ipv6: bool,
        _net30: bool,
    ) -> bool {
        false
    }

    fn set_route_metric_default(&self, _metric: i32) -> bool {
        true
    }

    fn reroute_gateway(&self, _ipv4: bool, _ipv6: bool, _flags: u32) -> bool {
        false
    }

    fn add_route(&self, _address: &str, _prefix_length: i32, _metric: i32, _ipv6: bool) -> bool {
        false
    }

    fn exclude_route(
        &self,
        _address: &str,
        _prefix_length: i32,
        _metric: i32,
        _ipv6: bool,
    ) -> bool {
        false
    }

    fn set_dns_options(&self, _dns: &DnsOptions) -> bool {
        false
    }

    fn set_mtu(&self, _mtu: i32) -> bool {
        false
    }

    fn set_session_name(&self, _name: &str) -> bool {
        false
    }

    fn add_proxy_bypass(&self, _host: &str) -> bool {
        false
    }

    fn set_proxy_auto_config_url(&self, _url: &str) -> bool {
        false
    }

    fn set_proxy_http(&self, _host: &str, _port: i32) -> bool {
        false
    }

    fn set_proxy_https(&self, _host: &str, _port: i32) -> bool {
        false
    }

    fn add_wins_server(&self, _address: &str) -> bool {
        false
    }

    /// `address_family` is the platform `AF_INET` or `AF_INET6` value.
    fn set_allow_family(&self, _address_family: i32, _allow: bool) -> bool {
        true
    }

    fn set_allow_local_dns(&self, _allow: bool) -> bool {
        true
    }

    /// Returns an owned tunnel file descriptor, or `-1` on failure.
    fn establish(&self) -> i32 {
        -1
    }

    fn persist(&self) -> bool {
        true
    }

    fn local_networks(&self, _ipv6: bool) -> Vec<String> {
        Vec::new()
    }

    fn establish_lite(&self) {}

    fn teardown(&self, _disconnect: bool) {}

    fn dco_available(&self) -> bool {
        false
    }

    /// Returns the control socket descriptor, or `-1` when DCO cannot be enabled.
    fn dco_enable(&self, _device_name: &str) -> i32 {
        -1
    }

    fn dco_new_peer(&self, _peer: DcoPeer) {}

    fn dco_set_peer(&self, _peer_id: u32, _keepalive_interval: i32, _keepalive_timeout: i32) {}

    fn dco_delete_peer(&self, _peer_id: u32) {}

    fn dco_get_peer(&self, _peer_id: u32, _synchronous: bool) {}

    fn dco_new_key(&self, _key_slot: u32, _key: DcoKeyConfig) {}

    fn dco_swap_keys(&self, _peer_id: u32) {}

    fn dco_delete_key(&self, _peer_id: u32, _key_slot: u32) {}

    fn dco_establish(&self) {}
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPkiCertificateRequest {
    pub alias: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPkiCertificate {
    pub certificate: String,
    pub supporting_chain: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPkiSignRequest {
    pub alias: String,
    /// Base64-encoded data supplied by OpenVPN Core.
    pub data: String,
    pub algorithm: String,
    pub hash_algorithm: String,
    pub salt_length: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalPkiError {
    pub message: String,
    pub invalid_alias: bool,
}

impl ExternalPkiError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            invalid_alias: false,
        }
    }
}

/// Receives synchronous callbacks from the thread running [`crate::Client::connect`].
///
/// Defaults are suitable for profiles that do not use external PKI. Panics are
/// contained at the FFI boundary and never unwind into C++.
pub trait EventHandler: Send + Sync + 'static {
    fn event(&self, _event: Event) {}

    fn log(&self, _text: &str) {}

    fn app_control_message(&self, _message: AppControlMessage) {}

    /// Protects a transport socket from being routed back through the VPN.
    fn socket_protect(&self, _socket: isize, _remote: &str, _ipv6: bool) -> bool {
        true
    }

    fn pause_on_connection_timeout(&self) -> bool {
        false
    }

    fn clock_tick(&self) {}

    fn remote_override_enabled(&self) -> bool {
        false
    }

    fn remote_override(&self) -> std::result::Result<RemoteOverride, String> {
        Err("remote override callback is not implemented".into())
    }

    /// Returns the platform tunnel builder, if this application provides one.
    fn tun_builder(&self) -> Option<&dyn TunBuilder> {
        None
    }

    /// Returns the application transport selected by the
    /// `external-transport` Cargo feature.
    fn external_transport(&self) -> Option<&dyn crate::ExternalTransport> {
        None
    }

    /// Returns the low-level tunnel selected by the `external-tun` Cargo feature.
    fn external_tun(&self) -> Option<&dyn crate::ExternalTun> {
        None
    }

    fn external_pki_certificate(
        &self,
        _request: ExternalPkiCertificateRequest,
    ) -> std::result::Result<ExternalPkiCertificate, ExternalPkiError> {
        Err(ExternalPkiError::new(
            "external PKI certificate callback is not implemented",
        ))
    }

    /// Returns a base64-encoded signature.
    fn external_pki_sign(
        &self,
        _request: ExternalPkiSignRequest,
    ) -> std::result::Result<String, ExternalPkiError> {
        Err(ExternalPkiError::new(
            "external PKI signing callback is not implemented",
        ))
    }
}

impl EventHandler for () {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DynamicChallenge {
    pub challenge: String,
    pub echo: bool,
    pub response_required: bool,
    pub state_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionInfo {
    pub user: String,
    pub server_host: String,
    pub server_port: String,
    pub server_proto: String,
    pub server_ip: String,
    pub vpn_ip4: String,
    pub vpn_ip6: String,
    pub vpn_mtu: String,
    pub gateway_ip4: String,
    pub gateway_ip6: String,
    pub client_ip: String,
    pub tun_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionToken {
    pub username: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Statistic {
    pub name: String,
    pub value: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct InterfaceStats {
    pub bytes_in: i64,
    pub packets_in: i64,
    pub errors_in: i64,
    pub bytes_out: i64,
    pub packets_out: i64,
    pub errors_out: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransportStats {
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub packets_in: i64,
    pub packets_out: i64,
    /// Binary milliseconds (1/1024 second), or `-1` when unavailable.
    pub last_packet_received: i32,
}
