#![allow(clippy::too_many_lines)]

//! Guards the safe API against accidental drift from the vendored `OpenVPN` 3
//! public client surface. These checks intentionally read the canonical C++
//! headers: upgrading the vendored Core must fail loudly until every new field
//! and virtual method is mapped through the native adapter and safe Rust API.

use std::collections::BTreeSet;

const OVPNCLI: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../openvpn-connect-sys/vendor/openvpn3/client/ovpncli.hpp"
));
const TUN_BUILDER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../openvpn-connect-sys/vendor/openvpn3/openvpn/tun/builder/base.hpp"
));
const WRAPPER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../openvpn-connect-sys/src/wrapper.h"
));
const BRIDGE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../openvpn-connect-sys/src/bridge.cpp"
));
const TYPES: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/types.rs"));
const CLIENT: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/client.rs"));
const LIB: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
const EXTERNAL_TRANSPORT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/external_transport.rs"
));
const EXTERNAL_TUN: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/external_tun.rs"));
const TOKIO: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/tokio.rs"));
const E2E: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e.rs"));
const CALLBACK_E2E: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/callbacks.rs"));

fn assert_mapping(
    category: &str,
    upstream: &str,
    adapter: &str,
    safe: &str,
    mappings: &[(&str, &str, &str)],
) {
    for &(upstream_name, adapter_name, safe_name) in mappings {
        assert!(
            upstream.contains(upstream_name),
            "{category}: upstream member `{upstream_name}` disappeared; audit the Core upgrade"
        );
        assert!(
            adapter.contains(adapter_name),
            "{category}: native adapter mapping `{adapter_name}` is missing"
        );
        assert!(
            safe.contains(safe_name),
            "{category}: safe Rust mapping `{safe_name}` is missing"
        );
    }
}

fn struct_fields(source: &str, start: &str, end: &str) -> BTreeSet<String> {
    let body = source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing struct start `{start}`"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing struct end after `{start}`"))
        .0;
    body.lines()
        .filter_map(|line| {
            let declaration = line.split("//").next().unwrap_or_default().trim();
            let remainder = [
                "std::string ",
                "std::vector<KeyValue> ",
                "unsigned int ",
                "bool ",
                "int ",
            ]
            .iter()
            .find_map(|prefix| declaration.strip_prefix(prefix))?;
            let name = remainder
                .split(['=', ';'])
                .next()
                .unwrap_or_default()
                .trim();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

fn virtual_methods(source: &str, prefix: &str) -> BTreeSet<String> {
    source
        .lines()
        .filter_map(|line| {
            let declaration = line.trim();
            if !declaration.starts_with("virtual ") {
                return None;
            }
            let offset = declaration.find(prefix)?;
            let name = declaration[offset..]
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .next()
                .unwrap_or_default();
            (!name.is_empty()).then(|| name.to_owned())
        })
        .collect()
}

#[test]
fn every_public_config_setting_has_native_and_safe_mappings() {
    const CONFIG: &[(&str, &str, &str)] = &[
        ("guiVersion", "gui_version", "gui_version"),
        ("ssoMethods", "sso_methods", "sso_methods"),
        (
            "appCustomProtocols",
            "app_custom_protocols",
            "app_custom_protocols",
        ),
        ("hwAddrOverride", "hw_addr_override", "hw_addr_override"),
        ("platformVersion", "platform_version", "platform_version"),
        ("serverOverride", "server_override", "server_override"),
        ("portOverride", "port_override", "port_override"),
        ("connTimeout", "conn_timeout", "connection_timeout_seconds"),
        ("tunPersist", "tun_persist", "tun_persist"),
        (
            "googleDnsFallback",
            "google_dns_fallback",
            "google_dns_fallback",
        ),
        (
            "dhcpSearchDomainsAsSplitDomains",
            "dhcp_search_domains_as_split_domains",
            "dhcp_search_domains_as_split_domains",
        ),
        (
            "synchronousDnsLookup",
            "synchronous_dns_lookup",
            "synchronous_dns_lookup",
        ),
        (
            "autologinSessions",
            "autologin_sessions",
            "autologin_sessions",
        ),
        (
            "retryOnAuthFailed",
            "retry_on_auth_failed",
            "retry_on_auth_failed",
        ),
        (
            "disableClientCert",
            "disable_client_cert",
            "disable_client_cert",
        ),
        ("sslDebugLevel", "ssl_debug_level", "ssl_debug_level"),
        (
            "privateKeyPassword",
            "private_key_password",
            "private_key_password",
        ),
        (
            "defaultKeyDirection",
            "default_key_direction",
            "default_key_direction",
        ),
        (
            "tlsVersionMinOverride",
            "tls_version_min_override",
            "tls_version_min_override",
        ),
        (
            "tlsCertProfileOverride",
            "tls_cert_profile_override",
            "tls_cert_profile_override",
        ),
        ("tlsCipherList", "tls_cipher_list", "tls_cipher_list"),
        (
            "tlsCiphersuitesList",
            "tls_ciphersuites_list",
            "tls_ciphersuites_list",
        ),
        ("proxyHost", "proxy_host", "proxy_host"),
        ("proxyPort", "proxy_port", "proxy_port"),
        ("proxyUsername", "proxy_username", "proxy_username"),
        ("proxyPassword", "proxy_password", "proxy_password"),
        (
            "proxyAllowCleartextAuth",
            "proxy_allow_cleartext_auth",
            "proxy_allow_cleartext_auth",
        ),
        ("altProxy", "alt_proxy", "alternative_proxy"),
        ("dco", "dco", "dco"),
        ("echo", "echo", "echo"),
        ("info", "info", "info"),
        (
            "allowLocalLanAccess",
            "allow_local_lan_access",
            "allow_local_lan_access",
        ),
        (
            "enableRouteEmulation",
            "enable_route_emulation",
            "enable_route_emulation",
        ),
        ("clockTickMS", "clock_tick_ms", "clock_tick_ms"),
        ("gremlinConfig", "gremlin_config", "gremlin_config"),
        ("wintun", "wintun", "wintun"),
        (
            "allowLocalDnsResolvers",
            "allow_local_dns_resolvers",
            "allow_local_dns_resolvers",
        ),
        (
            "enableLegacyAlgorithms",
            "enable_legacy_algorithms",
            "enable_legacy_algorithms",
        ),
        (
            "enableNonPreferredDCAlgorithms",
            "enable_non_preferred_dc_algorithms",
            "enable_non_preferred_data_channel_algorithms",
        ),
        (
            "generateTunBuilderCaptureEvent",
            "generate_tun_builder_capture_event",
            "generate_tun_builder_capture_event",
        ),
        ("content", "content", "content"),
        ("contentList", "content_list", "content_list"),
        ("protoOverride", "proto_override", "proto_override"),
        (
            "protoVersionOverride",
            "proto_version_override",
            "protocol_version_override",
        ),
        (
            "allowUnusedAddrFamilies",
            "allow_unused_addr_families",
            "allow_unused_addr_families",
        ),
        ("compressionMode", "compression_mode", "compression_mode"),
        (
            "externalPkiAlias",
            "external_pki_alias",
            "external_pki_alias",
        ),
        ("peerInfo", "peer_info", "peer_info"),
    ];

    assert_mapping("Config", OVPNCLI, WRAPPER, TYPES, CONFIG);
    for &(upstream, _, safe) in CONFIG {
        assert!(
            BRIDGE.contains(upstream),
            "Config: bridge does not assign upstream member `{upstream}`"
        );
        assert!(
            E2E.contains(safe),
            "Config field `{safe}` is missing from the all-field E2E traversal"
        );
    }

    let mut upstream_fields = struct_fields(
        OVPNCLI,
        "struct ConfigCommon\n{",
        "\n};\n\n// OpenVPN config-file/profile",
    );
    upstream_fields.extend(struct_fields(
        OVPNCLI,
        "struct Config : public ConfigCommon\n{",
        "\n};\n\n// used to communicate VPN events",
    ));
    let mapped_fields = CONFIG
        .iter()
        .map(|(upstream, _, _)| (*upstream).to_owned())
        .collect();
    assert_eq!(
        upstream_fields, mapped_fields,
        "the complete upstream Config field set must be mapped"
    );
}

#[test]
fn every_tun_builder_method_has_native_and_safe_mappings() {
    const METHODS: &[(&str, &str, &str)] = &[
        ("tun_builder_new", "tun_builder_new", "fn new_tunnel"),
        (
            "tun_builder_set_layer",
            "tun_builder_set_layer",
            "fn set_layer",
        ),
        (
            "tun_builder_set_remote_address",
            "tun_builder_set_remote_address",
            "fn set_remote_address",
        ),
        (
            "tun_builder_add_address",
            "tun_builder_add_address",
            "fn add_address",
        ),
        (
            "tun_builder_set_route_metric_default",
            "tun_builder_set_route_metric_default",
            "fn set_route_metric_default",
        ),
        (
            "tun_builder_reroute_gw",
            "tun_builder_reroute_gw",
            "fn reroute_gateway",
        ),
        (
            "tun_builder_add_route",
            "tun_builder_add_route",
            "fn add_route",
        ),
        (
            "tun_builder_exclude_route",
            "tun_builder_exclude_route",
            "fn exclude_route",
        ),
        (
            "tun_builder_set_dns_options",
            "tun_builder_set_dns_options",
            "fn set_dns_options",
        ),
        ("tun_builder_set_mtu", "tun_builder_set_mtu", "fn set_mtu"),
        (
            "tun_builder_set_session_name",
            "tun_builder_set_session_name",
            "fn set_session_name",
        ),
        (
            "tun_builder_add_proxy_bypass",
            "tun_builder_add_proxy_bypass",
            "fn add_proxy_bypass",
        ),
        (
            "tun_builder_set_proxy_auto_config_url",
            "tun_builder_set_proxy_auto_config_url",
            "fn set_proxy_auto_config_url",
        ),
        (
            "tun_builder_set_proxy_http",
            "tun_builder_set_proxy_http",
            "fn set_proxy_http",
        ),
        (
            "tun_builder_set_proxy_https",
            "tun_builder_set_proxy_https",
            "fn set_proxy_https",
        ),
        (
            "tun_builder_add_wins_server",
            "tun_builder_add_wins_server",
            "fn add_wins_server",
        ),
        (
            "tun_builder_set_allow_family",
            "tun_builder_set_allow_family",
            "fn set_allow_family",
        ),
        (
            "tun_builder_set_allow_local_dns",
            "tun_builder_set_allow_local_dns",
            "fn set_allow_local_dns",
        ),
        (
            "tun_builder_establish",
            "tun_builder_establish",
            "fn establish",
        ),
        ("tun_builder_persist", "tun_builder_persist", "fn persist"),
        (
            "tun_builder_get_local_networks",
            "tun_builder_get_local_networks",
            "fn local_networks",
        ),
        (
            "tun_builder_establish_lite",
            "tun_builder_establish_lite",
            "fn establish_lite",
        ),
        (
            "tun_builder_teardown",
            "tun_builder_teardown",
            "fn teardown",
        ),
        (
            "tun_builder_dco_available",
            "tun_builder_dco_available",
            "fn dco_available",
        ),
        (
            "tun_builder_dco_enable",
            "tun_builder_dco_enable",
            "fn dco_enable",
        ),
        (
            "tun_builder_dco_new_peer",
            "tun_builder_dco_new_peer",
            "fn dco_new_peer",
        ),
        (
            "tun_builder_dco_set_peer",
            "tun_builder_dco_set_peer",
            "fn dco_set_peer",
        ),
        (
            "tun_builder_dco_del_peer",
            "tun_builder_dco_del_peer",
            "fn dco_delete_peer",
        ),
        (
            "tun_builder_dco_get_peer",
            "tun_builder_dco_get_peer",
            "fn dco_get_peer",
        ),
        (
            "tun_builder_dco_new_key",
            "tun_builder_dco_new_key",
            "fn dco_new_key",
        ),
        (
            "tun_builder_dco_swap_keys",
            "tun_builder_dco_swap_keys",
            "fn dco_swap_keys",
        ),
        (
            "tun_builder_dco_del_key",
            "tun_builder_dco_del_key",
            "fn dco_delete_key",
        ),
        (
            "tun_builder_dco_establish",
            "tun_builder_dco_establish",
            "fn dco_establish",
        ),
    ];

    assert_mapping("TunBuilder", TUN_BUILDER, WRAPPER, TYPES, METHODS);
    for &(upstream, _, _) in METHODS {
        assert!(
            BRIDGE.contains(upstream),
            "TunBuilder: bridge override `{upstream}` is missing"
        );
    }
    let upstream_methods = virtual_methods(TUN_BUILDER, "tun_builder_");
    let mapped_methods = METHODS
        .iter()
        .map(|(upstream, _, _)| (*upstream).to_owned())
        .collect();
    assert_eq!(
        upstream_methods, mapped_methods,
        "the complete upstream TunBuilder virtual method set must be mapped"
    );
}

#[test]
fn every_openvpn_client_operation_has_a_safe_method() {
    const METHODS: &[(&str, &str, &str)] = &[
        ("eval_config", "ovpn_client_eval_config", "pub fn evaluate"),
        (
            "provide_creds",
            "ovpn_client_provide_creds",
            "pub fn provide_credentials",
        ),
        ("connect()", "ovpn_client_connect", "pub fn connect"),
        (
            "connection_info",
            "ovpn_client_connection_info",
            "pub fn connection_info",
        ),
        (
            "session_token",
            "ovpn_client_session_token",
            "pub fn session_token",
        ),
        ("stop()", "ovpn_client_stop", "pub fn stop"),
        ("pause(", "ovpn_client_pause", "pub fn pause"),
        ("resume()", "ovpn_client_resume", "pub fn resume"),
        ("reconnect(", "ovpn_client_reconnect", "pub fn reconnect"),
        (
            "stats_bundle",
            "ovpn_client_stats_bundle",
            "pub fn statistics",
        ),
        (
            "tun_stats",
            "ovpn_client_tun_stats",
            "pub fn interface_stats",
        ),
        (
            "transport_stats",
            "ovpn_client_transport_stats",
            "pub fn transport_stats",
        ),
        (
            "post_cc_msg",
            "ovpn_client_post_cc_msg",
            "pub fn post_control_message",
        ),
        (
            "send_app_control_channel_msg",
            "ovpn_client_send_app_control_channel_msg",
            "pub fn send_app_control_message",
        ),
        (
            "start_cert_check(",
            "ovpn_client_start_cert_check",
            "pub fn start_certificate_check",
        ),
        (
            "start_cert_check_epki",
            "ovpn_client_start_cert_check_epki",
            "pub fn start_external_pki_certificate_check",
        ),
    ];

    assert_mapping("OpenVPNClient", OVPNCLI, WRAPPER, CLIENT, METHODS);
}

#[test]
fn low_level_factories_ignored_by_swig_have_safe_rust_extensions() {
    assert!(OVPNCLI.contains("public ExternalTun::Factory"));
    assert!(OVPNCLI.contains("public ExternalTransport::Factory"));

    for name in [
        "external_transport_configure",
        "external_transport_start",
        "external_transport_send",
        "ovpn_external_transport_receive",
        "ovpn_external_transport_disable_keepalive",
    ] {
        assert!(
            WRAPPER.contains(name),
            "external transport adapter `{name}` is missing"
        );
    }
    for name in [
        "trait ExternalTransport",
        "struct ExternalTransportIo",
        "pub fn receive",
        "pub fn disable_keepalive",
    ] {
        assert!(
            EXTERNAL_TRANSPORT.contains(name),
            "safe external transport API `{name}` is missing"
        );
    }

    for name in [
        "external_tun_configure",
        "external_tun_start",
        "external_tun_send",
        "ovpn_external_tun_receive",
        "ovpn_external_tun_connected",
    ] {
        assert!(
            WRAPPER.contains(name),
            "external TUN adapter `{name}` is missing"
        );
    }
    for name in [
        "trait ExternalTun",
        "struct ExternalTunIo",
        "pub fn receive",
        "pub fn connected",
    ] {
        assert!(
            EXTERNAL_TUN.contains(name),
            "safe external TUN API `{name}` is missing"
        );
    }
}

#[test]
fn every_helper_and_callback_operation_is_mapped() {
    const HELPERS: &[(&str, &str, &str)] = &[
        (
            "merge_config(",
            "ovpn_merge_config_path",
            "pub fn merge_config_path",
        ),
        (
            "merge_config_string",
            "ovpn_merge_config_string",
            "pub fn merge_config_string",
        ),
        (
            "eval_config(const Config",
            "ovpn_eval_config_static",
            "pub fn evaluate_config",
        ),
        (
            "max_profile_size",
            "ovpn_max_profile_size",
            "pub fn max_profile_size",
        ),
        (
            "parse_dynamic_challenge",
            "ovpn_parse_dynamic_challenge",
            "pub fn parse_dynamic_challenge",
        ),
        (
            "crypto_self_test",
            "ovpn_crypto_self_test",
            "pub fn crypto_self_test",
        ),
        ("platform()", "ovpn_platform", "pub fn platform"),
        ("copyright()", "ovpn_copyright", "pub fn copyright"),
    ];
    const CALLBACKS: &[(&str, &str, &str)] = &[
        ("virtual void event", "ovpn_event_fn", "fn event"),
        (
            "virtual void acc_event",
            "ovpn_acc_event_fn",
            "fn app_control_message",
        ),
        ("virtual void log", "ovpn_log_fn", "fn log"),
        (
            "socket_protect",
            "ovpn_socket_protect_fn",
            "fn socket_protect",
        ),
        (
            "pause_on_connection_timeout",
            "ovpn_pause_on_connection_timeout_fn",
            "fn pause_on_connection_timeout",
        ),
        (
            "external_pki_cert_request",
            "ovpn_external_pki_cert_request_fn",
            "fn external_pki_certificate",
        ),
        (
            "external_pki_sign_request",
            "ovpn_external_pki_sign_request_fn",
            "fn external_pki_sign",
        ),
        (
            "remote_override_enabled",
            "ovpn_remote_override_enabled_fn",
            "fn remote_override_enabled",
        ),
        (
            "remote_override(RemoteOverride",
            "ovpn_remote_override_request_fn",
            "fn remote_override",
        ),
        ("clock_tick", "ovpn_clock_tick_fn", "fn clock_tick"),
    ];

    assert_mapping("OpenVPNClientHelper", OVPNCLI, WRAPPER, LIB, HELPERS);
    assert_mapping(
        "OpenVPNClient callbacks",
        OVPNCLI,
        WRAPPER,
        TYPES,
        CALLBACKS,
    );
}

#[test]
fn every_safe_binding_is_owned_by_the_e2e_contract() {
    for operation in [
        "capabilities",
        "platform",
        "copyright",
        "max_profile_size",
        "crypto_self_test",
        "parse_dynamic_challenge",
        "merge_config_path",
        "merge_config_string",
        "evaluate_config",
        "Client::new",
        "Client::without_callbacks",
        "Client::evaluate",
        "Client::provide_credentials",
        "Client::connect",
        "Client::start_certificate_check",
        "Client::start_external_pki_certificate_check",
        "Client::stop",
        "Client::pause",
        "Client::resume",
        "Client::reconnect",
        "Client::post_control_message",
        "Client::send_app_control_message",
        "Client::connection_info",
        "Client::session_token",
        "Client::statistics",
        "Client::interface_stats",
        "Client::transport_stats",
        "Client::callback_self_test",
        "tokio::merge_config_path",
        "tokio::merge_config_string",
        "tokio::evaluate_config",
        "tokio::crypto_self_test",
        "tokio::ClientBuilder::new",
        "tokio::ClientBuilder::handler",
        "tokio::ClientBuilder::async_handler",
        "tokio::ClientBuilder::event_capacity",
        "tokio::ClientBuilder::log_capacity",
        "tokio::ClientBuilder::app_control_capacity",
        "tokio::ClientBuilder::command_capacity",
        "tokio::ClientBuilder::build",
        "tokio::Client::builder",
        "tokio::Client::new",
        "tokio::Client::new_async",
        "tokio::Client::without_callbacks",
        "tokio::Client::evaluate",
        "tokio::Client::provide_credentials",
        "tokio::Client::callback_self_test",
        "tokio::Client::connect",
        "tokio::Client::subscribe_events",
        "tokio::Client::event_stream",
        "tokio::Client::subscribe_logs",
        "tokio::Client::log_stream",
        "tokio::Client::subscribe_app_control",
        "tokio::Client::app_control_stream",
        "tokio::Session::handle",
        "tokio::Session::cancellation_token",
        "tokio::Session::wait",
        "tokio::SessionHandle::stop",
        "tokio::SessionHandle::cancel",
        "tokio::SessionHandle::cancellation_token",
        "tokio::SessionHandle::pause",
        "tokio::SessionHandle::resume",
        "tokio::SessionHandle::reconnect",
        "tokio::SessionHandle::post_control_message",
        "tokio::SessionHandle::send_app_control_message",
        "tokio::SessionHandle::start_certificate_check",
        "tokio::SessionHandle::start_external_pki_certificate_check",
        "tokio::SessionHandle::connection_info",
        "tokio::SessionHandle::session_token",
        "tokio::SessionHandle::statistics",
        "tokio::SessionHandle::interface_stats",
        "tokio::SessionHandle::transport_stats",
        "TunBuilder::*",
        "ExternalTransport::*",
        "ExternalTransportIo::*",
        "ExternalTun::*",
        "ExternalTunIo::*",
    ] {
        assert!(
            E2E.contains(&format!("\"{operation}\"")),
            "safe binding `{operation}` is missing from E2E_BINDING_COVERAGE"
        );
    }

    for method in [
        "pub async fn callback_self_test",
        "pub async fn start_certificate_check",
        "pub async fn start_external_pki_certificate_check",
        "pub async fn transport_stats",
        "pub fn app_control_stream",
        "pub async fn wait",
    ] {
        assert!(TOKIO.contains(method), "Tokio API `{method}` disappeared");
    }

    for method in [
        "fn dco_new_key",
        "fn external_transport",
        "fn start(&self, io: openvpn_connect::ExternalTransportIo)",
        "io.disable_keepalive()",
        "fn external_tun",
        "io.pre_tun_config()",
        "io.connected()",
    ] {
        assert!(
            CALLBACK_E2E.contains(method),
            "callback/low-level binding `{method}` lacks executable coverage"
        );
    }
}
