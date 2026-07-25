use std::ffi::c_void;
use std::marker::PhantomData;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};
use std::slice;

use openvpn_connect_sys as sys;

use crate::error::{Error, Result};
use crate::external_transport::{
    ExternalRemote, ExternalTransport, ExternalTransportConfig, ExternalTransportEndpoint,
    ExternalTransportIo,
};
use crate::external_tun::{
    ExternalTun, ExternalTunConfig, ExternalTunInfo, ExternalTunIo, ExternalTunStartConfig,
};
use crate::types::{
    AppControlMessage, Capabilities, Config, ConnectionInfo, Credentials, DcoKeyConfig,
    DcoKeyDirection, DcoPeer, DnsAddress, DnsOptions, DnsSecurity, DnsServer, DnsTransport,
    DynamicChallenge, Evaluation, Event, EventHandler, ExternalPkiCertificate,
    ExternalPkiCertificateRequest, ExternalPkiError, ExternalPkiSignRequest, InterfaceStats,
    MergedConfig, RemoteOverride, ServerEntry, SessionToken, Statistic, Status, TransportStats,
    TunBuilder,
};

pub(crate) struct CallbackState {
    pub handler: Box<dyn EventHandler>,
}

pub(crate) fn callback_table(context: *mut c_void) -> sys::ovpn_callbacks {
    sys::ovpn_callbacks {
        context,
        event: Some(event_callback),
        log: Some(log_callback),
        acc_event: Some(app_control_callback),
        socket_protect: Some(socket_protect_callback),
        pause_on_connection_timeout: Some(pause_on_timeout_callback),
        clock_tick: Some(clock_tick_callback),
        external_pki_cert_request: Some(external_pki_certificate_callback),
        external_pki_sign_request: Some(external_pki_sign_callback),
        remote_override_enabled: Some(remote_override_enabled_callback),
        remote_override_request: Some(remote_override_callback),
        tun_builder_new: Some(tun_builder_new_callback),
        tun_builder_set_layer: Some(tun_builder_set_layer_callback),
        tun_builder_set_remote_address: Some(tun_builder_set_remote_address_callback),
        tun_builder_add_address: Some(tun_builder_add_address_callback),
        tun_builder_set_route_metric_default: Some(tun_builder_set_route_metric_default_callback),
        tun_builder_reroute_gw: Some(tun_builder_reroute_gw_callback),
        tun_builder_add_route: Some(tun_builder_add_route_callback),
        tun_builder_exclude_route: Some(tun_builder_exclude_route_callback),
        tun_builder_set_dns_options: Some(tun_builder_set_dns_options_callback),
        tun_builder_set_mtu: Some(tun_builder_set_mtu_callback),
        tun_builder_set_session_name: Some(tun_builder_set_session_name_callback),
        tun_builder_add_proxy_bypass: Some(tun_builder_add_proxy_bypass_callback),
        tun_builder_set_proxy_auto_config_url: Some(tun_builder_set_proxy_auto_config_url_callback),
        tun_builder_set_proxy_http: Some(tun_builder_set_proxy_http_callback),
        tun_builder_set_proxy_https: Some(tun_builder_set_proxy_https_callback),
        tun_builder_add_wins_server: Some(tun_builder_add_wins_server_callback),
        tun_builder_set_allow_family: Some(tun_builder_set_allow_family_callback),
        tun_builder_set_allow_local_dns: Some(tun_builder_set_allow_local_dns_callback),
        tun_builder_establish: Some(tun_builder_establish_callback),
        tun_builder_persist: Some(tun_builder_persist_callback),
        tun_builder_get_local_networks: Some(tun_builder_get_local_networks_callback),
        tun_builder_establish_lite: Some(tun_builder_establish_lite_callback),
        tun_builder_teardown: Some(tun_builder_teardown_callback),
        tun_builder_dco_available: Some(tun_builder_dco_available_callback),
        tun_builder_dco_enable: Some(tun_builder_dco_enable_callback),
        tun_builder_dco_new_peer: Some(tun_builder_dco_new_peer_callback),
        tun_builder_dco_set_peer: Some(tun_builder_dco_set_peer_callback),
        tun_builder_dco_del_peer: Some(tun_builder_dco_del_peer_callback),
        tun_builder_dco_get_peer: Some(tun_builder_dco_get_peer_callback),
        tun_builder_dco_new_key: Some(tun_builder_dco_new_key_callback),
        tun_builder_dco_swap_keys: Some(tun_builder_dco_swap_keys_callback),
        tun_builder_dco_del_key: Some(tun_builder_dco_del_key_callback),
        tun_builder_dco_establish: Some(tun_builder_dco_establish_callback),
        external_transport_configure: Some(external_transport_configure_callback),
        external_transport_start: Some(external_transport_start_callback),
        external_transport_stop: Some(external_transport_stop_callback),
        external_transport_send: Some(external_transport_send_callback),
        external_transport_send_queue_empty: Some(external_transport_send_queue_empty_callback),
        external_transport_has_send_queue: Some(external_transport_has_send_queue_callback),
        external_transport_stop_requeueing: Some(external_transport_stop_requeueing_callback),
        external_transport_send_queue_size: Some(external_transport_send_queue_size_callback),
        external_transport_reset_align_adjust: Some(external_transport_reset_align_adjust_callback),
        external_transport_endpoint: Some(external_transport_endpoint_callback),
        external_transport_native_handle: Some(external_transport_native_handle_callback),
        external_transport_is_relay: Some(external_transport_is_relay_callback),
        external_transport_process_push: Some(external_transport_process_push_callback),
        external_tun_configure: Some(external_tun_configure_callback),
        external_tun_start: Some(external_tun_start_callback),
        external_tun_stop: Some(external_tun_stop_callback),
        external_tun_set_disconnect: Some(external_tun_set_disconnect_callback),
        external_tun_send: Some(external_tun_send_callback),
        external_tun_info: Some(external_tun_info_callback),
        external_tun_adjust_mss: Some(external_tun_adjust_mss_callback),
        external_tun_apply_push_update: Some(external_tun_apply_push_update_callback),
        external_tun_layer_2_supported: Some(external_tun_layer_2_supported_callback),
        external_tun_supports_epoch_data: Some(external_tun_supports_epoch_data_callback),
        external_tun_finalize: Some(external_tun_finalize_callback),
    }
}

pub(crate) fn new_client(callbacks: &sys::ovpn_callbacks) -> Result<NonNull<sys::ovpn_client>> {
    sys::install_rust_backend();
    let mut status = sys::ovpn_status::default();
    // SAFETY: `status` is writable and the callback context outlives the returned client.
    let native = unsafe { sys::ovpn_client_new(*callbacks, &raw mut status) };
    if status.error != 0 {
        let error = status_error(&status);
        // SAFETY: the status was initialized by the native API and is consumed once.
        unsafe { sys::ovpn_status_free(status) };
        if !native.is_null() {
            // SAFETY: a non-null result is an owned client from `ovpn_client_new`.
            unsafe { sys::ovpn_client_free(native) };
        }
        return Err(error);
    }
    // SAFETY: the status was initialized by the native API and is consumed once.
    unsafe { sys::ovpn_status_free(status) };
    NonNull::new(native)
        .ok_or_else(|| Error::Initialization("OpenVPN Core returned a null client".into()))
}

pub(crate) fn free_client(client: NonNull<sys::ovpn_client>) {
    // SAFETY: `client` is uniquely finalized by `Inner::drop` after all handles are gone.
    unsafe { sys::ovpn_client_free(client.as_ptr()) }
}

pub(crate) fn stop(client: NonNull<sys::ovpn_client>) {
    // SAFETY: the native API documents `stop` for concurrent use with `connect`.
    unsafe { sys::ovpn_client_stop(client.as_ptr()) }
}

pub(crate) fn merge_config_path(path: &str, follow_references: bool) -> MergedConfig {
    // SAFETY: the path view lives through this synchronous call.
    let raw = unsafe { sys::ovpn_merge_config_path(view(path), bool_i32(follow_references)) };
    take_merged_config(raw)
}

pub(crate) fn merge_config_string(content: &str) -> MergedConfig {
    // SAFETY: the content view lives through this synchronous call.
    let raw = unsafe { sys::ovpn_merge_config_string(view(content)) };
    take_merged_config(raw)
}

fn take_merged_config(raw: sys::ovpn_merge_config) -> MergedConfig {
    let referenced_paths = if raw.ref_path_list.is_null() {
        Vec::new()
    } else {
        // SAFETY: the native aggregate owns this initialized array until it is freed below.
        unsafe { slice::from_raw_parts(raw.ref_path_list, raw.ref_path_list_len) }
            .iter()
            .map(string_from_owned)
            .collect()
    };
    let result = MergedConfig {
        status: string_from_owned(&raw.status),
        error_text: string_from_owned(&raw.error_text),
        basename: string_from_owned(&raw.basename),
        profile_content: string_from_owned(&raw.profile_content),
        referenced_paths,
    };
    // SAFETY: every owned field has been copied and the aggregate is consumed once.
    unsafe { sys::ovpn_merge_config_free(raw) };
    result
}

pub(crate) fn evaluate(client: NonNull<sys::ovpn_client>, config: &Config) -> Result<Evaluation> {
    let raw_config = RawConfig::new(config);
    // SAFETY: all views in `raw_config` remain valid through this synchronous call.
    let raw = unsafe { sys::ovpn_client_eval_config(client.as_ptr(), &raw const raw_config.raw) };
    let result = if raw.error != 0 {
        Err(Error::Core {
            status: "CONFIG_ERROR".into(),
            message: string_from_owned(&raw.message),
        })
    } else {
        let servers = if raw.server_list.is_null() {
            Vec::new()
        } else {
            // SAFETY: the native aggregate owns this initialized array until its free call.
            unsafe { slice::from_raw_parts(raw.server_list, raw.server_list_len) }
                .iter()
                .map(|server| ServerEntry {
                    server: string_from_owned(&server.server),
                    friendly_name: string_from_owned(&server.friendly_name),
                })
                .collect()
        };
        Ok(Evaluation {
            userlocked_username: string_from_owned(&raw.userlocked_username),
            profile_name: string_from_owned(&raw.profile_name),
            friendly_name: string_from_owned(&raw.friendly_name),
            autologin: raw.autologin != 0,
            external_pki: raw.external_pki != 0,
            vpn_ca: string_from_owned(&raw.vpn_ca),
            static_challenge: string_from_owned(&raw.static_challenge),
            static_challenge_echo: raw.static_challenge_echo != 0,
            private_key_password_required: raw.private_key_password_required != 0,
            allow_password_save: raw.allow_password_save != 0,
            remote_host: string_from_owned(&raw.remote_host),
            remote_port: string_from_owned(&raw.remote_port),
            remote_proto: string_from_owned(&raw.remote_proto),
            servers,
            windows_driver: string_from_owned(&raw.windows_driver),
            dco_compatible: raw.dco_compatible != 0,
            dco_incompatibility_reason: string_from_owned(&raw.dco_incompatibility_reason),
        })
    };
    // SAFETY: every owned member is copied above, and the aggregate is freed exactly once.
    unsafe { sys::ovpn_eval_config_free(raw) };
    result
}

pub(crate) fn evaluate_static(config: &Config) -> Result<Evaluation> {
    let raw_config = RawConfig::new(config);
    // SAFETY: all views remain valid through this synchronous helper call.
    let raw = unsafe { sys::ovpn_eval_config_static(&raw const raw_config.raw) };
    evaluation_result(raw)
}

fn evaluation_result(raw: sys::ovpn_eval_config) -> Result<Evaluation> {
    let result = if raw.error != 0 {
        Err(Error::Core {
            status: "CONFIG_ERROR".into(),
            message: string_from_owned(&raw.message),
        })
    } else {
        let servers = if raw.server_list.is_null() {
            Vec::new()
        } else {
            // SAFETY: the native aggregate owns this initialized array until its free call.
            unsafe { slice::from_raw_parts(raw.server_list, raw.server_list_len) }
                .iter()
                .map(|server| ServerEntry {
                    server: string_from_owned(&server.server),
                    friendly_name: string_from_owned(&server.friendly_name),
                })
                .collect()
        };
        Ok(Evaluation {
            userlocked_username: string_from_owned(&raw.userlocked_username),
            profile_name: string_from_owned(&raw.profile_name),
            friendly_name: string_from_owned(&raw.friendly_name),
            autologin: raw.autologin != 0,
            external_pki: raw.external_pki != 0,
            vpn_ca: string_from_owned(&raw.vpn_ca),
            static_challenge: string_from_owned(&raw.static_challenge),
            static_challenge_echo: raw.static_challenge_echo != 0,
            private_key_password_required: raw.private_key_password_required != 0,
            allow_password_save: raw.allow_password_save != 0,
            remote_host: string_from_owned(&raw.remote_host),
            remote_port: string_from_owned(&raw.remote_port),
            remote_proto: string_from_owned(&raw.remote_proto),
            servers,
            windows_driver: string_from_owned(&raw.windows_driver),
            dco_compatible: raw.dco_compatible != 0,
            dco_incompatibility_reason: string_from_owned(&raw.dco_incompatibility_reason),
        })
    };
    // SAFETY: every owned member is copied above, and the aggregate is freed exactly once.
    unsafe { sys::ovpn_eval_config_free(raw) };
    result
}

pub(crate) fn provide_credentials(
    client: NonNull<sys::ovpn_client>,
    credentials: &Credentials,
) -> Result<Status> {
    let raw_credentials = sys::ovpn_credentials {
        username: view(&credentials.username),
        password: view(&credentials.password),
        http_proxy_username: view(&credentials.http_proxy_username),
        http_proxy_password: view(&credentials.http_proxy_password),
        response: view(&credentials.response),
        dynamic_challenge_cookie: view(&credentials.dynamic_challenge_cookie),
    };
    // SAFETY: every borrowed string lives through this synchronous call.
    let raw =
        unsafe { sys::ovpn_client_provide_creds(client.as_ptr(), &raw const raw_credentials) };
    status_result(raw)
}

pub(crate) fn connect(client: NonNull<sys::ovpn_client>) -> Result<Status> {
    // SAFETY: lifecycle synchronization ensures one active `connect` call per native client.
    status_result(unsafe { sys::ovpn_client_connect(client.as_ptr()) })
}

#[cfg(feature = "tokio")]
pub(crate) fn connect_with_started<F>(
    client: NonNull<sys::ovpn_client>,
    started: F,
) -> Result<Status>
where
    F: FnOnce(),
{
    unsafe extern "C" fn started_callback<F: FnOnce()>(context: *mut c_void) {
        if context.is_null() {
            return;
        }
        // SAFETY: context points to the stack-local Option below and native
        // connect invokes this callback synchronously at most once.
        let started = unsafe { &mut *context.cast::<Option<F>>() };
        if let Some(started) = started.take() {
            let _ = catch_unwind(AssertUnwindSafe(started));
        }
    }

    let mut started = Some(started);
    // SAFETY: the callback context remains live until this blocking call
    // returns, and the adapter clears its stored pointer before returning.
    let raw = unsafe {
        sys::ovpn_client_connect_started(
            client.as_ptr(),
            (&raw mut started).cast::<c_void>(),
            Some(started_callback::<F>),
        )
    };
    status_result(raw)
}

pub(crate) fn callback_self_test(client: NonNull<sys::ovpn_client>) -> Result<Status> {
    // SAFETY: `client` is live and Core invokes callbacks synchronously.
    status_result(unsafe { sys::ovpn_client_callback_self_test(client.as_ptr()) })
}

pub(crate) fn start_cert_check(
    client: NonNull<sys::ovpn_client>,
    client_certificate: &str,
    client_key: &str,
    ca: Option<&str>,
) -> Result<Status> {
    let (ca, has_ca) = ca.map_or(("", false), |value| (value, true));
    // SAFETY: all borrowed string views live through this synchronous call.
    status_result(unsafe {
        sys::ovpn_client_start_cert_check(
            client.as_ptr(),
            view(client_certificate),
            view(client_key),
            view(ca),
            bool_i32(has_ca),
        )
    })
}

pub(crate) fn start_cert_check_epki(
    client: NonNull<sys::ovpn_client>,
    alias: &str,
    ca: Option<&str>,
) -> Result<Status> {
    let (ca, has_ca) = ca.map_or(("", false), |value| (value, true));
    // SAFETY: all borrowed string views live through this synchronous call.
    status_result(unsafe {
        sys::ovpn_client_start_cert_check_epki(
            client.as_ptr(),
            view(alias),
            view(ca),
            bool_i32(has_ca),
        )
    })
}

pub(crate) fn pause(client: NonNull<sys::ovpn_client>, reason: &str) {
    // SAFETY: the string view lives through the call; `pause` is concurrency-safe upstream.
    unsafe { sys::ovpn_client_pause(client.as_ptr(), view(reason)) }
}

pub(crate) fn resume(client: NonNull<sys::ovpn_client>) {
    // SAFETY: `resume` is documented for concurrent use with `connect`.
    unsafe { sys::ovpn_client_resume(client.as_ptr()) }
}

pub(crate) fn reconnect(client: NonNull<sys::ovpn_client>, seconds: i32) {
    // SAFETY: `reconnect` is documented for concurrent use with `connect`.
    unsafe { sys::ovpn_client_reconnect(client.as_ptr(), seconds) }
}

pub(crate) fn post_control_message(client: NonNull<sys::ovpn_client>, message: &str) {
    // SAFETY: the string view lives through this synchronous call.
    unsafe { sys::ovpn_client_post_cc_msg(client.as_ptr(), view(message)) }
}

pub(crate) fn send_app_control_message(
    client: NonNull<sys::ovpn_client>,
    protocol: &str,
    message: &str,
) {
    // SAFETY: both string views live through this synchronous call.
    unsafe {
        sys::ovpn_client_send_app_control_channel_msg(
            client.as_ptr(),
            view(protocol),
            view(message),
        );
    }
}

pub(crate) fn connection_info(client: NonNull<sys::ovpn_client>) -> Option<ConnectionInfo> {
    // SAFETY: the client is alive and the native call returns an owned aggregate.
    let raw = unsafe { sys::ovpn_client_connection_info(client.as_ptr()) };
    let result = (raw.defined != 0).then(|| ConnectionInfo {
        user: string_from_owned(&raw.user),
        server_host: string_from_owned(&raw.server_host),
        server_port: string_from_owned(&raw.server_port),
        server_proto: string_from_owned(&raw.server_proto),
        server_ip: string_from_owned(&raw.server_ip),
        vpn_ip4: string_from_owned(&raw.vpn_ip4),
        vpn_ip6: string_from_owned(&raw.vpn_ip6),
        vpn_mtu: string_from_owned(&raw.vpn_mtu),
        gateway_ip4: string_from_owned(&raw.gateway_ip4),
        gateway_ip6: string_from_owned(&raw.gateway_ip6),
        client_ip: string_from_owned(&raw.client_ip),
        tun_name: string_from_owned(&raw.tun_name),
    });
    // SAFETY: all fields have been copied and this aggregate is freed once.
    unsafe { sys::ovpn_connection_info_free(raw) };
    result
}

pub(crate) fn session_token(client: NonNull<sys::ovpn_client>) -> Option<SessionToken> {
    // SAFETY: the client is alive and the native call returns an owned aggregate.
    let raw = unsafe { sys::ovpn_client_session_token(client.as_ptr()) };
    let result = (raw.defined != 0).then(|| SessionToken {
        username: string_from_owned(&raw.username),
        session_id: string_from_owned(&raw.session_id),
    });
    // SAFETY: all fields have been copied and this aggregate is freed once.
    unsafe { sys::ovpn_session_token_free(raw) };
    result
}

pub(crate) fn statistics(client: NonNull<sys::ovpn_client>) -> Vec<Statistic> {
    // SAFETY: this static query has no preconditions.
    let count = unsafe { sys::ovpn_client_stats_count() }.max(0);
    // SAFETY: upstream documents the bundle query for concurrent use.
    let bundle = unsafe { sys::ovpn_client_stats_bundle(client.as_ptr()) };
    let values = if bundle.data.is_null() {
        &[][..]
    } else {
        // SAFETY: the returned allocation contains `len` initialized values.
        unsafe { slice::from_raw_parts(bundle.data, bundle.len) }
    };
    let result = (0..count)
        .zip(values.iter().copied())
        .map(|(index, value)| {
            // SAFETY: the index is in the range reported by OpenVPN Core.
            let name = take_owned(unsafe { sys::ovpn_client_stats_name(index) });
            Statistic { name, value }
        })
        .collect();
    // SAFETY: all values have been copied and the allocation is consumed once.
    unsafe { sys::ovpn_i64_array_free(bundle) };
    result
}

pub(crate) fn interface_stats(client: NonNull<sys::ovpn_client>) -> InterfaceStats {
    // SAFETY: upstream documents stats queries for concurrent use.
    let raw = unsafe { sys::ovpn_client_tun_stats(client.as_ptr()) };
    InterfaceStats {
        bytes_in: raw.bytes_in,
        packets_in: raw.packets_in,
        errors_in: raw.errors_in,
        bytes_out: raw.bytes_out,
        packets_out: raw.packets_out,
        errors_out: raw.errors_out,
    }
}

pub(crate) fn transport_stats(client: NonNull<sys::ovpn_client>) -> TransportStats {
    // SAFETY: upstream documents stats queries for concurrent use.
    let raw = unsafe { sys::ovpn_client_transport_stats(client.as_ptr()) };
    TransportStats {
        bytes_in: raw.bytes_in,
        bytes_out: raw.bytes_out,
        packets_in: raw.packets_in,
        packets_out: raw.packets_out,
        last_packet_received: raw.last_packet_received,
    }
}

pub(crate) fn platform() -> String {
    // SAFETY: static native query returns one owned string.
    take_owned(unsafe { sys::ovpn_platform() })
}

pub(crate) fn capabilities() -> Capabilities {
    // SAFETY: static native query has no preconditions and returns a POD value.
    let raw = unsafe { sys::ovpn_get_capabilities() };
    Capabilities {
        tun_builder: raw.tun_builder != 0,
        dco: raw.dco != 0,
        dco_tun_builder: raw.dco_tun_builder != 0,
        gremlin: raw.gremlin != 0,
        external_tun: raw.external_tun != 0,
        external_transport: raw.external_transport != 0,
        private_tunnel_proxy: raw.private_tunnel_proxy != 0,
    }
}

pub(crate) fn copyright() -> String {
    // SAFETY: static native query returns one owned string.
    take_owned(unsafe { sys::ovpn_copyright() })
}

pub(crate) fn max_profile_size() -> usize {
    // SAFETY: static native query has no preconditions.
    usize::try_from(unsafe { sys::ovpn_max_profile_size() }).unwrap_or_default()
}

pub(crate) fn crypto_self_test() -> String {
    // SAFETY: static native query returns one owned string.
    take_owned(unsafe { sys::ovpn_crypto_self_test() })
}

pub(crate) fn parse_dynamic_challenge(cookie: &str) -> Option<DynamicChallenge> {
    // SAFETY: `cookie` lives through the call and the result is an owned aggregate.
    let raw = unsafe { sys::ovpn_parse_dynamic_challenge(view(cookie)) };
    let result = (raw.defined != 0).then(|| DynamicChallenge {
        challenge: string_from_owned(&raw.challenge),
        echo: raw.echo != 0,
        response_required: raw.response_required != 0,
        state_id: string_from_owned(&raw.state_id),
    });
    // SAFETY: all fields have been copied and this aggregate is freed once.
    unsafe { sys::ovpn_dynamic_challenge_free(raw) };
    result
}

struct RawConfig<'a> {
    raw: sys::ovpn_config,
    _content_list: Vec<sys::ovpn_key_value_view>,
    _peer_info: Vec<sys::ovpn_key_value_view>,
    _lifetime: PhantomData<&'a Config>,
}

impl<'a> RawConfig<'a> {
    fn new(config: &'a Config) -> Self {
        let content_list: Vec<_> = config
            .content_list
            .iter()
            .map(|(key, value)| sys::ovpn_key_value_view {
                key: view(key),
                value: view(value),
            })
            .collect();
        let peer_info: Vec<_> = config
            .peer_info
            .iter()
            .map(|(key, value)| sys::ovpn_key_value_view {
                key: view(key),
                value: view(value),
            })
            .collect();
        let raw = sys::ovpn_config {
            content: view(&config.content),
            content_list: slice_pointer(&content_list),
            content_list_len: content_list.len(),
            peer_info: slice_pointer(&peer_info),
            peer_info_len: peer_info.len(),
            gui_version: view(&config.gui_version),
            sso_methods: view(&config.sso_methods),
            app_custom_protocols: view(&config.app_custom_protocols),
            hw_addr_override: view(&config.hw_addr_override),
            platform_version: view(&config.platform_version),
            server_override: view(&config.server_override),
            port_override: view(&config.port_override),
            proto_override: view(&config.proto_override),
            allow_unused_addr_families: view(&config.allow_unused_addr_families),
            compression_mode: view(&config.compression_mode),
            external_pki_alias: view(&config.external_pki_alias),
            private_key_password: view(&config.private_key_password),
            tls_version_min_override: view(&config.tls_version_min_override),
            tls_cert_profile_override: view(&config.tls_cert_profile_override),
            tls_cipher_list: view(&config.tls_cipher_list),
            tls_ciphersuites_list: view(&config.tls_ciphersuites_list),
            proxy_host: view(&config.proxy_host),
            proxy_port: view(&config.proxy_port),
            proxy_username: view(&config.proxy_username),
            proxy_password: view(&config.proxy_password),
            gremlin_config: view(&config.gremlin_config),
            conn_timeout: config.connection_timeout_seconds,
            ssl_debug_level: config.ssl_debug_level,
            default_key_direction: config.default_key_direction,
            proto_version_override: config.protocol_version_override,
            clock_tick_ms: config.clock_tick_ms,
            tun_persist: bool_i32(config.tun_persist),
            google_dns_fallback: bool_i32(config.google_dns_fallback),
            dhcp_search_domains_as_split_domains: bool_i32(
                config.dhcp_search_domains_as_split_domains,
            ),
            synchronous_dns_lookup: bool_i32(config.synchronous_dns_lookup),
            autologin_sessions: bool_i32(config.autologin_sessions),
            retry_on_auth_failed: bool_i32(config.retry_on_auth_failed),
            disable_client_cert: bool_i32(config.disable_client_cert),
            proxy_allow_cleartext_auth: bool_i32(config.proxy_allow_cleartext_auth),
            alt_proxy: bool_i32(config.alternative_proxy),
            dco: bool_i32(config.dco),
            echo: bool_i32(config.echo),
            info: bool_i32(config.info),
            allow_local_lan_access: bool_i32(config.allow_local_lan_access),
            enable_route_emulation: bool_i32(config.enable_route_emulation),
            wintun: bool_i32(config.wintun),
            allow_local_dns_resolvers: bool_i32(config.allow_local_dns_resolvers),
            enable_legacy_algorithms: bool_i32(config.enable_legacy_algorithms),
            enable_non_preferred_dc_algorithms: bool_i32(
                config.enable_non_preferred_data_channel_algorithms,
            ),
            generate_tun_builder_capture_event: bool_i32(config.generate_tun_builder_capture_event),
        };
        Self {
            raw,
            _content_list: content_list,
            _peer_info: peer_info,
            _lifetime: PhantomData,
        }
    }
}

fn slice_pointer<T>(values: &[T]) -> *const T {
    if values.is_empty() {
        ptr::null()
    } else {
        values.as_ptr()
    }
}

fn bool_i32(value: bool) -> i32 {
    i32::from(value)
}

fn view(value: &str) -> sys::ovpn_string_view {
    sys::ovpn_string_view {
        data: value.as_ptr(),
        len: value.len(),
    }
}

fn string_from_view(value: sys::ovpn_string_view) -> String {
    if value.data.is_null() || value.len == 0 {
        return String::new();
    }
    // SAFETY: callbacks receive a native view guaranteed valid for the callback duration.
    let bytes = unsafe { slice::from_raw_parts(value.data, value.len) };
    String::from_utf8_lossy(bytes).into_owned()
}

fn string_from_owned(value: &sys::ovpn_owned_string) -> String {
    if value.data.is_null() || value.len == 0 {
        return String::new();
    }
    // SAFETY: aggregate result fields point to readable allocations of the reported length.
    let bytes = unsafe { slice::from_raw_parts(value.data, value.len) };
    String::from_utf8_lossy(bytes).into_owned()
}

fn take_owned(value: sys::ovpn_owned_string) -> String {
    let result = string_from_owned(&value);
    // SAFETY: this top-level owned string is consumed exactly once.
    unsafe { sys::ovpn_owned_string_free(value) };
    result
}

fn status_error(raw: &sys::ovpn_status) -> Error {
    Error::Core {
        status: string_from_owned(&raw.status),
        message: string_from_owned(&raw.message),
    }
}

fn status_result(raw: sys::ovpn_status) -> Result<Status> {
    let result = if raw.error != 0 {
        Err(status_error(&raw))
    } else {
        Ok(Status {
            status: string_from_owned(&raw.status),
            message: string_from_owned(&raw.message),
        })
    };
    // SAFETY: all strings have been copied and this status is consumed once.
    unsafe { sys::ovpn_status_free(raw) };
    result
}

unsafe fn handler_from<'a>(context: *mut c_void) -> &'a dyn EventHandler {
    // SAFETY: context is created from `Box<CallbackState>` and retained by `Inner`.
    let state = unsafe { &*context.cast::<CallbackState>() };
    state.handler.as_ref()
}

unsafe extern "C" fn event_callback(
    context: *mut c_void,
    error: i32,
    fatal: i32,
    name: sys::ovpn_string_view,
    info: sys::ovpn_string_view,
) {
    if context.is_null() {
        return;
    }
    let event = Event {
        error: error != 0,
        fatal: fatal != 0,
        name: string_from_view(name),
        info: string_from_view(info),
    };
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| handler.event(event)));
}

unsafe extern "C" fn log_callback(context: *mut c_void, text: sys::ovpn_string_view) {
    if context.is_null() {
        return;
    }
    let text = string_from_view(text);
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| handler.log(&text)));
}

unsafe extern "C" fn app_control_callback(
    context: *mut c_void,
    protocol: sys::ovpn_string_view,
    payload: sys::ovpn_string_view,
) {
    if context.is_null() {
        return;
    }
    let message = AppControlMessage {
        protocol: string_from_view(protocol),
        payload: string_from_view(payload),
    };
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| handler.app_control_message(message)));
}

unsafe extern "C" fn socket_protect_callback(
    context: *mut c_void,
    socket: isize,
    remote: sys::ovpn_string_view,
    ipv6: i32,
) -> i32 {
    if context.is_null() {
        return 0;
    }
    let remote = string_from_view(remote);
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    catch_unwind(AssertUnwindSafe(|| {
        handler.socket_protect(socket, &remote, ipv6 != 0)
    }))
    .map_or(0, bool_i32)
}

unsafe extern "C" fn pause_on_timeout_callback(context: *mut c_void) -> i32 {
    if context.is_null() {
        return 0;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    catch_unwind(AssertUnwindSafe(|| handler.pause_on_connection_timeout())).map_or(0, bool_i32)
}

unsafe extern "C" fn clock_tick_callback(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| handler.clock_tick()));
}

unsafe extern "C" fn external_pki_certificate_callback(
    context: *mut c_void,
    alias: sys::ovpn_string_view,
    response_context: *mut c_void,
    complete: sys::ovpn_external_pki_cert_complete_fn,
) {
    let Some(complete) = complete else {
        return;
    };
    let result = if context.is_null() {
        Err(ExternalPkiError::new(
            "external PKI callback context is null",
        ))
    } else {
        let request = ExternalPkiCertificateRequest {
            alias: string_from_view(alias),
        };
        // SAFETY: non-null callback context is valid for the native client's lifetime.
        let handler = unsafe { handler_from(context) };
        catch_unwind(AssertUnwindSafe(|| {
            handler.external_pki_certificate(request)
        }))
        .unwrap_or_else(|_| Err(ExternalPkiError::new("external PKI callback panicked")))
    };

    match result {
        Ok(ExternalPkiCertificate {
            certificate,
            supporting_chain,
        }) => {
            // SAFETY: completion copies these borrowed views before returning.
            unsafe {
                complete(
                    response_context,
                    0,
                    0,
                    view(""),
                    view(&certificate),
                    view(&supporting_chain),
                );
            }
        }
        Err(error) => {
            // SAFETY: completion copies this borrowed view before returning.
            unsafe {
                complete(
                    response_context,
                    1,
                    bool_i32(error.invalid_alias),
                    view(&error.message),
                    view(""),
                    view(""),
                );
            }
        }
    }
}

unsafe extern "C" fn external_pki_sign_callback(
    context: *mut c_void,
    alias: sys::ovpn_string_view,
    data: sys::ovpn_string_view,
    algorithm: sys::ovpn_string_view,
    hash_algorithm: sys::ovpn_string_view,
    salt_length: sys::ovpn_string_view,
    response_context: *mut c_void,
    complete: sys::ovpn_external_pki_sign_complete_fn,
) {
    let Some(complete) = complete else {
        return;
    };
    let result = if context.is_null() {
        Err(ExternalPkiError::new(
            "external PKI callback context is null",
        ))
    } else {
        let request = ExternalPkiSignRequest {
            alias: string_from_view(alias),
            data: string_from_view(data),
            algorithm: string_from_view(algorithm),
            hash_algorithm: string_from_view(hash_algorithm),
            salt_length: string_from_view(salt_length),
        };
        // SAFETY: non-null callback context is valid for the native client's lifetime.
        let handler = unsafe { handler_from(context) };
        catch_unwind(AssertUnwindSafe(|| handler.external_pki_sign(request)))
            .unwrap_or_else(|_| Err(ExternalPkiError::new("external PKI callback panicked")))
    };

    match result {
        Ok(signature) => {
            // SAFETY: completion copies this borrowed view before returning.
            unsafe { complete(response_context, 0, 0, view(""), view(&signature)) };
        }
        Err(error) => {
            // SAFETY: completion copies this borrowed view before returning.
            unsafe {
                complete(
                    response_context,
                    1,
                    bool_i32(error.invalid_alias),
                    view(&error.message),
                    view(""),
                );
            }
        }
    }
}

unsafe extern "C" fn remote_override_enabled_callback(context: *mut c_void) -> i32 {
    if context.is_null() {
        return 0;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    catch_unwind(AssertUnwindSafe(|| handler.remote_override_enabled())).map_or(0, bool_i32)
}

unsafe extern "C" fn remote_override_callback(
    context: *mut c_void,
    response_context: *mut c_void,
    complete: sys::ovpn_remote_override_complete_fn,
) {
    let Some(complete) = complete else {
        return;
    };
    let result = if context.is_null() {
        Err("remote override callback context is null".to_owned())
    } else {
        // SAFETY: non-null callback context is valid for the native client's lifetime.
        let handler = unsafe { handler_from(context) };
        catch_unwind(AssertUnwindSafe(|| handler.remote_override()))
            .unwrap_or_else(|_| Err("remote override callback panicked".into()))
    };
    match result {
        Ok(RemoteOverride {
            host,
            ip,
            port,
            protocol,
        }) => {
            // SAFETY: native completion copies all views before returning.
            unsafe {
                complete(
                    response_context,
                    view(&host),
                    view(&ip),
                    view(&port),
                    view(&protocol),
                    view(""),
                );
            }
        }
        Err(error) => {
            // SAFETY: native completion copies the error before returning.
            unsafe {
                complete(
                    response_context,
                    view(""),
                    view(""),
                    view(""),
                    view(""),
                    view(&error),
                );
            }
        }
    }
}

unsafe fn call_tun<R: Copy>(
    context: *mut c_void,
    default: R,
    action: impl FnOnce(&dyn TunBuilder) -> R,
) -> R {
    if context.is_null() {
        return default;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    catch_unwind(AssertUnwindSafe(|| {
        handler.tun_builder().map_or(default, action)
    }))
    .unwrap_or(default)
}

unsafe fn call_tun_void(context: *mut c_void, action: impl FnOnce(&dyn TunBuilder)) {
    if context.is_null() {
        return;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(tun) = handler.tun_builder() {
            action(tun);
        }
    }));
}

unsafe fn call_external_transport<R: Clone>(
    context: *mut c_void,
    default: R,
    action: impl FnOnce(&dyn ExternalTransport) -> R,
) -> R {
    if context.is_null() {
        return default;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    catch_unwind(AssertUnwindSafe(|| {
        handler
            .external_transport()
            .map_or_else(|| default.clone(), action)
    }))
    .unwrap_or(default)
}

unsafe fn call_external_transport_void(
    context: *mut c_void,
    action: impl FnOnce(&dyn ExternalTransport),
) {
    if context.is_null() {
        return;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(transport) = handler.external_transport() {
            action(transport);
        }
    }));
}

unsafe extern "C" fn external_transport_configure_callback(
    context: *mut c_void,
    config: *const sys::ovpn_external_transport_config_view,
) -> i32 {
    if config.is_null() {
        return 0;
    }
    // SAFETY: C++ keeps this view alive for the callback duration.
    let config = unsafe { &*config };
    // SAFETY: C++ owns every remote view for this callback's duration.
    let remotes = unsafe { raw_view_slice(config.remotes, config.remotes_len) }
        .iter()
        .map(|remote| ExternalRemote {
            host: string_from_view(remote.host),
            port: string_from_view(remote.port),
            protocol: string_from_view(remote.protocol),
        })
        .collect();
    let config = ExternalTransportConfig {
        host: string_from_view(config.host),
        port: string_from_view(config.port),
        protocol: string_from_view(config.protocol),
        gremlin_config: string_from_view(config.gremlin_config),
        remotes,
        server_address_float: config.server_address_float != 0,
        synchronous_dns_lookup: config.synchronous_dns_lookup != 0,
    };
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    bool_i32(unsafe {
        call_external_transport(context, false, |transport| transport.configure(&config))
    })
}

unsafe extern "C" fn external_transport_start_callback(
    context: *mut c_void,
    handle: *mut sys::ovpn_external_transport_handle,
) {
    // SAFETY: C++ lends a live handle and `retain` acquires an owned reference.
    let Some(io) = (unsafe { ExternalTransportIo::retain(handle) }) else {
        return;
    };
    // SAFETY: forwarded callback context follows `call_external_transport_void`'s contract.
    unsafe { call_external_transport_void(context, |transport| transport.start(io)) };
}

unsafe extern "C" fn external_transport_stop_callback(context: *mut c_void) {
    // SAFETY: forwarded callback context follows `call_external_transport_void`'s contract.
    unsafe { call_external_transport_void(context, ExternalTransport::stop) };
}

unsafe extern "C" fn external_transport_send_callback(
    context: *mut c_void,
    data: *const u8,
    len: usize,
) -> i32 {
    // SAFETY: C++ keeps the packet valid for this callback.
    let packet = unsafe { raw_view_slice(data, len) };
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    bool_i32(unsafe { call_external_transport(context, false, |transport| transport.send(packet)) })
}

unsafe extern "C" fn external_transport_send_queue_empty_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    bool_i32(unsafe { call_external_transport(context, true, ExternalTransport::send_queue_empty) })
}

unsafe extern "C" fn external_transport_has_send_queue_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    bool_i32(unsafe { call_external_transport(context, false, ExternalTransport::has_send_queue) })
}

unsafe extern "C" fn external_transport_stop_requeueing_callback(context: *mut c_void) {
    // SAFETY: forwarded callback context follows `call_external_transport_void`'s contract.
    unsafe { call_external_transport_void(context, ExternalTransport::stop_requeueing) };
}

unsafe extern "C" fn external_transport_send_queue_size_callback(context: *mut c_void) -> usize {
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    unsafe { call_external_transport(context, 0, ExternalTransport::send_queue_size) }
}

unsafe extern "C" fn external_transport_reset_align_adjust_callback(
    context: *mut c_void,
    align_adjust: usize,
) {
    // SAFETY: forwarded callback context follows `call_external_transport_void`'s contract.
    unsafe {
        call_external_transport_void(context, |transport| {
            transport.reset_align_adjust(align_adjust);
        });
    }
}

unsafe extern "C" fn external_transport_endpoint_callback(
    context: *mut c_void,
    response_context: *mut c_void,
    complete: sys::ovpn_external_transport_endpoint_complete_fn,
) {
    let Some(complete) = complete else {
        return;
    };
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    let endpoint = unsafe {
        call_external_transport(
            context,
            ExternalTransportEndpoint::default(),
            ExternalTransport::endpoint,
        )
    };
    let raw = sys::ovpn_external_transport_endpoint_view {
        host: view(&endpoint.host),
        port: view(&endpoint.port),
        protocol: view(&endpoint.protocol),
        ip_address: view(&endpoint.ip_address),
    };
    // SAFETY: C++ copies every string view during this completion call.
    unsafe { complete(response_context, &raw const raw) };
}

unsafe extern "C" fn external_transport_native_handle_callback(context: *mut c_void) -> isize {
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    unsafe {
        call_external_transport(context, None, ExternalTransport::native_handle).unwrap_or(-1)
    }
}

unsafe extern "C" fn external_transport_is_relay_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_external_transport`'s contract.
    bool_i32(unsafe { call_external_transport(context, false, ExternalTransport::is_relay) })
}

unsafe extern "C" fn external_transport_process_push_callback(
    context: *mut c_void,
    options: sys::ovpn_string_view,
) {
    let options = string_from_view(options);
    // SAFETY: forwarded callback context follows `call_external_transport_void`'s contract.
    unsafe {
        call_external_transport_void(context, |transport| transport.process_push(&options));
    }
}

unsafe fn call_external_tun<R: Clone>(
    context: *mut c_void,
    default: R,
    action: impl FnOnce(&dyn ExternalTun) -> R,
) -> R {
    if context.is_null() {
        return default;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    catch_unwind(AssertUnwindSafe(|| {
        handler
            .external_tun()
            .map_or_else(|| default.clone(), action)
    }))
    .unwrap_or(default)
}

unsafe fn call_external_tun_void(context: *mut c_void, action: impl FnOnce(&dyn ExternalTun)) {
    if context.is_null() {
        return;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(tun) = handler.external_tun() {
            action(tun);
        }
    }));
}

unsafe extern "C" fn external_tun_configure_callback(
    context: *mut c_void,
    config: *const sys::ovpn_external_tun_config_view,
) -> i32 {
    if config.is_null() {
        return 0;
    }
    // SAFETY: C++ keeps this view alive for the callback duration.
    let config = unsafe { &*config };
    let config = ExternalTunConfig {
        session_name: string_from_view(config.session_name),
        layer: config.layer,
        mtu: config.mtu,
        mtu_max: config.mtu_max,
        google_dns_fallback: config.google_dns_fallback != 0,
        dhcp_search_domains_as_split_domains: config.dhcp_search_domains_as_split_domains != 0,
        allow_local_lan_access: config.allow_local_lan_access != 0,
        remote_bypass: config.remote_bypass != 0,
        tun_persist: config.tun_persist != 0,
    };
    // SAFETY: forwarded callback context follows `call_external_tun`'s contract.
    bool_i32(unsafe { call_external_tun(context, false, |tun| tun.configure(&config)) })
}

unsafe extern "C" fn external_tun_start_callback(
    context: *mut c_void,
    handle: *mut sys::ovpn_external_tun_handle,
    start: *const sys::ovpn_external_tun_start_view,
) {
    if start.is_null() {
        return;
    }
    // SAFETY: C++ lends a live handle and `retain` acquires an owned reference.
    let Some(io) = (unsafe { ExternalTunIo::retain(handle) }) else {
        return;
    };
    // SAFETY: C++ keeps this view alive for the callback duration.
    let start = unsafe { &*start };
    let config = ExternalTunStartConfig {
        options: string_from_view(start.options),
        cipher_algorithm: start.cipher_algorithm,
        digest_algorithm: start.digest_algorithm,
        key_derivation: start.key_derivation,
        use_epoch_keys: start.use_epoch_keys != 0,
    };
    // SAFETY: forwarded callback context follows `call_external_tun_void`'s contract.
    unsafe { call_external_tun_void(context, |tun| tun.start(&config, io)) };
}

unsafe extern "C" fn external_tun_stop_callback(context: *mut c_void) {
    // SAFETY: forwarded callback context follows `call_external_tun_void`'s contract.
    unsafe { call_external_tun_void(context, ExternalTun::stop) };
}

unsafe extern "C" fn external_tun_set_disconnect_callback(context: *mut c_void) {
    // SAFETY: forwarded callback context follows `call_external_tun_void`'s contract.
    unsafe { call_external_tun_void(context, ExternalTun::set_disconnect) };
}

unsafe extern "C" fn external_tun_send_callback(
    context: *mut c_void,
    data: *const u8,
    len: usize,
) -> i32 {
    // SAFETY: C++ keeps the packet valid for this callback.
    let packet = unsafe { raw_view_slice(data, len) };
    // SAFETY: forwarded callback context follows `call_external_tun`'s contract.
    bool_i32(unsafe { call_external_tun(context, false, |tun| tun.send(packet)) })
}

unsafe extern "C" fn external_tun_info_callback(
    context: *mut c_void,
    response_context: *mut c_void,
    complete: sys::ovpn_external_tun_info_complete_fn,
) {
    let Some(complete) = complete else {
        return;
    };
    // SAFETY: forwarded callback context follows `call_external_tun`'s contract.
    let info = unsafe { call_external_tun(context, ExternalTunInfo::default(), ExternalTun::info) };
    let raw = sys::ovpn_external_tun_info_view {
        name: view(&info.name),
        vpn_ipv4: view(&info.vpn_ipv4),
        vpn_ipv6: view(&info.vpn_ipv6),
        gateway_ipv4: view(&info.gateway_ipv4),
        gateway_ipv6: view(&info.gateway_ipv6),
        mtu: info.mtu,
        interface_index: info.interface_index.unwrap_or(u32::MAX),
    };
    // SAFETY: C++ copies every string view during this completion call.
    unsafe { complete(response_context, &raw const raw) };
}

unsafe extern "C" fn external_tun_adjust_mss_callback(context: *mut c_void, mss: i32) {
    // SAFETY: forwarded callback context follows `call_external_tun_void`'s contract.
    unsafe { call_external_tun_void(context, |tun| tun.adjust_mss(mss)) };
}

unsafe extern "C" fn external_tun_apply_push_update_callback(
    context: *mut c_void,
    options: sys::ovpn_string_view,
) {
    let options = string_from_view(options);
    // SAFETY: forwarded callback context follows `call_external_tun_void`'s contract.
    unsafe { call_external_tun_void(context, |tun| tun.apply_push_update(&options)) };
}

unsafe extern "C" fn external_tun_layer_2_supported_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_external_tun`'s contract.
    bool_i32(unsafe { call_external_tun(context, false, ExternalTun::layer_2_supported) })
}

unsafe extern "C" fn external_tun_supports_epoch_data_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_external_tun`'s contract.
    bool_i32(unsafe { call_external_tun(context, false, ExternalTun::supports_epoch_data) })
}

unsafe extern "C" fn external_tun_finalize_callback(context: *mut c_void, disconnected: i32) {
    // SAFETY: forwarded callback context follows `call_external_tun_void`'s contract.
    unsafe { call_external_tun_void(context, |tun| tun.finalize(disconnected != 0)) };
}

unsafe extern "C" fn tun_builder_new_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, TunBuilder::new_tunnel) })
}

unsafe extern "C" fn tun_builder_set_layer_callback(context: *mut c_void, layer: i32) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, true, |tun| tun.set_layer(layer)) })
}

unsafe extern "C" fn tun_builder_set_remote_address_callback(
    context: *mut c_void,
    address: sys::ovpn_string_view,
    ipv6: i32,
) -> i32 {
    let address = string_from_view(address);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe {
        call_tun(context, false, |tun| {
            tun.set_remote_address(&address, ipv6 != 0)
        })
    })
}

unsafe extern "C" fn tun_builder_add_address_callback(
    context: *mut c_void,
    address: sys::ovpn_string_view,
    prefix_length: i32,
    gateway: sys::ovpn_string_view,
    ipv6: i32,
    net30: i32,
) -> i32 {
    let address = string_from_view(address);
    let gateway = string_from_view(gateway);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe {
        call_tun(context, false, |tun| {
            tun.add_address(&address, prefix_length, &gateway, ipv6 != 0, net30 != 0)
        })
    })
}

unsafe extern "C" fn tun_builder_set_route_metric_default_callback(
    context: *mut c_void,
    metric: i32,
) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, true, |tun| tun.set_route_metric_default(metric)) })
}

unsafe extern "C" fn tun_builder_reroute_gw_callback(
    context: *mut c_void,
    ipv4: i32,
    ipv6: i32,
    flags: u32,
) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe {
        call_tun(context, false, |tun| {
            tun.reroute_gateway(ipv4 != 0, ipv6 != 0, flags)
        })
    })
}

unsafe extern "C" fn tun_builder_add_route_callback(
    context: *mut c_void,
    address: sys::ovpn_string_view,
    prefix_length: i32,
    metric: i32,
    ipv6: i32,
) -> i32 {
    let address = string_from_view(address);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe {
        call_tun(context, false, |tun| {
            tun.add_route(&address, prefix_length, metric, ipv6 != 0)
        })
    })
}

unsafe extern "C" fn tun_builder_exclude_route_callback(
    context: *mut c_void,
    address: sys::ovpn_string_view,
    prefix_length: i32,
    metric: i32,
    ipv6: i32,
) -> i32 {
    let address = string_from_view(address);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe {
        call_tun(context, false, |tun| {
            tun.exclude_route(&address, prefix_length, metric, ipv6 != 0)
        })
    })
}

unsafe extern "C" fn tun_builder_set_dns_options_callback(
    context: *mut c_void,
    dns: *const sys::ovpn_dns_options_view,
) -> i32 {
    if dns.is_null() {
        return 0;
    }
    // SAFETY: C++ provides a valid view for this callback's duration.
    let raw = unsafe { &*dns };
    // SAFETY: every nested view is owned by `dns` for the callback duration.
    let search_domains = unsafe { raw_view_slice(raw.search_domains, raw.search_domains_len) }
        .iter()
        .copied()
        .map(string_from_view)
        .collect();
    // SAFETY: every nested view is owned by `dns` for the callback duration.
    let servers = unsafe { raw_view_slice(raw.servers, raw.servers_len) }
        .iter()
        .map(|server| DnsServer {
            priority: server.priority,
            // SAFETY: server members remain alive for the callback duration.
            addresses: unsafe { raw_view_slice(server.addresses, server.addresses_len) }
                .iter()
                .map(|address| DnsAddress {
                    address: string_from_view(address.address),
                    port: address.port,
                })
                .collect(),
            // SAFETY: server members remain alive for the callback duration.
            resolve_domains: unsafe { raw_view_slice(server.domains, server.domains_len) }
                .iter()
                .copied()
                .map(string_from_view)
                .collect(),
            security: match server.dnssec {
                1 => DnsSecurity::No,
                2 => DnsSecurity::Yes,
                3 => DnsSecurity::Optional,
                _ => DnsSecurity::Unset,
            },
            transport: match server.transport {
                1 => DnsTransport::Plain,
                2 => DnsTransport::Https,
                3 => DnsTransport::Tls,
                _ => DnsTransport::Unset,
            },
            sni: string_from_view(server.sni),
        })
        .collect();
    let dns = DnsOptions {
        from_dhcp_options: raw.from_dhcp_options != 0,
        search_domains,
        servers,
    };
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.set_dns_options(&dns)) })
}

unsafe fn raw_view_slice<'a, T>(data: *const T, len: usize) -> &'a [T] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: this helper is used only with native callback views valid for `len` elements.
        unsafe { slice::from_raw_parts(data, len) }
    }
}

unsafe extern "C" fn tun_builder_set_mtu_callback(context: *mut c_void, mtu: i32) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.set_mtu(mtu)) })
}

unsafe extern "C" fn tun_builder_set_session_name_callback(
    context: *mut c_void,
    name: sys::ovpn_string_view,
) -> i32 {
    let name = string_from_view(name);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.set_session_name(&name)) })
}

unsafe extern "C" fn tun_builder_add_proxy_bypass_callback(
    context: *mut c_void,
    host: sys::ovpn_string_view,
) -> i32 {
    let host = string_from_view(host);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.add_proxy_bypass(&host)) })
}

unsafe extern "C" fn tun_builder_set_proxy_auto_config_url_callback(
    context: *mut c_void,
    url: sys::ovpn_string_view,
) -> i32 {
    let url = string_from_view(url);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.set_proxy_auto_config_url(&url)) })
}

unsafe extern "C" fn tun_builder_set_proxy_http_callback(
    context: *mut c_void,
    host: sys::ovpn_string_view,
    port: i32,
) -> i32 {
    let host = string_from_view(host);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.set_proxy_http(&host, port)) })
}

unsafe extern "C" fn tun_builder_set_proxy_https_callback(
    context: *mut c_void,
    host: sys::ovpn_string_view,
    port: i32,
) -> i32 {
    let host = string_from_view(host);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.set_proxy_https(&host, port)) })
}

unsafe extern "C" fn tun_builder_add_wins_server_callback(
    context: *mut c_void,
    address: sys::ovpn_string_view,
) -> i32 {
    let address = string_from_view(address);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, |tun| tun.add_wins_server(&address)) })
}

unsafe extern "C" fn tun_builder_set_allow_family_callback(
    context: *mut c_void,
    address_family: i32,
    allow: i32,
) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe {
        call_tun(context, true, |tun| {
            tun.set_allow_family(address_family, allow != 0)
        })
    })
}

unsafe extern "C" fn tun_builder_set_allow_local_dns_callback(
    context: *mut c_void,
    allow: i32,
) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, true, |tun| tun.set_allow_local_dns(allow != 0)) })
}

unsafe extern "C" fn tun_builder_establish_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    unsafe { call_tun(context, -1, TunBuilder::establish) }
}

unsafe extern "C" fn tun_builder_persist_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, true, TunBuilder::persist) })
}

unsafe extern "C" fn tun_builder_get_local_networks_callback(
    context: *mut c_void,
    ipv6: i32,
    response_context: *mut c_void,
    complete: sys::ovpn_tun_builder_local_networks_complete_fn,
) {
    let Some(complete) = complete else {
        return;
    };
    let networks = if context.is_null() {
        Vec::new()
    } else {
        // SAFETY: non-null callback context is valid for the native client's lifetime.
        let handler = unsafe { handler_from(context) };
        catch_unwind(AssertUnwindSafe(|| {
            handler
                .tun_builder()
                .map_or_else(Vec::new, |tun| tun.local_networks(ipv6 != 0))
        }))
        .unwrap_or_default()
    };
    let views: Vec<_> = networks.iter().map(|network| view(network)).collect();
    // SAFETY: native completion copies all views before returning.
    unsafe { complete(response_context, slice_pointer(&views), views.len()) };
}

unsafe extern "C" fn tun_builder_establish_lite_callback(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(tun) = handler.tun_builder() {
            tun.establish_lite();
        }
    }));
}

unsafe extern "C" fn tun_builder_teardown_callback(context: *mut c_void, disconnect: i32) {
    if context.is_null() {
        return;
    }
    // SAFETY: non-null callback context is valid for the native client's lifetime.
    let handler = unsafe { handler_from(context) };
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(tun) = handler.tun_builder() {
            tun.teardown(disconnect != 0);
        }
    }));
}

unsafe extern "C" fn tun_builder_dco_available_callback(context: *mut c_void) -> i32 {
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    bool_i32(unsafe { call_tun(context, false, TunBuilder::dco_available) })
}

unsafe extern "C" fn tun_builder_dco_enable_callback(
    context: *mut c_void,
    device_name: sys::ovpn_string_view,
) -> i32 {
    let device_name = string_from_view(device_name);
    // SAFETY: forwarded callback context follows `call_tun`'s contract.
    unsafe { call_tun(context, -1, |tun| tun.dco_enable(&device_name)) }
}

unsafe extern "C" fn tun_builder_dco_new_peer_callback(
    context: *mut c_void,
    peer: *const sys::ovpn_dco_peer_view,
) {
    if peer.is_null() {
        return;
    }
    // SAFETY: C++ provides a valid peer view for this callback's duration.
    let peer = unsafe { &*peer };
    let peer = DcoPeer {
        peer_id: peer.peer_id,
        transport_fd: peer.transport_fd,
        remote_ip: string_from_view(peer.remote_ip),
        remote_port: peer.remote_port,
        vpn_ipv4: string_from_view(peer.vpn_ipv4),
        vpn_ipv6: string_from_view(peer.vpn_ipv6),
    };
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe { call_tun_void(context, |tun| tun.dco_new_peer(peer)) };
}

unsafe extern "C" fn tun_builder_dco_set_peer_callback(
    context: *mut c_void,
    peer_id: u32,
    keepalive_interval: i32,
    keepalive_timeout: i32,
) {
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe {
        call_tun_void(context, |tun| {
            tun.dco_set_peer(peer_id, keepalive_interval, keepalive_timeout);
        });
    }
}

unsafe extern "C" fn tun_builder_dco_del_peer_callback(context: *mut c_void, peer_id: u32) {
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe { call_tun_void(context, |tun| tun.dco_delete_peer(peer_id)) };
}

unsafe extern "C" fn tun_builder_dco_get_peer_callback(
    context: *mut c_void,
    peer_id: u32,
    synchronous: i32,
) {
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe {
        call_tun_void(context, |tun| {
            tun.dco_get_peer(peer_id, synchronous != 0);
        });
    }
}

unsafe extern "C" fn tun_builder_dco_new_key_callback(
    context: *mut c_void,
    key_slot: u32,
    key: *const sys::ovpn_dco_key_config_view,
) {
    if key.is_null() {
        return;
    }
    // SAFETY: C++ provides a valid key view for this callback's duration.
    let key = unsafe { &*key };
    let key = DcoKeyConfig {
        // SAFETY: both directions remain valid for this callback's duration.
        encrypt: unsafe { dco_key_direction(&key.encrypt) },
        // SAFETY: both directions remain valid for this callback's duration.
        decrypt: unsafe { dco_key_direction(&key.decrypt) },
        key_id: key.key_id,
        remote_peer_id: key.remote_peer_id,
        cipher_algorithm: key.cipher_algorithm,
    };
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe { call_tun_void(context, |tun| tun.dco_new_key(key_slot, key)) };
}

unsafe fn dco_key_direction(direction: &sys::ovpn_dco_key_direction_view) -> DcoKeyDirection {
    // SAFETY: the native callback guarantees both views for their reported lengths.
    let cipher_key = unsafe { raw_view_slice(direction.cipher_key, direction.cipher_key_len) };
    // SAFETY: the native callback guarantees both views for their reported lengths.
    let native_nonce = unsafe { raw_view_slice(direction.nonce_tail, direction.nonce_tail_len) };
    let mut nonce_tail = [0; 8];
    let copied = native_nonce.len().min(nonce_tail.len());
    nonce_tail[..copied].copy_from_slice(&native_nonce[..copied]);
    DcoKeyDirection {
        cipher_key: cipher_key.to_vec(),
        nonce_tail,
    }
}

unsafe extern "C" fn tun_builder_dco_swap_keys_callback(context: *mut c_void, peer_id: u32) {
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe { call_tun_void(context, |tun| tun.dco_swap_keys(peer_id)) };
}

unsafe extern "C" fn tun_builder_dco_del_key_callback(
    context: *mut c_void,
    peer_id: u32,
    key_slot: u32,
) {
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe { call_tun_void(context, |tun| tun.dco_delete_key(peer_id, key_slot)) };
}

unsafe extern "C" fn tun_builder_dco_establish_callback(context: *mut c_void) {
    // SAFETY: forwarded callback context follows `call_tun_void`'s contract.
    unsafe { call_tun_void(context, TunBuilder::dco_establish) };
}
