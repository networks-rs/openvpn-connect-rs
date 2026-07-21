//! A compile-checked inventory of every setting exposed by `OpenVPN` Core's
//! `ClientAPI::Config` and `ClientAPI::ConfigCommon`.

use openvpn_connect::Config;

fn main() {
    let config = Config {
        content: "client\ndev tun\nremote vpn.example.test 1194\n".into(),
        content_list: vec![("verb".into(), "3".into())],
        peer_info: vec![("IV_APP_VER".into(), "1.0".into())],
        gui_version: "example 1.0".into(),
        sso_methods: "webauth,crtext".into(),
        app_custom_protocols: "example-protocol".into(),
        hw_addr_override: String::new(),
        platform_version: String::new(),
        server_override: String::new(),
        port_override: String::new(),
        proto_override: "adaptive".into(),
        allow_unused_addr_families: "default".into(),
        compression_mode: "no".into(),
        external_pki_alias: String::new(),
        private_key_password: String::new(),
        tls_version_min_override: "tls_1_2".into(),
        tls_cert_profile_override: "preferred".into(),
        tls_cipher_list: String::new(),
        tls_ciphersuites_list: String::new(),
        proxy_host: String::new(),
        proxy_port: String::new(),
        proxy_username: String::new(),
        proxy_password: String::new(),
        alternative_proxy: false,
        gremlin_config: String::new(),
        connection_timeout_seconds: 30,
        ssl_debug_level: 0,
        default_key_direction: -1,
        protocol_version_override: 0,
        clock_tick_ms: 1_000,
        tun_persist: true,
        google_dns_fallback: false,
        dhcp_search_domains_as_split_domains: true,
        synchronous_dns_lookup: false,
        autologin_sessions: true,
        retry_on_auth_failed: true,
        disable_client_cert: false,
        proxy_allow_cleartext_auth: false,
        dco: openvpn_connect::capabilities().dco,
        echo: true,
        info: true,
        allow_local_lan_access: false,
        enable_route_emulation: true,
        wintun: false,
        allow_local_dns_resolvers: false,
        enable_legacy_algorithms: false,
        enable_non_preferred_data_channel_algorithms: false,
        generate_tun_builder_capture_event: false,
    };

    println!("configured {} profile bytes", config.content.len());
}
