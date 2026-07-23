use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use openvpn_connect::{
    AppControlMessage, Client, DnsOptions, Event, EventHandler, ExternalPkiCertificate,
    ExternalPkiCertificateRequest, ExternalPkiError, ExternalPkiSignRequest, RemoteOverride,
    TunBuilder,
};

#[derive(Default)]
struct ProbeState {
    calls: AtomicUsize,
    failures: Mutex<Vec<String>>,
}

struct Recorder(Arc<ProbeState>);

impl Recorder {
    fn hit(&self) {
        self.0.calls.fetch_add(1, Ordering::Relaxed);
    }

    fn check(&self, condition: bool, message: &str) {
        if !condition {
            self.0
                .failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(message.to_owned());
        }
    }
}

impl TunBuilder for Recorder {
    fn new_tunnel(&self) -> bool {
        self.hit();
        true
    }
    fn set_layer(&self, layer: i32) -> bool {
        self.hit();
        self.check(layer == 3, "TUN layer was lost");
        true
    }
    fn set_remote_address(&self, address: &str, ipv6: bool) -> bool {
        self.hit();
        self.check(
            address == "192.0.2.1" && !ipv6,
            "TUN remote address was lost",
        );
        true
    }
    fn add_address(
        &self,
        address: &str,
        prefix_length: i32,
        gateway: &str,
        ipv6: bool,
        net30: bool,
    ) -> bool {
        self.hit();
        self.check(
            address == "10.8.0.2"
                && prefix_length == 24
                && gateway == "10.8.0.1"
                && !ipv6
                && !net30,
            "TUN address was lost",
        );
        true
    }
    fn set_route_metric_default(&self, metric: i32) -> bool {
        self.hit();
        self.check(metric == 100, "default route metric was lost");
        true
    }
    fn reroute_gateway(&self, ipv4: bool, ipv6: bool, flags: u32) -> bool {
        self.hit();
        self.check(
            ipv4 && !ipv6 && flags == 0,
            "reroute-gateway values were lost",
        );
        true
    }
    fn add_route(&self, address: &str, prefix_length: i32, metric: i32, ipv6: bool) -> bool {
        self.hit();
        self.check(
            address == "10.9.0.0" && prefix_length == 24 && metric == 100 && !ipv6,
            "included route was lost",
        );
        true
    }
    fn exclude_route(&self, address: &str, prefix_length: i32, metric: i32, ipv6: bool) -> bool {
        self.hit();
        self.check(
            address == "192.168.0.0" && prefix_length == 16 && metric == 100 && !ipv6,
            "excluded route was lost",
        );
        true
    }
    fn set_dns_options(&self, dns: &DnsOptions) -> bool {
        self.hit();
        self.check(dns.from_dhcp_options, "DNS DHCP source flag was lost");
        self.check(
            dns.search_domains == ["search.example.test"],
            "DNS search domains were not marshalled",
        );
        self.check(dns.servers.len() == 1, "DNS server list was not marshalled");
        if let Some(server) = dns.servers.first() {
            self.check(server.priority == -42, "DNS priority was lost");
            self.check(
                server.addresses.len() == 1
                    && server.addresses[0].address == "192.0.2.53"
                    && server.addresses[0].port == 5353,
                "DNS address or port was lost",
            );
            self.check(
                server.resolve_domains == ["split.example.test"],
                "DNS resolve domains were lost",
            );
            self.check(
                server.security == openvpn_connect::DnsSecurity::Optional,
                "DNSSEC setting was lost",
            );
            self.check(
                server.transport == openvpn_connect::DnsTransport::Tls,
                "DNS transport was lost",
            );
            self.check(server.sni == "resolver.example.test", "DNS SNI was lost");
        }
        true
    }
    fn set_mtu(&self, mtu: i32) -> bool {
        self.hit();
        self.check(mtu == 1500, "TUN MTU was lost");
        true
    }
    fn set_session_name(&self, name: &str) -> bool {
        self.hit();
        self.check(name == "self-test", "TUN session name was lost");
        true
    }
    fn add_proxy_bypass(&self, host: &str) -> bool {
        self.hit();
        self.check(host == "localhost", "proxy bypass host was lost");
        true
    }
    fn set_proxy_auto_config_url(&self, url: &str) -> bool {
        self.hit();
        self.check(
            url == "https://example.test/proxy.pac",
            "proxy auto-config URL was lost",
        );
        true
    }
    fn set_proxy_http(&self, host: &str, port: i32) -> bool {
        self.hit();
        self.check(
            host == "127.0.0.1" && port == 8080,
            "HTTP proxy values were lost",
        );
        true
    }
    fn set_proxy_https(&self, host: &str, port: i32) -> bool {
        self.hit();
        self.check(
            host == "127.0.0.1" && port == 8443,
            "HTTPS proxy values were lost",
        );
        true
    }
    fn add_wins_server(&self, address: &str) -> bool {
        self.hit();
        self.check(address == "192.0.2.53", "WINS server was lost");
        true
    }
    fn set_allow_family(&self, address_family: i32, allow: bool) -> bool {
        self.hit();
        self.check(
            address_family == 2 && allow,
            "allowed address family was lost",
        );
        true
    }
    fn set_allow_local_dns(&self, allow: bool) -> bool {
        self.hit();
        self.check(allow, "local DNS flag was lost");
        true
    }
    fn establish(&self) -> i32 {
        self.hit();
        -1
    }
    fn persist(&self) -> bool {
        self.hit();
        true
    }
    fn local_networks(&self, ipv6: bool) -> Vec<String> {
        self.hit();
        self.check(!ipv6, "local-network address family was lost");
        vec!["192.168.0.0/16".into()]
    }
    fn establish_lite(&self) {
        self.hit();
    }
    fn teardown(&self, disconnect: bool) {
        self.hit();
        self.check(disconnect, "TUN teardown flag was lost");
    }

    fn dco_available(&self) -> bool {
        self.hit();
        true
    }

    fn dco_enable(&self, device_name: &str) -> i32 {
        self.hit();
        self.check(device_name == "ovpn-self-test", "DCO device name was lost");
        -1
    }

    fn dco_new_peer(&self, peer: openvpn_connect::DcoPeer) {
        self.hit();
        self.check(
            peer.peer_id == 1
                && peer.transport_fd == 0
                && peer.remote_ip == "192.0.2.1"
                && peer.remote_port == 1194
                && peer.vpn_ipv4 == "10.8.0.2",
            "DCO peer was not marshalled",
        );
    }

    fn dco_set_peer(&self, peer_id: u32, interval: i32, timeout: i32) {
        self.hit();
        self.check(
            (peer_id, interval, timeout) == (1, 10, 60),
            "DCO keepalive values were lost",
        );
    }

    fn dco_delete_peer(&self, peer_id: u32) {
        self.hit();
        self.check(peer_id == 1, "DCO delete-peer id was lost");
    }

    fn dco_get_peer(&self, peer_id: u32, synchronous: bool) {
        self.hit();
        self.check(peer_id == 1 && synchronous, "DCO get-peer values were lost");
    }

    fn dco_new_key(&self, key_slot: u32, key: openvpn_connect::DcoKeyConfig) {
        self.hit();
        self.check(
            key_slot == 0
                && key.key_id == 7
                && key.remote_peer_id == 1
                && key.cipher_algorithm == 99
                && key.encrypt.cipher_key == (0_u8..16).collect::<Vec<_>>()
                && key.decrypt.cipher_key == (0_u8..16).rev().collect::<Vec<_>>()
                && key.encrypt.nonce_tail == [16, 17, 18, 19, 20, 21, 22, 23]
                && key.decrypt.nonce_tail == [32, 33, 34, 35, 36, 37, 38, 39],
            "DCO key material was not marshalled",
        );
    }

    fn dco_swap_keys(&self, peer_id: u32) {
        self.hit();
        self.check(peer_id == 1, "DCO swap-key peer id was lost");
    }

    fn dco_delete_key(&self, peer_id: u32, key_slot: u32) {
        self.hit();
        self.check(
            (peer_id, key_slot) == (1, 0),
            "DCO delete-key values were lost",
        );
    }

    fn dco_establish(&self) {
        self.hit();
    }
}

impl EventHandler for Recorder {
    fn event(&self, event: Event) {
        self.hit();
        self.check(
            !event.error
                && !event.fatal
                && event.name == "SELF_TEST"
                && event.info == "callback adapter self-test",
            "event fields were not marshalled",
        );
    }
    fn log(&self, text: &str) {
        self.hit();
        self.check(text == "callback adapter self-test\n", "log text was lost");
    }
    fn app_control_message(&self, message: AppControlMessage) {
        self.hit();
        self.check(
            message.protocol == "self-test" && message.payload == "payload",
            "app-control message was not marshalled",
        );
    }
    fn socket_protect(&self, socket: isize, remote: &str, ipv6: bool) -> bool {
        self.hit();
        self.check(
            socket == -1 && remote == "192.0.2.1" && !ipv6,
            "socket-protect values were lost",
        );
        true
    }
    fn pause_on_connection_timeout(&self) -> bool {
        self.hit();
        false
    }
    fn clock_tick(&self) {
        self.hit();
    }
    fn remote_override_enabled(&self) -> bool {
        self.hit();
        true
    }
    fn remote_override(&self) -> Result<RemoteOverride, String> {
        self.hit();
        Ok(RemoteOverride {
            host: "override.example.test".into(),
            ip: "192.0.2.200".into(),
            port: "443".into(),
            protocol: "TCP".into(),
        })
    }
    fn tun_builder(&self) -> Option<&dyn TunBuilder> {
        Some(self)
    }
    fn external_pki_certificate(
        &self,
        request: ExternalPkiCertificateRequest,
    ) -> Result<ExternalPkiCertificate, ExternalPkiError> {
        self.hit();
        self.check(request.alias == "self-test", "external PKI alias was lost");
        Ok(ExternalPkiCertificate {
            certificate: "self-test-certificate".into(),
            supporting_chain: "self-test-supporting-chain".into(),
        })
    }
    fn external_pki_sign(
        &self,
        request: ExternalPkiSignRequest,
    ) -> Result<String, ExternalPkiError> {
        self.hit();
        self.check(
            request.alias == "self-test"
                && request.data == "c2VsZi10ZXN0"
                && request.algorithm == "RSA_PKCS1_PADDING"
                && request.hash_algorithm == "SHA256"
                && request.salt_length == "32",
            "external PKI signing request was not marshalled",
        );
        Ok("c2lnbmF0dXJl".into())
    }

    #[cfg(feature = "external-transport")]
    fn external_transport(&self) -> Option<&dyn openvpn_connect::ExternalTransport> {
        Some(self)
    }

    #[cfg(feature = "external-tun")]
    fn external_tun(&self) -> Option<&dyn openvpn_connect::ExternalTun> {
        Some(self)
    }
}

#[cfg(feature = "external-transport")]
impl openvpn_connect::ExternalTransport for Recorder {
    fn configure(&self, config: &openvpn_connect::ExternalTransportConfig) -> bool {
        self.hit();
        self.check(
            config.host == "vpn.example.test"
                && config.port == "1194"
                && config.protocol == "UDP"
                && config.gremlin_config == "delay=1"
                && config.server_address_float
                && config.synchronous_dns_lookup
                && config.remotes.len() == 2
                && config.remotes[1].host == "backup.example.test"
                && config.remotes[1].port == "443"
                && config.remotes[1].protocol == "TCP",
            "external transport configuration was not marshalled",
        );
        true
    }

    fn start(&self, io: openvpn_connect::ExternalTransportIo) {
        self.hit();
        let retained = io.clone();
        self.check(
            retained.receive(&[1, 2, 3, 4]).is_ok(),
            "transport receive failed",
        );
        self.check(io.needs_send().is_ok(), "transport needs-send failed");
        self.check(io.error("self-test").is_ok(), "transport error failed");
        self.check(
            io.error_with_code(1, "self-test-code").is_ok(),
            "coded transport error failed",
        );
        self.check(io.proxy_error("self-test").is_ok(), "proxy error failed");
        self.check(
            io.proxy_error_with_code(1, "self-test-code").is_ok(),
            "coded proxy error failed",
        );
        self.check(io.pre_resolve().is_ok(), "transport pre-resolve failed");
        self.check(io.wait_proxy().is_ok(), "transport wait-proxy failed");
        self.check(io.wait().is_ok(), "transport wait failed");
        self.check(io.connecting().is_ok(), "transport connecting failed");
        self.check(io.is_openvpn_protocol(), "transport protocol query failed");
        self.check(
            io.is_keepalive_enabled(),
            "transport keepalive query failed",
        );
        self.check(
            io.disable_keepalive() == Ok((17, 43)),
            "transport keepalive disable values were lost",
        );
    }

    fn stop(&self) {
        self.hit();
    }

    fn send(&self, packet: &[u8]) -> bool {
        self.hit();
        self.check(packet == [1, 2, 3, 4], "external transport packet was lost");
        true
    }

    fn send_queue_empty(&self) -> bool {
        self.hit();
        true
    }
    fn has_send_queue(&self) -> bool {
        self.hit();
        false
    }

    fn stop_requeueing(&self) {
        self.hit();
    }

    fn send_queue_size(&self) -> usize {
        self.hit();
        0
    }

    fn reset_align_adjust(&self, align_adjust: usize) {
        self.hit();
        self.check(align_adjust == 32, "transport alignment was lost");
    }

    fn endpoint(&self) -> openvpn_connect::ExternalTransportEndpoint {
        self.hit();
        openvpn_connect::ExternalTransportEndpoint {
            host: "vpn.example.test".into(),
            port: "1194".into(),
            protocol: "UDP".into(),
            ip_address: "192.0.2.1".into(),
        }
    }

    fn native_handle(&self) -> Option<isize> {
        self.hit();
        Some(7)
    }

    fn is_relay(&self) -> bool {
        self.hit();
        false
    }

    fn process_push(&self, options: &str) {
        self.hit();
        self.check(
            options == "push-option self-test\n",
            "transport push options were lost",
        );
    }
}

#[cfg(feature = "external-tun")]
impl openvpn_connect::ExternalTun for Recorder {
    fn configure(&self, config: &openvpn_connect::ExternalTunConfig) -> bool {
        self.hit();
        self.check(
            config.session_name == "self-test"
                && config.layer == 3
                && config.mtu == 1500
                && config.mtu_max == 1600
                && !config.google_dns_fallback
                && config.dhcp_search_domains_as_split_domains
                && !config.allow_local_lan_access
                && !config.remote_bypass
                && !config.tun_persist,
            "external TUN configuration was not marshalled",
        );
        true
    }

    fn start(
        &self,
        config: &openvpn_connect::ExternalTunStartConfig,
        io: openvpn_connect::ExternalTunIo,
    ) {
        self.hit();
        self.check(
            config.options == "route 10.9.0.0 255.255.255.0\n"
                && config.cipher_algorithm == 11
                && config.digest_algorithm == 22
                && config.key_derivation == 33
                && config.use_epoch_keys,
            "external TUN start configuration was not marshalled",
        );
        let retained = io.clone();
        self.check(
            retained.receive(&[5, 6, 7, 8]).is_ok(),
            "TUN receive failed",
        );
        self.check(io.error("self-test").is_ok(), "TUN error failed");
        self.check(
            io.error_with_code(1, "self-test-code").is_ok(),
            "coded TUN error failed",
        );
        self.check(io.pre_tun_config().is_ok(), "TUN pre-config failed");
        self.check(io.pre_route_config().is_ok(), "TUN pre-route failed");
        self.check(io.connected().is_ok(), "TUN connected failed");
    }

    fn stop(&self) {
        self.hit();
    }

    fn set_disconnect(&self) {
        self.hit();
    }

    fn send(&self, packet: &[u8]) -> bool {
        self.hit();
        self.check(packet == [5, 6, 7, 8], "external TUN packet was lost");
        true
    }

    fn info(&self) -> openvpn_connect::ExternalTunInfo {
        self.hit();
        openvpn_connect::ExternalTunInfo {
            name: "self-test-tun".into(),
            vpn_ipv4: "10.8.0.2".into(),
            vpn_ipv6: "2001:db8::2".into(),
            gateway_ipv4: "10.8.0.1".into(),
            gateway_ipv6: "2001:db8::1".into(),
            mtu: 1500,
            interface_index: Some(9),
        }
    }

    fn adjust_mss(&self, mss: i32) {
        self.hit();
        self.check(mss == 1234, "external TUN MSS was lost");
    }

    fn apply_push_update(&self, options: &str) {
        self.hit();
        self.check(
            options == "dhcp-option DNS 192.0.2.53\n",
            "external TUN push update was lost",
        );
    }

    fn layer_2_supported(&self) -> bool {
        self.hit();
        false
    }
    fn supports_epoch_data(&self) -> bool {
        self.hit();
        false
    }

    fn finalize(&self, disconnected: bool) {
        self.hit();
        self.check(disconnected, "external TUN finalize flag was lost");
    }
}

#[test]
fn native_adapter_reaches_every_standard_platform_callback() {
    let state = Arc::new(ProbeState::default());
    let client = Client::new(Recorder(state.clone())).expect("create callback test client");
    let status = client
        .callback_self_test()
        .expect("native callback self-test");
    assert_eq!(status.status, "CALLBACK_SELF_TEST_OK");

    let expected = 33
        + usize::from(cfg!(feature = "dco")) * 10
        + usize::from(cfg!(feature = "external-transport")) * 13
        + usize::from(cfg!(feature = "external-tun")) * 11;
    assert_eq!(state.calls.load(Ordering::Relaxed), expected);
    let failures = state
        .failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        failures.is_empty(),
        "callback marshalling failures: {failures:#?}"
    );
}
