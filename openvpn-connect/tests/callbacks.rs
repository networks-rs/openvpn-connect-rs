use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use openvpn_connect::{
    AppControlMessage, Client, DnsOptions, Event, EventHandler, ExternalPkiCertificate,
    ExternalPkiCertificateRequest, ExternalPkiError, ExternalPkiSignRequest, RemoteOverride,
    TunBuilder,
};

struct Recorder(Arc<AtomicUsize>);

impl Recorder {
    fn hit(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl TunBuilder for Recorder {
    fn new_tunnel(&self) -> bool {
        self.hit();
        true
    }
    fn set_layer(&self, _: i32) -> bool {
        self.hit();
        true
    }
    fn set_remote_address(&self, _: &str, _: bool) -> bool {
        self.hit();
        true
    }
    fn add_address(&self, _: &str, _: i32, _: &str, _: bool, _: bool) -> bool {
        self.hit();
        true
    }
    fn set_route_metric_default(&self, _: i32) -> bool {
        self.hit();
        true
    }
    fn reroute_gateway(&self, _: bool, _: bool, _: u32) -> bool {
        self.hit();
        true
    }
    fn add_route(&self, _: &str, _: i32, _: i32, _: bool) -> bool {
        self.hit();
        true
    }
    fn exclude_route(&self, _: &str, _: i32, _: i32, _: bool) -> bool {
        self.hit();
        true
    }
    fn set_dns_options(&self, _: &DnsOptions) -> bool {
        self.hit();
        true
    }
    fn set_mtu(&self, _: i32) -> bool {
        self.hit();
        true
    }
    fn set_session_name(&self, _: &str) -> bool {
        self.hit();
        true
    }
    fn add_proxy_bypass(&self, _: &str) -> bool {
        self.hit();
        true
    }
    fn set_proxy_auto_config_url(&self, _: &str) -> bool {
        self.hit();
        true
    }
    fn set_proxy_http(&self, _: &str, _: i32) -> bool {
        self.hit();
        true
    }
    fn set_proxy_https(&self, _: &str, _: i32) -> bool {
        self.hit();
        true
    }
    fn add_wins_server(&self, _: &str) -> bool {
        self.hit();
        true
    }
    fn set_allow_family(&self, _: i32, _: bool) -> bool {
        self.hit();
        true
    }
    fn set_allow_local_dns(&self, _: bool) -> bool {
        self.hit();
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
    fn local_networks(&self, _: bool) -> Vec<String> {
        self.hit();
        Vec::new()
    }
    fn establish_lite(&self) {
        self.hit();
    }
    fn teardown(&self, _: bool) {
        self.hit();
    }
}

impl EventHandler for Recorder {
    fn event(&self, _: Event) {
        self.hit();
    }
    fn log(&self, _: &str) {
        self.hit();
    }
    fn app_control_message(&self, _: AppControlMessage) {
        self.hit();
    }
    fn socket_protect(&self, _: isize, _: &str, _: bool) -> bool {
        self.hit();
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
        Err("self-test".into())
    }
    fn tun_builder(&self) -> Option<&dyn TunBuilder> {
        Some(self)
    }
    fn external_pki_certificate(
        &self,
        _: ExternalPkiCertificateRequest,
    ) -> Result<ExternalPkiCertificate, ExternalPkiError> {
        self.hit();
        Err(ExternalPkiError::new("self-test"))
    }
    fn external_pki_sign(&self, _: ExternalPkiSignRequest) -> Result<String, ExternalPkiError> {
        self.hit();
        Err(ExternalPkiError::new("self-test"))
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
    fn configure(&self, _: &openvpn_connect::ExternalTransportConfig) -> bool {
        self.hit();
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
    fn send_queue_size(&self) -> usize {
        self.hit();
        0
    }
    fn endpoint(&self) -> openvpn_connect::ExternalTransportEndpoint {
        self.hit();
        openvpn_connect::ExternalTransportEndpoint::default()
    }
    fn process_push(&self, _: &str) {
        self.hit();
    }
}

#[cfg(feature = "external-tun")]
impl openvpn_connect::ExternalTun for Recorder {
    fn configure(&self, _: &openvpn_connect::ExternalTunConfig) -> bool {
        self.hit();
        true
    }
    fn info(&self) -> openvpn_connect::ExternalTunInfo {
        self.hit();
        openvpn_connect::ExternalTunInfo::default()
    }
    fn layer_2_supported(&self) -> bool {
        self.hit();
        false
    }
    fn supports_epoch_data(&self) -> bool {
        self.hit();
        false
    }
}

#[test]
fn native_adapter_reaches_every_standard_platform_callback() {
    let calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(Recorder(calls.clone())).expect("create callback test client");
    let status = client
        .callback_self_test()
        .expect("native callback self-test");
    assert_eq!(status.status, "CALLBACK_SELF_TEST_OK");

    let expected = 33
        + usize::from(cfg!(feature = "external-transport")) * 6
        + usize::from(cfg!(feature = "external-tun")) * 4;
    assert_eq!(calls.load(Ordering::Relaxed), expected);
}
