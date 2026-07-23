#![cfg(feature = "tokio")]

use std::env;
use std::future::Future;
#[cfg(feature = "external-transport")]
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
#[cfg(any(feature = "external-transport", feature = "external-tun"))]
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
#[cfg(feature = "external-transport")]
use std::thread::JoinHandle;
use std::time::Duration;

use openvpn_connect::tokio::{AsyncEventHandler, CallbackFuture, Client, Session};
use openvpn_connect::{
    Config, Credentials, Error, Event, EventHandler, ExternalPkiCertificate,
    ExternalPkiCertificateRequest, ExternalPkiError, ExternalPkiSignRequest, RemoteOverride,
};
use tokio_stream::StreamExt;

#[cfg(feature = "external-transport")]
#[derive(Default)]
struct TransportState {
    config: Option<openvpn_connect::ExternalTransportConfig>,
    endpoint: openvpn_connect::ExternalTransportEndpoint,
    sender: Option<mpsc::Sender<Vec<u8>>>,
    stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    worker: Option<JoinHandle<()>>,
    queued: Arc<AtomicUsize>,
}

#[cfg(feature = "external-transport")]
#[derive(Default)]
struct E2eExternalTransport {
    state: Arc<Mutex<TransportState>>,
}

#[cfg(feature = "external-transport")]
impl openvpn_connect::ExternalTransport for E2eExternalTransport {
    fn configure(&self, config: &openvpn_connect::ExternalTransportConfig) -> bool {
        if !config.protocol.to_ascii_lowercase().starts_with("udp") {
            return false;
        }
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .config = Some(config.clone());
        true
    }

    fn start(&self, io: openvpn_connect::ExternalTransportIo) {
        let config = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .config
            .clone()
            .expect("external transport must be configured before start");
        let (sender, receiver) = mpsc::channel();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = self.state.clone();
        let worker_stop = stop.clone();
        let queued = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queued
            .clone();
        let worker = std::thread::spawn(move || {
            if let Err(error) =
                run_external_udp(&config, &io, &state, &receiver, &worker_stop, &queued)
            {
                let _ = io.error(&error);
            }
        });
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sender = Some(sender);
        state.stop = Some(stop);
        state.worker = Some(worker);
    }

    fn stop(&self) {
        let worker = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(stop) = state.stop.take() {
                stop.store(true, Ordering::Release);
            }
            state.sender = None;
            state.worker.take()
        };
        if let Some(worker) = worker {
            worker.join().expect("external UDP worker panicked");
        }
    }

    fn send(&self, packet: &[u8]) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(sender) = state.sender.as_ref() else {
            return false;
        };
        state.queued.fetch_add(1, Ordering::Relaxed);
        if sender.send(packet.to_vec()).is_err() {
            state.queued.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    fn send_queue_empty(&self) -> bool {
        self.send_queue_size() == 0
    }

    fn has_send_queue(&self) -> bool {
        true
    }

    fn send_queue_size(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .queued
            .load(Ordering::Relaxed)
    }

    fn endpoint(&self) -> openvpn_connect::ExternalTransportEndpoint {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .endpoint
            .clone()
    }
}

#[cfg(feature = "external-transport")]
fn run_external_udp(
    config: &openvpn_connect::ExternalTransportConfig,
    io: &openvpn_connect::ExternalTransportIo,
    state: &Mutex<TransportState>,
    receiver: &mpsc::Receiver<Vec<u8>>,
    stop: &std::sync::atomic::AtomicBool,
    queued: &AtomicUsize,
) -> Result<(), String> {
    io.pre_resolve().map_err(|error| error.to_string())?;
    let port = config
        .port
        .parse::<u16>()
        .map_err(|error| error.to_string())?;
    let remote = (config.host.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "external transport DNS returned no addresses".to_owned())?;
    let bind: SocketAddr = if remote.is_ipv6() {
        "[::]:0".parse().expect("IPv6 wildcard address")
    } else {
        "0.0.0.0:0".parse().expect("IPv4 wildcard address")
    };
    let socket = UdpSocket::bind(bind).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|error| error.to_string())?;
    socket.connect(remote).map_err(|error| error.to_string())?;
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .endpoint = openvpn_connect::ExternalTransportEndpoint {
        host: config.host.clone(),
        port: remote.port().to_string(),
        protocol: config.protocol.clone(),
        ip_address: remote.ip().to_string(),
    };
    io.connecting().map_err(|error| error.to_string())?;

    let mut buffer = [0_u8; 65_536];
    while !stop.load(Ordering::Acquire) {
        while let Ok(packet) = receiver.try_recv() {
            queued.fetch_sub(1, Ordering::Relaxed);
            socket.send(&packet).map_err(|error| error.to_string())?;
            io.needs_send().map_err(|error| error.to_string())?;
        }
        match socket.recv(&mut buffer) {
            Ok(length) => io
                .receive(&buffer[..length])
                .map_err(|error| error.to_string())?,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

#[cfg(feature = "external-tun")]
#[derive(Default)]
struct E2eExternalTun {
    io: Mutex<Option<openvpn_connect::ExternalTunIo>>,
}

#[cfg(feature = "external-tun")]
impl openvpn_connect::ExternalTun for E2eExternalTun {
    fn configure(&self, config: &openvpn_connect::ExternalTunConfig) -> bool {
        config.layer == 3
    }

    fn start(
        &self,
        _: &openvpn_connect::ExternalTunStartConfig,
        io: openvpn_connect::ExternalTunIo,
    ) {
        io.pre_tun_config().expect("external TUN pre-config");
        io.pre_route_config().expect("external TUN pre-route");
        io.connected().expect("external TUN connected");
        *self
            .io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(io);
    }

    fn stop(&self) {
        self.io
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }

    fn send(&self, _: &[u8]) -> bool {
        true
    }

    fn info(&self) -> openvpn_connect::ExternalTunInfo {
        openvpn_connect::ExternalTunInfo {
            name: "e2e-external-tun".into(),
            vpn_ipv4: "10.8.0.2".into(),
            gateway_ipv4: "10.8.0.1".into(),
            mtu: 1500,
            ..openvpn_connect::ExternalTunInfo::default()
        }
    }
}

#[derive(Default)]
struct E2eHandler {
    #[cfg(feature = "external-transport")]
    transport: E2eExternalTransport,
    #[cfg(feature = "external-tun")]
    tun: E2eExternalTun,
}

impl EventHandler for E2eHandler {
    fn log(&self, text: &str) {
        eprint!("{text}");
    }

    #[cfg(feature = "external-transport")]
    fn external_transport(&self) -> Option<&dyn openvpn_connect::ExternalTransport> {
        Some(&self.transport)
    }

    #[cfg(feature = "external-tun")]
    fn external_tun(&self) -> Option<&dyn openvpn_connect::ExternalTun> {
        Some(&self.tun)
    }
}

fn e2e_tokio_client() -> Client {
    Client::new(E2eHandler::default()).expect("create E2E Tokio client")
}

// api_surface.rs treats this as the reviewable coverage contract. Entries
// describe calls made in this file or in callbacks.rs; adding a safe binding
// without adding it to the E2E contract fails the ordinary test suite.
const E2E_BINDING_COVERAGE: &[&str] = &[
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
];

fn profile_path() -> String {
    env::var("OPENVPN_CONNECT_E2E_PROFILE")
        .expect("set OPENVPN_CONNECT_E2E_PROFILE or run tests/e2e/run.sh")
}

fn profile() -> String {
    std::fs::read_to_string(profile_path()).expect("read E2E profile")
}

fn timeout() -> Duration {
    Duration::from_secs(
        env::var("OPENVPN_CONNECT_E2E_TIMEOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(45),
    )
}

fn credentials() -> Credentials {
    Credentials::new(
        env::var("OPENVPN_USERNAME").expect("OPENVPN_USERNAME is required"),
        env::var("OPENVPN_PASSWORD").expect("OPENVPN_PASSWORD is required"),
    )
}

fn session_config(content: String) -> Config {
    let mut config = Config::new(content)
        .with_gui_version("openvpn-connect-rs/e2e")
        .with_server_override("server")
        .with_port_override("1194")
        .with_protocol_override("udp");
    // The container builds DCO to test its binding adapter but intentionally
    // uses the portable TUN path because CI hosts do not install ovpn-dco.
    config.dco = false;
    config.peer_info.push(("IV_E2E".into(), "1".into()));
    config
}

fn exhaustive_config(content: String) -> Config {
    let mut config = session_config(content);
    config.gui_version = "openvpn-connect-rs/all-fields".into();
    config.server_override = "server".into();
    config.port_override = "1194".into();
    config.proto_override = "udp".into();
    config.content_list = vec![("e2e-extra".into(), "setenv E2E_CONTENT_LIST 1\n".into())];
    config
        .peer_info
        .push(("IV_BINDING".into(), "all-fields".into()));
    config.sso_methods = "openurl,crtext".into();
    config.app_custom_protocols = "e2e".into();
    config.hw_addr_override = "02:00:00:00:00:01".into();
    config.platform_version = "e2e-platform".into();
    config.allow_unused_addr_families = "yes".into();
    config.compression_mode = "stub".into();
    config.external_pki_alias = "e2e-alias".into();
    config.private_key_password = "unused".into();
    config.tls_version_min_override = "1.2".into();
    config.tls_cert_profile_override = "preferred".into();
    config.tls_cipher_list = "DEFAULT".into();
    config.tls_ciphersuites_list = "TLS_AES_256_GCM_SHA384".into();
    config.proxy_host = String::new();
    config.proxy_port = "8080".into();
    config.proxy_username = "proxy-user".into();
    config.proxy_password = "proxy-password".into();
    config.gremlin_config = "transport-packet=0".into();
    config.connection_timeout_seconds = 17;
    config.ssl_debug_level = 1;
    config.default_key_direction = 1;
    config.protocol_version_override = 6;
    config.clock_tick_ms = 250;
    config.tun_persist = true;
    config.google_dns_fallback = true;
    config.dhcp_search_domains_as_split_domains = true;
    config.synchronous_dns_lookup = true;
    config.autologin_sessions = false;
    config.retry_on_auth_failed = true;
    config.disable_client_cert = false;
    config.proxy_allow_cleartext_auth = true;
    config.echo = true;
    config.info = true;
    config.allow_local_lan_access = true;
    config.enable_route_emulation = true;
    config.wintun = true;
    config.allow_local_dns_resolvers = true;
    config.enable_legacy_algorithms = true;
    config.enable_non_preferred_data_channel_algorithms = true;
    config.generate_tun_builder_capture_event = true;
    config
}

async fn wait_for_event(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    session: &mut Session,
    wanted: &str,
) -> Event {
    tokio::time::timeout(timeout(), async {
        loop {
            tokio::select! {
                event = events.recv() => {
                    let event = event.expect("event stream closed while waiting for an event");
                    eprintln!("{}: {}", event.name, event.info);
                    assert!(!event.fatal, "fatal OpenVPN event: {event:?}");
                    if event.name == wanted {
                        return event;
                    }
                }
                result = &mut *session => {
                    panic!("session exited while waiting for {wanted}: {result:?}");
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for OpenVPN event {wanted}"))
}

struct AsyncProbe(Arc<AtomicUsize>);

impl AsyncProbe {
    fn hit(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl AsyncEventHandler for AsyncProbe {
    fn event(&self, _: Event) {
        self.hit();
    }

    fn log(&self, _: &str) {
        self.hit();
    }

    fn app_control_message(&self, _: openvpn_connect::AppControlMessage) {
        self.hit();
    }

    fn socket_protect(&self, _: isize, _: String, _: bool) -> CallbackFuture<'_, bool> {
        self.hit();
        Box::pin(async { true })
    }

    fn pause_on_connection_timeout(&self) -> CallbackFuture<'_, bool> {
        self.hit();
        Box::pin(async { false })
    }

    fn clock_tick(&self) {
        self.hit();
    }

    fn remote_override_enabled(&self) -> bool {
        self.hit();
        true
    }

    fn remote_override(&self) -> CallbackFuture<'_, Result<RemoteOverride, String>> {
        self.hit();
        Box::pin(async { Err("intentional E2E remote override failure".into()) })
    }

    fn external_pki_certificate(
        &self,
        _: ExternalPkiCertificateRequest,
    ) -> CallbackFuture<'_, Result<ExternalPkiCertificate, ExternalPkiError>> {
        self.hit();
        Box::pin(async { Err(ExternalPkiError::new("intentional E2E certificate failure")) })
    }

    fn external_pki_sign(
        &self,
        _: ExternalPkiSignRequest,
    ) -> CallbackFuture<'_, Result<String, ExternalPkiError>> {
        self.hit();
        Box::pin(async { Err(ExternalPkiError::new("intentional E2E signing failure")) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENVPN_CONNECT_E2E_PROFILE or tests/e2e/run.sh"]
async fn helpers_configuration_callbacks_and_state_errors_are_covered() {
    eprintln!("E2E stage: static helpers");
    assert!(E2E_BINDING_COVERAGE.len() > 70);
    let source = profile();
    let path = profile_path();

    let capabilities = openvpn_connect::capabilities();
    assert!(capabilities.gremlin);
    assert_eq!(capabilities.dco, cfg!(feature = "dco"));
    assert_eq!(
        capabilities.external_transport,
        cfg!(feature = "external-transport")
    );
    assert_eq!(capabilities.external_tun, cfg!(feature = "external-tun"));
    assert_eq!(
        capabilities.dco_tun_builder,
        capabilities.dco && capabilities.tun_builder
    );
    assert!(!capabilities.private_tunnel_proxy);
    assert!(openvpn_connect::platform().contains("OpenVPN core"));
    assert!(openvpn_connect::copyright().contains("OpenVPN"));
    assert!(openvpn_connect::max_profile_size() >= source.len());
    eprintln!("E2E stage: sync crypto self-test");
    let _ = openvpn_connect::crypto_self_test();

    eprintln!("E2E stage: dynamic challenge");
    let challenge = openvpn_connect::parse_dynamic_challenge(
        "CRV1:E,R:e2e-state:ZTJlLXVzZXI=:Enter verification code",
    )
    .expect("parse a valid dynamic challenge");
    assert_eq!(challenge.state_id, "e2e-state");
    assert_eq!(challenge.challenge, "Enter verification code");
    assert!(challenge.echo && challenge.response_required);
    assert!(openvpn_connect::parse_dynamic_challenge("invalid").is_none());

    eprintln!("E2E stage: sync merge helpers");
    for merged in [
        openvpn_connect::merge_config_path(&path, false),
        openvpn_connect::merge_config_path(&path, true),
        openvpn_connect::merge_config_string(&source),
    ] {
        assert!(merged.error_text.is_empty(), "merge failed: {merged:?}");
        assert!(merged.profile_content.contains("remote server 1194"));
    }
    let async_path = openvpn_connect::tokio::merge_config_path(path, true)
        .await
        .expect("Tokio path merge");
    let async_string = openvpn_connect::tokio::merge_config_string(source.clone())
        .await
        .expect("Tokio string merge");
    assert!(async_path.error_text.is_empty() && async_string.error_text.is_empty());
    eprintln!("E2E stage: Tokio crypto self-test");
    let _ = openvpn_connect::tokio::crypto_self_test()
        .await
        .expect("Tokio crypto self-test");

    eprintln!("E2E stage: static evaluation helpers");
    let evaluation = openvpn_connect::evaluate_config(&session_config(source.clone()))
        .expect("static profile evaluation");
    assert_eq!(evaluation.remote_host, "server");
    let async_evaluation = openvpn_connect::tokio::evaluate_config(session_config(source.clone()))
        .await
        .expect("Tokio static profile evaluation");
    assert_eq!(async_evaluation.remote_port, "1194");

    eprintln!("E2E stage: exhaustive Config");
    // Every Config field is populated in one FFI traversal. Some sentinel
    // combinations are intentionally semantically invalid; either a complete
    // evaluation or a Core parser error is acceptable, but a capability error
    // or crash is not.
    match openvpn_connect::evaluate_config(&exhaustive_config(source.clone())) {
        Ok(_) | Err(Error::Core { .. }) => {}
        Err(error) => panic!("all-field Config did not reach Core: {error}"),
    }
    let mut unsupported = session_config(source.clone());
    unsupported.alternative_proxy = true;
    assert!(matches!(
        openvpn_connect::evaluate_config(&unsupported),
        Err(Error::UnsupportedCapability {
            capability: "private-tunnel-proxy",
            ..
        })
    ));
    if !capabilities.dco {
        let mut unsupported = session_config(source.clone());
        unsupported.dco = true;
        assert!(matches!(
            openvpn_connect::evaluate_config(&unsupported),
            Err(Error::UnsupportedCapability {
                capability: "dco",
                ..
            })
        ));
    }

    eprintln!("E2E stage: synchronous state and query paths");
    let raw = openvpn_connect::Client::without_callbacks().expect("create sync client");
    assert!(matches!(
        raw.provide_credentials(&Credentials::default()),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(raw.connect(), Err(Error::InvalidState(_))));
    raw.pause("outside-session");
    raw.resume();
    raw.reconnect(0);
    raw.post_control_message("PUSH_REQUEST");
    raw.send_app_control_message("e2e", "outside-session");
    assert!(raw.connection_info().is_none());
    assert!(raw.session_token().is_none());
    assert!(!raw.statistics().is_empty());
    let _ = raw.interface_stats();
    let _ = raw.transport_stats();
    raw.start_certificate_check("", "", None)
        .expect("certificate check outside a session is a no-op");
    raw.start_external_pki_certificate_check("e2e", None)
        .expect("external certificate check outside a session is a no-op");
    raw.stop();

    eprintln!("E2E stage: complete Credentials");
    let credential_probe =
        openvpn_connect::Client::without_callbacks().expect("create credential marshalling client");
    credential_probe
        .evaluate(&session_config(source.clone()))
        .expect("evaluate before credential marshalling");
    let mut every_credential = credentials();
    every_credential.http_proxy_username = "proxy-user".into();
    every_credential.http_proxy_password = "proxy-password".into();
    every_credential.response = "123456".into();
    every_credential.dynamic_challenge_cookie =
        "CRV1:R:e2e-state:ZTJlLXVzZXI=:Enter verification code".into();
    let _ = credential_probe.provide_credentials(&every_credential);

    eprintln!("E2E stage: Tokio async callbacks");
    let probe_calls = Arc::new(AtomicUsize::new(0));
    let async_callbacks = Client::new_async(AsyncProbe(probe_calls.clone()))
        .expect("create Tokio async-callback client");
    let status = async_callbacks
        .callback_self_test()
        .await
        .expect("run callbacks through Tokio adapter");
    assert_eq!(status.status, "CALLBACK_SELF_TEST_OK");
    assert_eq!(probe_calls.load(Ordering::Relaxed), 10);

    eprintln!("E2E stage: Tokio builder and active-state errors");
    let builder_client = Client::builder()
        .handler(E2eHandler::default())
        .event_capacity(0)
        .log_capacity(0)
        .app_control_capacity(0)
        .command_capacity(0)
        .build()
        .expect("build configured Tokio client");
    let _new_client = Client::new(()).expect("Tokio Client::new");
    let _without_callbacks = Client::without_callbacks().expect("Tokio callback-free client");
    let mut events = builder_client.subscribe_events();
    let mut logs = builder_client.subscribe_logs();
    let mut app_control = builder_client.subscribe_app_control();
    assert!(events.try_recv().is_err());
    assert!(logs.try_recv().is_err());
    assert!(app_control.try_recv().is_err());
    let _event_stream = builder_client.event_stream();
    let _log_stream = builder_client.log_stream();
    let _app_control_stream = builder_client.app_control_stream();

    builder_client
        .evaluate(session_config(source))
        .await
        .expect("evaluate state-error client");
    builder_client
        .provide_credentials(credentials())
        .await
        .expect("provide state-error credentials");
    let session = builder_client
        .connect()
        .await
        .expect("start state-error session");
    let handle = session.handle();
    let _session_token = session.cancellation_token();
    let _handle_token = handle.cancellation_token();
    assert!(matches!(
        builder_client.evaluate(Config::default()).await,
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        builder_client
            .provide_credentials(Credentials::default())
            .await,
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        builder_client.connect().await,
        Err(Error::InvalidState(_))
    ));
    handle.cancel();
    session.wait().await.expect("cancel session cleanly");
    assert!(matches!(
        handle.statistics().await,
        Err(Error::SessionClosed)
    ));
    eprintln!("E2E stage: helper test complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENVPN_CONNECT_E2E_PROFILE or tests/e2e/run.sh"]
async fn tokio_session_exercises_every_live_control_and_query() {
    let source = profile();
    let client = e2e_tokio_client();
    let mut events = client.subscribe_events();
    let mut event_stream = client.event_stream();
    let mut logs = client.subscribe_logs();
    let mut log_stream = client.log_stream();
    let mut app_control = client.subscribe_app_control();
    let mut app_control_stream = client.app_control_stream();

    let evaluation = client
        .evaluate(session_config(source))
        .await
        .expect("evaluate E2E profile");
    assert!(
        !evaluation.autologin,
        "server must require username/password"
    );
    client
        .provide_credentials(credentials())
        .await
        .expect("provide credentials verified by the server");

    let mut session = client.connect().await.expect("start E2E session");
    let handle = session.handle();
    assert!(!handle.cancellation_token().is_cancelled());
    wait_for_event(&mut events, &mut session, "CONNECTED").await;

    let streamed_event = tokio::time::timeout(timeout(), event_stream.next())
        .await
        .expect("event stream timed out")
        .expect("event stream closed")
        .expect("event stream lagged");
    assert!(!streamed_event.name.is_empty());
    let received_log = tokio::time::timeout(timeout(), logs.recv())
        .await
        .expect("log receiver timed out")
        .expect("log receiver closed");
    assert!(!received_log.is_empty());
    let streamed_log = tokio::time::timeout(timeout(), log_stream.next())
        .await
        .expect("log stream timed out")
        .expect("log stream closed")
        .expect("log stream lagged");
    assert!(!streamed_log.is_empty());
    assert!(app_control.try_recv().is_err());
    assert!(app_control_stream.next().now_or_never().is_none());

    let info = handle
        .connection_info()
        .await
        .expect("query connection info")
        .expect("connected session has connection info");
    assert_eq!(info.server_host, "server");
    assert_eq!(info.server_port, "1194");
    let _ = handle.session_token().await.expect("query session token");
    let statistics = handle.statistics().await.expect("query statistics");
    assert!(!statistics.is_empty());
    let _ = handle
        .interface_stats()
        .await
        .expect("query interface statistics");
    let _transport = handle
        .transport_stats()
        .await
        .expect("query transport statistics");

    handle
        .pause("binding E2E pause")
        .await
        .expect("pause session");
    wait_for_event(&mut events, &mut session, "PAUSE").await;
    handle.resume().await.expect("resume session");
    wait_for_event(&mut events, &mut session, "RESUME").await;

    handle
        .reconnect(0)
        .await
        .expect("request immediate reconnect");
    wait_for_event(&mut events, &mut session, "RECONNECTING").await;
    wait_for_event(&mut events, &mut session, "CONNECTED").await;

    handle
        .post_control_message("PUSH_REQUEST")
        .await
        .expect("post raw control message");
    handle
        .send_app_control_message("e2e", "binding-message")
        .await
        .expect("send application control message");

    let certificate =
        tokio::fs::read_to_string(env::var("OPENVPN_CONNECT_E2E_CERT").expect("certificate path"))
            .await
            .expect("read client certificate");
    let key = tokio::fs::read_to_string(env::var("OPENVPN_CONNECT_E2E_KEY").expect("key path"))
        .await
        .expect("read client key");
    let ca = tokio::fs::read_to_string(env::var("OPENVPN_CONNECT_E2E_CA").expect("CA path"))
        .await
        .expect("read CA");
    handle
        .start_certificate_check(certificate, key, Some(ca))
        .await
        .expect("start PEM certificate check");
    handle
        .start_external_pki_certificate_check("missing-e2e-alias", None)
        .await
        .expect("start external-PKI certificate error path");

    handle.stop().await.expect("request clean stop");
    assert!(handle.cancellation_token().is_cancelled());
    let status = tokio::time::timeout(Duration::from_secs(10), session.wait())
        .await
        .expect("session did not stop within ten seconds")
        .expect("session returned an error after clean stop");
    eprintln!("session exit {}: {}", status.status, status.message);
    assert!(matches!(
        handle.connection_info().await,
        Err(Error::SessionClosed)
    ));
}

struct ChannelHandler {
    sender: mpsc::Sender<Event>,
    #[cfg(any(feature = "external-transport", feature = "external-tun"))]
    e2e: E2eHandler,
}

impl EventHandler for ChannelHandler {
    fn event(&self, event: Event) {
        let _ = self.sender.send(event);
    }

    fn log(&self, text: &str) {
        eprint!("{text}");
    }

    #[cfg(feature = "external-transport")]
    fn external_transport(&self) -> Option<&dyn openvpn_connect::ExternalTransport> {
        self.e2e.external_transport()
    }

    #[cfg(feature = "external-tun")]
    fn external_tun(&self) -> Option<&dyn openvpn_connect::ExternalTun> {
        self.e2e.external_tun()
    }
}

fn wait_for_sync_event(receiver: &mpsc::Receiver<Event>, wanted: &str) {
    let deadline = std::time::Instant::now() + timeout();
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let event = receiver
            .recv_timeout(remaining)
            .unwrap_or_else(|_| panic!("timed out waiting for sync event {wanted}"));
        eprintln!("sync {}: {}", event.name, event.info);
        assert!(!event.fatal, "fatal sync OpenVPN event: {event:?}");
        if event.name == wanted {
            return;
        }
    }
}

#[test]
#[ignore = "requires OPENVPN_CONNECT_E2E_PROFILE or tests/e2e/run.sh"]
fn synchronous_client_connects_queries_and_stops_cross_thread() {
    let (sender, receiver) = mpsc::channel();
    let client = openvpn_connect::Client::new(ChannelHandler {
        sender,
        #[cfg(any(feature = "external-transport", feature = "external-tun"))]
        e2e: E2eHandler::default(),
    })
    .expect("create sync client");
    client
        .evaluate(&session_config(profile()))
        .expect("evaluate sync profile");
    client
        .provide_credentials(&credentials())
        .expect("provide sync credentials");

    let worker_client = client.clone();
    let worker = std::thread::spawn(move || worker_client.connect());
    wait_for_sync_event(&receiver, "CONNECTED");
    assert!(client.connection_info().is_some());
    let _ = client.session_token();
    assert!(!client.statistics().is_empty());
    let _ = client.interface_stats();
    let _ = client.transport_stats();
    client.pause("sync E2E pause");
    wait_for_sync_event(&receiver, "PAUSE");
    client.resume();
    wait_for_sync_event(&receiver, "RESUME");
    client.reconnect(0);
    wait_for_sync_event(&receiver, "CONNECTED");
    client.post_control_message("PUSH_REQUEST");
    client.send_app_control_message("e2e", "sync-binding-message");
    client.stop();
    worker
        .join()
        .expect("sync connection worker panicked")
        .expect("sync connection failed");
    assert!(matches!(
        client.evaluate(&Config::default()),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        client.provide_credentials(&Credentials::default()),
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(client.connect(), Err(Error::InvalidState(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENVPN_CONNECT_E2E_PROFILE or tests/e2e/run.sh"]
async fn invalid_credentials_emit_auth_failed_and_finish_the_client() {
    let client = e2e_tokio_client();
    let mut events = client.subscribe_events();
    client
        .evaluate(session_config(profile()))
        .await
        .expect("evaluate authentication-failure profile");
    let mut rejected = credentials();
    rejected.password.push_str("-incorrect");
    client
        .provide_credentials(rejected)
        .await
        .expect("provide credentials for server-side rejection");

    let mut session = client
        .connect()
        .await
        .expect("start authentication-failure session");
    let auth_failed = tokio::time::timeout(timeout(), async {
        loop {
            tokio::select! {
                event = events.recv() => {
                    let event = event.expect("event stream closed before AUTH_FAILED");
                    eprintln!("auth rejection {}: {}", event.name, event.info);
                    if event.name == "AUTH_FAILED" {
                        return event;
                    }
                }
                result = &mut session => {
                    panic!("session exited before AUTH_FAILED was observed: {result:?}");
                }
            }
        }
    })
    .await
    .expect("timed out waiting for AUTH_FAILED");
    assert!(auth_failed.error);
    assert!(auth_failed.fatal);

    let status = tokio::time::timeout(Duration::from_secs(10), session.wait())
        .await
        .expect("authentication-failure session did not exit")
        .expect("AUTH_FAILED is reported by the fatal event, then Core exits normally");
    assert!(status.status.is_empty());
    assert!(matches!(
        client.evaluate(Config::default()).await,
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        client.provide_credentials(Credentials::default()).await,
        Err(Error::InvalidState(_))
    ));
    assert!(matches!(
        client.connect().await,
        Err(Error::InvalidState(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENVPN_CONNECT_E2E_PROFILE or tests/e2e/run.sh"]
async fn cancellation_and_session_drop_are_cleanup_safe() {
    let client = e2e_tokio_client();
    client
        .evaluate(session_config(profile()))
        .await
        .expect("evaluate cancellation profile");
    client
        .provide_credentials(credentials())
        .await
        .expect("provide cancellation credentials");

    let session = client.connect().await.expect("start cancellable session");
    let handle = session.handle();
    handle.cancel();
    tokio::time::timeout(Duration::from_secs(10), session.wait())
        .await
        .expect("cancelled session did not stop")
        .expect("cancelled session returned an error");

    assert!(matches!(
        client.connect().await,
        Err(Error::InvalidState(_))
    ));

    let drop_client = e2e_tokio_client();
    drop_client
        .evaluate(session_config(profile()))
        .await
        .expect("evaluate drop-safety client");
    drop_client
        .provide_credentials(credentials())
        .await
        .expect("provide drop-safety credentials");
    let dropped = drop_client
        .connect()
        .await
        .expect("start drop-safety session");
    let token = dropped.cancellation_token();
    drop(dropped);
    tokio::time::timeout(Duration::from_secs(10), token.cancelled())
        .await
        .expect("dropping Session did not cancel it");

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match drop_client.connect().await {
                Err(Error::InvalidState(message)) if message.contains("supports one session") => {
                    break;
                }
                Err(Error::InvalidState(_)) => tokio::task::yield_now().await,
                Ok(_) => panic!("a completed native client must not accept a second session"),
                Err(error) => panic!("unexpected post-session error: {error}"),
            }
        }
    })
    .await
    .expect("dropped session did not finish native cleanup");

    let replacement = e2e_tokio_client();
    replacement
        .evaluate(session_config(profile()))
        .await
        .expect("evaluate replacement client");
    replacement
        .provide_credentials(credentials())
        .await
        .expect("provide replacement credentials");
    let replacement_session = replacement
        .connect()
        .await
        .expect("start replacement client");
    replacement_session.handle().cancel();
    replacement_session
        .wait()
        .await
        .expect("wait for replacement client");
}

trait NowOrNeverExt: Future + Sized {
    fn now_or_never(self) -> Option<Self::Output> {
        let mut future = std::pin::pin!(self);
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        future.as_mut().poll(&mut context).ready()
    }
}

impl<F: Future> NowOrNeverExt for F {}

trait PollReadyExt<T> {
    fn ready(self) -> Option<T>;
}

impl<T> PollReadyExt<T> for std::task::Poll<T> {
    fn ready(self) -> Option<T> {
        match self {
            std::task::Poll::Ready(value) => Some(value),
            std::task::Poll::Pending => None,
        }
    }
}
