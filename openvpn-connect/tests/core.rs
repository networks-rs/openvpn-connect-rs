use openvpn_connect::{
    Client, Config, Credentials, Error, capabilities, evaluate_config, max_profile_size,
    merge_config_string, platform,
};

const VALID_PROFILE: &str = concat!(
    "client\n",
    "dev tun\n",
    "proto udp\n",
    "remote vpn.example.test 1194\n",
    "remote-cert-tls server\n",
    "client-cert-not-required\n",
    "peer-fingerprint ",
    "01:F5:A6:4D:4A:CB:65:E1:8A:9F:55:89:7F:77:A0:79:",
    "AA:FB:CC:A1:37:2F:D8:B3:47:AA:9D:E3:D0:76:B1:44\n",
);

#[cfg(feature = "tokio")]
fn assert_send<T: Send>(_: &T) {}

#[test]
fn reports_source_built_core_version() {
    let description = platform();
    assert!(description.contains("OpenVPN core 3.11.7"), "{description}");
    assert!(max_profile_size() > 0);
    assert!(capabilities().gremlin, "source builds must include Gremlin");
}

#[test]
fn rejects_optional_settings_that_are_not_compiled_in() {
    let mut config = Config::new(VALID_PROFILE);
    config.alternative_proxy = true;
    assert!(matches!(
        evaluate_config(&config),
        Err(Error::UnsupportedCapability {
            capability: "private-tunnel-proxy",
            ..
        })
    ));

    if !capabilities().dco {
        config.alternative_proxy = false;
        config.dco = true;
        assert!(matches!(
            evaluate_config(&config),
            Err(Error::UnsupportedCapability {
                capability: "dco",
                ..
            })
        ));
    }
}

#[test]
fn rejects_invalid_profile_through_core_parser() {
    let client = Client::without_callbacks().expect("create client");
    let error = client
        .evaluate(&Config::new("this-is-not-an-openvpn-directive\n"))
        .expect_err("invalid profile should fail validation");

    assert!(matches!(error, Error::Core { .. }));
}

#[test]
fn evaluates_a_valid_inline_profile() {
    let client = Client::without_callbacks().expect("create client");
    let evaluation = client
        .evaluate(&Config::new(VALID_PROFILE))
        .expect("valid profile should evaluate");

    assert_eq!(evaluation.remote_host, "vpn.example.test");
    assert_eq!(evaluation.remote_port, "1194");
    assert_eq!(evaluation.remote_proto, "udp");
}

#[test]
fn helper_api_evaluates_and_merges_without_a_client() {
    let evaluation = evaluate_config(&Config::new(VALID_PROFILE)).expect("static evaluation");
    assert_eq!(evaluation.remote_host, "vpn.example.test");

    let merged = merge_config_string(VALID_PROFILE);
    assert!(merged.error_text.is_empty(), "{merged:?}");
    assert!(merged.profile_content.contains("vpn.example.test"));
}

#[test]
fn requires_evaluation_before_credentials_or_connect() {
    let client = Client::without_callbacks().expect("create client");

    assert!(matches!(client.connect(), Err(Error::InvalidState(_))));
    assert!(matches!(
        client.provide_credentials(&Credentials::default()),
        Err(Error::InvalidState(_))
    ));
}

#[test]
fn malformed_dynamic_challenge_is_rejected() {
    assert!(openvpn_connect::parse_dynamic_challenge("not-a-cookie").is_none());
}

#[cfg(feature = "external-transport")]
#[test]
fn external_transport_feature_compiles_the_native_factory() {
    assert!(capabilities().external_transport);
}

#[cfg(feature = "external-tun")]
#[test]
fn external_tun_feature_compiles_the_native_factory() {
    assert!(capabilities().external_tun);
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_client_runs_setup_off_runtime_workers_and_is_a_session_future() {
    let client = openvpn_connect::tokio::Client::without_callbacks().expect("create async client");
    let mut events = client.subscribe_events();
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let session = client.connect().await.expect("start session worker");
    assert_send(&session);
    assert!(matches!(session.await, Err(Error::InvalidState(_))));

    let helper_evaluation = openvpn_connect::tokio::evaluate_config(Config::new(VALID_PROFILE))
        .await
        .expect("async helper evaluation");
    assert_eq!(helper_evaluation.remote_host, "vpn.example.test");

    let evaluation = client
        .evaluate(Config::new(VALID_PROFILE))
        .await
        .expect("async client evaluation");
    assert_eq!(evaluation.remote_port, "1194");
}
