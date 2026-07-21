#![cfg(feature = "tokio")]

use std::env;
use std::time::Duration;

use openvpn_connect::tokio::Client;
use openvpn_connect::{Config, Credentials};

/// Connects to a real `OpenVPN` server, waits for Core's CONNECTED event, then
/// performs a clean asynchronous stop. The Docker harness under `tests/e2e`
/// supplies an isolated server, certificates, and TUN devices.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENVPN_CONNECT_E2E_PROFILE or tests/e2e/run.sh"]
async fn connects_authenticates_and_disconnects_cleanly() {
    let profile_path = env::var("OPENVPN_CONNECT_E2E_PROFILE")
        .expect("set OPENVPN_CONNECT_E2E_PROFILE to an OpenVPN client profile");
    let profile = tokio::fs::read_to_string(profile_path)
        .await
        .expect("read E2E profile");
    let timeout_seconds = env::var("OPENVPN_CONNECT_E2E_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(45);

    let client = Client::without_callbacks().expect("create Tokio client");
    let evaluation = client
        .evaluate(Config::new(profile))
        .await
        .expect("evaluate E2E profile");
    if !evaluation.autologin {
        let username = env::var("OPENVPN_USERNAME").expect("OPENVPN_USERNAME is required");
        let password = env::var("OPENVPN_PASSWORD").expect("OPENVPN_PASSWORD is required");
        client
            .provide_credentials(Credentials::new(username, password))
            .await
            .expect("provide E2E credentials");
    }

    let mut events = client.subscribe_events();
    let mut logs = client.subscribe_logs();
    let session = client.connect().await.expect("start E2E session");
    let handle = session.handle();
    tokio::pin!(session);
    let deadline = tokio::time::sleep(Duration::from_secs(timeout_seconds));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            event = events.recv() => {
                let event = event.expect("event stream closed before CONNECTED");
                eprintln!("{}: {}", event.name, event.info);
                assert!(!event.fatal, "fatal OpenVPN event: {event:?}");
                if event.name == "CONNECTED" {
                    handle.stop().await.expect("request clean stop");
                    let status = tokio::time::timeout(
                        Duration::from_secs(10),
                        &mut session,
                    )
                    .await
                    .expect("session did not stop within ten seconds")
                    .expect("session returned an error after clean stop");
                    eprintln!("session exit {}: {}", status.status, status.message);
                    break;
                }
            }
            log = logs.recv() => {
                match log {
                    Ok(log) => eprint!("{log}"),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        eprintln!("OpenVPN log stream lagged; skipped {skipped} messages");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        panic!("log stream closed before CONNECTED");
                    }
                }
            }
            result = &mut session => {
                panic!("session exited before CONNECTED: {result:?}");
            }
            () = &mut deadline => {
                handle.cancel();
                panic!("timed out waiting for CONNECTED after {timeout_seconds} seconds");
            }
        }
    }
}

/// Exercises cancellation immediately after Core has entered its blocking
/// connect call. This guards both the stop-before-start race and native crypto
/// thread cleanup when a Tokio runtime shuts down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OPENVPN_CONNECT_E2E_PROFILE or tests/e2e/run.sh"]
async fn cancels_during_connection_and_drops_safely() {
    let profile_path = env::var("OPENVPN_CONNECT_E2E_PROFILE")
        .expect("set OPENVPN_CONNECT_E2E_PROFILE to an OpenVPN client profile");
    let profile = tokio::fs::read_to_string(profile_path)
        .await
        .expect("read E2E profile");
    let client = Client::without_callbacks().expect("create Tokio client");
    client
        .evaluate(Config::new(profile))
        .await
        .expect("evaluate E2E profile");

    let session = client.connect().await.expect("start E2E session");
    let handle = session.handle();
    handle.cancel();
    let status = tokio::time::timeout(Duration::from_secs(10), session)
        .await
        .expect("cancelled session did not stop within ten seconds")
        .expect("cancelled session returned an error");
    eprintln!(
        "cancelled session exit {}: {}",
        status.status, status.message
    );
}
