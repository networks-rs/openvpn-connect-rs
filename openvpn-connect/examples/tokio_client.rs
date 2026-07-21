use std::env;

use openvpn_connect::tokio::Client;
use openvpn_connect::{Config, Credentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: cargo run -p openvpn-connect --example tokio_client -- client.ovpn")?;
    let profile = tokio::fs::read_to_string(path).await?;
    let client = Client::without_callbacks()?;
    let evaluation = client.evaluate(Config::new(profile)).await?;

    if !evaluation.autologin {
        let username = env::var("OPENVPN_USERNAME")?;
        let password = env::var("OPENVPN_PASSWORD")?;
        client
            .provide_credentials(Credentials::new(username, password))
            .await?;
    }

    let mut events = client.subscribe_events();
    let event_task = tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            eprintln!("event {}: {}", event.name, event.info);
        }
    });

    let session = client.connect().await?;
    let handle = session.handle();
    tokio::pin!(session);
    let status = tokio::select! {
        result = &mut session => result?,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            handle.stop().await?;
            session.await?
        }
    };
    event_task.abort();
    println!("{}: {}", status.status, status.message);
    Ok(())
}
