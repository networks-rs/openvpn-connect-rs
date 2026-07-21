use std::env;
use std::io;

use openvpn_connect::{Client, Config, Credentials, Event, EventHandler};

struct Handler;

impl EventHandler for Handler {
    fn event(&self, event: Event) {
        eprintln!("event {}: {}", event.name, event.info);
    }

    fn log(&self, text: &str) {
        eprint!("{text}");
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: cargo run -p openvpn-connect --example sync_client -- client.ovpn")?;
    let profile = std::fs::read_to_string(path)?;
    let client = Client::new(Handler)?;
    let evaluation = client.evaluate(&Config::new(profile))?;

    if !evaluation.autologin {
        let username = env::var("OPENVPN_USERNAME")?;
        let password = env::var("OPENVPN_PASSWORD")?;
        client.provide_credentials(&Credentials::new(username, password))?;
    }

    let control = client.clone();
    std::thread::spawn(move || {
        eprintln!("press Enter to disconnect");
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        control.stop();
    });

    let status = client.connect()?;
    println!("{}: {}", status.status, status.message);
    Ok(())
}
