//! Skeleton for a packet-level desktop/mobile tunnel. The platform-specific
//! TUN driver owns the descriptor and forwards packets through `ExternalTunIo`.

use std::sync::Mutex;

use openvpn_connect::{
    EventHandler, ExternalTun, ExternalTunConfig, ExternalTunInfo, ExternalTunIo,
    ExternalTunStartConfig,
};

#[derive(Default)]
struct State {
    info: ExternalTunInfo,
    io: Option<ExternalTunIo>,
}

struct PlatformTun {
    state: Mutex<State>,
}

impl ExternalTun for PlatformTun {
    fn configure(&self, config: &ExternalTunConfig) -> bool {
        config.layer == 3
    }

    fn start(&self, config: &ExternalTunStartConfig, io: ExternalTunIo) {
        println!("negotiated cipher id {}", config.cipher_algorithm);
        // Open/configure the platform TUN here, then publish its actual values.
        let mut state = self.state.lock().expect("TUN state poisoned");
        state.info = ExternalTunInfo {
            name: "platform-tun".into(),
            mtu: 1500,
            ..ExternalTunInfo::default()
        };
        state.io = Some(io.clone());
        let _ = io.pre_tun_config();
        let _ = io.pre_route_config();
        let _ = io.connected();
    }

    fn stop(&self) {
        self.state.lock().expect("TUN state poisoned").io = None;
    }

    fn send(&self, packet: &[u8]) -> bool {
        // Write this packet to the platform TUN descriptor.
        println!("Core sent a {} byte cleartext packet", packet.len());
        true
    }

    fn info(&self) -> ExternalTunInfo {
        self.state.lock().expect("TUN state poisoned").info.clone()
    }
}

struct Handler {
    tun: PlatformTun,
}

impl EventHandler for Handler {
    fn external_tun(&self) -> Option<&dyn ExternalTun> {
        Some(&self.tun)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _client = openvpn_connect::Client::new(Handler {
        tun: PlatformTun {
            state: Mutex::new(State::default()),
        },
    })?;
    println!("external TUN client initialized; enable `external-tun` before connecting");
    Ok(())
}
