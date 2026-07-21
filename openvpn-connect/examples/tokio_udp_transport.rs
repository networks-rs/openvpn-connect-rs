//! A complete Tokio UDP implementation of `OpenVPN` Core's low-level external
//! transport. Run with `--no-default-features --features
//! vendor,tokio,external-transport`.

#[cfg(feature = "external-transport")]
mod enabled {
    use std::env;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use openvpn_connect::tokio::Client;
    use openvpn_connect::{
        Config, Credentials, EventHandler, ExternalTransport, ExternalTransportConfig,
        ExternalTransportEndpoint, ExternalTransportIo,
    };
    use tokio::net::UdpSocket;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    const QUEUE_CAPACITY: usize = 256;

    #[derive(Default)]
    struct State {
        config: Option<ExternalTransportConfig>,
        endpoint: ExternalTransportEndpoint,
        sender: Option<mpsc::Sender<Vec<u8>>>,
        cancellation: Option<CancellationToken>,
    }

    struct TokioUdpTransport {
        runtime: tokio::runtime::Handle,
        state: Arc<Mutex<State>>,
    }

    impl TokioUdpTransport {
        fn new() -> Self {
            Self {
                runtime: tokio::runtime::Handle::current(),
                state: Arc::new(Mutex::new(State::default())),
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, State> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    impl ExternalTransport for TokioUdpTransport {
        fn configure(&self, config: &ExternalTransportConfig) -> bool {
            if !config.protocol.to_ascii_lowercase().starts_with("udp") {
                return false;
            }
            self.state().config = Some(config.clone());
            true
        }

        fn start(&self, io: ExternalTransportIo) {
            let Some(config) = self.state().config.clone() else {
                return;
            };
            let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
            let cancellation = CancellationToken::new();
            {
                let mut state = self.state();
                state.sender = Some(sender);
                state.cancellation = Some(cancellation.clone());
            }
            let state = self.state.clone();
            self.runtime.spawn(async move {
                if let Err(error) = run_udp(config, io.clone(), state, receiver, cancellation).await
                {
                    let _ = io.error(&error.to_string());
                }
            });
        }

        fn stop(&self) {
            if let Some(cancellation) = self.state().cancellation.take() {
                cancellation.cancel();
            }
            self.state().sender = None;
        }

        fn send(&self, packet: &[u8]) -> bool {
            self.state()
                .sender
                .as_ref()
                .is_some_and(|sender| sender.try_send(packet.to_vec()).is_ok())
        }

        fn send_queue_empty(&self) -> bool {
            self.send_queue_size() == 0
        }

        fn has_send_queue(&self) -> bool {
            true
        }

        fn send_queue_size(&self) -> usize {
            self.state()
                .sender
                .as_ref()
                .map_or(0, |sender| sender.max_capacity() - sender.capacity())
        }

        fn endpoint(&self) -> ExternalTransportEndpoint {
            self.state().endpoint.clone()
        }
    }

    async fn run_udp(
        config: ExternalTransportConfig,
        io: ExternalTransportIo,
        state: Arc<Mutex<State>>,
        mut outbound: mpsc::Receiver<Vec<u8>>,
        cancellation: CancellationToken,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        io.pre_resolve()?;
        let mut resolved =
            tokio::net::lookup_host((config.host.as_str(), config.port.parse()?)).await?;
        let remote = resolved.next().ok_or("DNS returned no addresses")?;
        let bind = if remote.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(remote).await?;
        {
            let mut state = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.endpoint = endpoint(&config, remote);
        }
        io.connecting()?;

        let mut buffer = vec![0; 65_536];
        loop {
            tokio::select! {
                () = cancellation.cancelled() => break,
                packet = outbound.recv() => match packet {
                    Some(packet) => {
                        socket.send(&packet).await?;
                        io.needs_send()?;
                    }
                    None => break,
                },
                received = socket.recv(&mut buffer) => {
                    let length = received?;
                    io.receive(&buffer[..length])?;
                }
            }
        }
        Ok(())
    }

    fn endpoint(config: &ExternalTransportConfig, remote: SocketAddr) -> ExternalTransportEndpoint {
        ExternalTransportEndpoint {
            host: config.host.clone(),
            port: remote.port().to_string(),
            protocol: config.protocol.clone(),
            ip_address: remote.ip().to_string(),
        }
    }

    struct Handler {
        transport: TokioUdpTransport,
    }

    impl EventHandler for Handler {
        fn external_transport(&self) -> Option<&dyn ExternalTransport> {
            Some(&self.transport)
        }
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let path = env::args().nth(1).ok_or("pass a client.ovpn path")?;
        let profile = tokio::fs::read_to_string(path).await?;
        let client = Client::new(Handler {
            transport: TokioUdpTransport::new(),
        })?;
        let evaluation = client.evaluate(Config::new(profile)).await?;
        if !evaluation.autologin {
            client
                .provide_credentials(Credentials::new(
                    env::var("OPENVPN_USERNAME")?,
                    env::var("OPENVPN_PASSWORD")?,
                ))
                .await?;
        }
        let session = client.connect().await?;
        let handle = session.handle();
        tokio::select! {
            result = session => {
                let status = result?;
                println!("{}: {}", status.status, status.message);
            }
            signal = tokio::signal::ctrl_c() => {
                signal?;
                handle.stop().await?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "external-transport")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enabled::run().await
}

#[cfg(not(feature = "external-transport"))]
fn main() {
    eprintln!("enable the `external-transport` feature to run this example");
}
