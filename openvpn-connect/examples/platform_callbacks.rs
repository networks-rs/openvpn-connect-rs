//! Shows the platform integration points used by Android, iOS, `OpenHarmony`,
//! custom DNS/route implementations, External PKI, and DCO `TunBuilder` builds.

use openvpn_connect::{
    DcoKeyConfig, DcoPeer, DnsOptions, EventHandler, ExternalPkiCertificate,
    ExternalPkiCertificateRequest, ExternalPkiError, ExternalPkiSignRequest, RemoteOverride,
    TunBuilder,
};

struct PlatformTunnel;

impl TunBuilder for PlatformTunnel {
    fn new_tunnel(&self) -> bool {
        true
    }

    fn set_layer(&self, layer: i32) -> bool {
        layer == 3
    }

    fn set_remote_address(&self, address: &str, ipv6: bool) -> bool {
        println!("remote {address}, IPv6={ipv6}");
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
        println!("address {address}/{prefix_length} via {gateway}, IPv6={ipv6}, net30={net30}");
        true
    }

    fn reroute_gateway(&self, ipv4: bool, ipv6: bool, flags: u32) -> bool {
        println!("reroute IPv4={ipv4}, IPv6={ipv6}, flags={flags:#x}");
        true
    }

    fn add_route(&self, address: &str, prefix: i32, metric: i32, ipv6: bool) -> bool {
        println!("route {address}/{prefix}, metric={metric}, IPv6={ipv6}");
        true
    }

    fn exclude_route(&self, address: &str, prefix: i32, metric: i32, ipv6: bool) -> bool {
        println!("exclude {address}/{prefix}, metric={metric}, IPv6={ipv6}");
        true
    }

    fn set_dns_options(&self, dns: &DnsOptions) -> bool {
        println!("DNS: {dns:?}");
        true
    }

    fn set_mtu(&self, mtu: i32) -> bool {
        println!("MTU: {mtu}");
        true
    }

    fn establish(&self) -> i32 {
        // Return an owned descriptor obtained from the platform VPN API.
        -1
    }

    fn teardown(&self, disconnect: bool) {
        println!("tunnel teardown, final disconnect={disconnect}");
    }

    fn dco_available(&self) -> bool {
        false
    }

    fn dco_new_peer(&self, peer: DcoPeer) {
        println!("DCO peer {} at {}", peer.peer_id, peer.remote_ip);
    }

    fn dco_new_key(&self, slot: u32, key: DcoKeyConfig) {
        // Key material is intentionally not Debug. Transfer it directly to the
        // platform DCO API and zeroize it there after installation.
        println!("DCO key slot {slot}, key id {}", key.key_id);
    }
}

struct PlatformHandler {
    tunnel: PlatformTunnel,
}

impl EventHandler for PlatformHandler {
    fn socket_protect(&self, socket: isize, remote: &str, ipv6: bool) -> bool {
        println!("protect socket {socket} for {remote}, IPv6={ipv6}");
        true
    }

    fn remote_override_enabled(&self) -> bool {
        true
    }

    fn remote_override(&self) -> Result<RemoteOverride, String> {
        Ok(RemoteOverride {
            host: "vpn.example.test".into(),
            ip: String::new(),
            port: "1194".into(),
            protocol: "udp".into(),
        })
    }

    fn tun_builder(&self) -> Option<&dyn TunBuilder> {
        Some(&self.tunnel)
    }

    fn external_pki_certificate(
        &self,
        request: ExternalPkiCertificateRequest,
    ) -> Result<ExternalPkiCertificate, ExternalPkiError> {
        Err(ExternalPkiError::new(format!(
            "load certificate for alias {} from the platform key store",
            request.alias
        )))
    }

    fn external_pki_sign(
        &self,
        request: ExternalPkiSignRequest,
    ) -> Result<String, ExternalPkiError> {
        Err(ExternalPkiError::new(format!(
            "sign {} bytes with alias {} and return base64",
            request.data.len(),
            request.alias
        )))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _client = openvpn_connect::Client::new(PlatformHandler {
        tunnel: PlatformTunnel,
    })?;
    println!("platform callback client initialized");
    Ok(())
}
