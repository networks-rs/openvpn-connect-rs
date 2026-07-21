//! Tokio-native External PKI and remote-override callbacks. Real applications
//! can await a key-store service, HSM, UI broker, or DNS/service-discovery API.

use openvpn_connect::tokio::{AsyncEventHandler, CallbackFuture, Client};
use openvpn_connect::{
    ExternalPkiCertificate, ExternalPkiCertificateRequest, ExternalPkiError,
    ExternalPkiSignRequest, RemoteOverride,
};

struct AsyncPlatform;

impl AsyncEventHandler for AsyncPlatform {
    fn remote_override_enabled(&self) -> bool {
        true
    }

    fn remote_override(&self) -> CallbackFuture<'_, Result<RemoteOverride, String>> {
        Box::pin(async {
            // Replace with async service discovery.
            Ok(RemoteOverride {
                host: "vpn.example.test".into(),
                ip: String::new(),
                port: "1194".into(),
                protocol: "udp".into(),
            })
        })
    }

    fn external_pki_certificate(
        &self,
        request: ExternalPkiCertificateRequest,
    ) -> CallbackFuture<'_, Result<ExternalPkiCertificate, ExternalPkiError>> {
        Box::pin(async move {
            Err(ExternalPkiError::new(format!(
                "fetch alias {} asynchronously from your key store",
                request.alias
            )))
        })
    }

    fn external_pki_sign(
        &self,
        request: ExternalPkiSignRequest,
    ) -> CallbackFuture<'_, Result<String, ExternalPkiError>> {
        Box::pin(async move {
            Err(ExternalPkiError::new(format!(
                "sign {} asynchronously and return a base64 signature",
                request.algorithm
            )))
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _client = Client::new_async(AsyncPlatform)?;
    println!("Tokio-aware callback client initialized");
    Ok(())
}
