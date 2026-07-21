use std::ptr::NonNull;

use openvpn_connect_sys as sys;

use crate::{Error, Result};

/// Static tunnel settings supplied by OpenVPN Core's external TUN factory.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ExternalTunConfig {
    pub session_name: String,
    pub layer: i32,
    pub mtu: i32,
    pub mtu_max: i32,
    pub google_dns_fallback: bool,
    pub dhcp_search_domains_as_split_domains: bool,
    pub allow_local_lan_access: bool,
    pub remote_bypass: bool,
    pub tun_persist: bool,
}

/// Per-start options and negotiated data-channel properties.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalTunStartConfig {
    pub options: String,
    pub cipher_algorithm: u32,
    pub digest_algorithm: u32,
    pub key_derivation: u32,
    pub use_epoch_keys: bool,
}

/// Live interface information reported by an external TUN implementation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExternalTunInfo {
    pub name: String,
    pub vpn_ipv4: String,
    pub vpn_ipv6: String,
    pub gateway_ipv4: String,
    pub gateway_ipv6: String,
    pub mtu: i32,
    /// `None` maps to OpenVPN Core's `INVALID_ADAPTER_INDEX`.
    pub interface_index: Option<u32>,
}

/// Low-level custom tunnel implementation selected by the `external-tun`
/// feature. Unlike [`crate::TunBuilder`], this interface transfers complete IP
/// packets and can replace Core's native TUN object on desktop platforms.
pub trait ExternalTun: Send + Sync + 'static {
    fn configure(&self, _config: &ExternalTunConfig) -> bool {
        false
    }

    fn start(&self, _config: &ExternalTunStartConfig, _io: ExternalTunIo) {}

    fn stop(&self) {}

    fn set_disconnect(&self) {}

    /// Sends one cleartext packet from Core to the platform tunnel.
    fn send(&self, _packet: &[u8]) -> bool {
        false
    }

    fn info(&self) -> ExternalTunInfo {
        ExternalTunInfo::default()
    }

    fn adjust_mss(&self, _mss: i32) {}

    fn apply_push_update(&self, _options: &str) {}

    fn layer_2_supported(&self) -> bool {
        false
    }

    fn supports_epoch_data(&self) -> bool {
        false
    }

    fn finalize(&self, _disconnected: bool) {}
}

/// Thread-safe route back into OpenVPN Core for a custom tunnel.
pub struct ExternalTunIo {
    raw: NonNull<sys::ovpn_external_tun_handle>,
}

impl ExternalTunIo {
    pub(crate) unsafe fn retain(raw: *mut sys::ovpn_external_tun_handle) -> Option<Self> {
        if raw.is_null() {
            return None;
        }
        // SAFETY: C++ supplies a live borrowed handle; retain creates an owned reference.
        let retained = unsafe { sys::ovpn_external_tun_handle_retain(raw) };
        NonNull::new(retained).map(|raw| Self { raw })
    }

    /// Delivers one cleartext packet read from the platform tunnel to Core.
    pub fn receive(&self, packet: &[u8]) -> Result<()> {
        // SAFETY: the owned handle is live and C++ copies the packet.
        active_result(unsafe {
            sys::ovpn_external_tun_receive(self.raw.as_ptr(), packet.as_ptr(), packet.len())
        })
    }

    /// Reports a fatal general TUN error.
    pub fn error(&self, message: &str) -> Result<()> {
        // SAFETY: this static query has no preconditions.
        let error_code = unsafe { sys::ovpn_error_code_tun() };
        self.error_with_code(error_code, message)
    }

    /// Reports a fatal TUN error using an advanced `openvpn::Error::Type` code.
    pub fn error_with_code(&self, error_code: i32, message: &str) -> Result<()> {
        // SAFETY: the owned handle is live and C++ copies the message.
        active_result(unsafe {
            sys::ovpn_external_tun_error(self.raw.as_ptr(), error_code, view(message))
        })
    }

    pub fn pre_tun_config(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_tun_pre_tun_config(self.raw.as_ptr()) })
    }

    pub fn pre_route_config(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_tun_pre_route_config(self.raw.as_ptr()) })
    }

    pub fn connected(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_tun_connected(self.raw.as_ptr()) })
    }
}

impl Clone for ExternalTunIo {
    fn clone(&self) -> Self {
        // SAFETY: retaining an owned live handle creates another owned reference.
        unsafe { Self::retain(self.raw.as_ptr()) }.expect("live external TUN handle")
    }
}

impl Drop for ExternalTunIo {
    fn drop(&mut self) {
        // SAFETY: this releases exactly the reference owned by `self`.
        unsafe { sys::ovpn_external_tun_handle_free(self.raw.as_ptr()) };
    }
}

// SAFETY: all native methods synchronize with the Core I/O context and copy
// Rust-owned buffers before returning.
unsafe impl Send for ExternalTunIo {}
// SAFETY: native state access is serialized internally.
unsafe impl Sync for ExternalTunIo {}

fn active_result(active: i32) -> Result<()> {
    if active != 0 {
        Ok(())
    } else {
        Err(Error::SessionClosed)
    }
}

fn view(value: &str) -> sys::ovpn_string_view {
    sys::ovpn_string_view {
        data: value.as_ptr(),
        len: value.len(),
    }
}
