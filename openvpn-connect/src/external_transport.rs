use std::ptr::NonNull;

use openvpn_connect_sys as sys;

use crate::{Error, Result};

/// Configuration supplied before Core creates a custom transport session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalTransportConfig {
    pub host: String,
    pub port: String,
    pub protocol: String,
    /// Fault-injection parameters requested by `Config::gremlin_config`.
    pub gremlin_config: String,
    /// Every selectable `remote` entry from the profile.
    pub remotes: Vec<ExternalRemote>,
    pub server_address_float: bool,
    pub synchronous_dns_lookup: bool,
}

/// One profile `remote` entry available to a custom transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalRemote {
    pub host: String,
    pub port: String,
    pub protocol: String,
}

/// The endpoint currently used by a custom transport.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExternalTransportEndpoint {
    pub host: String,
    pub port: String,
    pub protocol: String,
    /// Resolved numeric IPv4 or IPv6 address.
    pub ip_address: String,
}

/// Application-supplied packet transport used when the
/// `external-transport` Cargo feature is enabled.
///
/// Core calls these methods on its blocking connection thread. The transport
/// may perform I/O on any thread and return packets/events through the cloned
/// [`ExternalTransportIo`] handle.
pub trait ExternalTransport: Send + Sync + 'static {
    /// Accepts or rejects a new transport session.
    fn configure(&self, _config: &ExternalTransportConfig) -> bool {
        false
    }

    fn start(&self, _io: ExternalTransportIo) {}

    fn stop(&self) {}

    /// Sends one complete OpenVPN transport packet.
    fn send(&self, _packet: &[u8]) -> bool {
        false
    }

    fn send_queue_empty(&self) -> bool {
        true
    }

    fn has_send_queue(&self) -> bool {
        false
    }

    fn stop_requeueing(&self) {}

    fn send_queue_size(&self) -> usize {
        0
    }

    fn reset_align_adjust(&self, _align_adjust: usize) {}

    fn endpoint(&self) -> ExternalTransportEndpoint {
        ExternalTransportEndpoint::default()
    }

    /// Returns a platform socket descriptor/handle, or `None` when unavailable.
    fn native_handle(&self) -> Option<isize> {
        None
    }

    fn is_relay(&self) -> bool {
        false
    }

    fn process_push(&self, _options: &str) {}
}

/// Thread-safe route back into OpenVPN Core for a custom transport.
pub struct ExternalTransportIo {
    raw: NonNull<sys::ovpn_external_transport_handle>,
}

impl ExternalTransportIo {
    pub(crate) unsafe fn retain(raw: *mut sys::ovpn_external_transport_handle) -> Option<Self> {
        if raw.is_null() {
            return None;
        }
        // SAFETY: C++ supplies a live borrowed handle; retain creates an owned reference.
        let retained = unsafe { sys::ovpn_external_transport_handle_retain(raw) };
        NonNull::new(retained).map(|raw| Self { raw })
    }

    /// Delivers a complete packet received from the custom transport.
    pub fn receive(&self, packet: &[u8]) -> Result<()> {
        // SAFETY: the owned handle is live and the native side copies `packet`.
        let accepted = unsafe {
            sys::ovpn_external_transport_receive(self.raw.as_ptr(), packet.as_ptr(), packet.len())
        };
        active_result(accepted)
    }

    pub fn needs_send(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_transport_needs_send(self.raw.as_ptr()) })
    }

    /// Reports a fatal general transport error.
    pub fn error(&self, message: &str) -> Result<()> {
        // SAFETY: this static query has no preconditions.
        let error_code = unsafe { sys::ovpn_error_code_transport() };
        self.error_with_code(error_code, message)
    }

    /// Reports a fatal transport error using an advanced
    /// `openvpn::Error::Type` numeric code.
    pub fn error_with_code(&self, error_code: i32, message: &str) -> Result<()> {
        // SAFETY: the handle is live and C++ copies the string before returning.
        active_result(unsafe {
            sys::ovpn_external_transport_error(self.raw.as_ptr(), error_code, view(message))
        })
    }

    /// Reports a fatal general proxy error.
    pub fn proxy_error(&self, message: &str) -> Result<()> {
        // SAFETY: this static query has no preconditions.
        let error_code = unsafe { sys::ovpn_error_code_proxy() };
        self.proxy_error_with_code(error_code, message)
    }

    /// Reports a fatal proxy error using an advanced `openvpn::Error::Type` code.
    pub fn proxy_error_with_code(&self, error_code: i32, message: &str) -> Result<()> {
        // SAFETY: the handle is live and C++ copies the string before returning.
        active_result(unsafe {
            sys::ovpn_external_transport_proxy_error(self.raw.as_ptr(), error_code, view(message))
        })
    }

    pub fn pre_resolve(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_transport_pre_resolve(self.raw.as_ptr()) })
    }

    pub fn wait_proxy(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_transport_wait_proxy(self.raw.as_ptr()) })
    }

    pub fn wait(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_transport_wait(self.raw.as_ptr()) })
    }

    pub fn connecting(&self) -> Result<()> {
        // SAFETY: the owned handle is live.
        active_result(unsafe { sys::ovpn_external_transport_connecting(self.raw.as_ptr()) })
    }

    #[must_use]
    pub fn is_openvpn_protocol(&self) -> bool {
        // SAFETY: the owned handle is live; inactive handles return false.
        unsafe { sys::ovpn_external_transport_is_openvpn_protocol(self.raw.as_ptr()) != 0 }
    }

    #[must_use]
    pub fn is_keepalive_enabled(&self) -> bool {
        // SAFETY: the owned handle is live; inactive handles return false.
        unsafe { sys::ovpn_external_transport_is_keepalive_enabled(self.raw.as_ptr()) != 0 }
    }

    /// Disables Core keepalive and returns its `(ping, timeout)` seconds.
    pub fn disable_keepalive(&self) -> Result<(u32, u32)> {
        let mut ping = 0;
        let mut timeout = 0;
        // SAFETY: output pointers and the owned handle are valid.
        let accepted = unsafe {
            sys::ovpn_external_transport_disable_keepalive(
                self.raw.as_ptr(),
                &raw mut ping,
                &raw mut timeout,
            )
        };
        active_result(accepted).map(|()| (ping, timeout))
    }
}

impl Clone for ExternalTransportIo {
    fn clone(&self) -> Self {
        // SAFETY: retaining an owned live handle creates another owned reference.
        unsafe { Self::retain(self.raw.as_ptr()) }.expect("live external transport handle")
    }
}

impl Drop for ExternalTransportIo {
    fn drop(&mut self) {
        // SAFETY: this releases exactly the reference owned by `self`.
        unsafe { sys::ovpn_external_transport_handle_free(self.raw.as_ptr()) };
    }
}

// SAFETY: all handle operations synchronize with the Core I/O context and copy
// caller-owned data before returning.
unsafe impl Send for ExternalTransportIo {}
// SAFETY: the native handle implementation serializes access to session state.
unsafe impl Sync for ExternalTransportIo {}

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
