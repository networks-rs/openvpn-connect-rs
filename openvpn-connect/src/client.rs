use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use openvpn_connect_sys as sys;

use crate::error::{Error, Result};
use crate::native::{self, CallbackState};
use crate::types::{
    Config, ConnectionInfo, Credentials, Evaluation, EventHandler, InterfaceStats, SessionToken,
    Statistic, Status, TransportStats,
};

/// An owned OpenVPN client and cloneable connection-control handle.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Creates a native client and installs its callback handler.
    pub fn new(handler: impl EventHandler) -> Result<Self> {
        let callbacks = Box::new(CallbackState {
            handler: Box::new(handler),
        });
        let context = NonNull::from(callbacks.as_ref()).as_ptr().cast::<c_void>();
        let callback_table = native::callback_table(context);
        let native = native::new_client(&callback_table)?;
        Ok(Self {
            inner: Arc::new(Inner {
                native,
                lifecycle: Mutex::new(Lifecycle::New),
                stop_requested: AtomicBool::new(false),
                _callbacks: callbacks,
            }),
        })
    }

    /// Creates a client whose callbacks use their default behavior.
    pub fn without_callbacks() -> Result<Self> {
        Self::new(())
    }

    /// Parses and validates a profile and stores the configuration for `connect`.
    pub fn evaluate(&self, config: &Config) -> Result<Evaluation> {
        config.validate_capabilities()?;
        let mut lifecycle = self.inner.lifecycle();
        match *lifecycle {
            Lifecycle::Connecting => {
                return Err(Error::InvalidState(
                    "cannot evaluate a profile while the client is connecting",
                ));
            }
            Lifecycle::Finished => {
                return Err(Error::InvalidState(
                    "an OpenVPN client supports one session; create a new client",
                ));
            }
            Lifecycle::New | Lifecycle::Ready => {}
        }
        let evaluation = native::evaluate(self.inner.native, config)?;
        *lifecycle = Lifecycle::Ready;
        Ok(evaluation)
    }

    /// Supplies authentication, proxy, or dynamic-challenge credentials.
    pub fn provide_credentials(&self, credentials: &Credentials) -> Result<Status> {
        let lifecycle = self.inner.lifecycle();
        match *lifecycle {
            Lifecycle::New => {
                return Err(Error::InvalidState(
                    "evaluate a profile before providing credentials",
                ));
            }
            Lifecycle::Connecting => {
                return Err(Error::InvalidState(
                    "cannot replace credentials while the client is connecting",
                ));
            }
            Lifecycle::Finished => {
                return Err(Error::InvalidState(
                    "an OpenVPN client supports one session; create a new client",
                ));
            }
            Lifecycle::Ready => {}
        }
        native::provide_credentials(self.inner.native, credentials)
    }

    /// Runs the VPN session until it disconnects or [`Self::stop`] is called.
    ///
    /// This method blocks. OpenVPN events and logs are delivered synchronously on
    /// the current thread.
    pub fn connect(&self) -> Result<Status> {
        self.prepare_connect()?;
        let reset = ConnectLifecycleReset(&self.inner);
        let result = native::connect(self.inner.native);
        drop(reset);
        result
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn connect_with_started(&self, started: impl FnOnce()) -> Result<Status> {
        let preparation = self.prepare_connect();
        if let Err(error) = preparation {
            started();
            return Err(error);
        }

        let reset = ConnectLifecycleReset(&self.inner);
        let result = native::connect_with_started(self.inner.native, started);
        drop(reset);
        result
    }

    fn prepare_connect(&self) -> Result<()> {
        {
            let mut lifecycle = self.inner.lifecycle();
            match *lifecycle {
                Lifecycle::New => {
                    return Err(Error::InvalidState("evaluate a profile before connecting"));
                }
                Lifecycle::Connecting => {
                    return Err(Error::InvalidState("the client is already connecting"));
                }
                Lifecycle::Finished => {
                    return Err(Error::InvalidState(
                        "an OpenVPN client supports one session; create a new client",
                    ));
                }
                Lifecycle::Ready => *lifecycle = Lifecycle::Connecting,
            }
            self.inner.stop_requested.store(false, Ordering::Release);
        }
        Ok(())
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn ensure_connectable(&self) -> Result<()> {
        match *self.inner.lifecycle() {
            Lifecycle::New => Err(Error::InvalidState("evaluate a profile before connecting")),
            Lifecycle::Connecting => Err(Error::InvalidState("the client is already connecting")),
            Lifecycle::Finished => Err(Error::InvalidState(
                "an OpenVPN client supports one session; create a new client",
            )),
            Lifecycle::Ready => Ok(()),
        }
    }

    /// Starts an application-control-channel certificate check with PEM material.
    pub fn start_certificate_check(
        &self,
        client_certificate: &str,
        client_key: &str,
        ca: Option<&str>,
    ) -> Result<Status> {
        native::start_cert_check(self.inner.native, client_certificate, client_key, ca)
    }

    /// Starts an application-control-channel certificate check through external PKI.
    pub fn start_external_pki_certificate_check(
        &self,
        alias: &str,
        ca: Option<&str>,
    ) -> Result<Status> {
        native::start_cert_check_epki(self.inner.native, alias, ca)
    }

    /// Requests termination of a running session. Safe to call from another thread.
    pub fn stop(&self) {
        if !self.inner.stop_requested.swap(true, Ordering::AcqRel) {
            native::stop(self.inner.native);
        }
    }

    /// Pauses a running session. Safe to call from another thread.
    pub fn pause(&self, reason: &str) {
        native::pause(self.inner.native, reason);
    }

    /// Resumes a paused session. Safe to call from another thread.
    pub fn resume(&self) {
        native::resume(self.inner.native);
    }

    /// Schedules a disconnect/reconnect cycle.
    pub fn reconnect(&self, seconds: i32) {
        native::reconnect(self.inner.native, seconds);
    }

    /// Posts a raw OpenVPN control-channel message.
    pub fn post_control_message(&self, message: &str) {
        native::post_control_message(self.inner.native, message);
    }

    /// Sends a custom application control-channel message.
    pub fn send_app_control_message(&self, protocol: &str, message: &str) {
        native::send_app_control_message(self.inner.native, protocol, message);
    }

    /// Returns details for the most recently connected session.
    #[must_use]
    pub fn connection_info(&self) -> Option<ConnectionInfo> {
        native::connection_info(self.inner.native)
    }

    /// Returns the current session token when one is available.
    #[must_use]
    pub fn session_token(&self) -> Option<SessionToken> {
        native::session_token(self.inner.native)
    }

    /// Returns all named core counters.
    #[must_use]
    pub fn statistics(&self) -> Vec<Statistic> {
        native::statistics(self.inner.native)
    }

    /// Returns TUN interface counters.
    #[must_use]
    pub fn interface_stats(&self) -> InterfaceStats {
        native::interface_stats(self.inner.native)
    }

    /// Returns transport counters.
    #[must_use]
    pub fn transport_stats(&self) -> TransportStats {
        native::transport_stats(self.inner.native)
    }

    /// Runs deterministic native-to-Rust callback probes without opening a VPN.
    ///
    /// This is intended for platform integration and CI smoke tests.
    #[doc(hidden)]
    pub fn callback_self_test(&self) -> Result<Status> {
        native::callback_self_test(self.inner.native)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Lifecycle {
    New,
    Ready,
    Connecting,
    Finished,
}

struct Inner {
    native: NonNull<sys::ovpn_client>,
    lifecycle: Mutex<Lifecycle>,
    stop_requested: AtomicBool,
    _callbacks: Box<CallbackState>,
}

impl Inner {
    fn lifecycle(&self) -> MutexGuard<'_, Lifecycle> {
        self.lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

// SAFETY: OpenVPN documents stop/pause/resume/reconnect and statistics as
// callable from threads other than the blocking connect thread. Configuration
// mutations and connect entry are serialized by `lifecycle`; callbacks require
// `Send + Sync` and remain allocated for the whole native-client lifetime.
unsafe impl Send for Inner {}
// SAFETY: same invariants as the `Send` implementation above.
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        if !self.stop_requested.swap(true, Ordering::AcqRel) {
            native::stop(self.native);
        }
        native::free_client(self.native);
    }
}

struct ConnectLifecycleReset<'a>(&'a Inner);

impl Drop for ConnectLifecycleReset<'_> {
    fn drop(&mut self) {
        *self.0.lifecycle() = Lifecycle::Finished;
    }
}
