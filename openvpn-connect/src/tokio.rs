//! Tokio-native OpenVPN client sessions.
//!
//! The native Core owns one blocking worker for each active session. All
//! session controls are serialized through a bounded Tokio channel, while
//! events, logs, and application-control messages are broadcast as streams.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tokio_stream::wrappers::BroadcastStream;
use tokio_util::sync::CancellationToken;

use crate::{
    AppControlMessage, Config, ConnectionInfo, Credentials, Error, Evaluation, Event, EventHandler,
    ExternalPkiCertificate, ExternalPkiCertificateRequest, ExternalPkiError,
    ExternalPkiSignRequest, ExternalTransport, ExternalTun, InterfaceStats, RemoteOverride, Result,
    SessionToken, Statistic, Status, TransportStats, TunBuilder,
};

const DEFAULT_BROADCAST_CAPACITY: usize = 256;
const DEFAULT_COMMAND_CAPACITY: usize = 32;

/// Boxed future returned by [`AsyncEventHandler`] request callbacks.
pub type CallbackFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Tokio-aware callback handler for platform operations that may need async I/O.
///
/// OpenVPN Core invokes these callbacks synchronously on its dedicated blocking
/// connection thread. This adapter waits there while the returned future runs
/// on the caller's Tokio runtime, so no Tokio worker thread is blocked.
pub trait AsyncEventHandler: Send + Sync + 'static {
    fn event(&self, _event: Event) {}

    fn log(&self, _text: &str) {}

    fn app_control_message(&self, _message: AppControlMessage) {}

    fn socket_protect(
        &self,
        _socket: isize,
        _remote: String,
        _ipv6: bool,
    ) -> CallbackFuture<'_, bool> {
        Box::pin(async { true })
    }

    fn pause_on_connection_timeout(&self) -> CallbackFuture<'_, bool> {
        Box::pin(async { false })
    }

    fn clock_tick(&self) {}

    fn remote_override_enabled(&self) -> bool {
        false
    }

    fn remote_override(&self) -> CallbackFuture<'_, std::result::Result<RemoteOverride, String>> {
        Box::pin(async { Err("remote override callback is not implemented".into()) })
    }

    fn tun_builder(&self) -> Option<&dyn TunBuilder> {
        None
    }

    fn external_transport(&self) -> Option<&dyn ExternalTransport> {
        None
    }

    fn external_tun(&self) -> Option<&dyn ExternalTun> {
        None
    }

    fn external_pki_certificate(
        &self,
        _request: ExternalPkiCertificateRequest,
    ) -> CallbackFuture<'_, std::result::Result<ExternalPkiCertificate, ExternalPkiError>> {
        Box::pin(async {
            Err(ExternalPkiError::new(
                "external PKI certificate callback is not implemented",
            ))
        })
    }

    fn external_pki_sign(
        &self,
        _request: ExternalPkiSignRequest,
    ) -> CallbackFuture<'_, std::result::Result<String, ExternalPkiError>> {
        Box::pin(async {
            Err(ExternalPkiError::new(
                "external PKI signing callback is not implemented",
            ))
        })
    }
}

/// Reads a profile and resolves file references on Tokio's blocking pool.
pub async fn merge_config_path(
    path: impl Into<String>,
    follow_references: bool,
) -> Result<crate::MergedConfig> {
    let path = path.into();
    run_blocking_value(move || crate::merge_config_path(&path, follow_references)).await
}

/// Merges inline profile content on Tokio's blocking pool.
pub async fn merge_config_string(content: impl Into<String>) -> Result<crate::MergedConfig> {
    let content = content.into();
    run_blocking_value(move || crate::merge_config_string(&content)).await
}

/// Evaluates a profile without allocating a stateful client.
pub async fn evaluate_config(config: Config) -> Result<Evaluation> {
    run_blocking(move || crate::evaluate_config(&config)).await
}

/// Runs the Core crypto backend self-test outside Tokio worker threads.
pub async fn crypto_self_test() -> Result<String> {
    run_blocking_value(crate::crypto_self_test).await
}

/// Builder for a Tokio-native [`Client`].
pub struct ClientBuilder {
    handler: BuilderHandler,
    event_capacity: usize,
    log_capacity: usize,
    app_control_capacity: usize,
    command_capacity: usize,
}

enum BuilderHandler {
    Sync(Arc<dyn EventHandler>),
    Async(Arc<dyn AsyncEventHandler>),
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            handler: BuilderHandler::Sync(Arc::new(())),
            event_capacity: DEFAULT_BROADCAST_CAPACITY,
            log_capacity: DEFAULT_BROADCAST_CAPACITY,
            app_control_capacity: DEFAULT_BROADCAST_CAPACITY,
            command_capacity: DEFAULT_COMMAND_CAPACITY,
        }
    }
}

impl ClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn handler(mut self, handler: impl EventHandler) -> Self {
        self.handler = BuilderHandler::Sync(Arc::new(handler));
        self
    }

    /// Installs callbacks whose request/response operations can await Tokio I/O.
    #[must_use]
    pub fn async_handler(mut self, handler: impl AsyncEventHandler) -> Self {
        self.handler = BuilderHandler::Async(Arc::new(handler));
        self
    }

    #[must_use]
    pub fn event_capacity(mut self, capacity: usize) -> Self {
        self.event_capacity = capacity.max(1);
        self
    }

    #[must_use]
    pub fn log_capacity(mut self, capacity: usize) -> Self {
        self.log_capacity = capacity.max(1);
        self
    }

    #[must_use]
    pub fn app_control_capacity(mut self, capacity: usize) -> Self {
        self.app_control_capacity = capacity.max(1);
        self
    }

    #[must_use]
    pub fn command_capacity(mut self, capacity: usize) -> Self {
        self.command_capacity = capacity.max(1);
        self
    }

    pub fn build(self) -> Result<Client> {
        let (events, _) = broadcast::channel(self.event_capacity);
        let (logs, _) = broadcast::channel(self.log_capacity);
        let (app_control, _) = broadcast::channel(self.app_control_capacity);
        let delegate: Arc<dyn EventHandler> = match self.handler {
            BuilderHandler::Sync(handler) => handler,
            BuilderHandler::Async(handler) => Arc::new(AsyncHandlerBridge {
                handler,
                runtime: tokio::runtime::Handle::try_current().map_err(|error| {
                    Error::Runtime(format!(
                        "an active Tokio runtime is required for async callbacks: {error}"
                    ))
                })?,
            }),
        };
        let handler = BroadcastHandler {
            delegate,
            events: events.clone(),
            logs: logs.clone(),
            app_control: app_control.clone(),
        };
        Ok(Client {
            core: crate::Client::new(handler)?,
            events,
            logs,
            app_control,
            setup: Arc::new(Mutex::new(())),
            session_active: Arc::new(AtomicBool::new(false)),
            command_capacity: self.command_capacity,
        })
    }
}

/// A cloneable Tokio-native OpenVPN client.
#[derive(Clone)]
pub struct Client {
    core: crate::Client,
    events: broadcast::Sender<Event>,
    logs: broadcast::Sender<String>,
    app_control: broadcast::Sender<AppControlMessage>,
    setup: Arc<Mutex<()>>,
    session_active: Arc<AtomicBool>,
    command_capacity: usize,
}

impl Client {
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn new(handler: impl EventHandler) -> Result<Self> {
        ClientBuilder::new().handler(handler).build()
    }

    /// Creates a client with Tokio-aware request callbacks.
    pub fn new_async(handler: impl AsyncEventHandler) -> Result<Self> {
        ClientBuilder::new().async_handler(handler).build()
    }

    pub fn without_callbacks() -> Result<Self> {
        ClientBuilder::new().build()
    }

    /// Parses and stores a profile without blocking a Tokio worker thread.
    pub async fn evaluate(&self, config: Config) -> Result<Evaluation> {
        let setup = self.setup.clone().lock_owned().await;
        self.ensure_idle()?;
        let core = self.core.clone();
        run_blocking(move || {
            let _setup = setup;
            core.evaluate(&config)
        })
        .await
    }

    /// Supplies credentials before a session is started.
    pub async fn provide_credentials(&self, credentials: Credentials) -> Result<Status> {
        let setup = self.setup.clone().lock_owned().await;
        self.ensure_idle()?;
        let core = self.core.clone();
        run_blocking(move || {
            let _setup = setup;
            core.provide_credentials(&credentials)
        })
        .await
    }

    /// Starts a session and immediately returns its future and control handle.
    pub async fn connect(&self) -> Result<Session> {
        let _setup = self.setup.lock().await;
        self.session_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::InvalidState("the client is already connecting"))?;

        let (commands, receiver) = mpsc::channel(self.command_capacity);
        let cancellation = CancellationToken::new();
        let (completion_sender, completion) = oneshot::channel();
        let (started_sender, started) = oneshot::channel();
        let handle = SessionHandle {
            commands,
            cancellation: cancellation.clone(),
            core: self.core.clone(),
        };
        spawn_driver(
            self.core.clone(),
            self.session_active.clone(),
            cancellation,
            receiver,
            started_sender,
            completion_sender,
        );
        started.await.map_err(|_| {
            self.session_active.store(false, Ordering::Release);
            Error::Runtime("OpenVPN session worker exited before starting Core".into())
        })?;
        Ok(Session {
            handle,
            completion: Some(completion),
            completed: false,
        })
    }

    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    #[must_use]
    pub fn event_stream(&self) -> BroadcastStream<Event> {
        BroadcastStream::new(self.subscribe_events())
    }

    #[must_use]
    pub fn subscribe_logs(&self) -> broadcast::Receiver<String> {
        self.logs.subscribe()
    }

    #[must_use]
    pub fn log_stream(&self) -> BroadcastStream<String> {
        BroadcastStream::new(self.subscribe_logs())
    }

    #[must_use]
    pub fn subscribe_app_control(&self) -> broadcast::Receiver<AppControlMessage> {
        self.app_control.subscribe()
    }

    #[must_use]
    pub fn app_control_stream(&self) -> BroadcastStream<AppControlMessage> {
        BroadcastStream::new(self.subscribe_app_control())
    }

    fn ensure_idle(&self) -> Result<()> {
        if self.session_active.load(Ordering::Acquire) {
            Err(Error::InvalidState(
                "cannot mutate configuration while the client is connecting",
            ))
        } else {
            Ok(())
        }
    }
}

struct AsyncHandlerBridge {
    handler: Arc<dyn AsyncEventHandler>,
    runtime: tokio::runtime::Handle,
}

impl EventHandler for AsyncHandlerBridge {
    fn event(&self, event: Event) {
        self.handler.event(event);
    }

    fn log(&self, text: &str) {
        self.handler.log(text);
    }

    fn app_control_message(&self, message: AppControlMessage) {
        self.handler.app_control_message(message);
    }

    fn socket_protect(&self, socket: isize, remote: &str, ipv6: bool) -> bool {
        self.runtime
            .block_on(self.handler.socket_protect(socket, remote.to_owned(), ipv6))
    }

    fn pause_on_connection_timeout(&self) -> bool {
        self.runtime
            .block_on(self.handler.pause_on_connection_timeout())
    }

    fn clock_tick(&self) {
        self.handler.clock_tick();
    }

    fn remote_override_enabled(&self) -> bool {
        self.handler.remote_override_enabled()
    }

    fn remote_override(&self) -> std::result::Result<RemoteOverride, String> {
        self.runtime.block_on(self.handler.remote_override())
    }

    fn tun_builder(&self) -> Option<&dyn TunBuilder> {
        self.handler.tun_builder()
    }

    fn external_transport(&self) -> Option<&dyn ExternalTransport> {
        self.handler.external_transport()
    }

    fn external_tun(&self) -> Option<&dyn ExternalTun> {
        self.handler.external_tun()
    }

    fn external_pki_certificate(
        &self,
        request: ExternalPkiCertificateRequest,
    ) -> std::result::Result<ExternalPkiCertificate, ExternalPkiError> {
        self.runtime
            .block_on(self.handler.external_pki_certificate(request))
    }

    fn external_pki_sign(
        &self,
        request: ExternalPkiSignRequest,
    ) -> std::result::Result<String, ExternalPkiError> {
        self.runtime
            .block_on(self.handler.external_pki_sign(request))
    }
}

/// Cloneable asynchronous controls and live queries for a running [`Session`].
#[derive(Clone)]
pub struct SessionHandle {
    commands: mpsc::Sender<Command>,
    cancellation: CancellationToken,
    core: crate::Client,
}

impl SessionHandle {
    /// Requests a clean stop and marks the cancellation token as cancelled.
    pub async fn stop(&self) -> Result<()> {
        self.request(Command::Stop).await?;
        self.cancellation.cancel();
        Ok(())
    }

    /// Requests termination without waiting for the command actor.
    pub fn cancel(&self) {
        self.cancellation.cancel();
        self.core.stop();
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub async fn pause(&self, reason: impl Into<String>) -> Result<()> {
        let reason = reason.into();
        self.request(|reply| Command::Pause { reason, reply }).await
    }

    pub async fn resume(&self) -> Result<()> {
        self.request(Command::Resume).await
    }

    pub async fn reconnect(&self, seconds: i32) -> Result<()> {
        self.request(|reply| Command::Reconnect { seconds, reply })
            .await
    }

    pub async fn post_control_message(&self, message: impl Into<String>) -> Result<()> {
        let message = message.into();
        self.request(|reply| Command::PostControl { message, reply })
            .await
    }

    pub async fn send_app_control_message(
        &self,
        protocol: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<()> {
        let protocol = protocol.into();
        let message = message.into();
        self.request(|reply| Command::SendAppControl {
            protocol,
            message,
            reply,
        })
        .await
    }

    pub async fn start_certificate_check(
        &self,
        client_certificate: impl Into<String>,
        client_key: impl Into<String>,
        ca: Option<String>,
    ) -> Result<Status> {
        let client_certificate = client_certificate.into();
        let client_key = client_key.into();
        self.query(|reply| Command::StartCertCheck {
            client_certificate,
            client_key,
            ca,
            reply,
        })
        .await?
    }

    pub async fn start_external_pki_certificate_check(
        &self,
        alias: impl Into<String>,
        ca: Option<String>,
    ) -> Result<Status> {
        let alias = alias.into();
        self.query(|reply| Command::StartEpkiCertCheck { alias, ca, reply })
            .await?
    }

    pub async fn connection_info(&self) -> Result<Option<ConnectionInfo>> {
        self.query(Command::ConnectionInfo).await
    }

    pub async fn session_token(&self) -> Result<Option<SessionToken>> {
        self.query(Command::SessionToken).await
    }

    pub async fn statistics(&self) -> Result<Vec<Statistic>> {
        self.query(Command::Statistics).await
    }

    pub async fn interface_stats(&self) -> Result<InterfaceStats> {
        self.query(Command::InterfaceStats).await
    }

    pub async fn transport_stats(&self) -> Result<TransportStats> {
        self.query(Command::TransportStats).await
    }

    async fn request(&self, build: impl FnOnce(oneshot::Sender<()>) -> Command) -> Result<()> {
        self.query(build).await
    }

    async fn query<T>(&self, build: impl FnOnce(oneshot::Sender<T>) -> Command) -> Result<T> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(build(reply))
            .await
            .map_err(|_| Error::SessionClosed)?;
        response.await.map_err(|_| Error::SessionClosed)
    }
}

/// A running OpenVPN session. It is itself a `Future<Output = Result<Status>>`.
///
/// Dropping an unfinished session is cancellation-safe: Core receives `stop()`
/// and its blocking worker is allowed to finish cleanup in the background.
pub struct Session {
    handle: SessionHandle,
    completion: Option<oneshot::Receiver<Result<Status>>>,
    completed: bool,
}

impl Session {
    #[must_use]
    pub fn handle(&self) -> SessionHandle {
        self.handle.clone()
    }

    #[must_use]
    pub fn cancellation_token(&self) -> CancellationToken {
        self.handle.cancellation_token()
    }

    pub async fn wait(self) -> Result<Status> {
        self.await
    }
}

impl Future for Session {
    type Output = Result<Status>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(completion) = self.completion.as_mut() else {
            return Poll::Ready(Err(Error::SessionClosed));
        };
        match Pin::new(completion).poll(context) {
            Poll::Ready(Ok(result)) => {
                self.completed = true;
                self.completion = None;
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => {
                self.completed = true;
                self.completion = None;
                Poll::Ready(Err(Error::Runtime(
                    "OpenVPN session driver exited without a result".into(),
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.completed {
            self.handle.cancel();
        }
    }
}

enum Command {
    Stop(oneshot::Sender<()>),
    Pause {
        reason: String,
        reply: oneshot::Sender<()>,
    },
    Resume(oneshot::Sender<()>),
    Reconnect {
        seconds: i32,
        reply: oneshot::Sender<()>,
    },
    PostControl {
        message: String,
        reply: oneshot::Sender<()>,
    },
    SendAppControl {
        protocol: String,
        message: String,
        reply: oneshot::Sender<()>,
    },
    StartCertCheck {
        client_certificate: String,
        client_key: String,
        ca: Option<String>,
        reply: oneshot::Sender<Result<Status>>,
    },
    StartEpkiCertCheck {
        alias: String,
        ca: Option<String>,
        reply: oneshot::Sender<Result<Status>>,
    },
    ConnectionInfo(oneshot::Sender<Option<ConnectionInfo>>),
    SessionToken(oneshot::Sender<Option<SessionToken>>),
    Statistics(oneshot::Sender<Vec<Statistic>>),
    InterfaceStats(oneshot::Sender<InterfaceStats>),
    TransportStats(oneshot::Sender<TransportStats>),
}

fn spawn_driver(
    core: crate::Client,
    session_active: Arc<AtomicBool>,
    cancellation: CancellationToken,
    mut commands: mpsc::Receiver<Command>,
    started: oneshot::Sender<()>,
    completion: oneshot::Sender<Result<Status>>,
) {
    let connection_core = core.clone();
    let mut connection = tokio::task::spawn_blocking(move || {
        connection_core.connect_with_started(|| {
            let _ = started.send(());
        })
    });
    let active_guard = ActiveSessionGuard {
        core: core.clone(),
        active: session_active,
    };
    tokio::spawn(async move {
        let mut commands_open = true;
        let result = loop {
            tokio::select! {
                joined = &mut connection => break flatten_join(joined),
                () = cancellation.cancelled() => {
                    core.stop();
                    break flatten_join(connection.await);
                }
                command = commands.recv(), if commands_open => {
                    match command {
                        Some(command) => run_command(&core, command).await,
                        None => commands_open = false,
                    }
                }
            }
        };
        drop(active_guard);
        let _ = completion.send(result);
    });
}

async fn run_command(core: &crate::Client, command: Command) {
    match command {
        Command::Stop(reply) => {
            core.stop();
            let _ = reply.send(());
        }
        Command::Pause { reason, reply } => {
            core.pause(&reason);
            let _ = reply.send(());
        }
        Command::Resume(reply) => {
            core.resume();
            let _ = reply.send(());
        }
        Command::Reconnect { seconds, reply } => {
            core.reconnect(seconds);
            let _ = reply.send(());
        }
        Command::PostControl { message, reply } => {
            core.post_control_message(&message);
            let _ = reply.send(());
        }
        Command::SendAppControl {
            protocol,
            message,
            reply,
        } => {
            core.send_app_control_message(&protocol, &message);
            let _ = reply.send(());
        }
        Command::StartCertCheck {
            client_certificate,
            client_key,
            ca,
            reply,
        } => {
            let core = core.clone();
            let result = run_blocking(move || {
                core.start_certificate_check(&client_certificate, &client_key, ca.as_deref())
            })
            .await;
            let _ = reply.send(result);
        }
        Command::StartEpkiCertCheck { alias, ca, reply } => {
            let core = core.clone();
            let result = run_blocking(move || {
                core.start_external_pki_certificate_check(&alias, ca.as_deref())
            })
            .await;
            let _ = reply.send(result);
        }
        Command::ConnectionInfo(reply) => {
            let _ = reply.send(core.connection_info());
        }
        Command::SessionToken(reply) => {
            let _ = reply.send(core.session_token());
        }
        Command::Statistics(reply) => {
            let _ = reply.send(core.statistics());
        }
        Command::InterfaceStats(reply) => {
            let _ = reply.send(core.interface_stats());
        }
        Command::TransportStats(reply) => {
            let _ = reply.send(core.transport_stats());
        }
    }
}

struct ActiveSessionGuard {
    core: crate::Client,
    active: Arc<AtomicBool>,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        self.core.stop();
        self.active.store(false, Ordering::Release);
    }
}

fn flatten_join<T>(result: std::result::Result<Result<T>, tokio::task::JoinError>) -> Result<T> {
    result.unwrap_or_else(|error| Err(Error::Runtime(format!("OpenVPN worker failed: {error}"))))
}

async fn run_blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    flatten_join(tokio::task::spawn_blocking(operation).await)
}

async fn run_blocking_value<T: Send + 'static>(
    operation: impl FnOnce() -> T + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| Error::Runtime(format!("OpenVPN worker failed: {error}")))
}

struct BroadcastHandler {
    delegate: Arc<dyn EventHandler>,
    events: broadcast::Sender<Event>,
    logs: broadcast::Sender<String>,
    app_control: broadcast::Sender<AppControlMessage>,
}

impl EventHandler for BroadcastHandler {
    fn event(&self, event: Event) {
        let _ = self.events.send(event.clone());
        self.delegate.event(event);
    }

    fn log(&self, text: &str) {
        let _ = self.logs.send(text.to_owned());
        self.delegate.log(text);
    }

    fn app_control_message(&self, message: AppControlMessage) {
        let _ = self.app_control.send(message.clone());
        self.delegate.app_control_message(message);
    }

    fn socket_protect(&self, socket: isize, remote: &str, ipv6: bool) -> bool {
        self.delegate.socket_protect(socket, remote, ipv6)
    }

    fn pause_on_connection_timeout(&self) -> bool {
        self.delegate.pause_on_connection_timeout()
    }

    fn clock_tick(&self) {
        self.delegate.clock_tick();
    }

    fn remote_override_enabled(&self) -> bool {
        self.delegate.remote_override_enabled()
    }

    fn remote_override(&self) -> std::result::Result<RemoteOverride, String> {
        self.delegate.remote_override()
    }

    fn tun_builder(&self) -> Option<&dyn TunBuilder> {
        self.delegate.tun_builder()
    }

    fn external_transport(&self) -> Option<&dyn ExternalTransport> {
        self.delegate.external_transport()
    }

    fn external_tun(&self) -> Option<&dyn ExternalTun> {
        self.delegate.external_tun()
    }

    fn external_pki_certificate(
        &self,
        request: ExternalPkiCertificateRequest,
    ) -> std::result::Result<ExternalPkiCertificate, ExternalPkiError> {
        self.delegate.external_pki_certificate(request)
    }

    fn external_pki_sign(
        &self,
        request: ExternalPkiSignRequest,
    ) -> std::result::Result<String, ExternalPkiError> {
        self.delegate.external_pki_sign(request)
    }
}
