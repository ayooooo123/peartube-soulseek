//! Multi-threaded non-blocking Soulseek client session, peer connection broker,
//! search collector, peer share browser, and ticket-matched download coordinator.
//!
//! Security & logging rules:
//! - Credentials (`password`) are never logged at any level and never auto-generated.
//! - Remote/local full paths are redacted to leaf basenames at `info`/`warn`/`error`.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::proto::{
    ConnectionType, DEFAULT_MAJOR_VERSION, DEFAULT_MINOR_VERSION, FrameDecoder, PeerInitMessage,
    PeerMessage, ProtoError, ServerRequest, ServerResponse, SharedFileRecord,
    flatten_shared_folders,
};
use crate::transfer::{
    DownloadOutcome, ProgressCallback, TransferError, TransferPhase, TransferProgress,
    dial_pierced_file_socket, redacted_basename, resolve_dest_file, stream_file_download,
};
use parking_lot::{Mutex, RwLock};

const SERVER_PING_INTERVAL: Duration = Duration::from_secs(45);
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(2);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);
const BROWSE_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PLACE_IN_QUEUE_POLL_INTERVAL: Duration = Duration::from_secs(30);
const MAX_SEARCH_FILES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEvent {
    pub level: LogLevel,
    pub event: String,
    pub message: String,
}

pub type LoggerHook = Arc<dyn Fn(LogEvent) + Send + Sync>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientState {
    pub connected: bool,
    pub logged_in: bool,
    pub privileges: u32,
    pub listen_port: u16,
}

#[derive(Debug, Clone)]
pub enum ClientError {
    InvalidCredentials(String),
    LoginRejected {
        reason: String,
        detail: Option<String>,
    },
    NotLoggedIn,
    Disconnected(String),
    Timeout(String),
    Io(String),
    Protocol(ProtoError),
    Transfer(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials(msg) => write!(f, "invalid credentials: {msg}"),
            Self::LoginRejected {
                reason,
                detail: Some(d),
            } => write!(f, "login rejected by server ({reason}: {d})"),
            Self::LoginRejected {
                reason,
                detail: None,
            } => write!(f, "login rejected by server ({reason})"),
            Self::NotLoggedIn => write!(f, "client is not logged in"),
            Self::Disconnected(msg) => write!(f, "disconnected: {msg}"),
            Self::Timeout(op) => write!(f, "{op} timed out"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Transfer(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ClientError {}

#[derive(Clone)]
struct Credentials {
    server_host: String,
    server_port: u16,
    username: String,
    password: String,
    major_version: u32,
    minor_version: u32,
}

struct ActiveSearch {
    results: Vec<SharedFileRecord>,
    deadline: Instant,
    reply: Option<Sender<Result<Vec<SharedFileRecord>, ClientError>>>,
}

struct ActiveBrowse {
    username: String,
    deadline: Instant,
    slots: bool,
    queue: u32,
    speed: u32,
    got_info: bool,
    files: Option<Vec<SharedFileRecord>>,
    reply: Option<Sender<Result<Vec<SharedFileRecord>, ClientError>>>,
}

struct ActiveDownload {
    id: u64,
    username: String,
    remote_filename: String,
    final_path: PathBuf,
    expected_size: Option<u64>,
    transfer_token: Option<u32>,
    queue_place: Option<u32>,
    in_flight_socket: bool,
    last_queue_poll: Instant,
    cancel: Arc<AtomicBool>,
    progress: Option<ProgressCallback>,
    reply: Option<Sender<Result<DownloadOutcome, ClientError>>>,
}

enum WorkerCmd {
    Login {
        creds: Credentials,
        reply: Sender<Result<ClientState, ClientError>>,
    },
    Search {
        query: String,
        timeout: Duration,
        reply: Sender<Result<Vec<SharedFileRecord>, ClientError>>,
    },
    Browse {
        username: String,
        timeout: Duration,
        reply: Sender<Result<Vec<SharedFileRecord>, ClientError>>,
    },
    Download {
        username: String,
        filename: String,
        dest_path: PathBuf,
        size_hint: Option<u64>,
        cancel: Arc<AtomicBool>,
        progress: Option<ProgressCallback>,
        reply: Sender<Result<DownloadOutcome, ClientError>>,
    },
    Shutdown,
}

enum WorkerEvent {
    Cmd(WorkerCmd),
    PeerControlConnected {
        conn_id: u64,
        username: String,
        writer: Arc<Mutex<TcpStream>>,
    },
    PeerControlMessage {
        username: String,
        msg: PeerMessage,
    },
    PeerControlClosed {
        conn_id: u64,
        username: String,
    },
    IncomingPiercedPeer {
        connect_token: u32,
        stream: TcpStream,
        decoder: FrameDecoder,
    },
    IncomingFileSocket {
        username: Option<String>,
        transfer_token: u32,
        stream: TcpStream,
        buffered: Vec<u8>,
    },
    PeerDialFailed {
        username: String,
        connect_token: Option<u32>,
        reason: String,
    },
    TransferFinished {
        download_id: u64,
        result: Result<DownloadOutcome, TransferError>,
    },
}

static NEXT_CONN_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

static NEXT_TOKEN: AtomicU32 = AtomicU32::new(100);

fn next_token() -> u32 {
    let v = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    if v == 0 { 1 } else { v }
}

/// Thread-safe handle to a Soulseek client worker.
pub struct SoulseekClient {
    cmd_tx: Sender<WorkerCmd>,
    state: Arc<RwLock<ClientState>>,
    logger: Arc<RwLock<Option<LoggerHook>>>,
    shutdown: Arc<AtomicBool>,
    worker_join: Mutex<Option<JoinHandle<()>>>,
}

impl Default for SoulseekClient {
    fn default() -> Self {
        Self::new()
    }
}

impl SoulseekClient {
    #[must_use]
    pub fn new() -> Self {
        Self::with_listen_port(0)
    }

    /// Create a client binding TCP peer listener on `listen_port` (`0` = OS-assigned port).
    #[must_use]
    pub fn with_listen_port(listen_port: u16) -> Self {
        let logger: Arc<RwLock<Option<LoggerHook>>> = Arc::new(RwLock::new(None));
        let shutdown = Arc::new(AtomicBool::new(false));

        let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();
        let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();

        let bound_port = WorkerEngine::spawn_listener(
            listen_port,
            event_tx.clone(),
            Arc::clone(&shutdown),
            Arc::clone(&logger),
        )
        .unwrap_or(0);

        let state = Arc::new(RwLock::new(ClientState {
            connected: false,
            logged_in: false,
            privileges: 0,
            listen_port: bound_port,
        }));

        // Bridge user commands into the unified worker event channel.
        let bridge_tx = event_tx.clone();
        thread::Builder::new()
            .name("slsk-cmd-bridge".to_string())
            .spawn(move || {
                while let Ok(cmd) = cmd_rx.recv() {
                    let is_stop = matches!(cmd, WorkerCmd::Shutdown);
                    if bridge_tx.send(WorkerEvent::Cmd(cmd)).is_err() || is_stop {
                        break;
                    }
                }
            })
            .expect("failed to spawn slsk-cmd-bridge");

        let state_worker = Arc::clone(&state);
        let logger_worker = Arc::clone(&logger);
        let shutdown_worker = Arc::clone(&shutdown);

        let worker_join = thread::Builder::new()
            .name("slsk-worker".to_string())
            .spawn(move || {
                let mut engine = WorkerEngine::new(
                    bound_port,
                    event_tx,
                    state_worker,
                    logger_worker,
                    shutdown_worker,
                );
                engine.run(event_rx);
            })
            .expect("failed to spawn slsk-worker");

        Self {
            cmd_tx,
            state,
            logger,
            shutdown,
            worker_join: Mutex::new(Some(worker_join)),
        }
    }

    pub fn set_logger(&self, hook: Option<LoggerHook>) {
        *self.logger.write() = hook;
    }

    #[must_use]
    pub fn state(&self) -> ClientState {
        self.state.read().clone()
    }

    /// Connect and log in to a Soulseek server using mandatory operator credentials.
    /// Never generates random usernames or overwrites stored credentials.
    pub fn login(
        &self,
        server: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<ClientState, ClientError> {
        self.login_with_version(
            server,
            port,
            username,
            password,
            DEFAULT_MAJOR_VERSION,
            DEFAULT_MINOR_VERSION,
        )
    }

    pub fn login_with_version(
        &self,
        server: &str,
        port: u16,
        username: &str,
        password: &str,
        major_version: u32,
        minor_version: u32,
    ) -> Result<ClientState, ClientError> {
        let trimmed_server = server.trim();
        if trimmed_server.is_empty() || port == 0 {
            return Err(ClientError::InvalidCredentials(
                "server host and non-zero port are required".to_string(),
            ));
        }
        if username.is_empty() {
            return Err(ClientError::InvalidCredentials(
                "username is required (accounts are never auto-generated)".to_string(),
            ));
        }
        if password.is_empty() {
            return Err(ClientError::InvalidCredentials(
                "password is required".to_string(),
            ));
        }

        let (tx, rx) = mpsc::channel();
        self.cmd_tx
            .send(WorkerCmd::Login {
                creds: Credentials {
                    server_host: trimmed_server.to_owned(),
                    server_port: port,
                    username: username.to_owned(),
                    password: password.to_owned(),
                    major_version,
                    minor_version,
                },
                reply: tx,
            })
            .map_err(|_| ClientError::Disconnected("worker stopped".to_string()))?;

        rx.recv()
            .map_err(|_| ClientError::Disconnected("worker dropped login reply".to_string()))?
    }

    /// Fan out a file search to the server and collect peer `FileSearchResponse`s for `timeout_ms`.
    pub fn search(
        &self,
        query: &str,
        timeout_ms: u64,
    ) -> Result<Vec<SharedFileRecord>, ClientError> {
        let q = query.trim();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let (tx, rx) = mpsc::channel();
        self.cmd_tx
            .send(WorkerCmd::Search {
                query: q.to_owned(),
                timeout: Duration::from_millis(timeout_ms.max(50)),
                reply: tx,
            })
            .map_err(|_| ClientError::Disconnected("worker stopped".to_string()))?;
        rx.recv()
            .map_err(|_| ClientError::Disconnected("worker dropped search reply".to_string()))?
    }

    /// Request a peer's shared file list (`SharedFileListRequest` -> `SharedFileListResponse`).
    pub fn browse(&self, username: &str) -> Result<Vec<SharedFileRecord>, ClientError> {
        self.browse_with_timeout(username, BROWSE_TIMEOUT)
    }

    pub fn browse_with_timeout(
        &self,
        username: &str,
        timeout: Duration,
    ) -> Result<Vec<SharedFileRecord>, ClientError> {
        let u = username.trim();
        if u.is_empty() {
            return Err(ClientError::InvalidCredentials(
                "peer username is empty".to_string(),
            ));
        }
        let (tx, rx) = mpsc::channel();
        self.cmd_tx
            .send(WorkerCmd::Browse {
                username: u.to_owned(),
                timeout,
                reply: tx,
            })
            .map_err(|_| ClientError::Disconnected("worker stopped".to_string()))?;
        rx.recv()
            .map_err(|_| ClientError::Disconnected("worker dropped browse reply".to_string()))?
    }

    /// Queue and download `filename` from `username` into `dest_path`, supporting multi-hour queues,
    /// `.part` resume, cancellation, and progress callbacks.
    pub fn download(
        &self,
        username: &str,
        filename: &str,
        dest_path: impl Into<PathBuf>,
        progress: Option<ProgressCallback>,
    ) -> Result<DownloadOutcome, ClientError> {
        self.download_with_cancel(
            username,
            filename,
            dest_path.into(),
            None,
            Arc::new(AtomicBool::new(false)),
            progress,
        )
    }

    pub fn download_with_cancel(
        &self,
        username: &str,
        filename: &str,
        dest_path: PathBuf,
        size_hint: Option<u64>,
        cancel: Arc<AtomicBool>,
        progress: Option<ProgressCallback>,
    ) -> Result<DownloadOutcome, ClientError> {
        let (tx, rx) = mpsc::channel();
        self.cmd_tx
            .send(WorkerCmd::Download {
                username: username.to_owned(),
                filename: filename.to_owned(),
                dest_path,
                size_hint,
                cancel,
                progress,
                reply: tx,
            })
            .map_err(|_| ClientError::Disconnected("worker stopped".to_string()))?;
        rx.recv()
            .map_err(|_| ClientError::Disconnected("worker dropped download reply".to_string()))?
    }

    pub fn close(&self) {
        if !self.shutdown.swap(true, Ordering::AcqRel) {
            let _ = self.cmd_tx.send(WorkerCmd::Shutdown);
        }
        if let Some(handle) = self.worker_join.lock().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SoulseekClient {
    fn drop(&mut self) {
        self.close();
    }
}

// ============================================================================
// Worker Engine (runs on its own OS thread, never on the Bare JS loop)
// ============================================================================

struct WorkerEngine {
    event_tx: Sender<WorkerEvent>,
    state: Arc<RwLock<ClientState>>,
    logger: Arc<RwLock<Option<LoggerHook>>>,
    shutdown: Arc<AtomicBool>,

    listen_port: u16,
    creds: Option<Credentials>,
    relogged_out: bool,

    server_stream: Option<TcpStream>,
    server_decoder: FrameDecoder,
    last_ping: Instant,
    reconnect_at: Option<Instant>,
    reconnect_backoff: Duration,

    peers: HashMap<String, (u64, Arc<Mutex<TcpStream>>)>,
    pending_peer_msgs: HashMap<String, Vec<PeerMessage>>,
    pending_connect_tokens: HashMap<u32, (String, Instant)>,

    searches: HashMap<u32, ActiveSearch>,
    browses: HashMap<String, ActiveBrowse>,
    downloads: Vec<ActiveDownload>,
    next_download_id: u64,
}

impl WorkerEngine {
    fn new(
        bound_port: u16,
        event_tx: Sender<WorkerEvent>,
        state: Arc<RwLock<ClientState>>,
        logger: Arc<RwLock<Option<LoggerHook>>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            event_tx,
            state,
            logger,
            shutdown,
            listen_port: bound_port,
            creds: None,
            relogged_out: false,
            server_stream: None,
            server_decoder: FrameDecoder::new(),
            last_ping: Instant::now(),
            reconnect_at: None,
            reconnect_backoff: RECONNECT_BACKOFF_MIN,
            peers: HashMap::new(),
            pending_peer_msgs: HashMap::new(),
            pending_connect_tokens: HashMap::new(),
            searches: HashMap::new(),
            browses: HashMap::new(),
            downloads: Vec::new(),
            next_download_id: 1,
        }
    }

    fn log(&self, level: LogLevel, event: &str, message: impl Into<String>) {
        if let Some(cb) = self.logger.read().as_ref() {
            cb(LogEvent {
                level,
                event: event.to_owned(),
                message: message.into(),
            });
        }
    }

    fn update_state(&self, connected: bool, logged_in: bool, privileges: Option<u32>) {
        let mut st = self.state.write();
        st.connected = connected;
        st.logged_in = logged_in;
        if let Some(p) = privileges {
            st.privileges = p;
        }
    }

    fn spawn_listener(
        port: u16,
        event_tx: Sender<WorkerEvent>,
        shutdown: Arc<AtomicBool>,
        logger: Arc<RwLock<Option<LoggerHook>>>,
    ) -> io::Result<u16> {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
        let actual_port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;

        thread::Builder::new()
            .name("slsk-listener".to_string())
            .spawn(move || {
                while !shutdown.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _peer_addr)) => {
                            let tx = event_tx.clone();
                            let log = Arc::clone(&logger);
                            let _ = thread::Builder::new()
                                .name("slsk-accept".to_string())
                                .spawn(move || {
                                    Self::handle_incoming_socket(stream, tx, log);
                                });
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Err(_) => {
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            })
            .expect("failed to spawn slsk-listener");

        Ok(actual_port)
    }

    fn handle_incoming_socket(
        mut stream: TcpStream,
        event_tx: Sender<WorkerEvent>,
        logger: Arc<RwLock<Option<LoggerHook>>>,
    ) {
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
        let mut decoder = FrameDecoder::new();
        let mut scratch = [0u8; 4096];
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;

        let init_payload = loop {
            if Instant::now() >= deadline {
                return;
            }
            match decoder.next_frame() {
                Ok(Some(frame)) => break frame,
                Ok(None) => {}
                Err(_) => return,
            }
            match stream.read(&mut scratch) {
                Ok(0) => return,
                Ok(n) => decoder.push(&scratch[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return,
            }
        };

        let Ok(init_msg) = PeerInitMessage::decode(&init_payload) else {
            return;
        };

        match init_msg {
            PeerInitMessage::PierceFirewall { token } => {
                // Could be a brokered P connection OR a brokered F connection; let worker inspect token.
                let _ = event_tx.send(WorkerEvent::IncomingPiercedPeer {
                    connect_token: token,
                    stream,
                    decoder,
                });
            }
            PeerInitMessage::PeerInit {
                username,
                conn_type: ConnectionType::Peer,
                ..
            } => {
                Self::spawn_peer_reader(username, stream, decoder, event_tx, logger);
            }
            PeerInitMessage::PeerInit {
                username,
                conn_type: ConnectionType::File,
                ..
            } => {
                // Read 4-byte FileTransferInit token
                while decoder.buffered_len() < 4 {
                    if Instant::now() >= deadline {
                        return;
                    }
                    match stream.read(&mut scratch) {
                        Ok(0) => return,
                        Ok(n) => decoder.push(&scratch[..n]),
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => return,
                    }
                }
                let Some(tok_bytes) = decoder.take_raw(4) else {
                    return;
                };
                let transfer_token =
                    u32::from_le_bytes([tok_bytes[0], tok_bytes[1], tok_bytes[2], tok_bytes[3]]);
                let buffered = decoder.take_all();
                let _ = event_tx.send(WorkerEvent::IncomingFileSocket {
                    username: Some(username),
                    transfer_token,
                    stream,
                    buffered,
                });
            }
            PeerInitMessage::PeerInit {
                conn_type: ConnectionType::Distributed,
                ..
            } => {
                // Distributed children are disabled (`AcceptChildren(false)`).
            }
        }
    }

    fn spawn_peer_reader(
        username: String,
        stream: TcpStream,
        mut decoder: FrameDecoder,
        event_tx: Sender<WorkerEvent>,
        _logger: Arc<RwLock<Option<LoggerHook>>>,
    ) {
        let conn_id = next_conn_id();
        let Ok(mut read_stream) = stream.try_clone() else {
            return;
        };
        let _ = read_stream.set_read_timeout(Some(Duration::from_millis(500)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let writer = Arc::new(Mutex::new(stream));

        if event_tx
            .send(WorkerEvent::PeerControlConnected {
                conn_id,
                username: username.clone(),
                writer,
            })
            .is_err()
        {
            return;
        }

        let _ = thread::Builder::new()
            .name("slsk-peer-rx".to_string())
            .spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    while let Ok(Some(payload)) = decoder.next_frame() {
                        if let Ok(msg) = PeerMessage::decode(&payload)
                            && event_tx
                                .send(WorkerEvent::PeerControlMessage {
                                    username: username.clone(),
                                    msg,
                                })
                                .is_err()
                        {
                            return;
                        }
                    }

                    match read_stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => decoder.push(&buf[..n]),
                        Err(e)
                            if matches!(
                                e.kind(),
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => break,
                    }
                }
                let _ = event_tx.send(WorkerEvent::PeerControlClosed { conn_id, username });
            });
    }

    fn run(&mut self, event_rx: Receiver<WorkerEvent>) {
        while !self.shutdown.load(Ordering::Acquire) {
            self.poll_server_socket();

            match event_rx.recv_timeout(Duration::from_millis(25)) {
                Ok(ev) => self.handle_event(ev),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }

            self.tick_timers();
        }

        self.disconnect_server();
        for (_, (_, writer)) in self.peers.drain() {
            let _ = writer.lock().shutdown(std::net::Shutdown::Both);
        }
    }

    fn disconnect_server(&mut self) {
        if let Some(s) = self.server_stream.take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        self.server_decoder = FrameDecoder::new();
        self.update_state(false, false, None);
    }

    fn send_server(&mut self, req: &ServerRequest) -> Result<(), ClientError> {
        let Some(stream) = self.server_stream.as_mut() else {
            return Err(ClientError::NotLoggedIn);
        };
        let bytes = req.encode();
        if let Err(e) = stream.write_all(&bytes).and_then(|()| stream.flush()) {
            self.log(
                LogLevel::Warn,
                "server_write_error",
                format!("server socket write failed: {e}"),
            );
            self.schedule_reconnect();
            return Err(ClientError::Disconnected(e.to_string()));
        }
        Ok(())
    }

    fn schedule_reconnect(&mut self) {
        self.disconnect_server();
        if self.creds.is_some() && !self.relogged_out {
            self.reconnect_at = Some(Instant::now() + self.reconnect_backoff);
            self.reconnect_backoff = (self.reconnect_backoff * 2).min(RECONNECT_BACKOFF_MAX);
        }
    }

    fn connect_and_authenticate(
        &mut self,
        creds: &Credentials,
    ) -> Result<ClientState, ClientError> {
        self.disconnect_server();

        let addr: SocketAddr = format!("{}:{}", creds.server_host, creds.server_port)
            .to_socket_addrs()
            .map_err(|e| ClientError::Io(format!("resolve {}: {e}", creds.server_host)))?
            .next()
            .ok_or_else(|| {
                ClientError::Io(format!("no addresses resolved for {}", creds.server_host))
            })?;

        self.log(
            LogLevel::Info,
            "connecting",
            format!(
                "connecting to {}:{} as {}",
                creds.server_host, creds.server_port, creds.username
            ),
        );

        let mut stream = TcpStream::connect_timeout(&addr, LOGIN_TIMEOUT)
            .map_err(|e| ClientError::Io(format!("connect {addr}: {e}")))?;
        let _ = stream.set_nodelay(true);
        stream
            .set_read_timeout(Some(LOGIN_TIMEOUT))
            .map_err(|e| ClientError::Io(e.to_string()))?;
        stream
            .set_write_timeout(Some(LOGIN_TIMEOUT))
            .map_err(|e| ClientError::Io(e.to_string()))?;

        self.update_state(true, false, Some(0));

        // Send Login (code 1) — single MD5(username+password) message, never challenge-response.
        let login_frame = ServerRequest::Login {
            username: creds.username.clone(),
            password: creds.password.clone(),
            major_version: creds.major_version,
            minor_version: creds.minor_version,
        }
        .encode();
        stream
            .write_all(&login_frame)
            .and_then(|()| stream.flush())
            .map_err(|e| ClientError::Io(format!("send login: {e}")))?;

        let mut decoder = FrameDecoder::new();
        let mut buf = [0u8; 4096];
        let deadline = Instant::now() + LOGIN_TIMEOUT;

        let login_resp = loop {
            if let Some(payload) = decoder.next_frame().map_err(ClientError::Protocol)? {
                let msg = ServerResponse::decode(&payload).map_err(ClientError::Protocol)?;
                match msg {
                    ServerResponse::LoginSuccess { .. } | ServerResponse::LoginFailure { .. } => {
                        break msg;
                    }
                    other => self.handle_server_message(other),
                }
            }
            if Instant::now() >= deadline {
                self.update_state(false, false, None);
                return Err(ClientError::Timeout("server login".to_string()));
            }
            let n = stream.read(&mut buf).map_err(|e| {
                self.update_state(false, false, None);
                ClientError::Io(format!("read login response: {e}"))
            })?;
            if n == 0 {
                self.update_state(false, false, None);
                return Err(ClientError::Disconnected(
                    "server closed connection during login".to_string(),
                ));
            }
            decoder.push(&buf[..n]);
        };

        match login_resp {
            ServerResponse::LoginFailure { reason, detail, .. } => {
                self.update_state(false, false, Some(0));
                self.log(
                    LogLevel::Error,
                    "login_rejected",
                    format!("server rejected login for {}: {reason}", creds.username),
                );
                Err(ClientError::LoginRejected { reason, detail })
            }
            ServerResponse::LoginSuccess { is_supporter, .. } => {
                stream
                    .set_nonblocking(true)
                    .map_err(|e| ClientError::Io(e.to_string()))?;
                self.server_stream = Some(stream);
                self.server_decoder = decoder;
                self.last_ping = Instant::now();
                self.reconnect_at = None;
                self.reconnect_backoff = RECONNECT_BACKOFF_MIN;
                self.relogged_out = false;
                self.update_state(true, true, Some(u32::from(is_supporter)));

                // Post-login initialization messages expected by Soulseek servers:
                if self.listen_port > 0 {
                    let _ = self.send_server(&ServerRequest::SetWaitPort {
                        port: u32::from(self.listen_port),
                    });
                }
                let _ = self.send_server(&ServerRequest::SharedFoldersFiles {
                    folders: 0,
                    files: 0,
                });
                let _ = self.send_server(&ServerRequest::AcceptChildren { accept: false });
                let _ = self.send_server(&ServerRequest::HaveNoParent { no_parent: true });
                let _ = self.send_server(&ServerRequest::SetStatus { status: 2 });
                let _ = self.send_server(&ServerRequest::CheckPrivileges);

                // Drain any immediate frames buffered alongside LoginSuccess (e.g. CheckPrivileges).
                self.drain_buffered_server_frames();

                self.log(
                    LogLevel::Info,
                    "logged_in",
                    format!(
                        "logged in as {} (listen_port={})",
                        creds.username, self.listen_port
                    ),
                );
                Ok(self.state.read().clone())
            }
            _ => unreachable!(),
        }
    }

    fn drain_buffered_server_frames(&mut self) {
        while let Ok(Some(payload)) = self.server_decoder.next_frame() {
            if let Ok(msg) = ServerResponse::decode(&payload) {
                self.handle_server_message(msg);
            }
        }
    }

    fn poll_server_socket(&mut self) {
        let mut scratch = [0u8; 16 * 1024];
        let mut disconnected = false;
        if let Some(stream) = self.server_stream.as_mut() {
            loop {
                match stream.read(&mut scratch) {
                    Ok(0) => {
                        disconnected = true;
                        break;
                    }
                    Ok(n) => self.server_decoder.push(&scratch[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        self.drain_buffered_server_frames();

        if disconnected {
            self.log(
                LogLevel::Warn,
                "server_disconnected",
                "server TCP connection closed",
            );
            self.schedule_reconnect();
        }
    }

    fn handle_server_message(&mut self, msg: ServerResponse) {
        match msg {
            ServerResponse::CheckPrivileges { seconds_left } => {
                let connected = self.server_stream.is_some();
                self.update_state(connected, connected, Some(seconds_left));
            }
            ServerResponse::Relogged => {
                self.relogged_out = true;
                self.log(
                    LogLevel::Warn,
                    "relogged",
                    "another client logged in with this account; stopping auto-reconnect",
                );
                self.disconnect_server();
            }
            ServerResponse::PeerAddress {
                username, ip, port, ..
            } => {
                self.dial_peer_direct(username, ip, port);
            }
            ServerResponse::ConnectToPeer {
                username,
                conn_type,
                ip,
                port,
                token,
                ..
            } => match conn_type {
                ConnectionType::Peer => {
                    self.dial_peer_pierce_p(username, ip, port, token);
                }
                ConnectionType::File => {
                    self.dial_peer_pierce_f(username, ip, port, token);
                }
                ConnectionType::Distributed => {
                    let _ = self.send_server(&ServerRequest::CantConnectToPeer { token, username });
                }
            },
            ServerResponse::MessageUser { message_id, .. } => {
                let _ = self.send_server(&ServerRequest::MessageAcked { message_id });
            }
            ServerResponse::CantConnectToPeer { token } => {
                if let Some((username, _)) = self.pending_connect_tokens.remove(&token)
                    && !self.peers.contains_key(&username)
                {
                    self.fail_peer_operations(
                        &username,
                        "peer could not establish indirect connection",
                    );
                }
            }
            ServerResponse::PossibleParents { parents } => {
                // Connect to first candidate parent passively for distributed search reach if needed,
                // or ignore when acting strictly as leaf.
                let _ = parents;
            }
            _ => {}
        }
    }

    fn ensure_peer_control(&mut self, username: &str, msg: PeerMessage) -> Result<(), ClientError> {
        if let Some((_, writer)) = self.peers.get(username).cloned()
            && Self::write_peer_msg(&writer, &msg).is_ok()
        {
            return Ok(());
        }
        self.peers.remove(username);

        let already_connecting = self.pending_peer_msgs.contains_key(username);
        self.pending_peer_msgs
            .entry(username.to_owned())
            .or_default()
            .push(msg);

        if !already_connecting {
            // Modern connection order (Nicotine+ 3.2.1+ / SoulseekQt):
            // Send both ConnectToPeer(token, user, "P") AND GetPeerAddress(user).
            let connect_token = next_token();
            self.pending_connect_tokens
                .insert(connect_token, (username.to_owned(), Instant::now()));
            self.send_server(&ServerRequest::ConnectToPeer {
                token: connect_token,
                username: username.to_owned(),
                conn_type: ConnectionType::Peer,
            })?;
            self.send_server(&ServerRequest::GetPeerAddress {
                username: username.to_owned(),
            })?;
        }
        Ok(())
    }

    fn write_peer_msg(writer: &Arc<Mutex<TcpStream>>, msg: &PeerMessage) -> io::Result<()> {
        let frame = msg
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let mut guard = writer.lock();
        guard.write_all(&frame)?;
        guard.flush()
    }

    fn dial_peer_direct(&self, username: String, ip: Ipv4Addr, port: u32) {
        if ip.is_unspecified() || port == 0 || port > 65535 {
            return;
        }
        if self.peers.contains_key(&username) {
            return;
        }
        let Some(own_user) = self.creds.as_ref().map(|c| c.username.clone()) else {
            return;
        };
        let tx = self.event_tx.clone();
        let log = Arc::clone(&self.logger);

        let _ = thread::Builder::new()
            .name("slsk-dial-p".to_string())
            .spawn(move || {
                let addr = SocketAddr::from((ip, port as u16));
                let Ok(mut stream) = TcpStream::connect_timeout(&addr, PEER_DIAL_TIMEOUT) else {
                    return;
                };
                let _ = stream.set_nodelay(true);
                let init = PeerInitMessage::PeerInit {
                    username: own_user,
                    conn_type: ConnectionType::Peer,
                    token: 0,
                }
                .encode();
                if stream
                    .write_all(&init)
                    .and_then(|()| stream.flush())
                    .is_err()
                {
                    return;
                }
                Self::spawn_peer_reader(username, stream, FrameDecoder::new(), tx, log);
            });
    }

    fn dial_peer_pierce_p(&self, username: String, ip: Ipv4Addr, port: u32, token: u32) {
        if ip.is_unspecified() || port == 0 || port > 65535 {
            tx_cant_connect(&self.event_tx, username, token, "invalid peer address");
            return;
        }
        let tx = self.event_tx.clone();
        let log = Arc::clone(&self.logger);

        let _ = thread::Builder::new()
            .name("slsk-pierce-p".to_string())
            .spawn(move || {
                let addr = SocketAddr::from((ip, port as u16));
                let mut stream = match TcpStream::connect_timeout(&addr, PEER_DIAL_TIMEOUT) {
                    Ok(s) => s,
                    Err(e) => {
                        tx_cant_connect(&tx, username, token, &e.to_string());
                        return;
                    }
                };
                let _ = stream.set_nodelay(true);
                let pierce = PeerInitMessage::PierceFirewall { token }.encode();
                if let Err(e) = stream.write_all(&pierce).and_then(|()| stream.flush()) {
                    tx_cant_connect(&tx, username, token, &e.to_string());
                    return;
                }
                Self::spawn_peer_reader(username, stream, FrameDecoder::new(), tx, log);
            });
    }

    fn dial_peer_pierce_f(&self, username: String, ip: Ipv4Addr, port: u32, token: u32) {
        if ip.is_unspecified() || port == 0 || port > 65535 {
            tx_cant_connect(&self.event_tx, username, token, "invalid F peer address");
            return;
        }
        let tx = self.event_tx.clone();
        let host = ip.to_string();
        let _ = thread::Builder::new()
            .name("slsk-pierce-f".to_string())
            .spawn(move || match dial_pierced_file_socket(&host, port, token) {
                Ok((stream, transfer_token)) => {
                    let _ = tx.send(WorkerEvent::IncomingFileSocket {
                        username: Some(username),
                        transfer_token,
                        stream,
                        buffered: Vec::new(),
                    });
                }
                Err(e) => {
                    tx_cant_connect(&tx, username, token, &e.to_string());
                }
            });
    }

    fn handle_event(&mut self, ev: WorkerEvent) {
        match ev {
            WorkerEvent::Cmd(cmd) => self.handle_command(cmd),
            WorkerEvent::PeerControlConnected {
                conn_id,
                username,
                writer,
            } => {
                self.peers
                    .insert(username.clone(), (conn_id, Arc::clone(&writer)));
                if let Some(queued) = self.pending_peer_msgs.remove(&username) {
                    for msg in queued {
                        let _ = Self::write_peer_msg(&writer, &msg);
                    }
                }
            }
            WorkerEvent::PeerControlMessage { username, msg } => {
                self.handle_peer_message(username, msg);
            }
            WorkerEvent::PeerControlClosed { conn_id, username } => {
                if self
                    .peers
                    .get(&username)
                    .is_some_and(|(active_id, _)| *active_id == conn_id)
                {
                    self.peers.remove(&username);
                }
            }
            WorkerEvent::IncomingPiercedPeer {
                connect_token,
                mut stream,
                mut decoder,
            } => {
                if let Some((username, _)) = self.pending_connect_tokens.remove(&connect_token) {
                    Self::spawn_peer_reader(
                        username,
                        stream,
                        decoder,
                        self.event_tx.clone(),
                        Arc::clone(&self.logger),
                    );
                } else {
                    // Otherwise treat as a pierced file socket carrying a 4-byte FileTransferInit ticket.
                    let tx = self.event_tx.clone();
                    let _ = thread::Builder::new()
                        .name("slsk-pierce-rx-f".to_string())
                        .spawn(move || {
                            let mut buf = [0u8; 1024];
                            while decoder.buffered_len() < 4 {
                                match stream.read(&mut buf) {
                                    Ok(0) | Err(_) => return,
                                    Ok(n) => decoder.push(&buf[..n]),
                                }
                            }
                            if let Some(tok) = decoder.take_raw(4) {
                                let transfer_token =
                                    u32::from_le_bytes([tok[0], tok[1], tok[2], tok[3]]);
                                let buffered = decoder.take_all();
                                let _ = tx.send(WorkerEvent::IncomingFileSocket {
                                    username: None,
                                    transfer_token,
                                    stream,
                                    buffered,
                                });
                            }
                        });
                }
            }
            WorkerEvent::IncomingFileSocket {
                username,
                transfer_token,
                stream,
                buffered,
            } => {
                self.start_matched_file_transfer(username, transfer_token, stream, buffered);
            }
            WorkerEvent::PeerDialFailed {
                username,
                connect_token,
                reason,
            } => {
                self.log(
                    LogLevel::Debug,
                    "peer_dial_failed",
                    format!("peer dial to {username} failed: {reason}"),
                );
                if let Some(token) = connect_token {
                    let _ = self.send_server(&ServerRequest::CantConnectToPeer { token, username });
                }
            }
            WorkerEvent::TransferFinished {
                download_id,
                result,
            } => {
                self.finish_download(download_id, result);
            }
        }
    }

    fn handle_command(&mut self, cmd: WorkerCmd) {
        match cmd {
            WorkerCmd::Login { creds, reply } => {
                let res = self.connect_and_authenticate(&creds);
                if res.is_ok() {
                    self.creds = Some(creds);
                }
                let _ = reply.send(res);
            }
            WorkerCmd::Search {
                query,
                timeout,
                reply,
            } => {
                let token = next_token();
                if let Err(e) = self.send_server(&ServerRequest::FileSearch {
                    token,
                    query: query.clone(),
                }) {
                    let _ = reply.send(Err(e));
                    return;
                }
                self.log(
                    LogLevel::Info,
                    "search_started",
                    format!("search dispatched (token={token})"),
                );
                self.searches.insert(
                    token,
                    ActiveSearch {
                        results: Vec::new(),
                        deadline: Instant::now() + timeout,
                        reply: Some(reply),
                    },
                );
            }
            WorkerCmd::Browse {
                username,
                timeout,
                reply,
            } => {
                if let Err(e) = self
                    .ensure_peer_control(&username, PeerMessage::UserInfoRequest)
                    .and_then(|()| {
                        self.ensure_peer_control(&username, PeerMessage::SharedFileListRequest)
                    })
                {
                    let _ = reply.send(Err(e));
                    return;
                }
                self.log(
                    LogLevel::Info,
                    "browse_started",
                    format!("browsing shares of {username}"),
                );
                self.browses.insert(
                    username.clone(),
                    ActiveBrowse {
                        username,
                        deadline: Instant::now() + timeout,
                        slots: true,
                        queue: 0,
                        speed: 0,
                        got_info: false,
                        files: None,
                        reply: Some(reply),
                    },
                );
            }
            WorkerCmd::Download {
                username,
                filename,
                dest_path,
                size_hint,
                cancel,
                progress,
                reply,
            } => {
                let final_path = match resolve_dest_file(&dest_path, &filename) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = reply.send(Err(ClientError::Transfer(e.to_string())));
                        return;
                    }
                };

                if let Err(e) = self.ensure_peer_control(
                    &username,
                    PeerMessage::QueueUpload {
                        filename: filename.clone(),
                    },
                ) {
                    let _ = reply.send(Err(e));
                    return;
                }
                let _ = self.ensure_peer_control(
                    &username,
                    PeerMessage::PlaceInQueueRequest {
                        filename: filename.clone(),
                    },
                );

                let id = self.next_download_id;
                self.next_download_id += 1;

                self.log(
                    LogLevel::Info,
                    "download_queued",
                    format!("queued {} from {}", redacted_basename(&filename), username),
                );

                if let Some(cb) = &progress {
                    cb(TransferProgress {
                        bytes_downloaded: 0,
                        total_bytes: size_hint.unwrap_or(0),
                        speed_bytes_per_sec: 0.0,
                        queue_place: None,
                        phase: TransferPhase::Queued { place: None },
                    });
                }

                self.downloads.push(ActiveDownload {
                    id,
                    username,
                    remote_filename: filename,
                    final_path,
                    expected_size: size_hint,
                    transfer_token: None,
                    queue_place: None,
                    in_flight_socket: false,
                    last_queue_poll: Instant::now(),
                    cancel,
                    progress,
                    reply: Some(reply),
                });
            }
            WorkerCmd::Shutdown => {
                self.shutdown.store(true, Ordering::Release);
            }
        }
    }

    fn handle_peer_message(&mut self, username: String, msg: PeerMessage) {
        match msg {
            PeerMessage::FileSearchResponse {
                token,
                username: resp_user,
                files,
                slot_free,
                upload_speed,
                queue_length,
                private_files,
            } => {
                if let Some(search) = self.searches.get_mut(&token) {
                    let peer_name = if resp_user.is_empty() {
                        username
                    } else {
                        resp_user
                    };
                    let reconstructed = PeerMessage::FileSearchResponse {
                        username: peer_name,
                        token,
                        files,
                        slot_free,
                        upload_speed,
                        queue_length,
                        private_files,
                    };
                    for rec in reconstructed.into_search_records() {
                        if search.results.len() < MAX_SEARCH_FILES {
                            search.results.push(rec);
                        }
                    }
                }
            }
            PeerMessage::UserInfoResponse {
                queue_length,
                slot_free,
                ..
            } => {
                if let Some(b) = self.browses.get_mut(&username) {
                    b.slots = slot_free;
                    b.queue = queue_length;
                    b.got_info = true;
                    if let Some(mut files) = b.files.take() {
                        for f in &mut files {
                            f.slots = slot_free;
                            f.queue = queue_length;
                        }
                        if let Some(reply) = b.reply.take() {
                            let _ = reply.send(Ok(files));
                        }
                        self.browses.remove(&username);
                    }
                }
            }
            PeerMessage::SharedFileListResponse { folders, .. } => {
                if let Some(mut browse) = self.browses.remove(&username) {
                    let records = flatten_shared_folders(
                        &browse.username,
                        &folders,
                        browse.slots,
                        browse.queue,
                        browse.speed,
                    );
                    if let Some(reply) = browse.reply.take() {
                        let _ = reply.send(Ok(records));
                    }
                }
            }
            PeerMessage::PlaceInQueueResponse { filename, place } => {
                for dl in &mut self.downloads {
                    if dl.username == username && paths_match(&dl.remote_filename, &filename) {
                        dl.queue_place = Some(place);
                        if let Some(cb) = &dl.progress {
                            cb(TransferProgress {
                                bytes_downloaded: 0,
                                total_bytes: dl.expected_size.unwrap_or(0),
                                speed_bytes_per_sec: 0.0,
                                queue_place: Some(place),
                                phase: TransferPhase::Queued { place: Some(place) },
                            });
                        }
                    }
                }
            }
            PeerMessage::TransferRequest {
                direction: 1,
                token,
                filename,
                file_size,
            } => {
                // Peer is ready to upload to us! Match our queued download and send TransferResponse(allowed=true).
                let matched = self.downloads.iter_mut().find(|dl| {
                    dl.username == username
                        && !dl.in_flight_socket
                        && paths_match(&dl.remote_filename, &filename)
                });

                if let Some(dl) = matched {
                    dl.transfer_token = Some(token);
                    if let Some(sz) = file_size {
                        dl.expected_size = Some(sz);
                    }
                    if let Some(cb) = &dl.progress {
                        cb(TransferProgress {
                            bytes_downloaded: 0,
                            total_bytes: dl.expected_size.unwrap_or(0),
                            speed_bytes_per_sec: 0.0,
                            queue_place: Some(0),
                            phase: TransferPhase::Connecting,
                        });
                    }
                    if let Some((_, writer)) = self.peers.get(&username) {
                        let _ = Self::write_peer_msg(
                            writer,
                            &PeerMessage::TransferResponse {
                                token,
                                allowed: true,
                                file_size: None,
                                reason: None,
                            },
                        );
                    }
                } else if let Some((_, writer)) = self.peers.get(&username) {
                    let _ = Self::write_peer_msg(
                        writer,
                        &PeerMessage::TransferResponse {
                            token,
                            allowed: false,
                            file_size: None,
                            reason: Some("Cancelled".to_string()),
                        },
                    );
                }
            }
            PeerMessage::TransferRequest {
                direction: 0,
                token,
                ..
            } => {
                if let Some((_, writer)) = self.peers.get(&username) {
                    let _ = Self::write_peer_msg(
                        writer,
                        &PeerMessage::TransferResponse {
                            token,
                            allowed: false,
                            file_size: None,
                            reason: Some("File not shared.".to_string()),
                        },
                    );
                }
            }
            PeerMessage::UploadDenied { filename, reason } => {
                if let Some(idx) = self.downloads.iter().position(|dl| {
                    dl.username == username && paths_match(&dl.remote_filename, &filename)
                }) {
                    let mut dl = self.downloads.remove(idx);
                    self.log(
                        LogLevel::Warn,
                        "upload_denied",
                        format!(
                            "peer {} denied {}: {}",
                            username,
                            redacted_basename(&filename),
                            reason
                        ),
                    );
                    if let Some(reply) = dl.reply.take() {
                        let _ = reply.send(Err(ClientError::Transfer(
                            TransferError::Denied(reason).to_string(),
                        )));
                    }
                }
            }
            PeerMessage::UploadFailed { filename } => {
                if let Some(idx) = self.downloads.iter().position(|dl| {
                    dl.username == username
                        && !dl.in_flight_socket
                        && paths_match(&dl.remote_filename, &filename)
                }) {
                    let mut dl = self.downloads.remove(idx);
                    self.log(
                        LogLevel::Warn,
                        "upload_failed",
                        format!(
                            "peer {} reported upload failed for {}",
                            username,
                            redacted_basename(&filename)
                        ),
                    );
                    if let Some(reply) = dl.reply.take() {
                        let _ = reply.send(Err(ClientError::Transfer(
                            TransferError::UploadFailed.to_string(),
                        )));
                    }
                }
            }
            PeerMessage::SharedFileListRequest => {
                if let Some((_, writer)) = self.peers.get(&username) {
                    let _ = Self::write_peer_msg(
                        writer,
                        &PeerMessage::SharedFileListResponse {
                            folders: Vec::new(),
                            private_folders: Vec::new(),
                        },
                    );
                }
            }
            PeerMessage::UserInfoRequest => {
                if let Some((_, writer)) = self.peers.get(&username) {
                    let _ = Self::write_peer_msg(
                        writer,
                        &PeerMessage::UserInfoResponse {
                            description: String::new(),
                            picture: None,
                            upload_slots: 0,
                            queue_length: 0,
                            slot_free: false,
                            upload_permission: Some(0),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    fn start_matched_file_transfer(
        &mut self,
        username: Option<String>,
        transfer_token: u32,
        stream: TcpStream,
        buffered: Vec<u8>,
    ) {
        let matched = self.downloads.iter_mut().find(|dl| {
            dl.transfer_token == Some(transfer_token)
                && !dl.in_flight_socket
                && username.as_ref().is_none_or(|u| u == &dl.username)
        });

        let Some(dl) = matched else {
            return;
        };

        let Some(expected_size) = dl.expected_size else {
            let dl_id = dl.id;
            self.finish_download(
                dl_id,
                Err(TransferError::Incomplete {
                    received: 0,
                    expected: 1,
                }),
            );
            return;
        };

        dl.in_flight_socket = true;
        let download_id = dl.id;
        let final_path = dl.final_path.clone();
        let cancel = Arc::clone(&dl.cancel);
        let progress = dl.progress.clone();
        let tx = self.event_tx.clone();

        let _ = thread::Builder::new()
            .name("slsk-file-rx".to_string())
            .spawn(move || {
                let result = stream_file_download(
                    stream,
                    &buffered,
                    final_path,
                    expected_size,
                    &cancel,
                    progress.as_ref(),
                );
                let _ = tx.send(WorkerEvent::TransferFinished {
                    download_id,
                    result,
                });
            });
    }

    fn finish_download(
        &mut self,
        download_id: u64,
        result: Result<DownloadOutcome, TransferError>,
    ) {
        let Some(idx) = self.downloads.iter().position(|d| d.id == download_id) else {
            return;
        };
        let mut dl = self.downloads.remove(idx);
        match result {
            Ok(outcome) => {
                self.log(
                    LogLevel::Info,
                    "download_complete",
                    format!(
                        "completed {} ({} bytes, resumed_from={})",
                        redacted_basename(&dl.remote_filename),
                        outcome.size,
                        outcome.resumed_from
                    ),
                );
                if let Some(reply) = dl.reply.take() {
                    let _ = reply.send(Ok(outcome));
                }
            }
            Err(e) => {
                self.log(
                    LogLevel::Warn,
                    "download_failed",
                    format!(
                        "download failed for {}: {e}",
                        redacted_basename(&dl.remote_filename)
                    ),
                );
                if let Some(reply) = dl.reply.take() {
                    let _ = reply.send(Err(ClientError::Transfer(e.to_string())));
                }
            }
        }
    }

    fn fail_peer_operations(&mut self, username: &str, reason: &str) {
        self.pending_peer_msgs.remove(username);
        if let Some(mut browse) = self.browses.remove(username)
            && let Some(reply) = browse.reply.take()
        {
            let _ = reply.send(Err(ClientError::Disconnected(reason.to_owned())));
        }
        let mut i = 0;
        while i < self.downloads.len() {
            if self.downloads[i].username == username && !self.downloads[i].in_flight_socket {
                let mut dl = self.downloads.remove(i);
                if let Some(reply) = dl.reply.take() {
                    let _ = reply.send(Err(ClientError::Disconnected(reason.to_owned())));
                }
            } else {
                i += 1;
            }
        }
    }

    fn tick_timers(&mut self) {
        let now = Instant::now();

        // 1. Server keepalive ping
        if self.server_stream.is_some()
            && now.duration_since(self.last_ping) >= SERVER_PING_INTERVAL
        {
            self.last_ping = now;
            let _ = self.send_server(&ServerRequest::ServerPing);
        }

        // 2. Automatic reconnect when session dropped unexpectedly (not Relogged)
        if self.server_stream.is_none()
            && !self.relogged_out
            && let Some(at) = self.reconnect_at
            && now >= at
            && let Some(creds) = self.creds.clone()
        {
            self.reconnect_at = None;
            if self.connect_and_authenticate(&creds).is_err() {
                self.schedule_reconnect();
            } else {
                // Re-queue any waiting downloads that were not yet actively streaming.
                let waiting: Vec<(String, String)> = self
                    .downloads
                    .iter()
                    .filter(|d| !d.in_flight_socket)
                    .map(|d| (d.username.clone(), d.remote_filename.clone()))
                    .collect();
                for (u, f) in waiting {
                    let _ = self.ensure_peer_control(&u, PeerMessage::QueueUpload { filename: f });
                }
            }
        }

        // 3. Complete searches whose collection window has elapsed
        let expired_searches: Vec<u32> = self
            .searches
            .iter()
            .filter(|(_, s)| now >= s.deadline)
            .map(|(&tok, _)| tok)
            .collect();
        for tok in expired_searches {
            if let Some(mut s) = self.searches.remove(&tok)
                && let Some(reply) = s.reply.take()
            {
                let _ = reply.send(Ok(s.results));
            }
        }

        // 4. Fail expired browses
        let expired_browses: Vec<String> = self
            .browses
            .iter()
            .filter(|(_, b)| now >= b.deadline)
            .map(|(u, _)| u.clone())
            .collect();
        for u in expired_browses {
            if let Some(mut b) = self.browses.remove(&u)
                && let Some(reply) = b.reply.take()
            {
                let _ = reply.send(Err(ClientError::Timeout(format!("browse {u}"))));
            }
        }

        // 5. Clean stale pending ConnectToPeer correlation tokens
        self.pending_connect_tokens
            .retain(|_, (_, created)| now.duration_since(*created) < Duration::from_secs(30));

        // 6. Check cancelled queued downloads & poll PlaceInQueue every 30s
        let mut to_poll = Vec::new();
        let mut i = 0;
        while i < self.downloads.len() {
            if !self.downloads[i].in_flight_socket
                && self.downloads[i].cancel.load(Ordering::Acquire)
            {
                let mut dl = self.downloads.remove(i);
                if let Some(reply) = dl.reply.take() {
                    let _ = reply.send(Err(ClientError::Transfer(
                        TransferError::Cancelled.to_string(),
                    )));
                }
                continue;
            }
            if !self.downloads[i].in_flight_socket
                && now.duration_since(self.downloads[i].last_queue_poll)
                    >= PLACE_IN_QUEUE_POLL_INTERVAL
            {
                self.downloads[i].last_queue_poll = now;
                to_poll.push((
                    self.downloads[i].username.clone(),
                    self.downloads[i].remote_filename.clone(),
                ));
            }
            i += 1;
        }
        for (u, f) in to_poll {
            let _ = self.ensure_peer_control(&u, PeerMessage::PlaceInQueueRequest { filename: f });
        }
    }
}

fn paths_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    a.replace('/', "\\")
        .eq_ignore_ascii_case(&b.replace('/', "\\"))
}

fn tx_cant_connect(tx: &Sender<WorkerEvent>, username: String, token: u32, reason: &str) {
    let _ = tx.send(WorkerEvent::PeerDialFailed {
        username,
        connect_token: Some(token),
        reason: reason.to_owned(),
    });
}
