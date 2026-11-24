//! Multi-threaded non-blocking Soulseek client session, peer connection broker,
//! search collector, peer share browser, disk share publisher, and ticket-matched
//! download/upload coordinator.
//!
//! Security & logging rules:
//! - Credentials (`password`) are never logged at any level and never auto-generated.
//! - Remote/local full paths are redacted to leaf basenames at `info`/`warn`/`error`.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::proto::{
    AudioAttributes, ConnectionType, DEFAULT_MAJOR_VERSION, DEFAULT_MINOR_VERSION, FrameDecoder,
    PeerInitMessage, PeerMessage, ProtoError, ServerRequest, ServerResponse, SharedFileRecord,
    SharedFolder, WireFileEntry, flatten_shared_folders,
};
use crate::transfer::{
    DownloadOutcome, ProgressCallback, TransferError, TransferPhase, TransferProgress,
    UploadOutcome, dial_direct_upload_socket, dial_pierced_file_socket, init_pierced_upload_socket,
    redacted_basename, resolve_dest_file, stream_file_download_with_options, stream_file_upload,
};
use parking_lot::{Mutex, RwLock};

const SERVER_PING_INTERVAL: Duration = Duration::from_secs(45);
const SERVER_READ_TIMEOUT: Duration = Duration::from_secs(120);
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(2);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);
const BROWSE_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PLACE_IN_QUEUE_POLL_INTERVAL: Duration = Duration::from_secs(30);
const MAX_SEARCH_FILES: usize = 10_000;
const SHARE_RESCAN_INTERVAL: Duration = Duration::from_secs(60);
const UPLOAD_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default file count cap for the advertised Soulseek share tree.
pub const DEFAULT_SHARE_MAX_FILES: usize = 2000;
/// Default concurrent upload slots advertised in `UserInfoResponse`.
pub const DEFAULT_UPLOAD_SLOTS: u32 = 2;
/// Maximum queued uploads accepted before answering `UploadDenied("Too many files")`.
pub const DEFAULT_UPLOAD_QUEUE_CAP: usize = 32;
/// Virtual Soulseek root prefix used for advertised album directories.
pub const SHARE_VIRTUAL_ROOT: &str = "@@peartube";
/// User info description advertised to peers browsing our user profile.
pub const USER_INFO_DESCRIPTION: &str = "PearTube Soulseek Relay";

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

/// Server-tracked upload speed and shared folder/file counts returned by `GetUserStats` (code 36).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserStats {
    pub username: String,
    pub upload_speed: u32,
    pub upload_count: u32,
    pub files: u32,
    pub folders: u32,
}

/// Options for configuring background server keepalive, read liveness, reconnect intervals,
/// and local disk sharing (`slskShare` / `PEARTUBE_SLSK_SHARE` and `PEARTUBE_SLSK_SHARE_MAX_FILES`).
#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub listen_port: u16,
    pub ping_interval: Duration,
    pub server_read_timeout: Duration,
    pub reconnect_backoff_min: Duration,
    pub reconnect_backoff_max: Duration,
    /// Explicit directory to share; when `None` and `share_enabled` is `true`, resolves from
    /// `PEARTUBE_SLSK_SHARE_DIR`, `PEARTUBE_WATCH_DIR`, or `<PEARTUBE_STORAGE>/staging`.
    pub share_dir: Option<PathBuf>,
    /// Opt-in share toggle (`PEARTUBE_SLSK_SHARE=1`, default `false` so private libraries are never published silently).
    pub share_enabled: bool,
    /// Maximum number of media files indexed and advertised (`DEFAULT_SHARE_MAX_FILES = 2000`).
    pub share_max_files: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            listen_port: 0,
            ping_interval: SERVER_PING_INTERVAL,
            server_read_timeout: SERVER_READ_TIMEOUT,
            reconnect_backoff_min: RECONNECT_BACKOFF_MIN,
            reconnect_backoff_max: RECONNECT_BACKOFF_MAX,
            share_dir: default_share_dir_from_env(),
            share_enabled: default_share_enabled_from_env(),
            share_max_files: default_share_max_files_from_env(),
        }
    }
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
    query: String,
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
    in_flight_socket: Option<Arc<Mutex<TcpStream>>>,
    last_queue_poll: Instant,
    cancel: Arc<AtomicBool>,
    preserve_part_on_cancel: bool,
    progress: Option<ProgressCallback>,
    reply: Option<Sender<Result<DownloadOutcome, ClientError>>>,
}

#[derive(Clone)]
struct SharedLocalFile {
    virtual_path: String,
    local_path: PathBuf,
    size: u64,
    attrs: AudioAttributes,
    search_haystack: String,
}

#[derive(Default, Clone)]
struct ShareSnapshot {
    folders: Vec<SharedFolder>,
    files: Vec<SharedLocalFile>,
    by_key: HashMap<String, usize>,
}

impl ShareSnapshot {
    fn folder_count(&self) -> u32 {
        self.folders.len() as u32
    }

    fn file_count(&self) -> u32 {
        self.files.len() as u32
    }

    fn lookup(&self, requested_path: &str) -> Option<&SharedLocalFile> {
        let norm = normalize_virtual_key(requested_path);
        self.by_key.get(&norm).and_then(|&idx| self.files.get(idx))
    }

    fn folder_contents(&self, requested_folder: &str) -> Vec<SharedFolder> {
        let norm = requested_folder
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase();
        if norm.is_empty() {
            return Vec::new();
        }
        let prefix_with_sep = format!("{norm}\\");
        self.folders
            .iter()
            .filter(|dir| {
                let dir_norm = dir
                    .path
                    .replace('/', "\\")
                    .trim_end_matches('\\')
                    .to_ascii_lowercase();
                dir_norm == norm || dir_norm.starts_with(&prefix_with_sep)
            })
            .cloned()
            .collect()
    }

    fn search_matches(&self, query: &str, cap: usize) -> Vec<WireFileEntry> {
        let terms: Vec<String> = query
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        if terms.is_empty() {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for f in &self.files {
            if terms.iter().all(|t| f.search_haystack.contains(t.as_str())) {
                hits.push(WireFileEntry {
                    filename: f.virtual_path.clone(),
                    size: f.size,
                    extension: String::new(),
                    attrs: f.attrs.clone(),
                });
                if hits.len() >= cap {
                    break;
                }
            }
        }
        hits
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UploadSocketState {
    Queued,
    WaitingTransferResponse { offered_at: Instant },
    Connecting { started_at: Instant },
    Transferring,
}

struct ActiveUpload {
    id: u64,
    username: String,
    virtual_path: String,
    local_path: PathBuf,
    file_size: u64,
    transfer_token: Option<u32>,
    connect_token: Option<u32>,
    state: UploadSocketState,
    in_flight_socket: Option<Arc<Mutex<TcpStream>>>,
    cancel: Arc<AtomicBool>,
    progress: Option<ProgressCallback>,
}

struct ActiveUserStatsQuery {
    deadline: Instant,
    reply: Sender<Result<UserStats, ClientError>>,
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
        preserve_part_on_cancel: bool,
        progress: Option<ProgressCallback>,
        reply: Sender<Result<DownloadOutcome, ClientError>>,
    },
    UserStats {
        username: String,
        timeout: Duration,
        reply: Sender<Result<UserStats, ClientError>>,
    },
    ConfigureShare {
        share_dir: Option<PathBuf>,
        share_enabled: bool,
        share_max_files: usize,
        reply: Sender<(u32, u32)>,
    },
    Shutdown,
}

enum WorkerEvent {
    Cmd(WorkerCmd),
    PeerControlConnected {
        session_epoch: Option<u64>,
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
        session_epoch: u64,
        username: String,
        connect_token: Option<u32>,
        reason: String,
    },
    TransferFinished {
        download_id: u64,
        result: Result<DownloadOutcome, TransferError>,
    },
    UploadSocketConnected {
        upload_id: u64,
        stream: TcpStream,
        buffered: Vec<u8>,
    },
    UploadFinished {
        upload_id: u64,
        result: Result<UploadOutcome, TransferError>,
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
        Self::with_options(ClientOptions {
            listen_port,
            ..ClientOptions::default()
        })
    }

    /// Create a client with custom keepalive, server read timeout, and reconnect backoff options.
    #[must_use]
    pub fn with_options(options: ClientOptions) -> Self {
        let listen_port = options.listen_port;
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
                    ClientOptions {
                        listen_port: bound_port,
                        ..options
                    },
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
        self.download_inner(
            username, filename, dest_path, size_hint, cancel, false, progress,
        )
    }

    /// Like [`Self::download_with_cancel`], keeping the `.part` file on disk when aborted via
    /// `cancel` so a subsequent retry or app restart can resume from the last written byte.
    pub fn download_resumable(
        &self,
        username: &str,
        filename: &str,
        dest_path: PathBuf,
        size_hint: Option<u64>,
        cancel: Arc<AtomicBool>,
        progress: Option<ProgressCallback>,
    ) -> Result<DownloadOutcome, ClientError> {
        self.download_inner(
            username, filename, dest_path, size_hint, cancel, true, progress,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn download_inner(
        &self,
        username: &str,
        filename: &str,
        dest_path: PathBuf,
        size_hint: Option<u64>,
        cancel: Arc<AtomicBool>,
        preserve_part_on_cancel: bool,
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
                preserve_part_on_cancel,
                progress,
                reply: tx,
            })
            .map_err(|_| ClientError::Disconnected("worker stopped".to_string()))?;
        rx.recv()
            .map_err(|_| ClientError::Disconnected("worker dropped download reply".to_string()))?
    }

    /// Query server-side user stats (`GetUserStats`, server code 36) for `username`.
    pub fn user_stats(&self, username: &str, timeout: Duration) -> Result<UserStats, ClientError> {
        let u = username.trim();
        if u.is_empty() {
            return Err(ClientError::InvalidCredentials(
                "username is empty".to_string(),
            ));
        }
        let (tx, rx) = mpsc::channel();
        self.cmd_tx
            .send(WorkerCmd::UserStats {
                username: u.to_owned(),
                timeout,
                reply: tx,
            })
            .map_err(|_| ClientError::Disconnected("worker stopped".to_string()))?;
        rx.recv()
            .map_err(|_| ClientError::Disconnected("worker dropped user_stats reply".to_string()))?
    }

    /// Update the local disk share configuration (`share_dir`, `share_enabled`, `share_max_files`)
    /// at runtime, immediately rescanning and advertising updated `SharedFoldersFiles` counts
    /// if logged in. Returns `(folders, files)`.
    pub fn configure_share(
        &self,
        share_dir: Option<PathBuf>,
        share_enabled: bool,
        share_max_files: usize,
    ) -> Result<(u32, u32), ClientError> {
        let (tx, rx) = mpsc::channel();
        self.cmd_tx
            .send(WorkerCmd::ConfigureShare {
                share_dir,
                share_enabled,
                share_max_files,
                reply: tx,
            })
            .map_err(|_| ClientError::Disconnected("worker stopped".to_string()))?;
        rx.recv()
            .map_err(|_| ClientError::Disconnected("worker dropped share reply".to_string()))
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

    options: ClientOptions,
    creds: Option<Credentials>,
    relogged_out: bool,

    session_epoch: u64,
    server_stream: Option<TcpStream>,
    server_decoder: FrameDecoder,
    last_ping: Instant,
    last_server_rx: Instant,
    reconnect_at: Option<Instant>,
    reconnect_backoff: Duration,
    peers: HashMap<String, (u64, Arc<Mutex<TcpStream>>)>,
    pending_peer_msgs: HashMap<String, Vec<PeerMessage>>,
    pending_connect_tokens: HashMap<u32, (String, Instant)>,

    searches: HashMap<u32, ActiveSearch>,
    browses: HashMap<String, ActiveBrowse>,
    downloads: Vec<ActiveDownload>,
    next_download_id: u64,
    share: ShareSnapshot,
    last_share_scan: Instant,
    uploads: Vec<ActiveUpload>,
    next_upload_id: u64,
    last_upload_speed: u32,
    user_stats_queries: HashMap<String, Vec<ActiveUserStatsQuery>>,
}

impl WorkerEngine {
    fn new(
        options: ClientOptions,
        event_tx: Sender<WorkerEvent>,
        state: Arc<RwLock<ClientState>>,
        logger: Arc<RwLock<Option<LoggerHook>>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let now = Instant::now();
        let share = scan_share_snapshot(&options);
        let engine = Self {
            event_tx,
            state,
            logger,
            shutdown,
            reconnect_backoff: options.reconnect_backoff_min,
            options,
            creds: None,
            relogged_out: false,
            session_epoch: 0,
            server_stream: None,
            server_decoder: FrameDecoder::new(),
            last_ping: now,
            last_server_rx: now,
            reconnect_at: None,
            peers: HashMap::new(),
            pending_peer_msgs: HashMap::new(),
            pending_connect_tokens: HashMap::new(),
            searches: HashMap::new(),
            browses: HashMap::new(),
            downloads: Vec::new(),
            next_download_id: 1,
            share,
            last_share_scan: now,
            uploads: Vec::new(),
            next_upload_id: 1,
            last_upload_speed: 0,
            user_stats_queries: HashMap::new(),
        };
        engine.emit_share_decision_log();
        engine
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
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
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
                Self::spawn_peer_reader(None, username, stream, decoder, event_tx, logger);
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
                                io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                                    | io::ErrorKind::Interrupted
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
        session_epoch: Option<u64>,
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
                session_epoch,
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

        self.disconnect_server(false);
        self.abort_session_peer_work("client shutting down", false);
    }

    fn abort_session_peer_work(&mut self, reason: &str, keep_active_transfers: bool) {
        self.pending_connect_tokens.clear();
        self.pending_peer_msgs.clear();
        for (_, (_, writer)) in self.peers.drain() {
            let _ = writer.lock().shutdown(std::net::Shutdown::Both);
        }
        for (_, mut browse) in self.browses.drain() {
            if let Some(reply) = browse.reply.take() {
                let _ = reply.send(Err(ClientError::Disconnected(reason.to_owned())));
            }
        }
        let mut i = 0;
        while i < self.downloads.len() {
            if keep_active_transfers && self.downloads[i].in_flight_socket.is_some() {
                i += 1;
                continue;
            }
            let mut dl = self.downloads.remove(i);
            if let Some(sock) = dl.in_flight_socket.take() {
                let _ = sock.lock().shutdown(std::net::Shutdown::Both);
            }
            if let Some(reply) = dl.reply.take() {
                let _ = reply.send(Err(ClientError::Disconnected(reason.to_owned())));
            }
        }
        for (_, waiting) in self.user_stats_queries.drain() {
            for q in waiting {
                let _ = q
                    .reply
                    .send(Err(ClientError::Disconnected(reason.to_owned())));
            }
        }
        let mut j = 0;
        while j < self.uploads.len() {
            if keep_active_transfers && self.uploads[j].in_flight_socket.is_some() {
                j += 1;
                continue;
            }
            let mut up = self.uploads.remove(j);
            up.cancel.store(true, Ordering::Release);
            if let Some(sock) = up.in_flight_socket.take() {
                let _ = sock.lock().shutdown(std::net::Shutdown::Both);
            }
        }
    }

    fn disconnect_server(&mut self, keep_active_transfers: bool) {
        let had_session = self.server_stream.is_some();
        if let Some(s) = self.server_stream.take() {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        self.server_decoder = FrameDecoder::new();
        self.update_state(false, false, None);
        if had_session {
            self.session_epoch = self.session_epoch.wrapping_add(1);
            self.abort_session_peer_work("server session disconnected", keep_active_transfers);
        }
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
        self.disconnect_server(true);
        if self.creds.is_some() && !self.relogged_out {
            self.reconnect_at = Some(Instant::now() + self.reconnect_backoff);
            self.reconnect_backoff =
                (self.reconnect_backoff * 2).min(self.options.reconnect_backoff_max);
        }
    }

    fn connect_and_authenticate(
        &mut self,
        creds: &Credentials,
    ) -> Result<ClientState, ClientError> {
        self.disconnect_server(false);

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
            let n = match stream.read(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(e) => {
                    self.update_state(false, false, None);
                    return Err(ClientError::Io(format!("read login response: {e}")));
                }
            };
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
                    .set_read_timeout(Some(self.options.server_read_timeout))
                    .map_err(|e| ClientError::Io(e.to_string()))?;
                stream
                    .set_nonblocking(true)
                    .map_err(|e| ClientError::Io(e.to_string()))?;
                let now = Instant::now();
                self.session_epoch = self.session_epoch.wrapping_add(1);
                self.server_stream = Some(stream);
                self.server_decoder = decoder;
                self.last_ping = now;
                self.last_server_rx = now;
                self.reconnect_at = None;
                self.reconnect_backoff = self.options.reconnect_backoff_min;
                self.relogged_out = false;
                self.update_state(true, true, Some(u32::from(is_supporter)));

                // Post-login initialization messages expected by Soulseek servers:
                if self.options.listen_port > 0 {
                    let _ = self.send_server(&ServerRequest::SetWaitPort {
                        port: u32::from(self.options.listen_port),
                    });
                }
                self.refresh_share(false);
                let _ = self.send_server(&ServerRequest::SharedFoldersFiles {
                    folders: self.share.folder_count(),
                    files: self.share.file_count(),
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
                        "logged in as {} (listen_port={}, shared_folders={}, shared_files={})",
                        creds.username,
                        self.options.listen_port,
                        self.share.folder_count(),
                        self.share.file_count()
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
        let mut read_timed_out = false;
        let now = Instant::now();
        if let Some(stream) = self.server_stream.as_mut() {
            loop {
                match stream.read(&mut scratch) {
                    Ok(0) => {
                        disconnected = true;
                        break;
                    }
                    Ok(n) => {
                        self.last_server_rx = Instant::now();
                        self.server_decoder.push(&scratch[..n]);
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        if now.duration_since(self.last_server_rx)
                            >= self.options.server_read_timeout
                        {
                            read_timed_out = true;
                        }
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        self.drain_buffered_server_frames();

        if read_timed_out {
            self.log(
                LogLevel::Warn,
                "server_read_timeout",
                format!(
                    "server socket read timed out after {:?}",
                    self.options.server_read_timeout
                ),
            );
            self.schedule_reconnect();
        } else if disconnected {
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
                self.disconnect_server(false);
            }
            ServerResponse::PeerAddress {
                username, ip, port, ..
            } => {
                self.dial_peer_direct(username.clone(), ip, port);
                self.dial_pending_uploads_direct(&username, ip, port);
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
            ServerResponse::FileSearch {
                username,
                token,
                query,
            } => {
                self.handle_incoming_file_search(username, token, &query);
            }
            ServerResponse::UserStats {
                username,
                upload_speed,
                upload_count,
                files,
                folders,
            } => {
                if let Some(waiters) = self.user_stats_queries.remove(&username) {
                    let stats = UserStats {
                        username,
                        upload_speed,
                        upload_count,
                        files,
                        folders,
                    };
                    for w in waiters {
                        let _ = w.reply.send(Ok(stats.clone()));
                    }
                }
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
                if let Some(idx) = self
                    .uploads
                    .iter()
                    .position(|u| u.connect_token == Some(token) && u.in_flight_socket.is_none())
                {
                    let up = self.uploads.remove(idx);
                    let _ = self.ensure_peer_control(
                        &up.username,
                        PeerMessage::UploadFailed {
                            filename: up.virtual_path,
                        },
                    );
                    self.pump_upload_slots();
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
        let epoch = self.session_epoch;
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
                Self::spawn_peer_reader(
                    Some(epoch),
                    username,
                    stream,
                    FrameDecoder::new(),
                    tx,
                    log,
                );
            });
    }

    fn dial_peer_pierce_p(&self, username: String, ip: Ipv4Addr, port: u32, token: u32) {
        let epoch = self.session_epoch;
        if ip.is_unspecified() || port == 0 || port > 65535 {
            tx_cant_connect(
                &self.event_tx,
                epoch,
                username,
                token,
                "invalid peer address",
            );
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
                        tx_cant_connect(&tx, epoch, username, token, &e.to_string());
                        return;
                    }
                };
                let _ = stream.set_nodelay(true);
                let pierce = PeerInitMessage::PierceFirewall { token }.encode();
                if let Err(e) = stream.write_all(&pierce).and_then(|()| stream.flush()) {
                    tx_cant_connect(&tx, epoch, username, token, &e.to_string());
                    return;
                }
                Self::spawn_peer_reader(
                    Some(epoch),
                    username,
                    stream,
                    FrameDecoder::new(),
                    tx,
                    log,
                );
            });
    }

    fn dial_peer_pierce_f(&self, username: String, ip: Ipv4Addr, port: u32, token: u32) {
        let epoch = self.session_epoch;
        if ip.is_unspecified() || port == 0 || port > 65535 {
            tx_cant_connect(
                &self.event_tx,
                epoch,
                username,
                token,
                "invalid F peer address",
            );
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
                    tx_cant_connect(&tx, epoch, username, token, &e.to_string());
                }
            });
    }

    fn handle_event(&mut self, ev: WorkerEvent) {
        match ev {
            WorkerEvent::Cmd(cmd) => self.handle_command(cmd),
            WorkerEvent::PeerControlConnected {
                session_epoch,
                conn_id,
                username,
                writer,
            } => {
                if session_epoch.is_some_and(|ep| ep != self.session_epoch) {
                    let _ = writer.lock().shutdown(std::net::Shutdown::Both);
                    return;
                }
                if self.server_stream.is_none() && self.searches.is_empty() {
                    let _ = writer.lock().shutdown(std::net::Shutdown::Both);
                    return;
                }
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
                        Some(self.session_epoch),
                        username,
                        stream,
                        decoder,
                        self.event_tx.clone(),
                        Arc::clone(&self.logger),
                    );
                } else if self.server_stream.is_some()
                    && let Some(idx) = self.uploads.iter().position(|u| {
                        u.connect_token == Some(connect_token)
                            && matches!(u.state, UploadSocketState::Connecting { .. })
                            && u.in_flight_socket.is_none()
                    })
                {
                    let upload_id = self.uploads[idx].id;
                    let Some(transfer_token) = self.uploads[idx].transfer_token else {
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    };
                    let buffered = decoder.take_all();
                    let tx = self.event_tx.clone();
                    let _ = thread::Builder::new()
                        .name("slsk-pierce-tx-f".to_string())
                        .spawn(
                            move || match init_pierced_upload_socket(stream, transfer_token) {
                                Ok(ready_stream) => {
                                    let _ = tx.send(WorkerEvent::UploadSocketConnected {
                                        upload_id,
                                        stream: ready_stream,
                                        buffered,
                                    });
                                }
                                Err(e) => {
                                    let _ = tx.send(WorkerEvent::UploadFinished {
                                        upload_id,
                                        result: Err(e),
                                    });
                                }
                            },
                        );
                } else if self.server_stream.is_some()
                    && self
                        .downloads
                        .iter()
                        .any(|d| d.transfer_token.is_some() && d.in_flight_socket.is_none())
                {
                    // Treat as a pierced file socket carrying a 4-byte FileTransferInit ticket.
                    let tx = self.event_tx.clone();
                    let _ = thread::Builder::new()
                        .name("slsk-pierce-rx-f".to_string())
                        .spawn(move || {
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                            let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
                            let mut buf = [0u8; 1024];
                            while decoder.buffered_len() < 4 {
                                if Instant::now() >= deadline {
                                    return;
                                }
                                match stream.read(&mut buf) {
                                    Ok(0) => return,
                                    Ok(n) => decoder.push(&buf[..n]),
                                    Err(e)
                                        if matches!(
                                            e.kind(),
                                            io::ErrorKind::Interrupted
                                                | io::ErrorKind::WouldBlock
                                                | io::ErrorKind::TimedOut
                                        ) => {}
                                    Err(_) => return,
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
                } else {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }
            WorkerEvent::IncomingFileSocket {
                username,
                transfer_token,
                stream,
                buffered,
            } => {
                if self.server_stream.is_none() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                self.start_matched_file_transfer(username, transfer_token, stream, buffered);
            }
            WorkerEvent::PeerDialFailed {
                session_epoch,
                username,
                connect_token,
                reason,
            } => {
                self.log(
                    LogLevel::Debug,
                    "peer_dial_failed",
                    format!("peer dial to {username} failed: {reason}"),
                );
                if session_epoch == self.session_epoch
                    && let Some(token) = connect_token
                {
                    let _ = self.send_server(&ServerRequest::CantConnectToPeer { token, username });
                }
            }
            WorkerEvent::TransferFinished {
                download_id,
                result,
            } => {
                self.finish_download(download_id, result);
            }
            WorkerEvent::UploadSocketConnected {
                upload_id,
                stream,
                buffered,
            } => {
                if self.server_stream.is_none() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                self.start_matched_file_upload(upload_id, stream, buffered);
            }
            WorkerEvent::UploadFinished { upload_id, result } => {
                self.finish_upload(upload_id, result);
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
                let deadline = Instant::now() + timeout;
                let dispatched = if self.server_stream.is_some() {
                    match self.send_server(&ServerRequest::FileSearch {
                        token,
                        query: query.clone(),
                    }) {
                        Ok(()) => true,
                        Err(_) if self.reconnect_at.is_some() => false,
                        Err(e) => {
                            let _ = reply.send(Err(e));
                            return;
                        }
                    }
                } else if self.reconnect_at.is_some() && !self.relogged_out {
                    false
                } else {
                    let _ = reply.send(Err(ClientError::NotLoggedIn));
                    return;
                };
                if dispatched {
                    self.log(
                        LogLevel::Info,
                        "search_started",
                        format!("search dispatched (token={token})"),
                    );
                }
                self.searches.insert(
                    token,
                    ActiveSearch {
                        query,
                        results: Vec::new(),
                        deadline,
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
                preserve_part_on_cancel,
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

                if self.server_stream.is_some() {
                    let _ = self.send_server(&ServerRequest::WatchUser {
                        username: username.clone(),
                    });
                    if let Err(e) = self.ensure_peer_control(
                        &username,
                        PeerMessage::QueueUpload {
                            filename: filename.clone(),
                        },
                    ) {
                        if self.reconnect_at.is_none() {
                            let _ = reply.send(Err(e));
                            return;
                        }
                    } else {
                        let _ = self.ensure_peer_control(
                            &username,
                            PeerMessage::PlaceInQueueRequest {
                                filename: filename.clone(),
                            },
                        );
                    }
                } else if self.reconnect_at.is_none() || self.relogged_out {
                    let _ = reply.send(Err(ClientError::NotLoggedIn));
                    return;
                }
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
                    in_flight_socket: None,
                    last_queue_poll: Instant::now(),
                    cancel,
                    preserve_part_on_cancel,
                    progress,
                    reply: Some(reply),
                });
            }
            WorkerCmd::UserStats {
                username,
                timeout,
                reply,
            } => {
                if let Err(e) = self.send_server(&ServerRequest::GetUserStats {
                    username: username.clone(),
                }) {
                    let _ = reply.send(Err(e));
                    return;
                }
                self.user_stats_queries
                    .entry(username)
                    .or_default()
                    .push(ActiveUserStatsQuery {
                        deadline: Instant::now() + timeout,
                        reply,
                    });
            }
            WorkerCmd::ConfigureShare {
                share_dir,
                share_enabled,
                share_max_files,
                reply,
            } => {
                self.options.share_dir = share_dir;
                self.options.share_enabled = share_enabled;
                self.options.share_max_files = share_max_files;
                self.refresh_share(true);
                self.emit_share_decision_log();
                let _ = reply.send((self.share.folder_count(), self.share.file_count()));
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
                        && dl.in_flight_socket.is_none()
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
                filename,
                ..
            } => {
                // Legacy download request (used by slskd / Seeker). Per SLSKPROTOCOL Peer Code 41a:
                // reject with "Queued" if shared and enqueue via normal upload path so we initiate
                // the F connection to a server-verified peer address; otherwise reject "File not shared.".
                if self.options.share_enabled && self.share.lookup(&filename).is_some() {
                    if let Some((_, writer)) = self.peers.get(&username) {
                        let _ = Self::write_peer_msg(
                            writer,
                            &PeerMessage::TransferResponse {
                                token,
                                allowed: false,
                                file_size: None,
                                reason: Some("Queued".to_string()),
                            },
                        );
                    }
                    self.enqueue_peer_upload(username, filename);
                } else if let Some((_, writer)) = self.peers.get(&username) {
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
            PeerMessage::TransferResponse {
                token,
                allowed,
                reason,
                ..
            } => {
                self.handle_upload_transfer_response(&username, token, allowed, reason);
            }
            PeerMessage::QueueUpload { filename } => {
                self.enqueue_peer_upload(username, filename);
            }
            PeerMessage::PlaceInQueueRequest { filename } => {
                if let Some(place) = self.upload_queue_place(&username, &filename) {
                    let _ = self.ensure_peer_control(
                        &username,
                        PeerMessage::PlaceInQueueResponse { filename, place },
                    );
                }
            }
            PeerMessage::FolderContentsRequest { token, folder } => {
                self.refresh_share_if_stale();
                let folders = if self.options.share_enabled {
                    self.share.folder_contents(&folder)
                } else {
                    Vec::new()
                };
                if let Some((_, writer)) = self.peers.get(&username) {
                    let _ = Self::write_peer_msg(
                        writer,
                        &PeerMessage::FolderContentsResponse {
                            token,
                            root_folder: folder,
                            folders,
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
                        && dl.in_flight_socket.is_none()
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
                self.refresh_share_if_stale();
                let folders = if self.options.share_enabled {
                    self.share.folders.clone()
                } else {
                    Vec::new()
                };
                if let Some((_, writer)) = self.peers.get(&username) {
                    let _ = Self::write_peer_msg(
                        writer,
                        &PeerMessage::SharedFileListResponse {
                            folders,
                            private_folders: Vec::new(),
                        },
                    );
                }
            }
            PeerMessage::UserInfoRequest => {
                let (upload_slots, queue_length, slot_free) = self.upload_slot_status();
                if let Some((_, writer)) = self.peers.get(&username) {
                    let _ = Self::write_peer_msg(
                        writer,
                        &PeerMessage::UserInfoResponse {
                            description: USER_INFO_DESCRIPTION.to_string(),
                            picture: None,
                            upload_slots,
                            queue_length,
                            slot_free,
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
                && dl.in_flight_socket.is_none()
                && username.as_ref().is_none_or(|u| u == &dl.username)
        });

        let Some(dl) = matched else {
            if let Some(upload_id) = self
                .uploads
                .iter()
                .find(|u| {
                    u.transfer_token == Some(transfer_token)
                        && matches!(u.state, UploadSocketState::Connecting { .. })
                        && u.in_flight_socket.is_none()
                        && username.as_ref().is_none_or(|usr| usr == &u.username)
                })
                .map(|u| u.id)
            {
                self.start_matched_file_upload(upload_id, stream, buffered);
            } else {
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
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

        if let Ok(ctrl_handle) = stream.try_clone() {
            dl.in_flight_socket = Some(Arc::new(Mutex::new(ctrl_handle)));
        }
        let download_id = dl.id;
        let final_path = dl.final_path.clone();
        let cancel = Arc::clone(&dl.cancel);
        let preserve_part = dl.preserve_part_on_cancel;
        let progress = dl.progress.clone();
        let tx = self.event_tx.clone();

        let _ = thread::Builder::new()
            .name("slsk-file-rx".to_string())
            .spawn(move || {
                let result = stream_file_download_with_options(
                    stream,
                    &buffered,
                    final_path,
                    expected_size,
                    &cancel,
                    preserve_part,
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
            if self.downloads[i].username == username
                && self.downloads[i].in_flight_socket.is_none()
            {
                let mut dl = self.downloads.remove(i);
                if let Some(reply) = dl.reply.take() {
                    let _ = reply.send(Err(ClientError::Disconnected(reason.to_owned())));
                }
            } else {
                i += 1;
            }
        }
    }

    fn redispatch_after_reconnect(&mut self) {
        let now = Instant::now();
        let active_searches: Vec<(u32, String)> = self
            .searches
            .iter()
            .filter(|(_, s)| now < s.deadline)
            .map(|(&tok, s)| (tok, s.query.clone()))
            .collect();

        let mut reissued_searches = 0usize;
        for (token, query) in active_searches {
            if self
                .send_server(&ServerRequest::FileSearch { token, query })
                .is_ok()
            {
                reissued_searches += 1;
            } else {
                break;
            }
        }

        let mut watched = HashSet::new();
        let waiting: Vec<(String, String)> = self
            .downloads
            .iter()
            .filter(|d| d.in_flight_socket.is_none())
            .map(|d| (d.username.clone(), d.remote_filename.clone()))
            .collect();
        for (u, f) in waiting {
            if watched.insert(u.clone()) {
                let _ = self.send_server(&ServerRequest::WatchUser {
                    username: u.clone(),
                });
            }
            let _ = self.ensure_peer_control(
                &u,
                PeerMessage::QueueUpload {
                    filename: f.clone(),
                },
            );
            let _ = self.ensure_peer_control(&u, PeerMessage::PlaceInQueueRequest { filename: f });
        }
        self.log(
            LogLevel::Info,
            "reconnected",
            format!("reconnected to server; re-issued {reissued_searches} pending search(es)"),
        );
    }

    fn tick_timers(&mut self) {
        let now = Instant::now();

        // 1. Server keepalive ping + privilege check (elicits server response for read liveness)
        if self.server_stream.is_some()
            && now.duration_since(self.last_ping) >= self.options.ping_interval
        {
            self.last_ping = now;
            if self.send_server(&ServerRequest::ServerPing).is_ok() {
                let _ = self.send_server(&ServerRequest::CheckPrivileges);
            }
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
                self.redispatch_after_reconnect();
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
            if self.downloads[i].in_flight_socket.is_none()
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
            if self.downloads[i].in_flight_socket.is_none()
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

        // 7. Expire pending UserStats queries
        let mut empty_stats_users = Vec::new();
        for (u, waiters) in &mut self.user_stats_queries {
            let mut j = 0;
            while j < waiters.len() {
                if now >= waiters[j].deadline {
                    let w = waiters.remove(j);
                    let _ = w
                        .reply
                        .send(Err(ClientError::Timeout(format!("user_stats {u}"))));
                } else {
                    j += 1;
                }
            }
            if waiters.is_empty() {
                empty_stats_users.push(u.clone());
            }
        }
        for u in empty_stats_users {
            self.user_stats_queries.remove(&u);
        }

        // 8. Expire stalled upload handshakes (`WaitingTransferResponse` / `Connecting`)
        let mut timed_out_uploads = Vec::new();
        let mut k = 0;
        while k < self.uploads.len() {
            let expired = match self.uploads[k].state {
                UploadSocketState::WaitingTransferResponse { offered_at } => {
                    now.duration_since(offered_at) >= UPLOAD_HANDSHAKE_TIMEOUT
                }
                UploadSocketState::Connecting { started_at } => {
                    now.duration_since(started_at) >= UPLOAD_HANDSHAKE_TIMEOUT
                }
                UploadSocketState::Queued | UploadSocketState::Transferring => false,
            };
            if expired {
                let up = self.uploads.remove(k);
                timed_out_uploads.push((up.username, up.virtual_path));
            } else {
                k += 1;
            }
        }
        if !timed_out_uploads.is_empty() {
            for (u, vpath) in timed_out_uploads {
                let _ = self.ensure_peer_control(&u, PeerMessage::UploadFailed { filename: vpath });
            }
            self.pump_upload_slots();
        }

        // 9. Periodically refresh watched disk share and advertise changed counts
        if self.server_stream.is_some()
            && now.duration_since(self.last_share_scan) >= SHARE_RESCAN_INTERVAL
        {
            self.refresh_share(true);
        }
    }
}

impl WorkerEngine {
    fn emit_share_decision_log(&self) {
        let line = format_share_decision_json(&self.options, self.share.file_count());
        eprintln!("{line}");
        self.log(LogLevel::Debug, "soulseek_share", line);
    }

    fn refresh_share_if_stale(&mut self) {
        if Instant::now().duration_since(self.last_share_scan) >= Duration::from_secs(10) {
            self.refresh_share(self.server_stream.is_some());
        }
    }

    fn refresh_share(&mut self, notify_server_if_changed: bool) {
        let prev_counts = (self.share.folder_count(), self.share.file_count());
        self.share = scan_share_snapshot(&self.options);
        self.last_share_scan = Instant::now();
        let new_counts = (self.share.folder_count(), self.share.file_count());
        if notify_server_if_changed && new_counts != prev_counts && self.server_stream.is_some() {
            let _ = self.send_server(&ServerRequest::SharedFoldersFiles {
                folders: new_counts.0,
                files: new_counts.1,
            });
        }
    }

    fn active_upload_slots_used(&self) -> usize {
        self.uploads
            .iter()
            .filter(|u| !matches!(u.state, UploadSocketState::Queued))
            .count()
    }

    fn queued_upload_count(&self) -> usize {
        self.uploads
            .iter()
            .filter(|u| matches!(u.state, UploadSocketState::Queued))
            .count()
    }

    fn upload_slot_status(&self) -> (u32, u32, bool) {
        if !self.options.share_enabled {
            return (0, 0, false);
        }
        let slots = DEFAULT_UPLOAD_SLOTS;
        let active = self.active_upload_slots_used() as u32;
        let queued = self.queued_upload_count() as u32;
        let slot_free = active < slots && queued == 0;
        (slots, queued, slot_free)
    }

    fn upload_queue_place(&self, username: &str, filename: &str) -> Option<u32> {
        let mut place = 0u32;
        for up in &self.uploads {
            if matches!(up.state, UploadSocketState::Queued) {
                place += 1;
                if up.username == username && paths_match(&up.virtual_path, filename) {
                    return Some(place);
                }
            }
        }
        None
    }

    fn handle_incoming_file_search(&mut self, requester: String, token: u32, query: &str) {
        if !self.options.share_enabled {
            return;
        }
        let Some(own_user) = self.creds.as_ref().map(|c| c.username.clone()) else {
            return;
        };
        if requester == own_user {
            return;
        }
        let files = self.share.search_matches(query, 50);
        if files.is_empty() {
            return;
        }
        let (_, queue_length, slot_free) = self.upload_slot_status();
        let _ = self.ensure_peer_control(
            &requester,
            PeerMessage::FileSearchResponse {
                username: own_user,
                token,
                files,
                slot_free,
                upload_speed: self.last_upload_speed,
                queue_length,
                private_files: Vec::new(),
            },
        );
    }

    fn enqueue_peer_upload(&mut self, username: String, filename: String) {
        self.refresh_share_if_stale();
        if !self.options.share_enabled {
            let _ = self.ensure_peer_control(
                &username,
                PeerMessage::UploadDenied {
                    filename,
                    reason: "File not shared.".to_string(),
                },
            );
            return;
        }

        let Some(entry) = self.share.lookup(&filename).cloned() else {
            let _ = self.ensure_peer_control(
                &username,
                PeerMessage::UploadDenied {
                    filename,
                    reason: "File not shared.".to_string(),
                },
            );
            return;
        };

        let live_size = match fs::metadata(&entry.local_path) {
            Ok(m) if m.is_file() => m.len(),
            _ => {
                let _ = self.ensure_peer_control(
                    &username,
                    PeerMessage::UploadDenied {
                        filename,
                        reason: "File read error.".to_string(),
                    },
                );
                return;
            }
        };

        // Deduplicate if this peer already has this exact file queued or transferring
        if let Some(existing_place) = self.upload_queue_place(&username, &filename) {
            let _ = self.ensure_peer_control(
                &username,
                PeerMessage::PlaceInQueueResponse {
                    filename,
                    place: existing_place,
                },
            );
            return;
        }
        if self
            .uploads
            .iter()
            .any(|u| u.username == username && paths_match(&u.virtual_path, &filename))
        {
            return;
        }

        if self.queued_upload_count() >= DEFAULT_UPLOAD_QUEUE_CAP {
            let _ = self.ensure_peer_control(
                &username,
                PeerMessage::UploadDenied {
                    filename,
                    reason: "Too many files".to_string(),
                },
            );
            return;
        }

        let id = self.next_upload_id;
        self.next_upload_id += 1;

        self.log(
            LogLevel::Info,
            "upload_queued",
            format!(
                "peer {} queued upload of {}",
                username,
                redacted_basename(&entry.virtual_path)
            ),
        );

        self.uploads.push(ActiveUpload {
            id,
            username: username.clone(),
            virtual_path: filename.clone(),
            local_path: entry.local_path,
            file_size: live_size,
            transfer_token: None,
            connect_token: None,
            state: UploadSocketState::Queued,
            in_flight_socket: None,
            cancel: Arc::new(AtomicBool::new(false)),
            progress: None,
        });

        self.pump_upload_slots();

        if let Some(place) = self.upload_queue_place(&username, &filename) {
            let _ = self.ensure_peer_control(
                &username,
                PeerMessage::PlaceInQueueResponse { filename, place },
            );
        }
    }

    fn pump_upload_slots(&mut self) {
        let max_slots = if self.options.share_enabled {
            DEFAULT_UPLOAD_SLOTS as usize
        } else {
            0
        };
        while self.active_upload_slots_used() < max_slots {
            let Some(idx) = self
                .uploads
                .iter()
                .position(|u| matches!(u.state, UploadSocketState::Queued))
            else {
                break;
            };
            let token = next_token();
            let now = Instant::now();
            self.uploads[idx].transfer_token = Some(token);
            self.uploads[idx].state =
                UploadSocketState::WaitingTransferResponse { offered_at: now };
            let username = self.uploads[idx].username.clone();
            let filename = self.uploads[idx].virtual_path.clone();
            let file_size = self.uploads[idx].file_size;

            if self
                .ensure_peer_control(
                    &username,
                    PeerMessage::TransferRequest {
                        direction: 1,
                        token,
                        filename: filename.clone(),
                        file_size: Some(file_size),
                    },
                )
                .is_err()
            {
                self.uploads.remove(idx);
            }
        }
    }

    fn handle_upload_transfer_response(
        &mut self,
        username: &str,
        token: u32,
        allowed: bool,
        reason: Option<String>,
    ) {
        let Some(idx) = self.uploads.iter().position(|u| {
            u.transfer_token == Some(token)
                && u.username == username
                && matches!(u.state, UploadSocketState::WaitingTransferResponse { .. })
        }) else {
            return;
        };

        if !allowed {
            let removed = self.uploads.remove(idx);
            self.log(
                LogLevel::Debug,
                "upload_rejected_by_peer",
                format!(
                    "peer {} declined upload offer for {} ({})",
                    removed.username,
                    redacted_basename(&removed.virtual_path),
                    reason.unwrap_or_else(|| "declined".to_string())
                ),
            );
            self.pump_upload_slots();
            return;
        }

        let connect_token = next_token();
        self.uploads[idx].connect_token = Some(connect_token);
        self.uploads[idx].state = UploadSocketState::Connecting {
            started_at: Instant::now(),
        };
        let peer_user = self.uploads[idx].username.clone();

        // Initiate F connection using modern dual-path order: ConnectToPeer("F") + GetPeerAddress.
        let _ = self.send_server(&ServerRequest::ConnectToPeer {
            token: connect_token,
            username: peer_user.clone(),
            conn_type: ConnectionType::File,
        });
        let _ = self.send_server(&ServerRequest::GetPeerAddress {
            username: peer_user,
        });
    }

    fn dial_pending_uploads_direct(&self, username: &str, ip: Ipv4Addr, port: u32) {
        if ip.is_unspecified() || port == 0 || port > 65535 {
            return;
        }
        let Some(own_user) = self.creds.as_ref().map(|c| c.username.clone()) else {
            return;
        };
        let host = ip.to_string();
        for up in &self.uploads {
            if up.username == username
                && matches!(up.state, UploadSocketState::Connecting { .. })
                && up.in_flight_socket.is_none()
                && let Some(transfer_token) = up.transfer_token
            {
                let upload_id = up.id;
                let host_clone = host.clone();
                let own_clone = own_user.clone();
                let tx = self.event_tx.clone();
                let _ = thread::Builder::new()
                    .name("slsk-dial-f".to_string())
                    .spawn(move || {
                        if let Ok(stream) =
                            dial_direct_upload_socket(&host_clone, port, &own_clone, transfer_token)
                        {
                            let _ = tx.send(WorkerEvent::UploadSocketConnected {
                                upload_id,
                                stream,
                                buffered: Vec::new(),
                            });
                        }
                    });
            }
        }
    }

    fn start_matched_file_upload(&mut self, upload_id: u64, stream: TcpStream, buffered: Vec<u8>) {
        let Some(up) = self.uploads.iter_mut().find(|u| u.id == upload_id) else {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        };
        if up.in_flight_socket.is_some() {
            // Another path (direct vs pierced) already connected first; close duplicate cleanly.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        up.state = UploadSocketState::Transferring;
        if let Ok(ctrl) = stream.try_clone() {
            up.in_flight_socket = Some(Arc::new(Mutex::new(ctrl)));
        }
        let local_path = up.local_path.clone();
        let cancel = Arc::clone(&up.cancel);
        let progress = up.progress.clone();
        let tx = self.event_tx.clone();

        let _ = thread::Builder::new()
            .name("slsk-file-tx".to_string())
            .spawn(move || {
                let result =
                    stream_file_upload(stream, &buffered, local_path, &cancel, progress.as_ref());
                let _ = tx.send(WorkerEvent::UploadFinished { upload_id, result });
            });
    }

    fn finish_upload(&mut self, upload_id: u64, result: Result<UploadOutcome, TransferError>) {
        let Some(idx) = self.uploads.iter().position(|u| u.id == upload_id) else {
            return;
        };
        let up = self.uploads.remove(idx);
        match result {
            Ok(outcome) => {
                if outcome.speed_bytes_per_sec > 0 {
                    self.last_upload_speed = outcome.speed_bytes_per_sec;
                    let _ = self.send_server(&ServerRequest::SendUploadSpeed {
                        speed: outcome.speed_bytes_per_sec,
                    });
                }
                self.log(
                    LogLevel::Info,
                    "upload_complete",
                    format!(
                        "uploaded {} to {} ({} bytes, offset={})",
                        redacted_basename(&up.virtual_path),
                        up.username,
                        outcome.bytes_sent,
                        outcome.start_offset
                    ),
                );
            }
            Err(e) => {
                self.log(
                    LogLevel::Warn,
                    "upload_failed_local",
                    format!(
                        "upload of {} to {} failed: {e}",
                        redacted_basename(&up.virtual_path),
                        up.username
                    ),
                );
                let _ = self.ensure_peer_control(
                    &up.username,
                    PeerMessage::UploadFailed {
                        filename: up.virtual_path,
                    },
                );
            }
        }
        self.pump_upload_slots();
    }
}

fn default_share_enabled_from_env() -> bool {
    match std::env::var("PEARTUBE_SLSK_SHARE") {
        Ok(raw) => {
            let v = raw.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        }
        Err(_) => false,
    }
}

fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use fmt::Write as _;
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Format the startup/reconfigure share decision JSON line matching the relay's staging log shape:
/// - disabled: `{"msg":"soulseek share","enabled":false,"files":0}` (omits `dir` so private paths stay unlogged)
/// - enabled:  `{"msg":"soulseek share","enabled":true,"files":N,"dir":"..."}`
#[must_use]
pub fn format_share_decision_json(options: &ClientOptions, files: u32) -> String {
    if !options.share_enabled {
        return r#"{"msg":"soulseek share","enabled":false,"files":0}"#.to_string();
    }
    match options.share_dir.as_ref() {
        Some(dir) => {
            let escaped = json_escape(&dir.to_string_lossy());
            format!(
                r#"{{"msg":"soulseek share","enabled":true,"files":{files},"dir":"{escaped}"}}"#
            )
        }
        None => format!(r#"{{"msg":"soulseek share","enabled":true,"files":{files},"dir":null}}"#),
    }
}

fn default_share_max_files_from_env() -> usize {
    std::env::var("PEARTUBE_SLSK_SHARE_MAX_FILES")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_SHARE_MAX_FILES)
}

fn default_share_dir_from_env() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("PEARTUBE_SLSK_SHARE_DIR")
        && !explicit.is_empty()
    {
        return Some(PathBuf::from(explicit));
    }
    if let Some(watch) = std::env::var_os("PEARTUBE_WATCH_DIR")
        && !watch.is_empty()
    {
        return Some(PathBuf::from(watch));
    }
    if let Some(storage) = std::env::var_os("PEARTUBE_STORAGE")
        && !storage.is_empty()
    {
        return Some(PathBuf::from(storage).join("staging"));
    }
    None
}

fn normalize_virtual_key(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

fn is_shareable_media_name(name: &str) -> bool {
    if name.starts_with('.') || name.starts_with('@') {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".part") || lower.ends_with(".json") || lower.ends_with(".tmp") {
        return false;
    }
    let Some((_, ext)) = lower.rsplit_once('.') else {
        return false;
    };
    matches!(
        ext,
        "flac"
            | "mp3"
            | "ogg"
            | "opus"
            | "wav"
            | "aac"
            | "m4a"
            | "alac"
            | "aiff"
            | "aif"
            | "wv"
            | "ape"
            | "mp4"
            | "m4v"
            | "mkv"
            | "webm"
            | "avi"
            | "mov"
            | "ts"
            | "m2ts"
            | "mts"
            | "mpg"
            | "mpeg"
            | "ogv"
    )
}

/// Probe lightweight audio attributes (FLAC `STREAMINFO` sample rate, bit depth, and duration)
/// from the first 128 bytes of a file without decoding audio frames.
fn probe_audio_attributes(path: &Path, file_size: u64) -> AudioAttributes {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if ext == "flac"
        && let Ok(mut f) = File::open(path)
    {
        let mut head = [0u8; 42];
        if f.read_exact(&mut head).is_ok() && &head[0..4] == b"fLaC" && (head[4] & 0x7f) == 0 {
            // FLAC STREAMINFO block (34 bytes starting at offset 8):
            // bytes 18..26 (offset 8 + 10 = 18):
            // [20 bits sample_rate][3 bits channels-1][5 bits bps-1][36 bits total_samples]
            let b = &head[18..26];
            let sr = (u32::from(b[0]) << 12) | (u32::from(b[1]) << 4) | (u32::from(b[2]) >> 4);
            let bps = (((u32::from(b[2]) & 0x01) << 4) | (u32::from(b[3]) >> 4)) + 1;
            let total_samples = ((u64::from(b[3]) & 0x0f) << 32)
                | (u64::from(b[4]) << 24)
                | (u64::from(b[5]) << 16)
                | (u64::from(b[6]) << 8)
                | u64::from(b[7]);
            let length_secs = if sr > 0 && total_samples > 0 {
                Some((total_samples / u64::from(sr)) as u32)
            } else {
                None
            };
            if sr > 0 {
                return AudioAttributes {
                    bitrate: None,
                    length_secs,
                    vbr: None,
                    sample_rate: Some(sr),
                    bit_depth: Some(bps),
                };
            }
        }
    }
    let _ = file_size;
    AudioAttributes::default()
}

/// Scan the configured share directory (one-level album subdirectories plus top-level media files,
/// skipping symlinks, hidden/dot files, `@eaDir`, and `.part` files) up to `options.share_max_files`.
fn scan_share_snapshot(options: &ClientOptions) -> ShareSnapshot {
    if !options.share_enabled || options.share_max_files == 0 {
        return ShareSnapshot::default();
    }
    let Some(root) = options.share_dir.as_ref() else {
        return ShareSnapshot::default();
    };
    let Ok(read_root) = fs::read_dir(root) else {
        return ShareSnapshot::default();
    };

    let mut top_entries: Vec<_> = read_root.filter_map(Result::ok).collect();
    top_entries.sort_by_key(|e| e.file_name());

    let cap = options.share_max_files;
    let mut folders = Vec::new();
    let mut files = Vec::new();
    let mut by_key = HashMap::new();
    let mut root_wire_files = Vec::new();

    for entry in top_entries {
        if files.len() >= cap {
            break;
        }
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        if ft.is_symlink() {
            continue;
        }
        let raw_name = entry.file_name();
        let Some(name) = raw_name.to_str() else {
            continue;
        };
        if name.starts_with('.') || name.starts_with('@') {
            continue;
        }
        let full_path = entry.path();
        if ft.is_dir() {
            let Ok(kids_iter) = fs::read_dir(&full_path) else {
                continue;
            };
            let mut kids: Vec<_> = kids_iter.filter_map(Result::ok).collect();
            kids.sort_by_key(|e| e.file_name());
            let clean_dir = name.replace(['\\', '/'], "_");
            let folder_vpath = format!("{SHARE_VIRTUAL_ROOT}\\{clean_dir}");
            let mut wire_files = Vec::new();

            for kid in kids {
                if files.len() >= cap {
                    break;
                }
                let Ok(kft) = kid.file_type() else {
                    continue;
                };
                if kft.is_symlink() || !kft.is_file() {
                    continue;
                }
                let kname_os = kid.file_name();
                let Some(kname) = kname_os.to_str() else {
                    continue;
                };
                if !is_shareable_media_name(kname) {
                    continue;
                }
                let kpath = kid.path();
                let Ok(meta) = fs::metadata(&kpath) else {
                    continue;
                };
                if !meta.is_file() || meta.len() == 0 {
                    continue;
                }
                let size = meta.len();
                let attrs = probe_audio_attributes(&kpath, size);
                let clean_leaf = kname.replace(['\\', '/'], "_");
                let vpath = format!("{folder_vpath}\\{clean_leaf}");
                let idx = files.len();
                by_key.insert(normalize_virtual_key(&vpath), idx);
                files.push(SharedLocalFile {
                    search_haystack: vpath.to_ascii_lowercase(),
                    virtual_path: vpath,
                    local_path: kpath,
                    size,
                    attrs: attrs.clone(),
                });
                wire_files.push(WireFileEntry {
                    filename: clean_leaf,
                    size,
                    extension: String::new(),
                    attrs,
                });
            }

            if !wire_files.is_empty() {
                folders.push(SharedFolder {
                    path: folder_vpath,
                    files: wire_files,
                });
            }
        } else if ft.is_file() && is_shareable_media_name(name) {
            let Ok(meta) = fs::metadata(&full_path) else {
                continue;
            };
            if !meta.is_file() || meta.len() == 0 {
                continue;
            }
            let size = meta.len();
            let attrs = probe_audio_attributes(&full_path, size);
            let clean_leaf = name.replace(['\\', '/'], "_");
            let vpath = format!("{SHARE_VIRTUAL_ROOT}\\{clean_leaf}");
            let idx = files.len();
            by_key.insert(normalize_virtual_key(&vpath), idx);
            files.push(SharedLocalFile {
                search_haystack: vpath.to_ascii_lowercase(),
                virtual_path: vpath,
                local_path: full_path,
                size,
                attrs: attrs.clone(),
            });
            root_wire_files.push(WireFileEntry {
                filename: clean_leaf,
                size,
                extension: String::new(),
                attrs,
            });
        }
    }

    if !root_wire_files.is_empty() {
        folders.insert(
            0,
            SharedFolder {
                path: SHARE_VIRTUAL_ROOT.to_string(),
                files: root_wire_files,
            },
        );
    }

    ShareSnapshot {
        folders,
        files,
        by_key,
    }
}

fn paths_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    a.replace('/', "\\")
        .eq_ignore_ascii_case(&b.replace('/', "\\"))
}

fn tx_cant_connect(
    tx: &Sender<WorkerEvent>,
    session_epoch: u64,
    username: String,
    token: u32,
    reason: &str,
) {
    let _ = tx.send(WorkerEvent::PeerDialFailed {
        session_epoch,
        username,
        connect_token: Some(token),
        reason: reason.to_owned(),
    });
}
