//! Standalone Soulseek client library in Rust with a non-blocking C ABI (`soulseek/soulseek.h`).

pub mod client;
pub mod ffi;
pub mod proto;
pub mod transfer;

pub use client::{
    ClientError, ClientOptions, ClientState, LogEvent, LogLevel, LoggerHook, SoulseekClient,
};
pub use proto::{
    AudioAttributes, ConnectionType, DEFAULT_MAJOR_VERSION, DEFAULT_MINOR_VERSION,
    DistributedMessage, FrameDecoder, LoginRejectReason, PeerInitMessage, PeerMessage, ProtoError,
    ServerRequest, ServerResponse, SharedFileRecord, SharedFolder, WireFileEntry, login_checksum,
    md5_hex,
};
pub use transfer::{
    DownloadOutcome, PartWriter, ProgressCallback, TransferError, TransferPhase, TransferProgress,
};
