//! Standalone Soulseek client library for PearTube, with C FFI for Bare native addons.

pub mod addon;
pub mod client;
pub mod proto;
pub mod transfer;

pub use client::{ClientError, ClientState, LogEvent, LogLevel, LoggerHook, SoulseekClient};
pub use proto::{
    AudioAttributes, ConnectionType, DEFAULT_MAJOR_VERSION, DEFAULT_MINOR_VERSION,
    DistributedMessage, FrameDecoder, LoginRejectReason, PeerInitMessage, PeerMessage, ProtoError,
    ServerRequest, ServerResponse, SharedFileRecord, SharedFolder, WireFileEntry, login_checksum,
    md5_hex,
};
pub use transfer::{
    DownloadOutcome, PartWriter, ProgressCallback, TransferError, TransferPhase, TransferProgress,
};
