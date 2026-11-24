//! Standalone Soulseek client library in Rust with a non-blocking C ABI (`soulseek/soulseek.h`).

pub mod client;
#[cfg(feature = "c-api")]
pub mod ffi;
pub mod proto;
pub mod transfer;

pub use client::{
    ClientError, ClientOptions, ClientState, DEFAULT_SHARE_MAX_FILES, DEFAULT_UPLOAD_QUEUE_CAP,
    DEFAULT_UPLOAD_SLOTS, LogEvent, LogLevel, LoggerHook, SHARE_VIRTUAL_ROOT, SoulseekClient,
    USER_INFO_DESCRIPTION, UserStats, format_share_decision_json,
};
pub use proto::{
    AudioAttributes, ConnectionType, DEFAULT_MAJOR_VERSION, DEFAULT_MINOR_VERSION,
    DistributedMessage, FrameDecoder, LoginRejectReason, PeerInitMessage, PeerMessage, ProtoError,
    ServerRequest, ServerResponse, SharedFileRecord, SharedFolder, WireFileEntry, login_checksum,
    md5_hex,
};
pub use transfer::{
    DownloadOutcome, PartWriter, ProgressCallback, TransferError, TransferPhase, TransferProgress,
    UploadOutcome, stream_file_download_with_options,
};
