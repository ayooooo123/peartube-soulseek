//! Soulseek P2P file transfer (`F` connection) streaming, `.part` resume, and queue state.
//!
//! Never logs full remote or local paths at `info` level (basenames only).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::proto::{PeerInitMessage, encode_file_offset};

const READ_CHUNK_BYTES: usize = 64 * 1024;
const PROGRESS_REPORT_BYTES: usize = 128 * 1024;
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);
const READ_POLL_TIMEOUT: Duration = Duration::from_secs(1);
const STALL_TIMEOUT: Duration = Duration::from_secs(45);

/// Extract only the leaf basename of a Soulseek virtual path (`\` or `/`) for safe logging.
#[must_use]
pub fn redacted_basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransferPhase {
    Queued { place: Option<u32> },
    Connecting,
    Transferring,
    Completed,
    Failed(String),
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub bytes_downloaded: u64,
    pub total_bytes: u64,
    pub speed_bytes_per_sec: f64,
    pub queue_place: Option<u32>,
    pub phase: TransferPhase,
}

pub type ProgressCallback = Arc<dyn Fn(TransferProgress) + Send + Sync>;

#[derive(Debug)]
pub enum TransferError {
    DialFailed(io::Error),
    HandshakeFailed(io::Error),
    ReadFailed(io::Error),
    WriteFailed(io::Error),
    Stalled,
    Cancelled,
    Denied(String),
    UploadFailed,
    Incomplete { received: u64, expected: u64 },
    InvalidDestination(String),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DialFailed(e) => write!(f, "file socket dial failed: {e}"),
            Self::HandshakeFailed(e) => write!(f, "file transfer handshake failed: {e}"),
            Self::ReadFailed(e) => write!(f, "file socket read error: {e}"),
            Self::WriteFailed(e) => write!(f, "disk write error: {e}"),
            Self::Stalled => write!(f, "file transfer stalled"),
            Self::Cancelled => write!(f, "download cancelled"),
            Self::Denied(reason) => write!(f, "upload denied by peer: {reason}"),
            Self::UploadFailed => write!(f, "peer reported upload failed"),
            Self::Incomplete { received, expected } => {
                write!(
                    f,
                    "incomplete transfer: received {received} of {expected} bytes"
                )
            }
            Self::InvalidDestination(msg) => write!(f, "invalid destination path: {msg}"),
        }
    }
}

impl std::error::Error for TransferError {}

#[derive(Debug, Clone)]
pub struct DownloadOutcome {
    pub path: PathBuf,
    pub size: u64,
    pub resumed_from: u64,
}

/// Resolve destination path: if `dest_path` is an existing directory (or ends with a path
/// separator), append the sanitized leaf basename of `remote_filename`. Otherwise treat
/// `dest_path` as the exact target file path.
pub fn resolve_dest_file(
    dest_path: &Path,
    remote_filename: &str,
) -> Result<PathBuf, TransferError> {
    let raw_str = dest_path.as_os_str().to_string_lossy();
    let looks_like_dir = dest_path.is_dir() || raw_str.ends_with('/') || raw_str.ends_with('\\');
    let target = if looks_like_dir {
        let leaf = redacted_basename(remote_filename);
        let safe_leaf: String = leaf
            .chars()
            .map(|c| match c {
                '/' | '\\' | '\0' => '_',
                other => other,
            })
            .collect();
        if safe_leaf.is_empty() || safe_leaf == "." || safe_leaf == ".." {
            return Err(TransferError::InvalidDestination(
                "remote filename has no valid basename".to_string(),
            ));
        }
        dest_path.join(safe_leaf)
    } else {
        dest_path.to_path_buf()
    };

    if target.as_os_str().is_empty() {
        return Err(TransferError::InvalidDestination(
            "empty destination path".to_string(),
        ));
    }
    Ok(target)
}

#[must_use]
pub fn part_path_for(final_path: &Path) -> PathBuf {
    let mut os = final_path.as_os_str().to_os_string();
    os.push(".part");
    PathBuf::from(os)
}

/// Resumable `.part` file handle. Keeps partial bytes on failure and atomically renames on full byte match.
pub struct PartWriter {
    file: File,
    part_path: PathBuf,
    final_path: PathBuf,
    written: u64,
    resumed_from: u64,
    expected: u64,
}

impl PartWriter {
    pub fn open(final_path: PathBuf, expected: u64) -> Result<Self, TransferError> {
        if let Some(parent) = final_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(TransferError::WriteFailed)?;
        }
        let part_path = part_path_for(&final_path);
        let existing_len = fs::metadata(&part_path).map_or(0, |m| m.len());
        // If .part exists and is strictly smaller than expected, resume from existing_len.
        // Otherwise truncate and start fresh at 0 so stale/oversized partials never corrupt.
        let resumed_from = if existing_len > 0 && existing_len < expected {
            existing_len
        } else {
            0
        };

        let file = if resumed_from > 0 {
            OpenOptions::new()
                .append(true)
                .open(&part_path)
                .map_err(TransferError::WriteFailed)?
        } else {
            File::create(&part_path).map_err(TransferError::WriteFailed)?
        };

        Ok(Self {
            file,
            part_path,
            final_path,
            written: resumed_from,
            resumed_from,
            expected,
        })
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.written
    }

    #[must_use]
    pub const fn resumed_from(&self) -> u64 {
        self.resumed_from
    }

    pub fn append_chunk(&mut self, data: &[u8]) -> Result<usize, TransferError> {
        let remaining = self.expected.saturating_sub(self.written);
        let to_write = (data.len() as u64).min(remaining) as usize;
        if to_write > 0 {
            self.file
                .write_all(&data[..to_write])
                .map_err(TransferError::WriteFailed)?;
            self.written += to_write as u64;
        }
        Ok(to_write)
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.written >= self.expected
    }

    pub fn discard(self) {
        drop(self.file);
        let _ = fs::remove_file(&self.part_path);
    }

    pub fn finalize(mut self) -> Result<DownloadOutcome, TransferError> {
        if !self.is_complete() {
            return Err(TransferError::Incomplete {
                received: self.written,
                expected: self.expected,
            });
        }
        self.file.flush().map_err(TransferError::WriteFailed)?;
        drop(self.file);
        fs::rename(&self.part_path, &self.final_path).map_err(TransferError::WriteFailed)?;
        Ok(DownloadOutcome {
            path: self.final_path,
            size: self.expected,
            resumed_from: self.resumed_from,
        })
    }
}

/// Dial a peer back on `ConnectToPeer("F")`, send `PierceFirewall(connect_token)`,
/// read the 4-byte `FileTransferInit` ticket, and return `(stream, transfer_token)`.
pub fn dial_pierced_file_socket(
    host: &str,
    port: u32,
    connect_token: u32,
) -> Result<(TcpStream, u32), TransferError> {
    let addr: SocketAddr = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(TransferError::DialFailed)?
        .next()
        .ok_or_else(|| {
            TransferError::DialFailed(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unresolvable peer address",
            ))
        })?;

    let mut stream =
        TcpStream::connect_timeout(&addr, DIAL_TIMEOUT).map_err(TransferError::DialFailed)?;
    let _ = stream.set_nodelay(true);
    stream
        .set_read_timeout(Some(DIAL_TIMEOUT))
        .map_err(TransferError::HandshakeFailed)?;
    stream
        .set_write_timeout(Some(DIAL_TIMEOUT))
        .map_err(TransferError::HandshakeFailed)?;

    let pierce = PeerInitMessage::PierceFirewall {
        token: connect_token,
    }
    .encode();
    stream
        .write_all(&pierce)
        .map_err(TransferError::HandshakeFailed)?;
    stream.flush().map_err(TransferError::HandshakeFailed)?;

    let mut ticket_bytes = [0u8; 4];
    stream
        .read_exact(&mut ticket_bytes)
        .map_err(TransferError::HandshakeFailed)?;
    let transfer_token = u32::from_le_bytes(ticket_bytes);
    Ok((stream, transfer_token))
}

/// Stream a matched `F` connection from offset to completion.
///
/// Protocol order:
/// 1. Downloader writes 8-byte little-endian `FileOffset` (`part.offset()`).
/// 2. Uploader streams raw file bytes `[offset..expected_size]`.
/// 3. Downloader closes the `F` socket once `expected_size` bytes are on disk.
pub fn stream_file_download(
    mut stream: TcpStream,
    initial_buffered: &[u8],
    final_path: PathBuf,
    expected_size: u64,
    cancel: &AtomicBool,
    on_progress: Option<&ProgressCallback>,
) -> Result<DownloadOutcome, TransferError> {
    let mut part = PartWriter::open(final_path, expected_size)?;
    let start_offset = part.offset();

    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(TransferError::HandshakeFailed)?;
    stream
        .write_all(&encode_file_offset(start_offset))
        .map_err(TransferError::HandshakeFailed)?;
    stream.flush().map_err(TransferError::HandshakeFailed)?;

    if let Some(cb) = on_progress {
        cb(TransferProgress {
            bytes_downloaded: part.offset(),
            total_bytes: expected_size,
            speed_bytes_per_sec: 0.0,
            queue_place: None,
            phase: TransferPhase::Transferring,
        });
    }

    if !initial_buffered.is_empty() {
        part.append_chunk(initial_buffered)?;
    }

    stream
        .set_read_timeout(Some(READ_POLL_TIMEOUT))
        .map_err(TransferError::ReadFailed)?;

    let mut buf = vec![0u8; READ_CHUNK_BYTES];
    let mut last_activity = Instant::now();
    let mut window_start = Instant::now();
    let mut window_bytes = 0usize;

    while !part.is_complete() {
        if cancel.load(Ordering::Acquire) {
            part.discard();
            return Err(TransferError::Cancelled);
        }

        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                last_activity = Instant::now();
                let written = part.append_chunk(&buf[..n])?;
                window_bytes += written;

                if window_bytes >= PROGRESS_REPORT_BYTES || part.is_complete() {
                    let elapsed = window_start.elapsed().as_secs_f64();
                    let speed = if elapsed > 0.0 {
                        window_bytes as f64 / elapsed
                    } else {
                        0.0
                    };
                    if let Some(cb) = on_progress {
                        cb(TransferProgress {
                            bytes_downloaded: part.offset(),
                            total_bytes: expected_size,
                            speed_bytes_per_sec: speed,
                            queue_place: None,
                            phase: TransferPhase::Transferring,
                        });
                    }
                    window_bytes = 0;
                    window_start = Instant::now();
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                if last_activity.elapsed() >= STALL_TIMEOUT {
                    return Err(TransferError::Stalled);
                }
            }
            Err(e) => return Err(TransferError::ReadFailed(e)),
        }
    }

    // Downloader closes the F socket immediately once expected bytes have arrived.
    drop(stream);

    let outcome = part.finalize()?;
    if let Some(cb) = on_progress {
        cb(TransferProgress {
            bytes_downloaded: outcome.size,
            total_bytes: outcome.size,
            speed_bytes_per_sec: 0.0,
            queue_place: None,
            phase: TransferPhase::Completed,
        });
    }
    Ok(outcome)
}
