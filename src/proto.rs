//! Soulseek binary wire protocol codec (little-endian length-prefixed framing).
//!
//! Grounded in Nicotine+ `pynicotine/slskmessages.py` and `SLSKPROTOCOL.md`.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;

use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use md5::{Digest, Md5};

/// Experimental / third-party client major version documented in SLSKPROTOCOL.
pub const DEFAULT_MAJOR_VERSION: u32 = 177;
/// Project minor version for PearTube Soulseek client.
pub const DEFAULT_MINOR_VERSION: u32 = 1;

/// Maximum uncompressed size accepted for zlib-compressed peer payloads (64 MiB).
pub const MAX_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;
/// Maximum raw frame length accepted from untrusted sockets (32 MiB).
pub const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;
/// Maximum array element count accepted before checking remaining bytes.
const MAX_COLLECTION_LEN: usize = 500_000;

/// File attribute codes from `SLSKPROTOCOL`.
pub mod attr {
    pub const BITRATE: u32 = 0;
    pub const DURATION: u32 = 1;
    pub const VBR: u32 = 2;
    pub const ENCODER: u32 = 3; // obsolete
    pub const SAMPLE_RATE: u32 = 4;
    pub const BIT_DEPTH: u32 = 5;
}

/// Server message codes.
pub mod server_code {
    pub const LOGIN: u32 = 1;
    pub const SET_WAIT_PORT: u32 = 2;
    pub const GET_PEER_ADDRESS: u32 = 3;
    pub const WATCH_USER: u32 = 5;
    pub const UNWATCH_USER: u32 = 6;
    pub const GET_USER_STATUS: u32 = 7;
    pub const CONNECT_TO_PEER: u32 = 18;
    pub const MESSAGE_USER: u32 = 22;
    pub const MESSAGE_ACKED: u32 = 23;
    pub const FILE_SEARCH: u32 = 26;
    pub const SET_STATUS: u32 = 28;
    pub const SERVER_PING: u32 = 32;
    pub const SHARED_FOLDERS_FILES: u32 = 35;
    pub const GET_USER_STATS: u32 = 36;
    pub const RELOGGED: u32 = 41;
    pub const USER_SEARCH: u32 = 42;
    pub const ROOM_LIST: u32 = 64;
    pub const ADMIN_MESSAGE: u32 = 66;
    pub const PRIVILEGED_USERS: u32 = 69;
    pub const HAVE_NO_PARENT: u32 = 71;
    pub const PARENT_MIN_SPEED: u32 = 83;
    pub const PARENT_SPEED_RATIO: u32 = 84;
    pub const CHECK_PRIVILEGES: u32 = 92;
    pub const EMBEDDED_MESSAGE: u32 = 93;
    pub const ACCEPT_CHILDREN: u32 = 100;
    pub const POSSIBLE_PARENTS: u32 = 102;
    pub const WISHLIST_INTERVAL: u32 = 104;
    pub const ROOM_SEARCH: u32 = 120;
    pub const SEND_UPLOAD_SPEED: u32 = 121;
    pub const BRANCH_LEVEL: u32 = 126;
    pub const BRANCH_ROOT: u32 = 127;
    pub const RESET_DISTRIBUTED: u32 = 130;
    pub const EXCLUDED_SEARCH_PHRASES: u32 = 160;
    pub const CANT_CONNECT_TO_PEER: u32 = 1001;
}

/// Peer init message codes (`uint8` code).
pub mod init_code {
    pub const PIERCE_FIREWALL: u8 = 0;
    pub const PEER_INIT: u8 = 1;
}

/// Peer message codes (`uint32` code on `P` connections).
pub mod peer_code {
    pub const SHARED_FILE_LIST_REQUEST: u32 = 4;
    pub const SHARED_FILE_LIST_RESPONSE: u32 = 5;
    pub const FILE_SEARCH_RESPONSE: u32 = 9;
    pub const USER_INFO_REQUEST: u32 = 15;
    pub const USER_INFO_RESPONSE: u32 = 16;
    pub const FOLDER_CONTENTS_REQUEST: u32 = 36;
    pub const FOLDER_CONTENTS_RESPONSE: u32 = 37;
    pub const TRANSFER_REQUEST: u32 = 40;
    pub const TRANSFER_RESPONSE: u32 = 41;
    pub const QUEUE_UPLOAD: u32 = 43;
    pub const PLACE_IN_QUEUE_RESPONSE: u32 = 44;
    pub const UPLOAD_FAILED: u32 = 46;
    pub const UPLOAD_DENIED: u32 = 50;
    pub const PLACE_IN_QUEUE_REQUEST: u32 = 51;
}

/// Distributed message codes (`uint8` code on `D` connections).
pub mod distrib_code {
    pub const PING: u8 = 0;
    pub const SEARCH: u8 = 3;
    pub const BRANCH_LEVEL: u8 = 4;
    pub const BRANCH_ROOT: u8 = 5;
    pub const EMBEDDED_MESSAGE: u8 = 93;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    UnexpectedEof { needed: usize, remaining: usize },
    FrameTooLarge(usize),
    FrameTooShort(usize),
    DecompressError(String),
    InvalidConnectionType(String),
    InvalidMessageCode(u32),
    InvalidBool(u8),
    CollectionTooLarge(usize),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof { needed, remaining } => {
                write!(f, "unexpected EOF: needed {needed} bytes, had {remaining}")
            }
            Self::FrameTooLarge(n) => write!(f, "frame exceeds limit ({n} bytes)"),
            Self::FrameTooShort(n) => write!(f, "frame shorter than header ({n} bytes)"),
            Self::DecompressError(msg) => write!(f, "zlib error: {msg}"),
            Self::InvalidConnectionType(s) => write!(f, "invalid connection type: {s:?}"),
            Self::InvalidMessageCode(c) => write!(f, "unknown or invalid message code: {c}"),
            Self::InvalidBool(b) => write!(f, "invalid bool byte: {b}"),
            Self::CollectionTooLarge(n) => write!(f, "collection count too large: {n}"),
        }
    }
}

impl std::error::Error for ProtoError {}

/// Compute lowercase 32-char ASCII hex MD5 digest of `input`.
#[must_use]
pub fn md5_hex(input: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(32);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// Compute MD5 login checksum `md5(username + password)` as lowercase hex.
#[must_use]
pub fn login_checksum(username: &str, password: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(username.as_bytes());
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(32);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn zlib_compress(raw: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(4));
    enc.write_all(raw)
        .map_err(|e| ProtoError::DecompressError(e.to_string()))?;
    enc.finish()
        .map_err(|e| ProtoError::DecompressError(e.to_string()))
}

pub fn zlib_decompress(compressed: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let decoder = ZlibDecoder::new(compressed);
    let mut limited = decoder.take(MAX_DECOMPRESSED_BYTES + 1);
    let mut out = Vec::new();
    limited
        .read_to_end(&mut out)
        .map_err(|e| ProtoError::DecompressError(e.to_string()))?;
    if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(ProtoError::DecompressError(
            "decompressed payload exceeds 64 MiB cap".to_string(),
        ));
    }
    Ok(out)
}

/// Low-level little-endian wire writer.
#[derive(Debug, Default, Clone)]
pub struct WireWriter {
    buf: Vec<u8>,
}

impl WireWriter {
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn write_bool(&mut self, v: bool) {
        self.buf.push(u8::from(v));
    }

    pub fn write_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_bytes_prefixed(&mut self, bytes: &[u8]) {
        self.write_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn write_str(&mut self, s: &str) {
        self.write_bytes_prefixed(s.as_bytes());
    }

    /// Soulseek packs IPv4 addresses in reversed network order (`a.b.c.d` -> `[d, c, b, a]`).
    pub fn write_ipv4(&mut self, ip: Ipv4Addr) {
        let octets = ip.octets();
        self.buf
            .extend_from_slice(&[octets[3], octets[2], octets[1], octets[0]]);
    }

    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Wrap body with `[u32 len][u32 code][body]`.
    #[must_use]
    pub fn into_u32_frame(self, code: u32) -> Vec<u8> {
        let payload_len = (4 + self.buf.len()) as u32;
        let mut frame = Vec::with_capacity(8 + self.buf.len());
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&code.to_le_bytes());
        frame.extend_from_slice(&self.buf);
        frame
    }

    /// Wrap body with `[u32 len][u8 code][body]` (used by PeerInit and Distributed messages).
    #[must_use]
    pub fn into_u8_frame(self, code: u8) -> Vec<u8> {
        let payload_len = (1 + self.buf.len()) as u32;
        let mut frame = Vec::with_capacity(5 + self.buf.len());
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.push(code);
        frame.extend_from_slice(&self.buf);
        frame
    }
}

/// Low-level little-endian wire reader with bounds checks on every read.
#[derive(Debug, Clone)]
pub struct WireReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireReader<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.remaining() < n {
            return Err(ProtoError::UnexpectedEof {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn read_u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_bool(&mut self) -> Result<bool, ProtoError> {
        Ok(self.read_u8()? != 0)
    }

    pub fn read_u16(&mut self) -> Result<u16, ProtoError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_i32(&mut self) -> Result<i32, ProtoError> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, ProtoError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Unpack file size with the Nicotine+ Soulseek NS >2 GiB sign-extension workaround.
    pub fn read_file_size(&mut self) -> Result<u64, ProtoError> {
        let b = self.take(8)?;
        if b[4..8] == [0xff, 0xff, 0xff, 0xff] {
            Ok(u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
        } else {
            Ok(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
    }

    pub fn read_bytes_prefixed(&mut self) -> Result<&'a [u8], ProtoError> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }

    /// Strings are UTF-8 in modern clients, falling back losslessly to Latin-1 for legacy peers.
    pub fn read_string(&mut self) -> Result<String, ProtoError> {
        let raw = self.read_bytes_prefixed()?;
        match std::str::from_utf8(raw) {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => Ok(raw.iter().map(|&b| char::from(b)).collect()),
        }
    }

    pub fn skip_string(&mut self) -> Result<(), ProtoError> {
        let len = self.read_u32()? as usize;
        let _ = self.take(len)?;
        Ok(())
    }

    pub fn read_ipv4(&mut self) -> Result<Ipv4Addr, ProtoError> {
        let b = self.take(4)?;
        Ok(Ipv4Addr::new(b[3], b[2], b[1], b[0]))
    }

    fn checked_count(&mut self, min_item_bytes: usize) -> Result<usize, ProtoError> {
        let n = self.read_u32()? as usize;
        if n > MAX_COLLECTION_LEN {
            return Err(ProtoError::CollectionTooLarge(n));
        }
        if min_item_bytes > 0 && n.saturating_mul(min_item_bytes) > self.remaining() {
            return Err(ProtoError::UnexpectedEof {
                needed: n.saturating_mul(min_item_bytes),
                remaining: self.remaining(),
            });
        }
        Ok(n)
    }
}

/// Incremental TCP frame buffer for `[u32 len][payload...]` streams.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    read_pos: usize,
}

impl FrameDecoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(8192),
            read_pos: 0,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) {
        if self.read_pos > 0 && self.read_pos == self.buf.len() {
            self.buf.clear();
            self.read_pos = 0;
        } else if self.read_pos >= 64 * 1024 && self.read_pos * 2 >= self.buf.len() {
            self.buf.drain(..self.read_pos);
            self.read_pos = 0;
        }
        self.buf.extend_from_slice(chunk);
    }

    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buf.len().saturating_sub(self.read_pos)
    }

    #[must_use]
    pub fn buffered_slice(&self) -> &[u8] {
        &self.buf[self.read_pos..]
    }

    /// Take exactly `n` raw bytes (used on `F` connections where there is no length prefix).
    pub fn take_raw(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.buffered_len() < n {
            return None;
        }
        let out = self.buf[self.read_pos..self.read_pos + n].to_vec();
        self.read_pos += n;
        if self.read_pos == self.buf.len() {
            self.buf.clear();
            self.read_pos = 0;
        }
        Some(out)
    }

    /// Drain all currently buffered bytes.
    pub fn take_all(&mut self) -> Vec<u8> {
        let out = self.buf[self.read_pos..].to_vec();
        self.buf.clear();
        self.read_pos = 0;
        out
    }

    /// Extract next length-prefixed payload (without the 4-byte length prefix).
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ProtoError> {
        let avail = self.buffered_len();
        if avail < 4 {
            return Ok(None);
        }
        let slice = &self.buf[self.read_pos..];
        let body_len = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize;
        if body_len > MAX_FRAME_BYTES {
            return Err(ProtoError::FrameTooLarge(body_len));
        }
        if avail < 4 + body_len {
            return Ok(None);
        }
        let payload = slice[4..4 + body_len].to_vec();
        self.read_pos += 4 + body_len;
        if self.read_pos == self.buf.len() {
            self.buf.clear();
            self.read_pos = 0;
        }
        Ok(Some(payload))
    }
}

/// Read one length-prefixed frame synchronously from a blocking `Read`.
pub fn read_frame_sync<R: Read>(reader: &mut R) -> Result<Vec<u8>, io::Error> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Soulseek frame too large: {len} bytes"),
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(body)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionType {
    Peer,
    File,
    Distributed,
}

impl ConnectionType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Peer => "P",
            Self::File => "F",
            Self::Distributed => "D",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ProtoError> {
        match s {
            "P" => Ok(Self::Peer),
            "F" => Ok(Self::File),
            "D" => Ok(Self::Distributed),
            other => Err(ProtoError::InvalidConnectionType(other.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginRejectReason {
    InvalidUsername,
    EmptyPassword,
    InvalidPass,
    InvalidVersion,
    ServerFull,
    ServerPrivate,
    Other,
}

impl LoginRejectReason {
    #[must_use]
    pub fn from_wire(s: &str) -> Self {
        match s {
            "INVALIDUSERNAME" => Self::InvalidUsername,
            "EMPTYPASSWORD" => Self::EmptyPassword,
            "INVALIDPASS" => Self::InvalidPass,
            "INVALIDVERSION" => Self::InvalidVersion,
            "SVRFULL" => Self::ServerFull,
            "SVRPRIVATE" | "SERVERPRIVATE" => Self::ServerPrivate,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AudioAttributes {
    pub bitrate: Option<u32>,
    pub length_secs: Option<u32>,
    pub vbr: Option<u32>,
    pub sample_rate: Option<u32>,
    pub bit_depth: Option<u32>,
}

impl AudioAttributes {
    pub fn read_from(r: &mut WireReader<'_>) -> Result<Self, ProtoError> {
        let count = r.checked_count(8)?;
        let mut attrs = Self::default();
        for _ in 0..count {
            let code = r.read_u32()?;
            let val = r.read_u32()?;
            match code {
                attr::BITRATE => attrs.bitrate = Some(val),
                attr::DURATION => attrs.length_secs = Some(val),
                attr::VBR => attrs.vbr = Some(val),
                attr::SAMPLE_RATE => attrs.sample_rate = Some(val),
                attr::BIT_DEPTH => attrs.bit_depth = Some(val),
                _ => {}
            }
        }
        Ok(attrs)
    }

    pub fn write_to(&self, w: &mut WireWriter) {
        let mut pairs = Vec::with_capacity(5);
        if let Some(v) = self.bitrate {
            pairs.push((attr::BITRATE, v));
        }
        if let Some(v) = self.length_secs {
            pairs.push((attr::DURATION, v));
        }
        if let Some(v) = self.vbr {
            pairs.push((attr::VBR, v));
        }
        if let Some(v) = self.sample_rate {
            pairs.push((attr::SAMPLE_RATE, v));
        }
        if let Some(v) = self.bit_depth {
            pairs.push((attr::BIT_DEPTH, v));
        }
        w.write_u32(pairs.len() as u32);
        for (code, val) in pairs {
            w.write_u32(code);
            w.write_u32(val);
        }
    }

    /// Derive effective bitrate when lossless files only advertise sample_rate + bit_depth.
    #[must_use]
    pub fn effective_bitrate(&self) -> Option<u32> {
        if let Some(br) = self.bitrate {
            return Some(br);
        }
        match (self.sample_rate, self.bit_depth) {
            (Some(sr), Some(bd)) if sr > 0 && bd > 0 => {
                Some((u64::from(sr) * u64::from(bd) * 2 / 1000) as u32)
            }
            _ => None,
        }
    }
}

/// Shared file entry inside search responses or directory listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFileEntry {
    pub filename: String,
    pub size: u64,
    pub extension: String,
    pub attrs: AudioAttributes,
}

impl WireFileEntry {
    pub fn read_from(r: &mut WireReader<'_>) -> Result<Self, ProtoError> {
        let _code = r.read_u8()?;
        let filename = r.read_string()?;
        let size = r.read_file_size()?;
        let extension = r.read_string()?;
        let attrs = AudioAttributes::read_from(r)?;
        Ok(Self {
            filename,
            size,
            extension,
            attrs,
        })
    }

    pub fn write_to(&self, w: &mut WireWriter) {
        w.write_u8(1);
        w.write_str(&self.filename);
        w.write_u64(self.size);
        w.write_str(&self.extension);
        self.attrs.write_to(w);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFolder {
    pub path: String,
    pub files: Vec<WireFileEntry>,
}

/// High-level normalized file record returned by `search` and `browse` for the importer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFileRecord {
    pub username: String,
    pub slots: bool,
    pub queue: u32,
    pub speed: u32,
    pub filename: String,
    pub size: u64,
    pub bitrate: Option<u32>,
    pub sample_rate: Option<u32>,
    pub bit_depth: Option<u32>,
    pub length_secs: Option<u32>,
}

// ============================================================================
// Server Messages (Client -> Server & Server -> Client)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerRequest {
    Login {
        username: String,
        password: String,
        major_version: u32,
        minor_version: u32,
    },
    SetWaitPort {
        port: u32,
    },
    GetPeerAddress {
        username: String,
    },
    WatchUser {
        username: String,
    },
    UnwatchUser {
        username: String,
    },
    GetUserStatus {
        username: String,
    },
    ConnectToPeer {
        token: u32,
        username: String,
        conn_type: ConnectionType,
    },
    MessageAcked {
        message_id: u32,
    },
    FileSearch {
        token: u32,
        query: String,
    },
    SetStatus {
        status: i32,
    },
    ServerPing,
    SharedFoldersFiles {
        folders: u32,
        files: u32,
    },
    GetUserStats {
        username: String,
    },
    HaveNoParent {
        no_parent: bool,
    },
    CheckPrivileges,
    AcceptChildren {
        accept: bool,
    },
    BranchLevel {
        level: u32,
    },
    BranchRoot {
        username: String,
    },
    CantConnectToPeer {
        token: u32,
        username: String,
    },
}

impl ServerRequest {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        match self {
            Self::Login {
                username,
                password,
                major_version,
                minor_version,
            } => {
                let checksum = login_checksum(username, password);
                w.write_str(username);
                w.write_str(password);
                w.write_u32(*major_version);
                w.write_str(&checksum);
                w.write_u32(*minor_version);
                w.into_u32_frame(server_code::LOGIN)
            }
            Self::SetWaitPort { port } => {
                w.write_u32(*port);
                w.into_u32_frame(server_code::SET_WAIT_PORT)
            }
            Self::GetPeerAddress { username } => {
                w.write_str(username);
                w.into_u32_frame(server_code::GET_PEER_ADDRESS)
            }
            Self::WatchUser { username } => {
                w.write_str(username);
                w.into_u32_frame(server_code::WATCH_USER)
            }
            Self::UnwatchUser { username } => {
                w.write_str(username);
                w.into_u32_frame(server_code::UNWATCH_USER)
            }
            Self::GetUserStatus { username } => {
                w.write_str(username);
                w.into_u32_frame(server_code::GET_USER_STATUS)
            }
            Self::ConnectToPeer {
                token,
                username,
                conn_type,
            } => {
                w.write_u32(*token);
                w.write_str(username);
                w.write_str(conn_type.as_str());
                w.into_u32_frame(server_code::CONNECT_TO_PEER)
            }
            Self::MessageAcked { message_id } => {
                w.write_u32(*message_id);
                w.into_u32_frame(server_code::MESSAGE_ACKED)
            }
            Self::FileSearch { token, query } => {
                w.write_u32(*token);
                w.write_str(query);
                w.into_u32_frame(server_code::FILE_SEARCH)
            }
            Self::SetStatus { status } => {
                w.write_i32(*status);
                w.into_u32_frame(server_code::SET_STATUS)
            }
            Self::ServerPing => w.into_u32_frame(server_code::SERVER_PING),
            Self::SharedFoldersFiles { folders, files } => {
                w.write_u32(*folders);
                w.write_u32(*files);
                w.into_u32_frame(server_code::SHARED_FOLDERS_FILES)
            }
            Self::GetUserStats { username } => {
                w.write_str(username);
                w.into_u32_frame(server_code::GET_USER_STATS)
            }
            Self::HaveNoParent { no_parent } => {
                w.write_bool(*no_parent);
                w.into_u32_frame(server_code::HAVE_NO_PARENT)
            }
            Self::CheckPrivileges => w.into_u32_frame(server_code::CHECK_PRIVILEGES),
            Self::AcceptChildren { accept } => {
                w.write_bool(*accept);
                w.into_u32_frame(server_code::ACCEPT_CHILDREN)
            }
            Self::BranchLevel { level } => {
                w.write_u32(*level);
                w.into_u32_frame(server_code::BRANCH_LEVEL)
            }
            Self::BranchRoot { username } => {
                w.write_str(username);
                w.into_u32_frame(server_code::BRANCH_ROOT)
            }
            Self::CantConnectToPeer { token, username } => {
                w.write_u32(*token);
                w.write_str(username);
                w.into_u32_frame(server_code::CANT_CONNECT_TO_PEER)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerResponse {
    LoginSuccess {
        motd: String,
        own_ip: Ipv4Addr,
        password_md5: String,
        is_supporter: bool,
    },
    LoginFailure {
        reason_code: LoginRejectReason,
        reason: String,
        detail: Option<String>,
    },
    PeerAddress {
        username: String,
        ip: Ipv4Addr,
        port: u32,
        obfuscation_type: u32,
        obfuscated_port: u16,
    },
    WatchUser {
        username: String,
        exists: bool,
        status: Option<u32>,
        upload_speed: Option<u32>,
    },
    UserStatus {
        username: String,
        status: u32,
        privileged: bool,
    },
    ConnectToPeer {
        username: String,
        conn_type: ConnectionType,
        ip: Ipv4Addr,
        port: u32,
        token: u32,
        privileged: bool,
        obfuscation_type: u32,
        obfuscated_port: u32,
    },
    MessageUser {
        message_id: u32,
        timestamp: u32,
        username: String,
        message: String,
        is_new: bool,
    },
    FileSearch {
        username: String,
        token: u32,
        query: String,
    },
    UserStats {
        username: String,
        upload_speed: u32,
        upload_count: u32,
        files: u32,
        folders: u32,
    },
    Relogged,
    AdminMessage {
        message: String,
    },
    PrivilegedUsers {
        users: Vec<String>,
    },
    ParentMinSpeed(u32),
    ParentSpeedRatio(u32),
    CheckPrivileges {
        seconds_left: u32,
    },
    EmbeddedMessage {
        distrib_code: u8,
        payload: Vec<u8>,
    },
    PossibleParents {
        parents: Vec<(String, Ipv4Addr, u32)>,
    },
    WishlistInterval {
        seconds: u32,
    },
    ResetDistributed,
    ExcludedSearchPhrases {
        phrases: Vec<String>,
    },
    CantConnectToPeer {
        token: u32,
    },
    Unknown {
        code: u32,
        payload_len: usize,
    },
}

impl ServerResponse {
    /// Decode a server frame payload (without the outer 4-byte length prefix).
    pub fn decode(frame_payload: &[u8]) -> Result<Self, ProtoError> {
        if frame_payload.len() < 4 {
            return Err(ProtoError::FrameTooShort(frame_payload.len()));
        }
        let mut r = WireReader::new(frame_payload);
        let code = r.read_u32()?;
        match code {
            server_code::LOGIN => {
                let ok = r.read_bool()?;
                if ok {
                    let motd = r.read_string()?;
                    let own_ip = r.read_ipv4()?;
                    let password_md5 = if !r.is_empty() {
                        r.read_string()?
                    } else {
                        String::new()
                    };
                    let is_supporter = if !r.is_empty() { r.read_bool()? } else { false };
                    Ok(Self::LoginSuccess {
                        motd,
                        own_ip,
                        password_md5,
                        is_supporter,
                    })
                } else {
                    let reason = r.read_string()?;
                    let reason_code = LoginRejectReason::from_wire(&reason);
                    let detail = if !r.is_empty() {
                        Some(r.read_string()?)
                    } else {
                        None
                    };
                    Ok(Self::LoginFailure {
                        reason_code,
                        reason,
                        detail,
                    })
                }
            }
            server_code::GET_PEER_ADDRESS => {
                let username = r.read_string()?;
                let ip = r.read_ipv4()?;
                let port = r.read_u32()?;
                let obfuscation_type = if r.remaining() >= 4 { r.read_u32()? } else { 0 };
                let obfuscated_port = if r.remaining() >= 2 { r.read_u16()? } else { 0 };
                Ok(Self::PeerAddress {
                    username,
                    ip,
                    port,
                    obfuscation_type,
                    obfuscated_port,
                })
            }
            server_code::WATCH_USER => {
                let username = r.read_string()?;
                let exists = r.read_bool()?;
                if !exists {
                    return Ok(Self::WatchUser {
                        username,
                        exists: false,
                        status: None,
                        upload_speed: None,
                    });
                }
                let status = r.read_u32()?;
                let upload_speed = r.read_u32()?;
                let _upload_num = r.read_u32()?;
                let _unknown = r.read_u32()?;
                let _files = r.read_u32()?;
                let _folders = r.read_u32()?;
                if !r.is_empty() {
                    let _ = r.skip_string();
                }
                Ok(Self::WatchUser {
                    username,
                    exists: true,
                    status: Some(status),
                    upload_speed: Some(upload_speed),
                })
            }
            server_code::GET_USER_STATUS => {
                let username = r.read_string()?;
                let status = r.read_u32()?;
                let privileged = if !r.is_empty() { r.read_bool()? } else { false };
                Ok(Self::UserStatus {
                    username,
                    status,
                    privileged,
                })
            }
            server_code::CONNECT_TO_PEER => {
                let username = r.read_string()?;
                let conn_str = r.read_string()?;
                let conn_type = ConnectionType::parse(&conn_str)?;
                let ip = r.read_ipv4()?;
                let port = r.read_u32()?;
                let token = r.read_u32()?;
                let privileged = if !r.is_empty() { r.read_bool()? } else { false };
                let obfuscation_type = if r.remaining() >= 4 { r.read_u32()? } else { 0 };
                let obfuscated_port = if r.remaining() >= 4 {
                    r.read_u32()?
                } else if r.remaining() >= 2 {
                    u32::from(r.read_u16()?)
                } else {
                    0
                };
                Ok(Self::ConnectToPeer {
                    username,
                    conn_type,
                    ip,
                    port,
                    token,
                    privileged,
                    obfuscation_type,
                    obfuscated_port,
                })
            }
            server_code::MESSAGE_USER => {
                let message_id = r.read_u32()?;
                let timestamp = r.read_u32()?;
                let username = r.read_string()?;
                let message = r.read_string()?;
                let is_new = if !r.is_empty() { r.read_bool()? } else { true };
                Ok(Self::MessageUser {
                    message_id,
                    timestamp,
                    username,
                    message,
                    is_new,
                })
            }
            server_code::FILE_SEARCH => {
                let username = r.read_string()?;
                let token = r.read_u32()?;
                let query = r.read_string()?;
                Ok(Self::FileSearch {
                    username,
                    token,
                    query,
                })
            }
            server_code::GET_USER_STATS => {
                let username = r.read_string()?;
                let upload_speed = r.read_u32()?;
                let upload_count = r.read_u32()?;
                let _unknown = r.read_u32()?;
                let files = r.read_u32()?;
                let folders = r.read_u32()?;
                Ok(Self::UserStats {
                    username,
                    upload_speed,
                    upload_count,
                    files,
                    folders,
                })
            }
            server_code::RELOGGED => Ok(Self::Relogged),
            server_code::ADMIN_MESSAGE => Ok(Self::AdminMessage {
                message: r.read_string()?,
            }),
            server_code::PRIVILEGED_USERS => {
                let count = r.checked_count(4)?;
                let mut users = Vec::with_capacity(count);
                for _ in 0..count {
                    users.push(r.read_string()?);
                }
                Ok(Self::PrivilegedUsers { users })
            }
            server_code::PARENT_MIN_SPEED => Ok(Self::ParentMinSpeed(r.read_u32()?)),
            server_code::PARENT_SPEED_RATIO => Ok(Self::ParentSpeedRatio(r.read_u32()?)),
            server_code::CHECK_PRIVILEGES => Ok(Self::CheckPrivileges {
                seconds_left: r.read_u32()?,
            }),
            server_code::EMBEDDED_MESSAGE => {
                let distrib_code = r.read_u8()?;
                let payload = r.rest().to_vec();
                Ok(Self::EmbeddedMessage {
                    distrib_code,
                    payload,
                })
            }
            server_code::POSSIBLE_PARENTS => {
                let count = r.checked_count(12)?;
                let mut parents = Vec::with_capacity(count);
                for _ in 0..count {
                    let u = r.read_string()?;
                    let ip = r.read_ipv4()?;
                    let port = r.read_u32()?;
                    parents.push((u, ip, port));
                }
                Ok(Self::PossibleParents { parents })
            }
            server_code::WISHLIST_INTERVAL => Ok(Self::WishlistInterval {
                seconds: r.read_u32()?,
            }),
            server_code::RESET_DISTRIBUTED => Ok(Self::ResetDistributed),
            server_code::EXCLUDED_SEARCH_PHRASES => {
                let count = r.checked_count(4)?;
                let mut phrases = Vec::with_capacity(count);
                for _ in 0..count {
                    phrases.push(r.read_string()?);
                }
                Ok(Self::ExcludedSearchPhrases { phrases })
            }
            server_code::CANT_CONNECT_TO_PEER => Ok(Self::CantConnectToPeer {
                token: r.read_u32()?,
            }),
            other => Ok(Self::Unknown {
                code: other,
                payload_len: r.remaining(),
            }),
        }
    }
}

// ============================================================================
// Peer Init Messages (uint8 code: PierceFirewall = 0, PeerInit = 1)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerInitMessage {
    PierceFirewall {
        token: u32,
    },
    PeerInit {
        username: String,
        conn_type: ConnectionType,
        token: u32,
    },
}

impl PeerInitMessage {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        match self {
            Self::PierceFirewall { token } => {
                w.write_u32(*token);
                w.into_u8_frame(init_code::PIERCE_FIREWALL)
            }
            Self::PeerInit {
                username,
                conn_type,
                token,
            } => {
                w.write_str(username);
                w.write_str(conn_type.as_str());
                w.write_u32(*token);
                w.into_u8_frame(init_code::PEER_INIT)
            }
        }
    }

    pub fn decode(frame_payload: &[u8]) -> Result<Self, ProtoError> {
        if frame_payload.is_empty() {
            return Err(ProtoError::FrameTooShort(0));
        }
        let mut r = WireReader::new(frame_payload);
        let code = r.read_u8()?;
        match code {
            init_code::PIERCE_FIREWALL => Ok(Self::PierceFirewall {
                token: r.read_u32()?,
            }),
            init_code::PEER_INIT => {
                let username = r.read_string()?;
                let conn_str = r.read_string()?;
                let conn_type = ConnectionType::parse(&conn_str)?;
                let token = if r.remaining() >= 4 { r.read_u32()? } else { 0 };
                Ok(Self::PeerInit {
                    username,
                    conn_type,
                    token,
                })
            }
            other => Err(ProtoError::InvalidMessageCode(u32::from(other))),
        }
    }
}

// ============================================================================
// Peer Messages (uint32 code on 'P' connections)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerMessage {
    SharedFileListRequest,
    SharedFileListResponse {
        folders: Vec<SharedFolder>,
        private_folders: Vec<SharedFolder>,
    },
    FileSearchResponse {
        username: String,
        token: u32,
        files: Vec<WireFileEntry>,
        slot_free: bool,
        upload_speed: u32,
        queue_length: u32,
        private_files: Vec<WireFileEntry>,
    },
    UserInfoRequest,
    UserInfoResponse {
        description: String,
        picture: Option<Vec<u8>>,
        upload_slots: u32,
        queue_length: u32,
        slot_free: bool,
        upload_permission: Option<u32>,
    },
    FolderContentsRequest {
        token: u32,
        folder: String,
    },
    FolderContentsResponse {
        token: u32,
        root_folder: String,
        folders: Vec<SharedFolder>,
    },
    TransferRequest {
        /// 0 = Download from peer, 1 = Upload to us
        direction: u32,
        token: u32,
        filename: String,
        file_size: Option<u64>,
    },
    TransferResponse {
        token: u32,
        allowed: bool,
        file_size: Option<u64>,
        reason: Option<String>,
    },
    QueueUpload {
        filename: String,
    },
    PlaceInQueueResponse {
        filename: String,
        place: u32,
    },
    UploadFailed {
        filename: String,
    },
    UploadDenied {
        filename: String,
        reason: String,
    },
    PlaceInQueueRequest {
        filename: String,
    },
    Unknown {
        code: u32,
        payload_len: usize,
    },
}

fn read_folder_list(r: &mut WireReader<'_>) -> Result<Vec<SharedFolder>, ProtoError> {
    let folder_count = r.checked_count(8)?;
    let mut folders = Vec::with_capacity(folder_count);
    for _ in 0..folder_count {
        let path = r.read_string()?;
        let file_count = r.checked_count(17)?;
        let mut files = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            files.push(WireFileEntry::read_from(r)?);
        }
        folders.push(SharedFolder { path, files });
    }
    Ok(folders)
}

fn write_folder_list(w: &mut WireWriter, folders: &[SharedFolder]) {
    w.write_u32(folders.len() as u32);
    for folder in folders {
        w.write_str(&folder.path);
        w.write_u32(folder.files.len() as u32);
        for file in &folder.files {
            file.write_to(w);
        }
    }
}

impl PeerMessage {
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut w = WireWriter::new();
        match self {
            Self::SharedFileListRequest => {
                Ok(w.into_u32_frame(peer_code::SHARED_FILE_LIST_REQUEST))
            }
            Self::SharedFileListResponse {
                folders,
                private_folders,
            } => {
                let mut inner = WireWriter::new();
                write_folder_list(&mut inner, folders);
                inner.write_u32(0); // unknown field
                write_folder_list(&mut inner, private_folders);
                let compressed = zlib_compress(&inner.into_inner())?;
                w.write_raw(&compressed);
                Ok(w.into_u32_frame(peer_code::SHARED_FILE_LIST_RESPONSE))
            }
            Self::FileSearchResponse {
                username,
                token,
                files,
                slot_free,
                upload_speed,
                queue_length,
                private_files,
            } => {
                let mut inner = WireWriter::new();
                inner.write_str(username);
                inner.write_u32(*token);
                inner.write_u32(files.len() as u32);
                for f in files {
                    f.write_to(&mut inner);
                }
                inner.write_bool(*slot_free);
                inner.write_u32(*upload_speed);
                inner.write_u32(*queue_length);
                inner.write_u32(0); // unknown field
                inner.write_u32(private_files.len() as u32);
                for f in private_files {
                    f.write_to(&mut inner);
                }
                let compressed = zlib_compress(&inner.into_inner())?;
                w.write_raw(&compressed);
                Ok(w.into_u32_frame(peer_code::FILE_SEARCH_RESPONSE))
            }
            Self::UserInfoRequest => Ok(w.into_u32_frame(peer_code::USER_INFO_REQUEST)),
            Self::UserInfoResponse {
                description,
                picture,
                upload_slots,
                queue_length,
                slot_free,
                upload_permission,
            } => {
                w.write_str(description);
                if let Some(pic) = picture {
                    w.write_bool(true);
                    w.write_bytes_prefixed(pic);
                } else {
                    w.write_bool(false);
                }
                w.write_u32(*upload_slots);
                w.write_u32(*queue_length);
                w.write_bool(*slot_free);
                if let Some(perm) = upload_permission {
                    w.write_u32(*perm);
                }
                Ok(w.into_u32_frame(peer_code::USER_INFO_RESPONSE))
            }
            Self::FolderContentsRequest { token, folder } => {
                w.write_u32(*token);
                w.write_str(folder);
                Ok(w.into_u32_frame(peer_code::FOLDER_CONTENTS_REQUEST))
            }
            Self::FolderContentsResponse {
                token,
                root_folder,
                folders,
            } => {
                let mut inner = WireWriter::new();
                inner.write_u32(*token);
                inner.write_str(root_folder);
                write_folder_list(&mut inner, folders);
                let compressed = zlib_compress(&inner.into_inner())?;
                w.write_raw(&compressed);
                Ok(w.into_u32_frame(peer_code::FOLDER_CONTENTS_RESPONSE))
            }
            Self::TransferRequest {
                direction,
                token,
                filename,
                file_size,
            } => {
                w.write_u32(*direction);
                w.write_u32(*token);
                w.write_str(filename);
                if *direction == 1 {
                    w.write_u64(file_size.unwrap_or(0));
                }
                Ok(w.into_u32_frame(peer_code::TRANSFER_REQUEST))
            }
            Self::TransferResponse {
                token,
                allowed,
                file_size,
                reason,
            } => {
                w.write_u32(*token);
                w.write_bool(*allowed);
                if *allowed {
                    if let Some(sz) = file_size {
                        w.write_u64(*sz);
                    }
                } else {
                    w.write_str(reason.as_deref().unwrap_or("Cancelled"));
                }
                Ok(w.into_u32_frame(peer_code::TRANSFER_RESPONSE))
            }
            Self::QueueUpload { filename } => {
                w.write_str(filename);
                Ok(w.into_u32_frame(peer_code::QUEUE_UPLOAD))
            }
            Self::PlaceInQueueResponse { filename, place } => {
                w.write_str(filename);
                w.write_u32(*place);
                Ok(w.into_u32_frame(peer_code::PLACE_IN_QUEUE_RESPONSE))
            }
            Self::UploadFailed { filename } => {
                w.write_str(filename);
                Ok(w.into_u32_frame(peer_code::UPLOAD_FAILED))
            }
            Self::UploadDenied { filename, reason } => {
                w.write_str(filename);
                w.write_str(reason);
                Ok(w.into_u32_frame(peer_code::UPLOAD_DENIED))
            }
            Self::PlaceInQueueRequest { filename } => {
                w.write_str(filename);
                Ok(w.into_u32_frame(peer_code::PLACE_IN_QUEUE_REQUEST))
            }
            Self::Unknown { code, .. } => Ok(w.into_u32_frame(*code)),
        }
    }

    pub fn decode(frame_payload: &[u8]) -> Result<Self, ProtoError> {
        if frame_payload.len() < 4 {
            return Err(ProtoError::FrameTooShort(frame_payload.len()));
        }
        let mut r = WireReader::new(frame_payload);
        let code = r.read_u32()?;
        match code {
            peer_code::SHARED_FILE_LIST_REQUEST => Ok(Self::SharedFileListRequest),
            peer_code::SHARED_FILE_LIST_RESPONSE => {
                let raw = zlib_decompress(r.rest())?;
                let mut zr = WireReader::new(&raw);
                let folders = read_folder_list(&mut zr)?;
                let mut private_folders = Vec::new();
                if zr.remaining() >= 4 {
                    let _unknown = zr.read_u32()?;
                    if zr.remaining() >= 4 {
                        private_folders = read_folder_list(&mut zr)?;
                    }
                }
                Ok(Self::SharedFileListResponse {
                    folders,
                    private_folders,
                })
            }
            peer_code::FILE_SEARCH_RESPONSE => {
                let raw = zlib_decompress(r.rest())?;
                let mut zr = WireReader::new(&raw);
                let username = zr.read_string()?;
                let token = zr.read_u32()?;
                let file_count = zr.checked_count(17)?;
                let mut files = Vec::with_capacity(file_count);
                for _ in 0..file_count {
                    files.push(WireFileEntry::read_from(&mut zr)?);
                }
                let slot_free = zr.read_bool()?;
                let upload_speed = zr.read_u32()?;
                // Note: older Museek/SoulseekNS clients wrote queue_length as u64 or u32;
                // SLSKPROTOCOL & Nicotine+ 3.x specify uint32.
                let queue_length = zr.read_u32()?;
                let mut private_files = Vec::new();
                if zr.remaining() >= 4 {
                    let _unknown = zr.read_u32()?;
                    if zr.remaining() >= 4 {
                        let priv_count = zr.checked_count(17)?;
                        for _ in 0..priv_count {
                            private_files.push(WireFileEntry::read_from(&mut zr)?);
                        }
                    }
                }
                Ok(Self::FileSearchResponse {
                    username,
                    token,
                    files,
                    slot_free,
                    upload_speed,
                    queue_length,
                    private_files,
                })
            }
            peer_code::USER_INFO_REQUEST => Ok(Self::UserInfoRequest),
            peer_code::USER_INFO_RESPONSE => {
                let description = r.read_string()?;
                let has_pic = r.read_bool()?;
                let picture = if has_pic {
                    Some(r.read_bytes_prefixed()?.to_vec())
                } else {
                    None
                };
                let upload_slots = r.read_u32()?;
                let queue_length = r.read_u32()?;
                let slot_free = r.read_bool()?;
                let upload_permission = if r.remaining() >= 4 {
                    Some(r.read_u32()?)
                } else {
                    None
                };
                Ok(Self::UserInfoResponse {
                    description,
                    picture,
                    upload_slots,
                    queue_length,
                    slot_free,
                    upload_permission,
                })
            }
            peer_code::FOLDER_CONTENTS_REQUEST => {
                let token = r.read_u32()?;
                let folder = r.read_string()?;
                Ok(Self::FolderContentsRequest { token, folder })
            }
            peer_code::FOLDER_CONTENTS_RESPONSE => {
                let raw = zlib_decompress(r.rest())?;
                let mut zr = WireReader::new(&raw);
                let token = zr.read_u32()?;
                let root_folder = zr.read_string()?;
                let folders = read_folder_list(&mut zr)?;
                Ok(Self::FolderContentsResponse {
                    token,
                    root_folder,
                    folders,
                })
            }
            peer_code::TRANSFER_REQUEST => {
                let direction = r.read_u32()?;
                let token = r.read_u32()?;
                let filename = r.read_string()?;
                let file_size = if direction == 1 {
                    Some(r.read_file_size()?)
                } else {
                    None
                };
                Ok(Self::TransferRequest {
                    direction,
                    token,
                    filename,
                    file_size,
                })
            }
            peer_code::TRANSFER_RESPONSE => {
                let token = r.read_u32()?;
                let allowed = r.read_bool()?;
                if allowed {
                    let file_size = if r.remaining() >= 8 {
                        Some(r.read_file_size()?)
                    } else {
                        None
                    };
                    Ok(Self::TransferResponse {
                        token,
                        allowed: true,
                        file_size,
                        reason: None,
                    })
                } else {
                    let reason = r.read_string()?;
                    Ok(Self::TransferResponse {
                        token,
                        allowed: false,
                        file_size: None,
                        reason: Some(reason),
                    })
                }
            }
            peer_code::QUEUE_UPLOAD => Ok(Self::QueueUpload {
                filename: r.read_string()?,
            }),
            peer_code::PLACE_IN_QUEUE_RESPONSE => {
                let filename = r.read_string()?;
                let place = r.read_u32()?;
                Ok(Self::PlaceInQueueResponse { filename, place })
            }
            peer_code::UPLOAD_FAILED => Ok(Self::UploadFailed {
                filename: r.read_string()?,
            }),
            peer_code::UPLOAD_DENIED => {
                let filename = r.read_string()?;
                let reason = r.read_string()?;
                Ok(Self::UploadDenied { filename, reason })
            }
            peer_code::PLACE_IN_QUEUE_REQUEST => Ok(Self::PlaceInQueueRequest {
                filename: r.read_string()?,
            }),
            other => Ok(Self::Unknown {
                code: other,
                payload_len: r.remaining(),
            }),
        }
    }

    /// Convert a `FileSearchResponse` into flat importer records.
    #[must_use]
    pub fn into_search_records(self) -> Vec<SharedFileRecord> {
        let Self::FileSearchResponse {
            username,
            files,
            slot_free,
            upload_speed,
            queue_length,
            ..
        } = self
        else {
            return Vec::new();
        };
        files
            .into_iter()
            .map(|f| {
                let bitrate = f.attrs.effective_bitrate();
                SharedFileRecord {
                    username: username.clone(),
                    slots: slot_free,
                    queue: queue_length,
                    speed: upload_speed,
                    filename: f.filename,
                    size: f.size,
                    bitrate,
                    sample_rate: f.attrs.sample_rate,
                    bit_depth: f.attrs.bit_depth,
                    length_secs: f.attrs.length_secs,
                }
            })
            .collect()
    }
}

/// Flatten `SharedFolder` trees (from `SharedFileListResponse`) into `SharedFileRecord`s.
#[must_use]
pub fn flatten_shared_folders(
    username: &str,
    folders: &[SharedFolder],
    slots: bool,
    queue: u32,
    speed: u32,
) -> Vec<SharedFileRecord> {
    let total: usize = folders.iter().map(|d| d.files.len()).sum();
    let mut out = Vec::with_capacity(total);
    for dir in folders {
        let prefix = dir.path.trim_end_matches('\\');
        for f in &dir.files {
            let full_path = if prefix.is_empty() || f.filename.contains('\\') {
                f.filename.clone()
            } else {
                format!("{prefix}\\{}", f.filename)
            };
            out.push(SharedFileRecord {
                username: username.to_owned(),
                slots,
                queue,
                speed,
                filename: full_path,
                size: f.size,
                bitrate: f.attrs.effective_bitrate(),
                sample_rate: f.attrs.sample_rate,
                bit_depth: f.attrs.bit_depth,
                length_secs: f.attrs.length_secs,
            });
        }
    }
    out
}

// ============================================================================
// File Connection ('F') Wire Primitives (unframed)
// ============================================================================

#[must_use]
pub const fn encode_file_transfer_init(token: u32) -> [u8; 4] {
    token.to_le_bytes()
}

pub fn decode_file_transfer_init(bytes: &[u8]) -> Result<u32, ProtoError> {
    let mut r = WireReader::new(bytes);
    r.read_u32()
}

#[must_use]
pub const fn encode_file_offset(offset: u64) -> [u8; 8] {
    offset.to_le_bytes()
}

pub fn decode_file_offset(bytes: &[u8]) -> Result<u64, ProtoError> {
    let mut r = WireReader::new(bytes);
    r.read_u64()
}

// ============================================================================
// Distributed Messages (uint8 code on 'D' connections)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributedMessage {
    Ping,
    Search {
        identifier: u32,
        username: String,
        token: u32,
        query: String,
    },
    BranchLevel {
        level: i32,
    },
    BranchRoot {
        username: String,
    },
    EmbeddedMessage {
        distrib_code: u8,
        payload: Vec<u8>,
    },
    Unknown {
        code: u8,
        payload_len: usize,
    },
}

impl DistributedMessage {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = WireWriter::new();
        match self {
            Self::Ping => w.into_u8_frame(distrib_code::PING),
            Self::Search {
                identifier,
                username,
                token,
                query,
            } => {
                w.write_u32(*identifier);
                w.write_str(username);
                w.write_u32(*token);
                w.write_str(query);
                w.into_u8_frame(distrib_code::SEARCH)
            }
            Self::BranchLevel { level } => {
                w.write_i32(*level);
                w.into_u8_frame(distrib_code::BRANCH_LEVEL)
            }
            Self::BranchRoot { username } => {
                w.write_str(username);
                w.into_u8_frame(distrib_code::BRANCH_ROOT)
            }
            Self::EmbeddedMessage {
                distrib_code,
                payload,
            } => {
                w.write_u8(*distrib_code);
                w.write_raw(payload);
                w.into_u8_frame(distrib_code::EMBEDDED_MESSAGE)
            }
            Self::Unknown { code, .. } => w.into_u8_frame(*code),
        }
    }

    pub fn decode(frame_payload: &[u8]) -> Result<Self, ProtoError> {
        if frame_payload.is_empty() {
            return Err(ProtoError::FrameTooShort(0));
        }
        let mut r = WireReader::new(frame_payload);
        let code = r.read_u8()?;
        match code {
            distrib_code::PING => Ok(Self::Ping),
            distrib_code::SEARCH => {
                let identifier = r.read_u32()?;
                let username = r.read_string()?;
                let token = r.read_u32()?;
                let query = r.read_string()?;
                Ok(Self::Search {
                    identifier,
                    username,
                    token,
                    query,
                })
            }
            distrib_code::BRANCH_LEVEL => Ok(Self::BranchLevel {
                level: r.read_i32()?,
            }),
            distrib_code::BRANCH_ROOT => Ok(Self::BranchRoot {
                username: r.read_string()?,
            }),
            distrib_code::EMBEDDED_MESSAGE => {
                let distrib_code = r.read_u8()?;
                let payload = r.rest().to_vec();
                Ok(Self::EmbeddedMessage {
                    distrib_code,
                    payload,
                })
            }
            other => Ok(Self::Unknown {
                code: other,
                payload_len: r.remaining(),
            }),
        }
    }
}
