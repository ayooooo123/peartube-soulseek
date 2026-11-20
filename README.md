# peartube-soulseek

Standalone Rust Soulseek client library (`rlib` + `staticlib`) with a non-blocking C ABI (`soulseek/soulseek.h`).

## Bare Addon Lives in `peartube-soulseek-bare`

This repository owns **only** the pure-Rust Soulseek protocol codec, client session/peer broker, P2P file transfer engine, and C ABI (`soulseek/soulseek.h` + `src/ffi.rs`). It contains zero Bare, `<js.h>`, or libuv code.

The native **Bare addon** (`BARE_MODULE`) for PearTube's distroless `bare` relay and Android worklet lives in:
- **https://github.com/ayooooo123/peartube-soulseek-bare**

## Crate Choice & License Decision

- **Evaluated upstream crate:** `soulseek-rs` / `soulseek-rs-lib` `=20.0.0` (`https://github.com/michel/soulseek-rs`, observed license: **MIT**, Copyright (c) 2026 Michel de Graaf, 868 crates.io downloads).
- **Decision:** **Wrote the protocol and client state machine directly in this repository (`src/proto.rs`, `src/client.rs`, `src/transfer.rs`, `src/ffi.rs`)** rather than depending on `soulseek-rs`.
- **Why:**
  1. `soulseek-rs-lib` 20.0.0 targets Rust edition 2024 with `rust-version = 1.91`, pulls its own actor/dispatcher/TUI/upload-server assumptions, hardcodes its own reserved client major version (`176`), and omits `queue_length` from `SearchResult` (`types.rs` drops the `uint32` queue count after `speed`), whereas PearTube's importer requires `{ username, slots, queue, speed, filename, size, bitrate, sample_rate, bit_depth, length_secs }` to rank peers.
  2. Writing the focused client directly keeps the dependency tree down to three pinned, pure-Rust crates with zero C/OpenSSL/zlib sys-crate baggage across `darwin-arm64`, `linux-arm64`, `linux-x64`, and `android-arm64`:
     - `md-5 = "=0.10.6"` (MIT OR Apache-2.0) — Soulseek login requires MD5.
     - `flate2 = "=1.1.2"` with `rust_backend` (`miniz_oxide`, MIT OR Apache-2.0) — zlib inflate/deflate for `FileSearchResponse` and `SharedFileListResponse`.
     - `parking_lot = "=0.12.5"` (MIT OR Apache-2.0) — non-poisoning synchronization between the worker loop and FFI handles.

## Account & Credential Policy (Mandatory)

- **Accounts do NOT auto-register.** Generating random usernames violates official Soulseek server rules (`https://www.slsknet.org/news/node/681`) and gets IPs/accounts banned.
- **The operator MUST supply an existing Soulseek username and password.** `login()` validates non-empty credentials and fails loudly with the server's exact rejection reason (`INVALIDUSERNAME`, `EMPTYPASSWORD`, `INVALIDPASS`, `INVALIDVERSION`, `SVRFULL`, `SVRPRIVATE`).
- **There is no password reset on Soulseek.** Never discard or overwrite stored operator credentials.
- Passwords are never logged at any log level; peer file paths are redacted to basenames in `info`/`warn`/`error` logs.

## Layout

```
soulseek/
  soulseek.h      C ABI header exported for C/C++ embedders and peartube-soulseek-bare
src/
  lib.rs          Rust library root (crate-type = ["rlib", "staticlib"])
  proto.rs        Binary little-endian codec, MD5 login checksum, zlib peer payloads
  client.rs       Dedicated background worker thread, server keepalive/reconnect, peer broker
  transfer.rs     P2P 'F' file transfer streaming, 8-byte offset .part resume, stall bounds
  ffi.rs          extern "C" non-blocking FFI entrypoints matching soulseek/soulseek.h
test/
  proto_codec.rs  Offline wire codec unit tests with in-code hex fixtures
  client_e2e.rs   Offline loopback server + peer integration tests (.part resume, queues)
  live_server.rs  #[ignore] live Soulseek smoke test (SOULSEEK_USER / SOULSEEK_PASS)
```

## Protocol Coverage (v1)

- **Implemented:**
  - Server login (`Login` code 1, major `177`, minor `1`, single-message `md5(username + password)` lowercase hex digest), `SetWaitPort` (2), `GetPeerAddress` (3), `WatchUser` (5), `UnwatchUser` (6), `GetUserStatus` (7), `ConnectToPeer` (18), `MessageUser` (22) + `MessageAcked` (23), `FileSearch` (26), `SetStatus` (28), `ServerPing` (32) keepalive + auto-reconnect backoff, `SharedFoldersFiles` (35), `GetUserStats` (36), `Relogged` (41), `CheckPrivileges` (92), `AcceptChildren` (100), `HaveNoParent` (71), `SendUploadSpeed` (121), `CantConnectToPeer` (1001).
  - Peer Init (`PierceFirewall` 0, `PeerInit` 1) for both direct outbound/inbound `P` & `F` sockets and server-brokered NAT traversal (`ConnectToPeer`).
  - Peer `P` messages: `SharedFileListRequest` (4), `SharedFileListResponse` (5, zlib), `FileSearchResponse` (9, zlib, including Soulseek NS >2 GiB uint64 bug workaround and Latin-1 fallback), `UserInfoRequest` (15), `UserInfoResponse` (16), `FolderContentsRequest` (36), `FolderContentsResponse` (37, zlib), `TransferRequest` (40), `TransferResponse` (41), `QueueUpload` (43), `PlaceInQueueResponse` (44), `UploadFailed` (46), `UploadDenied` (50), `PlaceInQueueRequest` (51).
  - File `F` stream (both download and upload): 4-byte `FileTransferInit` ticket matching, 8-byte little-endian `FileOffset` `.part` resume, chunked disk I/O, downloader-initiated socket close on exact byte count.
  - Opt-in local disk sharing & bounded P2P uploads: indexes one-level album folders (`Artist - Album (Year)/NN - Title.ext`) under the watched import folder up to a bounded file cap, answers `SharedFileListRequest`, `FolderContentsRequest`, `UserInfoRequest`, and server-forwarded `FileSearch` queries, and serves uploads with bounded slots (`2`) and queue depth (`32`) off-thread so downloads never stall.
- **Not implemented in v1:**
  - Chat rooms, private chat UI, recommendations/interests, wishlist scheduler, user/room-scoped searches, distributed child fan-out (`AcceptChildren` is explicitly `false`), and rotated/obfuscated peer ports. See `NOTES.md` for the complete message table.

## Local Share & Upload Environment Variables (Opt-In)

Sharing is **opt-in** (defaults **off**) so private files in an operator's import folder are never published to the Soulseek network unless explicitly enabled. At client startup (and whenever reconfigured), a structured JSON line is emitted on stderr (`{"msg":"soulseek share","enabled":false,"files":0}` when off, or `{"msg":"soulseek share","enabled":true,"files":N,"dir":"..."}` when on).

When enabled, a share exposes the media files on disk inside the relay's one-level album folders (`@@peartube\Artist - Album (Year)\NN - Title.ext`, skipping dot files, `@eaDir`, `.part`/`.json` sidecars, and symlinks), capped at `PEARTUBE_SLSK_SHARE_MAX_FILES` files. When disabled, the client advertises `SharedFoldersFiles { folders: 0, files: 0 }` and answers `UserInfoRequest` honestly with `upload_slots: 0` and `slot_free: false`.

| Variable | Default | Meaning |
| :--- | :--- | :--- |
| `PEARTUBE_SLSK_SHARE` | `0` (off) | Set to `1` (or `true`) to advertise and serve local disk shares to Soulseek peers. Unset, `0`, or `false` keeps sharing disabled. |
| `PEARTUBE_SLSK_SHARE_DIR` | `PEARTUBE_WATCH_DIR`, else `<PEARTUBE_STORAGE>/staging` | Override the root directory scanned for one-level `Artist - Album (Year)/NN - Title.ext` album folders when `PEARTUBE_SLSK_SHARE=1`. |
| `PEARTUBE_SLSK_SHARE_MAX_FILES` | `2000` | Maximum number of media files indexed and advertised in `SharedFoldersFiles` and `SharedFileListResponse`. |

## Build & Test Commands

```sh
# Offline unit + loopback integration suite (zero network access)
cargo test

# Host release build -> target/release/libpeartube_soulseek.a + .rlib
cargo build --release

# Cross-compile staticlib per target
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
cargo build --release --target aarch64-linux-android
```

## Rust Example (Search -> Download -> Verify FLAC)

```rust,no_run
use std::process::Command;
use peartube_soulseek::SoulseekClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let user = std::env::var("SOULSEEK_USER")?;
    let pass = std::env::var("SOULSEEK_PASS")?;

    let client = SoulseekClient::new();
    client.login("vps.slsknet.org", 2271, &user, &pass)?;

    let hits = client.search("boards of canada olson flac", 6_000)?;
    let best = hits
        .iter()
        .filter(|f| f.slots && f.filename.to_ascii_lowercase().ends_with(".flac"))
        .min_by_key(|f| f.queue)
        .ok_or("no free-slot FLAC candidate found")?;

    let outcome = client.download(&best.username, &best.filename, "./downloads/", None)?;
    let status = Command::new("flac")
        .args(["-t", "--silent"])
        .arg(&outcome.path)
        .status()?;
    assert!(status.success(), "FLAC verification failed");

    client.close();
    Ok(())
}
```
