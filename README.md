# peartube-soulseek

Standalone Rust Soulseek client library exposed in-process as a native **Bare addon** (`BARE_MODULE`) for PearTube's distroless `bare` relay and Android worklet.

PearTube's relay runs `bare` as PID 1 inside a distroless image with no `/bin/sh` and cannot spawn a 295 MB `.NET` daemon (`slskd`), nor can the Android worklet `exec` a child binary. This crate implements the binary Soulseek TCP wire protocol in Rust (`rlib` + `staticlib`) behind a thin C ABI shim (`soulseek/addon.c` + `soulseek/soulseek.h`) compiled by `cmake-bare` into `peartube-soulseek.bare`.

## Crate Choice & License Decision

- **Evaluated upstream crate:** `soulseek-rs` / `soulseek-rs-lib` `=20.0.0` (`https://github.com/michel/soulseek-rs`, observed license: **MIT**, Copyright (c) 2026 Michel de Graaf, 868 crates.io downloads).
- **Decision:** **Wrote the protocol and client state machine directly in this repository (`src/proto.rs`, `src/client.rs`, `src/transfer.rs`, `src/addon.rs`)** rather than depending on `soulseek-rs`.
- **Why:**
  1. `soulseek-rs-lib` 20.0.0 targets Rust edition 2024 with `rust-version = 1.91`, pulls its own actor/dispatcher/TUI/upload-server assumptions, hardcodes its own reserved client major version (`176`), and omits `queue_length` from `SearchResult` (`types.rs` drops the `uint32` queue count after `speed`), whereas PearTube's importer requires `{ username, slots, queue, speed, filename, size, bitrate, sample_rate, bit_depth, length_secs }` to rank peers.
  2. Writing the focused client directly keeps the dependency tree down to three pinned, pure-Rust crates with zero C/OpenSSL/zlib sys-crate baggage across `darwin-arm64`, `linux-arm64`, `linux-x64`, and `android-arm64`:
     - `md-5 = "=0.10.6"` (MIT OR Apache-2.0) — Soulseek login requires MD5, and Bare's sodium crypto shim only exposes SHA-256.
     - `flate2 = "=1.1.2"` with `rust_backend` (`miniz_oxide`, MIT OR Apache-2.0) — zlib inflate/deflate for `FileSearchResponse` and `SharedFileListResponse`.
     - `parking_lot = "=0.12.5"` (MIT OR Apache-2.0) — non-poisoning synchronization between the worker loop and FFI handles.

## Account & Credential Policy (Mandatory)

- **Accounts do NOT auto-register.** Generating random usernames violates official Soulseek server rules (`https://www.slsknet.org/news/node/681`) and gets IPs/accounts banned.
- **The operator MUST supply an existing Soulseek username and password.** `login()` validates non-empty credentials and fails loudly with the server's exact rejection reason (`INVALIDUSERNAME`, `EMPTYPASSWORD`, `INVALIDPASS`, `INVALIDVERSION`, `SVRFULL`, `SVRPRIVATE`).
- **There is no password reset on Soulseek.** Never discard or overwrite stored operator credentials.
- Passwords are never logged at any log level and are zeroed out of C shim temporary buffers immediately after marshaling; peer file paths are redacted to basenames in `info`/`warn`/`error` logs.

## Architecture & Threading Model

A Rust `cdylib` cannot be loaded directly as a Bare addon because Bare resolves native addons via the `BARE_MODULE` symbol registration macros in `<bare.h>` / `<js.h>`.

```
soulseek/
  soulseek.h      C ABI contract between CMake C shim and Rust staticlib
  addon.c         #include <bare.h> / <js.h> / <uv.h>, BARE_MODULE(soulseek, soulseek_exports),
                  marshals js_value_t <-> Rust C ABI via uv_async_t + uv_mutex_t + Promises
src/
  lib.rs          Rust library root (crate-type = ["rlib", "staticlib"])
  proto.rs        Binary little-endian codec, MD5 login checksum, zlib peer payloads
  client.rs       Dedicated background worker thread, server keepalive/reconnect, peer broker
  transfer.rs     P2P 'F' file transfer streaming, 8-byte offset .part resume, stall bounds
  addon.rs        extern "C" non-blocking FFI entrypoints
js/
  index.js        Thin Bare wrapper class (`Soulseek`) over `require.addon()`
```

- **Zero JS thread blocking:** Every network operation (`login`, `search`, `browse`, `download`) runs on background Rust threads and wakes Bare's libuv loop via `uv_async_t` + a mutex-guarded completion queue to settle `js_deferred_t` Promises and fire logger/progress `js_ref_t` callbacks. Multi-hour Soulseek upload queues never block Bare's event loop.
- **Exact host link line (`darwin-arm64`):** `cc -arch arm64 -dynamiclib -Wl,-undefined,dynamic_lookup -o peartube-soulseek@0.bare addon.c.o cargo/aarch64-apple-darwin/release/libpeartube_soulseek.a` (staged to `prebuilds/darwin-arm64/peartube-soulseek.bare`).

## Protocol Coverage (v1)

- **Implemented:**
  - Server login (`Login` code 1, major `177`, minor `1`, single-message `md5(username + password)` lowercase hex digest), `SetWaitPort` (2), `GetPeerAddress` (3), `WatchUser` (5), `UnwatchUser` (6), `GetUserStatus` (7), `ConnectToPeer` (18), `MessageUser` (22) + `MessageAcked` (23), `FileSearch` (26), `SetStatus` (28), `ServerPing` (32) keepalive + auto-reconnect backoff, `SharedFoldersFiles` (35), `GetUserStats` (36), `Relogged` (41), `CheckPrivileges` (92), `AcceptChildren` (100), `HaveNoParent` (71), `CantConnectToPeer` (1001).
  - Peer Init (`PierceFirewall` 0, `PeerInit` 1) for both direct outbound/inbound `P` & `F` sockets and server-brokered NAT traversal (`ConnectToPeer`).
  - Peer `P` messages: `SharedFileListRequest` (4), `SharedFileListResponse` (5, zlib), `FileSearchResponse` (9, zlib, including Soulseek NS >2 GiB uint64 bug workaround and Latin-1 fallback), `UserInfoRequest` (15), `UserInfoResponse` (16), `FolderContentsRequest` (36), `FolderContentsResponse` (37), `TransferRequest` (40), `TransferResponse` (41), `QueueUpload` (43), `PlaceInQueueResponse` (44), `UploadFailed` (46), `UploadDenied` (50), `PlaceInQueueRequest` (51).
  - File `F` stream: 4-byte `FileTransferInit` ticket matching, 8-byte little-endian `FileOffset` `.part` resume, chunked disk writes, downloader-initiated socket close on exact byte count.
- **Not implemented in v1:**
  - Chat rooms, private chat UI, recommendations/interests, wishlist scheduler, user/room-scoped searches, serving local shares/uploads to peers, distributed child fan-out (`AcceptChildren` is explicitly `false`), and rotated/obfuscated peer ports. See `NOTES.md` for the complete message table.

## Build Commands

First install the `cmake-bare` toolchain packages (required once from a clean checkout; `node_modules` is not vendored):

```sh
npm i -D cmake-bare cmake-fetch cmake-npm
```

### Offline Rust tests & host release build

```sh
cargo test
cargo build --release
```

### Host `.bare` addon (`darwin-arm64` / `linux-x64` / `linux-arm64`)

```sh
cmake -S . -B build -DBARE_ADDON=ON -DCMAKE_PREFIX_PATH="$PWD/node_modules"
cmake --build build
```

CMake invokes `cargo build --release --target <rust-triple>`, compiles `soulseek/addon.c` with `bare-headers`, links `libpeartube_soulseek.a` into `build/peartube-soulseek@0.bare`, and stages `prebuilds/<platform>-<arch>/peartube-soulseek.bare`.

### Per-Platform Cross-Build Commands

1. **`darwin-arm64` (macOS Apple Silicon):**
   ```sh
   rustup target add aarch64-apple-darwin
   cmake -S . -B build-darwin-arm64 -DBARE_ADDON=ON -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_PREFIX_PATH="$PWD/node_modules"
   cmake --build build-darwin-arm64
   ```
2. **`linux-x64` (Linux x86_64):**
   ```sh
   rustup target add x86_64-unknown-linux-gnu
   cmake -S . -B build-linux-x64 -DBARE_ADDON=ON -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=x86_64 -DRUST_TARGET=x86_64-unknown-linux-gnu -DCMAKE_PREFIX_PATH="$PWD/node_modules"
   cmake --build build-linux-x64
   ```
3. **`linux-arm64` (Linux aarch64):**
   ```sh
   rustup target add aarch64-unknown-linux-gnu
   cmake -S . -B build-linux-arm64 -DBARE_ADDON=ON -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DRUST_TARGET=aarch64-unknown-linux-gnu -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DCMAKE_PREFIX_PATH="$PWD/node_modules"
   cmake --build build-linux-arm64
   ```
4. **`android-arm64` (Android NDK arm64-v8a, API 29+):**
   ```sh
   rustup target add aarch64-linux-android
   export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/darwin-x86_64/bin/aarch64-linux-android29-clang"
   cmake -S . -B build-android-arm64 -DBARE_ADDON=ON \
     -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake" \
     -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-29 \
     -DRUST_TARGET=aarch64-linux-android \
     -DCMAKE_PREFIX_PATH="$PWD/node_modules"
   cmake --build build-android-arm64
   ```

## Usage Example (Bare + FLAC Verification)

```js
const { Soulseek } = require('peartube-soulseek')
const subprocess = require('bare-subprocess')

const client = new Soulseek({
  logger: ({ level, event, message }) => {
    console.error(`[slsk:${level}] ${event}: ${message}`)
  }
})

await client.login('vps.slsknet.org', 2271, process.env.SOULSEEK_USER, process.env.SOULSEEK_PASS)

// 1. Search and pick a lossless FLAC from a peer with a free upload slot
const hits = await client.search('boards of canada Olson flac', 6000)
const best = hits
  .filter((f) => f.slots && f.filename.toLowerCase().endsWith('.flac') && (f.bit_depth ?? 16) >= 16)
  .sort((a, b) => a.queue - b.queue || b.speed - a.speed)[0]

if (!best) throw new Error('No free-slot FLAC candidate found')

// 2. Download with live queue/byte progress and automatic .part resume
const { path } = await client.download(best.username, best.filename, './downloads/', (p) => {
  if (p.phase === 'queued') console.log(`Queued at position ${p.queue}`)
  else if (p.phase === 'transferring') console.log(`${p.bytes} / ${p.total} bytes (${Math.round(p.speed / 1024)} KiB/s)`)
})

// 3. Verify FLAC stream integrity (CRC + MD5 audio signature) with `flac -t`
const check = subprocess.spawnSync('flac', ['-t', '--silent', path])
if (check.status !== 0) throw new Error(`Corrupt FLAC download: ${path}`)
console.log('Verified lossless FLAC:', path)

client.close()
```
