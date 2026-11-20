# Soulseek Protocol Implementation Notes (`peartube-soulseek`)

Grounded in Nicotine+ (`pynicotine/slskmessages.py`) and `SLSKPROTOCOL.md`.

## 1. Implemented Protocol Messages

### Server Messages (`[uint32 len][uint32 code][payload]`)

| Code | Name | Direction | Status | Notes |
| ---: | :--- | :--- | :--- | :--- |
| `1` | `Login` | Send & Recv | Full | Single-shot MD5 checksum `md5(username + password)` lowercase hex, major `177`, minor `1`. Parses MOTD, own IPv4, supporter flag, and all rejection codes (`INVALIDUSERNAME`, `EMPTYPASSWORD`, `INVALIDPASS`, `INVALIDVERSION`, `SVRFULL`, `SVRPRIVATE`). |
| `2` | `SetWaitPort` | Send | Full | Reports bound inbound TCP peer listener port after login. |
| `3` | `GetPeerAddress` | Send & Recv | Full | Resolves peer IPv4 + port (plus optional obfuscation type/port). |
| `5` | `WatchUser` | Send & Recv | Codec | Encodes watch request and decodes user existence/status/speed. |
| `6` | `UnwatchUser` | Send | Codec | Encodes unwatch request. |
| `7` | `GetUserStatus` | Send & Recv | Full | Encodes/decodes online/away/offline status + privileged flag. |
| `18` | `ConnectToPeer` | Send & Recv | Full | Requests indirect connection and handles inbound brokered `P`/`F` dial requests (`D` answered with `CantConnectToPeer`). |
| `22` | `MessageUser` | Recv | Handled | Decodes private messages and acknowledges delivery via `MessageAcked` (23) so the server stops re-sending offline queue entries. |
| `23` | `MessageAcked` | Send | Full | Acknowledges `MessageUser` IDs. |
| `26` | `FileSearch` | Send & Recv | Full | Dispatches network search queries by 32-bit correlation token; decodes incoming server-forwarded search frames. |
| `28` | `SetStatus` | Send | Full | Sets client status (`2 = Online`) post-login. |
| `32` | `ServerPing` | Send | Full | Sent every 45s to keep NAT/TCP session alive. |
| `35` | `SharedFoldersFiles` | Send | Full | Reports `(0, 0)` shared counts post-login. |
| `36` | `GetUserStats` | Send & Recv | Codec | Encodes/decodes peer upload speed and file/folder counts. |
| `41` | `Relogged` | Recv | Full | Marks session replaced by another login and suppresses auto-reconnect loop. |
| `66` | `AdminMessage` | Recv | Codec | Decodes server broadcast string. |
| `69` | `PrivilegedUsers` | Recv | Codec | Decodes privileged username list. |
| `71` | `HaveNoParent` | Send | Full | Informs server of distributed parent state. |
| `83` | `ParentMinSpeed` | Recv | Codec | Decodes distributed parent minimum speed. |
| `84` | `ParentSpeedRatio` | Recv | Codec | Decodes distributed parent speed ratio. |
| `92` | `CheckPrivileges` | Send & Recv | Full | Queries remaining privilege seconds and updates `state().privileges`. |
| `93` | `EmbeddedMessage` | Recv | Codec | Decodes server-embedded distributed payload. |
| `100` | `AcceptChildren` | Send | Full | Sends `false` on login so relay does not absorb distributed child traffic. |
| `102` | `PossibleParents` | Recv | Codec | Decodes candidate parent list `(username, ipv4, port)`. |
| `104` | `WishlistInterval` | Recv | Codec | Decodes server-dictated wishlist interval. |
| `126` | `BranchLevel` | Send | Codec | Encodes distributed branch level. |
| `127` | `BranchRoot` | Send | Codec | Encodes distributed branch root username. |
| `130` | `ResetDistributed` | Recv | Codec | Decodes distributed topology reset. |
| `160` | `ExcludedSearchPhrases` | Recv | Codec | Decodes server-excluded search phrase list. |
| `1001` | `CantConnectToPeer` | Send & Recv | Full | Sent when a brokered peer dial fails; fails pending browse/download promptly on receipt when no direct socket succeeded. |

### Peer Init Messages (`[uint32 len][uint8 code][payload]`)

| Code | Name | Direction | Status | Notes |
| ---: | :--- | :--- | :--- | :--- |
| `0` | `PierceFirewall` | Send & Recv | Full | Correlates indirect `ConnectToPeer` sockets by 32-bit token for both `P` and `F` connections. |
| `1` | `PeerInit` | Send & Recv | Full | Direct `P` and `F` connection handshake (`token = 0`). |

### Peer Messages (`[uint32 len][uint32 code][payload]` on `P` socket)

| Code | Name | Direction | Status | Notes |
| ---: | :--- | :--- | :--- | :--- |
| `4` | `SharedFileListRequest` | Send & Recv | Full | Requests peer share listing; answers inbound requests with an empty list. |
| `5` | `SharedFileListResponse` | Send & Recv | Full | Zlib-compressed public + optional private folder/file trees. |
| `9` | `FileSearchResponse` | Send & Recv | Full | Zlib-compressed search hit list, audio attributes (`0,1,2,4,5`), slot availability, upload speed, and queue length. |
| `15` | `UserInfoRequest` | Send & Recv | Full | Queries peer slot/queue status during `browse()`; answers inbound requests politely. |
| `16` | `UserInfoResponse` | Send & Recv | Full | Parses description, optional picture bytes, upload slots, queue length, free-slot flag, and optional permission code. |
| `36` | `FolderContentsRequest` | Send & Recv | Codec | Single-folder listing request codec. |
| `37` | `FolderContentsResponse` | Send & Recv | Codec | Zlib-compressed single-folder listing response codec. |
| `40` | `TransferRequest` | Send & Recv | Full | Handles incoming `direction = 1` upload offers from peer; politely rejects `direction = 0` download requests (`"File not shared."`). |
| `41` | `TransferResponse` | Send & Recv | Full | Accepts matched transfer tickets (`allowed = true`) or rejects unknown/cancelled ones. |
| `43` | `QueueUpload` | Send & Recv | Full | Enqueues file download on remote peer. |
| `44` | `PlaceInQueueResponse` | Send & Recv | Full | Updates live queue placement and invokes the progress callback (`TransferPhase::Queued`). |
| `46` | `UploadFailed` | Send & Recv | Full | Fails waiting download cleanly when peer cannot read/upload file. |
| `50` | `UploadDenied` | Send & Recv | Full | Fails download immediately with peer's rejection reason (`File not shared.`, `Banned`, `Too many files`, etc.). |
| `51` | `PlaceInQueueRequest` | Send & Recv | Full | Sent after `QueueUpload` and polled every 30s while queued. |

### File Connection (`F` socket, unframed)

| Primitive | Wire Layout | Status | Notes |
| :--- | :--- | :--- | :--- |
| `FileTransferInit` | `uint32` LE (4 bytes) | Full | Ticket sent by uploader right after `PeerInit("F")` or `PierceFirewall`; matched to accepted `TransferRequest`. |
| `FileOffset` | `uint64` LE (8 bytes) | Full | Sent by downloader before raw stream begins (`0` for fresh download, `<dest>.part` byte length on resume). |

### Distributed Messages (`[uint32 len][uint8 code][payload]`)

| Code | Name | Status | Notes |
| ---: | :--- | :--- | :--- |
| `0` | `DistribPing` | Codec | Legacy ping codec. |
| `3` | `DistribSearch` | Codec | Distributed search frame (`identifier = 49`). |
| `4` | `DistribBranchLevel` | Codec | Signed 32-bit branch depth. |
| `5` | `DistribBranchRoot` | Codec | Branch root username. |
| `93` | `DistribEmbeddedMessage` | Codec | Unwraps embedded distributed code + payload. |

---

## 2. Skipped Protocol Messages

1. **Chat rooms & room moderation (out of v1 scope):**
   `SayChatroom` (13), `JoinRoom` (14), `LeaveRoom` (15), `UserJoinedRoom` (16), `UserLeftRoom` (17), `RoomList` (64), `RoomTickers` (113), `RoomTickerAdded` (114), `RoomTickerRemoved` (115), `SetRoomTicker` (116), `RoomSearch` (120), `RoomMembers` (133), `AddRoomMember` (134), `RemoveRoomMember` (135), `CancelRoomMembership` (136), `CancelRoomOwnership` (137), `RoomMembershipGranted` (139), `RoomMembershipRevoked` (140), `EnableRoomInvitations` (141), `AddRoomOperator` (143), `RemoveRoomOperator` (144), `RoomOperatorshipGranted` (145), `RoomOperatorshipRevoked` (146), `RoomOperators` (148), `JoinGlobalRoom` (150), `LeaveGlobalRoom` (151), `GlobalRoomMessage` (152), `CantCreateRoom` (1003). Unknown incoming server codes decode into `ServerResponse::Unknown { code, payload_len }` and are safely ignored without desynchronizing the stream.
2. **Social / recommendations / account management (out of v1 scope):**
   `UserSearch` (42), `AddThingILike` (51), `RemoveThingILike` (52), `Recommendations` (54), `GlobalRecommendations` (56), `UserInterests` (57), `WishlistSearch` (103), `SimilarUsers` (110), `ItemRecommendations` (111), `ItemSimilarUsers` (112), `AddThingIHate` (117), `RemoveThingIHate` (118), `SendUploadSpeed` (121), `GivePrivileges` (123), `ChangePassword` (142), `MessageUsers` (149).
3. **Obsolete / deprecated messages (deliberately omitted per `SLSKPROTOCOL`):**
   Server codes `11`, `12`, `25`, `33`, `34`, `40`, `50`, `55`, `58`, `59`, `60`, `62`, `63`, `65`, `67`, `68`, `73`, `86`, `87`, `88`, `90`, `91`, `122`, `124`, `125`, `129`, `138`, `153`; Peer codes `1`, `8`, `10`, `14`, `33`, `34`, `42`, `47`, `48`, `49`, `52`; Distributed code `7`.

---

## 3. Protocol Ambiguities & Real-World Quirks Observed

1. **Login is single-message MD5, NOT challenge-response:**
   Despite informal descriptions calling Soulseek login an "MD5 challenge", there is no server nonce. Client sends `username`, `password`, `major_version`, `md5(username + password)` lowercase hex, and `minor_version` in one `Login` (code 1) packet immediately after TCP connect.
2. **Header code width differs by channel:**
   Server and `P` peer messages use `[uint32 length][uint32 code]`, whereas `PeerInit` (`PierceFirewall` / `PeerInit`) and `D` distributed messages use `[uint32 length][uint8 code]`. `F` file sockets use **no frame length prefix and no message code at all** after the initial `PeerInit("F")` or `PierceFirewall` frame — just a raw 4-byte `uint32` ticket followed by the downloader's 8-byte `uint64` offset and raw file bytes.
3. **IPv4 byte endianness is reversed from network order:**
   IPv4 octets `a.b.c.d` are serialized on the wire as `[d, c, b, a]` (a little-endian `uint32` of the big-endian IPv4 integer).
4. **`GetPeerAddress` vs `ConnectToPeer` `obfuscated_port` width mismatch:**
   In `GetPeerAddress` (server code 3), `obfuscated_port` is a 2-byte `uint16`. In `ConnectToPeer` (server code 18), `obfuscated_port` is a 4-byte `uint32`. Our parser handles both widths plus truncated legacy frames.
5. **Soulseek NS >2 GiB file-size sign-extension bug:**
   Legacy Soulseek NS clients pack file sizes between 2 GiB and 4 GiB with the upper 4 bytes set to `0xff 0xff 0xff 0xff` (`~16 EiB` if read naively as `uint64`). Following Nicotine+'s `unpack_file_size`, `WireReader::read_file_size` masks to the lower `uint32` when bytes `[4..8] == [0xff; 4]`.
6. **`PierceFirewall` connection type ambiguity on listener sockets:**
   When a peer connects back to our listener with `PierceFirewall(token)`, the wire message carries **only** `token` and neither `username` nor connection type (`P` vs `F`). If `token` matches an outbound `ConnectToPeer("P")` token we minted, the socket is a `P` control stream; otherwise we read the 4-byte `FileTransferInit` ticket and match it against active `F` downloads.
7. **Lossless files omit `bitrate` attribute (code 0):**
   SoulseekQt, Nicotine+, and `slskd` send `{1: duration, 4: sample_rate, 5: bit_depth}` for FLAC/WAV/ALAC without code `0` (`bitrate`). `AudioAttributes::effective_bitrate()` derives PCM kbps (`sample_rate * bit_depth * 2 / 1000`) when code `0` is absent so downstream rankers always have a numeric bitrate alongside `sample_rate` and `bit_depth`.
8. **Museek+ `UserInfoResponse` trailing bytes:**
   Museek+ encodes `slot_available` as a 4-byte integer instead of 1-byte `bool`, leaving 3 trailing bytes before optional `upload_permission`. Checking `remaining() >= 4` before reading `upload_permission` avoids `UnexpectedEof`.
