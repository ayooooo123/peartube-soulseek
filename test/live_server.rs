//! Live Soulseek server integration test (`#[ignore]` by default so `cargo test` runs 100% offline).
//!
//! Run manually only with a real pre-existing Soulseek account:
//! `SOULSEEK_USER=... SOULSEEK_PASS=... cargo test --test live_server -- --ignored`

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use peartube_soulseek::client::{
    ClientOptions, DEFAULT_UPLOAD_SLOTS, LogEvent, SoulseekClient, USER_INFO_DESCRIPTION,
};
use peartube_soulseek::proto::{
    ConnectionType, PeerInitMessage, PeerMessage, encode_file_offset, encode_file_transfer_init,
    read_frame_sync,
};

#[test]
#[ignore = "hits live Soulseek server; requires SOULSEEK_USER and SOULSEEK_PASS env vars"]
fn live_login_and_search_smoke() {
    let Ok(user) = std::env::var("SOULSEEK_USER") else {
        eprintln!("SOULSEEK_USER not set; skipping live server test");
        return;
    };
    let Ok(pass) = std::env::var("SOULSEEK_PASS") else {
        eprintln!("SOULSEEK_PASS not set; skipping live server test");
        return;
    };
    if user.trim().is_empty() || pass.is_empty() {
        eprintln!("SOULSEEK_USER / SOULSEEK_PASS empty; skipping live server test");
        return;
    }

    let server = std::env::var("SOULSEEK_SERVER").unwrap_or_else(|_| "vps.slsknet.org".to_string());
    let port: u16 = std::env::var("SOULSEEK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2271);
    let search_ms: u64 = std::env::var("SOULSEEK_SEARCH_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50_000);

    let logs: Arc<Mutex<Vec<LogEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_hook = Arc::clone(&logs);

    let client = SoulseekClient::new();
    client.set_logger(Some(Arc::new(move |ev| {
        eprintln!("[slsk:{}] {}: {}", ev.level.as_str(), ev.event, ev.message);
        logs_hook.lock().push(ev);
    })));

    let st = client
        .login(&server, port, &user, &pass)
        .expect("live Soulseek login failed");
    assert!(st.connected);
    assert!(st.logged_in);

    let results = client
        .search("boards of canada flac", search_ms)
        .expect("live Soulseek search failed");
    eprintln!(
        "live search ({search_ms}ms) returned {} file records",
        results.len()
    );
    assert!(
        !results.is_empty(),
        "expected live search over {search_ms}ms to return hits"
    );

    let reconnect_count = logs
        .lock()
        .iter()
        .filter(|e| e.event == "reconnected")
        .count();
    eprintln!("reconnected events observed: {reconnect_count}");
    assert!(
        reconnect_count <= 1,
        "expected `reconnected` at most once across ping interval, got {reconnect_count}"
    );

    client.close();
}

fn seed_live_share_dir() -> (std::path::PathBuf, Vec<u8>) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let share_dir = std::env::temp_dir().join(format!("peartube-live-share-{nanos}"));
    let album_a = share_dir.join("Boards of Canada - Music Has the Right to Children (1998)");
    let album_b = share_dir.join("Burial - Untrue (2007)");
    fs::create_dir_all(&album_a).unwrap();
    fs::create_dir_all(&album_b).unwrap();

    let mut flac_bytes = Vec::with_capacity(42 + 65_536);
    flac_bytes.extend_from_slice(b"fLaC");
    flac_bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x22]);
    let mut si = [0u8; 34];
    si[0..2].copy_from_slice(&4096u16.to_be_bytes());
    si[2..4].copy_from_slice(&4096u16.to_be_bytes());
    let packed: u64 = ((44_100u64 & 0xfffff) << 44)
        | (1u64 << 41)
        | (15u64 << 36)
        | ((44_100u64 * 76) & 0x0f_ffff_ffff);
    si[10..18].copy_from_slice(&packed.to_be_bytes());
    flac_bytes.extend_from_slice(&si);
    for i in 0..65_536usize {
        flac_bytes.push(((i * 37 + 11) & 0xff) as u8);
    }

    fs::write(album_a.join("01 - Wildlife Analysis.flac"), &flac_bytes).unwrap();
    fs::write(album_a.join("04 - Telephasic Workshop.flac"), &flac_bytes).unwrap();
    fs::write(album_b.join("02 - Archangel.flac"), &flac_bytes).unwrap();
    (share_dir, flac_bytes)
}

#[test]
#[ignore = "hits live Soulseek server; run without PEARTUBE_SLSK_SHARE to verify opt-in default OFF"]
fn live_default_share_disabled_proof() {
    let Ok(user) = std::env::var("SOULSEEK_USER") else {
        eprintln!("SOULSEEK_USER not set; skipping");
        return;
    };
    let Ok(pass) = std::env::var("SOULSEEK_PASS") else {
        eprintln!("SOULSEEK_PASS not set; skipping");
        return;
    };
    let server = std::env::var("SOULSEEK_SERVER").unwrap_or_else(|_| "vps.slsknet.org".to_string());
    let port: u16 = std::env::var("SOULSEEK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2271);

    // Construct via `SoulseekClient::new()` (`ClientOptions::default()`) with no `PEARTUBE_SLSK_SHARE`:
    // startup log must print `{"msg":"soulseek share","enabled":false,"files":0}` and `GetUserStats`
    // must report 0 folders and 0 files even if `PEARTUBE_WATCH_DIR` / `PEARTUBE_SLSK_SHARE_DIR` has files!
    let client = SoulseekClient::new();
    client.set_logger(Some(Arc::new(|ev| {
        eprintln!("[slsk:{}] {}: {}", ev.level.as_str(), ev.event, ev.message);
    })));
    let st = client
        .login(&server, port, &user, &pass)
        .expect("live Soulseek login failed");
    assert!(st.connected && st.logged_in);

    let stats = client
        .user_stats(&user, Duration::from_secs(10))
        .expect("live GetUserStats failed");
    eprintln!("LIVE GetUserStats({user}) [default OFF]: {stats:?}");
    assert_eq!(stats.folders, 0, "default OFF must advertise 0 folders");
    assert_eq!(stats.files, 0, "default OFF must advertise 0 files");

    let mut p_sock = TcpStream::connect((Ipv4Addr::LOCALHOST, st.listen_port)).unwrap();
    p_sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    p_sock
        .write_all(
            &PeerInitMessage::PeerInit {
                username: user,
                conn_type: ConnectionType::Peer,
                token: 0,
            }
            .encode(),
        )
        .unwrap();
    p_sock
        .write_all(&PeerMessage::UserInfoRequest.encode().unwrap())
        .unwrap();
    let user_info = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    eprintln!("LIVE UserInfoResponse [default OFF]: {user_info:?}");
    assert_eq!(
        user_info,
        PeerMessage::UserInfoResponse {
            description: USER_INFO_DESCRIPTION.to_string(),
            picture: None,
            upload_slots: 0,
            queue_length: 0,
            slot_free: false,
            upload_permission: Some(0),
        }
    );
    drop(p_sock);
    client.close();
}

#[test]
#[ignore = "hits live Soulseek server; run with PEARTUBE_SLSK_SHARE=1"]
fn live_share_stats_browse_and_upload_proof() {
    let Ok(user) = std::env::var("SOULSEEK_USER") else {
        eprintln!("SOULSEEK_USER not set; skipping live share proof");
        return;
    };
    let Ok(pass) = std::env::var("SOULSEEK_PASS") else {
        eprintln!("SOULSEEK_PASS not set; skipping live share proof");
        return;
    };
    if user.trim().is_empty() || pass.is_empty() {
        eprintln!("SOULSEEK_USER / SOULSEEK_PASS empty; skipping live share proof");
        return;
    }

    let server = std::env::var("SOULSEEK_SERVER").unwrap_or_else(|_| "vps.slsknet.org".to_string());
    let port: u16 = std::env::var("SOULSEEK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2271);

    let (share_dir, flac_bytes, created_temp) = if let Ok(existing) =
        std::env::var("PEARTUBE_SLSK_SHARE_DIR")
        && !existing.trim().is_empty()
    {
        let dir = std::path::PathBuf::from(existing);
        let sample = fs::read(
            dir.join("Burial - Untrue (2007)")
                .join("02 - Archangel.flac"),
        )
        .unwrap();
        (dir, sample, false)
    } else {
        let (dir, sample) = seed_live_share_dir();
        (dir, sample, true)
    };

    let mut opts = ClientOptions::default();
    if opts.share_dir.is_none() {
        opts.share_dir = Some(share_dir.clone());
    }
    assert!(
        opts.share_enabled,
        "expected PEARTUBE_SLSK_SHARE=1 so ClientOptions::default() enables sharing"
    );
    let client = SoulseekClient::with_options(opts);
    client.set_logger(Some(Arc::new(|ev| {
        eprintln!("[slsk:{}] {}: {}", ev.level.as_str(), ev.event, ev.message);
    })));

    let st = client
        .login(&server, port, &user, &pass)
        .expect("live Soulseek login failed");
    assert!(st.connected && st.logged_in);
    let listen_port = st.listen_port;
    assert!(listen_port > 0);

    // 2. Query real central Soulseek server (`vps.slsknet.org`) with `GetUserStats` for our own user!
    let stats = client
        .user_stats(&user, Duration::from_secs(10))
        .expect("live GetUserStats failed");
    eprintln!("LIVE GetUserStats({user}): {stats:?}");
    assert_eq!(stats.username, user);
    assert_eq!(
        stats.folders, 2,
        "central server must record 2 shared folders"
    );
    assert_eq!(stats.files, 3, "central server must record 3 shared files");

    // 3. Connect peer socket to our client's bound listener port and verify `UserInfoResponse` + `SharedFileListResponse`
    let mut p_sock = TcpStream::connect((Ipv4Addr::LOCALHOST, listen_port)).unwrap();
    p_sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    p_sock
        .write_all(
            &PeerInitMessage::PeerInit {
                username: user.clone(),
                conn_type: ConnectionType::Peer,
                token: 0,
            }
            .encode(),
        )
        .unwrap();

    p_sock
        .write_all(&PeerMessage::UserInfoRequest.encode().unwrap())
        .unwrap();
    let user_info = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    eprintln!("LIVE UserInfoResponse: {user_info:?}");
    assert_eq!(
        user_info,
        PeerMessage::UserInfoResponse {
            description: USER_INFO_DESCRIPTION.to_string(),
            picture: None,
            upload_slots: DEFAULT_UPLOAD_SLOTS,
            queue_length: 0,
            slot_free: true,
            upload_permission: Some(0),
        }
    );

    p_sock
        .write_all(&PeerMessage::SharedFileListRequest.encode().unwrap())
        .unwrap();
    let browse_reply = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    eprintln!("LIVE SharedFileListResponse: {browse_reply:?}");
    let PeerMessage::SharedFileListResponse { folders, .. } = browse_reply else {
        panic!("expected SharedFileListResponse");
    };
    assert_eq!(folders.len(), 2);
    assert_eq!(
        folders[0].path,
        "@@peartube\\Boards of Canada - Music Has the Right to Children (1998)"
    );
    assert_eq!(folders[1].path, "@@peartube\\Burial - Untrue (2007)");

    // 4. Complete real upload handshake (`QueueUpload` -> `TransferRequest` -> `TransferResponse` -> `F` stream)
    //    and verify the bytes arriving at the peer match the file on disk byte-for-byte!
    let target_vpath = "@@peartube\\Burial - Untrue (2007)\\02 - Archangel.flac".to_string();
    p_sock
        .write_all(
            &PeerMessage::QueueUpload {
                filename: target_vpath.clone(),
            }
            .encode()
            .unwrap(),
        )
        .unwrap();

    let offer = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    eprintln!("LIVE TransferRequest offer: {offer:?}");
    let PeerMessage::TransferRequest {
        direction: 1,
        token: transfer_token,
        filename: offered_file,
        file_size: Some(offered_size),
    } = offer
    else {
        panic!("expected TransferRequest(direction=1)");
    };
    assert_eq!(offered_file, target_vpath);
    assert_eq!(offered_size, flac_bytes.len() as u64);

    p_sock
        .write_all(
            &PeerMessage::TransferResponse {
                token: transfer_token,
                allowed: true,
                file_size: None,
                reason: None,
            }
            .encode()
            .unwrap(),
        )
        .unwrap();

    // Open the `F` socket to the client's listener (`PeerInit("F")` + `FileTransferInit(transfer_token)`),
    // send `FileOffset(0)`, and read the full uploaded file stream!
    let mut f_sock = TcpStream::connect((Ipv4Addr::LOCALHOST, listen_port)).unwrap();
    f_sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    f_sock
        .write_all(
            &PeerInitMessage::PeerInit {
                username: user.clone(),
                conn_type: ConnectionType::File,
                token: 0,
            }
            .encode(),
        )
        .unwrap();
    f_sock
        .write_all(&encode_file_transfer_init(transfer_token))
        .unwrap();
    f_sock.write_all(&encode_file_offset(0)).unwrap();
    f_sock.flush().unwrap();

    let mut received_bytes = vec![0u8; flac_bytes.len()];
    f_sock.read_exact(&mut received_bytes).unwrap();
    drop(f_sock);
    assert_eq!(
        received_bytes, flac_bytes,
        "uploaded bytes arriving at peer must match file on disk byte-for-byte"
    );
    eprintln!(
        "LIVE Upload verified: {} bytes arrived matching disk file byte-for-byte!",
        received_bytes.len()
    );

    // Allow worker to transmit `SendUploadSpeed` to `vps.slsknet.org`
    std::thread::sleep(Duration::from_millis(150));
    let stats_after_upload = client
        .user_stats(&user, Duration::from_secs(10))
        .expect("live GetUserStats after upload failed");
    eprintln!("LIVE GetUserStats({user}) after upload: {stats_after_upload:?}");
    assert_eq!(stats_after_upload.folders, 2);
    assert_eq!(stats_after_upload.files, 3);

    // 5. Restore clean `(0, 0)` share count on the shared demo account before disconnecting so we put it back
    let (f_clean, c_clean) = client.configure_share(None, false, 0).unwrap();
    assert_eq!((f_clean, c_clean), (0, 0));
    let stats_restored = client
        .user_stats(&user, Duration::from_secs(10))
        .expect("live GetUserStats after restore failed");
    eprintln!("LIVE GetUserStats({user}) restored: {stats_restored:?}");
    assert_eq!((stats_restored.folders, stats_restored.files), (0, 0));

    drop(p_sock);
    client.close();
    if created_temp {
        let _ = fs::remove_dir_all(&share_dir);
    }
}
