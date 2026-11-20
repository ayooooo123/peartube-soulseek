//! Offline loopback integration tests exercising `SoulseekClient` against mock Soulseek
//! server and peer sockets:
//! - login success, CheckPrivileges state, and login rejection (`INVALIDPASS`)
//! - credential redaction and path redaction in logger hooks
//! - search fan-out + peer `FileSearchResponse` collection
//! - peer `browse()` (`SharedFileListRequest` -> `SharedFileListResponse`)
//! - `download()` with upload queue (`PlaceInQueueResponse`), ticket handoff, `.part` resume,
//!   and progress callbacks.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use peartube_soulseek::client::{
    ClientError, ClientOptions, DEFAULT_UPLOAD_QUEUE_CAP, DEFAULT_UPLOAD_SLOTS, LogEvent,
    SoulseekClient, USER_INFO_DESCRIPTION, format_share_decision_json,
};
use peartube_soulseek::proto::{
    AudioAttributes, ConnectionType, PeerInitMessage, PeerMessage, SharedFolder, WireFileEntry,
    WireReader, WireWriter, decode_file_offset, decode_file_transfer_init, encode_file_offset,
    encode_file_transfer_init, read_frame_sync, server_code,
};
use peartube_soulseek::transfer::{TransferProgress, part_path_for};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "peartube-slsk-test-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn server_login_ok_frame(motd: &str, own_ip: Ipv4Addr, supporter: bool) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_bool(true);
    w.write_str(motd);
    w.write_ipv4(own_ip);
    w.write_str("5f4dcc3b5aa765d61d8327deb882cf99");
    w.write_bool(supporter);
    w.into_u32_frame(server_code::LOGIN)
}

fn server_check_privs_frame(seconds: u32) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_u32(seconds);
    w.into_u32_frame(server_code::CHECK_PRIVILEGES)
}

fn server_peer_address_frame(username: &str, ip: Ipv4Addr, port: u16) -> Vec<u8> {
    let mut w = WireWriter::new();
    w.write_str(username);
    w.write_ipv4(ip);
    w.write_u32(u32::from(port));
    w.write_u32(0);
    w.write_u16(0);
    w.into_u32_frame(server_code::GET_PEER_ADDRESS)
}

#[test]
fn login_rejection_fails_loudly_and_never_logs_password() {
    let srv = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv.local_addr().unwrap().port();

    let srv_thread = thread::spawn(move || {
        let (mut sock, _) = srv.accept().unwrap();
        let frame = read_frame_sync(&mut sock).unwrap();
        let mut r = WireReader::new(&frame);
        assert_eq!(r.read_u32().unwrap(), server_code::LOGIN);
        assert_eq!(r.read_string().unwrap(), "operator_acct");
        assert_eq!(r.read_string().unwrap(), "TopSecretPass!99");

        let mut w = WireWriter::new();
        w.write_bool(false);
        w.write_str("INVALIDPASS");
        sock.write_all(&w.into_u32_frame(server_code::LOGIN))
            .unwrap();
    });

    let logs: Arc<Mutex<Vec<LogEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_hook = Arc::clone(&logs);

    let client = SoulseekClient::new();
    client.set_logger(Some(Arc::new(move |ev| {
        logs_hook.lock().push(ev);
    })));

    let err = client
        .login("127.0.0.1", srv_port, "operator_acct", "TopSecretPass!99")
        .unwrap_err();

    match err {
        ClientError::LoginRejected { reason, .. } => assert_eq!(reason, "INVALIDPASS"),
        other => panic!("expected LoginRejected, got {other:?}"),
    }
    assert!(!client.state().logged_in);

    // Empty username must be rejected locally without auto-generating anything
    assert!(matches!(
        client.login("127.0.0.1", srv_port, "", "TopSecretPass!99"),
        Err(ClientError::InvalidCredentials(_))
    ));

    srv_thread.join().unwrap();
    client.close();

    let captured = logs.lock();
    assert!(!captured.is_empty());
    for entry in captured.iter() {
        assert!(
            !entry.message.contains("TopSecretPass!99"),
            "password leaked in log message: {}",
            entry.message
        );
    }
}

#[test]
fn end_to_end_login_search_browse_and_resumed_download_over_loopback() {
    let peer_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_port = peer_listener.local_addr().unwrap().port();

    let srv_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    // Deterministic synthetic FLAC payload (384 KiB so multiple progress events fire)
    let file_payload: Vec<u8> = (0..(384 * 1024))
        .map(|i| ((i * 31 + 7) & 0xff) as u8)
        .collect();
    let payload_for_peer = file_payload.clone();

    // Spawn mock Soulseek server
    let srv_thread = thread::spawn(move || {
        let (mut sock, _) = srv_listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut client_listen_port: u16 = 0;

        while let Ok(frame) = read_frame_sync(&mut sock) {
            let mut r = WireReader::new(&frame);
            let code = r.read_u32().unwrap();
            match code {
                server_code::LOGIN => {
                    let user = r.read_string().unwrap();
                    assert_eq!(user, "peer_user");
                    sock.write_all(&server_login_ok_frame(
                        "Test MOTD",
                        Ipv4Addr::LOCALHOST,
                        true,
                    ))
                    .unwrap();
                }
                server_code::SET_WAIT_PORT => {
                    client_listen_port = r.read_u32().unwrap() as u16;
                }
                server_code::CHECK_PRIVILEGES => {
                    sock.write_all(&server_check_privs_frame(7200)).unwrap();
                }
                server_code::FILE_SEARCH => {
                    let search_token = r.read_u32().unwrap();
                    let query = r.read_string().unwrap();
                    assert_eq!(query, "burial archangel");
                    assert!(client_listen_port > 0);

                    // Simulate remote peer connecting inbound P socket to client's listen_port
                    // with a FileSearchResponse!
                    let mut p_sock =
                        TcpStream::connect((Ipv4Addr::LOCALHOST, client_listen_port)).unwrap();
                    let init = PeerInitMessage::PeerInit {
                        username: "flac_peer".to_string(),
                        conn_type: ConnectionType::Peer,
                        token: 0,
                    }
                    .encode();
                    p_sock.write_all(&init).unwrap();

                    let resp = PeerMessage::FileSearchResponse {
                        username: "flac_peer".to_string(),
                        token: search_token,
                        files: vec![WireFileEntry {
                            filename: "@@lossless\\Burial - Untrue\\02 - Archangel.flac"
                                .to_string(),
                            size: 28_500_000,
                            extension: String::new(),
                            attrs: AudioAttributes {
                                bitrate: Some(912),
                                length_secs: Some(238),
                                vbr: None,
                                sample_rate: Some(44_100),
                                bit_depth: Some(16),
                            },
                        }],
                        slot_free: true,
                        upload_speed: 2_500_000,
                        queue_length: 0,
                        private_files: Vec::new(),
                    }
                    .encode()
                    .unwrap();
                    p_sock.write_all(&resp).unwrap();
                    p_sock.flush().unwrap();
                }
                server_code::GET_PEER_ADDRESS => {
                    let target_user = r.read_string().unwrap();
                    sock.write_all(&server_peer_address_frame(
                        &target_user,
                        Ipv4Addr::LOCALHOST,
                        peer_port,
                    ))
                    .unwrap();
                }
                _ => {}
            }
        }
    });

    // Spawn mock remote peer (`uploader_peer`) accepting direct P connection for browse + download
    let logs: Arc<Mutex<Vec<LogEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_hook = Arc::clone(&logs);

    let client = SoulseekClient::new();
    let client_port = client.state().listen_port;
    assert!(client_port > 0, "listener must bind an ephemeral port");

    let peer_thread = thread::spawn(move || {
        let (mut p_sock, _) = peer_listener.accept().unwrap();
        p_sock
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let init_raw = read_frame_sync(&mut p_sock).unwrap();
        let init = PeerInitMessage::decode(&init_raw).unwrap();
        assert_eq!(
            init,
            PeerInitMessage::PeerInit {
                username: "peer_user".to_string(),
                conn_type: ConnectionType::Peer,
                token: 0,
            }
        );

        let remote_file = "@@vault\\PrivateDir\\SecretArtist\\01 - LosslessTrack.flac";

        while let Ok(frame) = read_frame_sync(&mut p_sock) {
            let msg = PeerMessage::decode(&frame).unwrap();
            match msg {
                PeerMessage::UserInfoRequest => {
                    let info = PeerMessage::UserInfoResponse {
                        description: "Hi".to_string(),
                        picture: None,
                        upload_slots: 2,
                        queue_length: 3,
                        slot_free: true,
                        upload_permission: Some(1),
                    }
                    .encode()
                    .unwrap();
                    p_sock.write_all(&info).unwrap();
                }
                PeerMessage::SharedFileListRequest => {
                    let list = PeerMessage::SharedFileListResponse {
                        folders: vec![SharedFolder {
                            path: "@@vault\\PrivateDir\\SecretArtist".to_string(),
                            files: vec![WireFileEntry {
                                filename: "01 - LosslessTrack.flac".to_string(),
                                size: payload_for_peer.len() as u64,
                                extension: String::new(),
                                attrs: AudioAttributes {
                                    bitrate: None,
                                    length_secs: Some(180),
                                    vbr: None,
                                    sample_rate: Some(96_000),
                                    bit_depth: Some(24),
                                },
                            }],
                        }],
                        private_folders: Vec::new(),
                    }
                    .encode()
                    .unwrap();
                    p_sock.write_all(&list).unwrap();
                }
                PeerMessage::PlaceInQueueRequest { filename } => {
                    let q = PeerMessage::PlaceInQueueResponse { filename, place: 2 }
                        .encode()
                        .unwrap();
                    p_sock.write_all(&q).unwrap();
                }
                PeerMessage::QueueUpload { filename } => {
                    assert_eq!(filename, remote_file);
                    // First tell downloader they are #2 in queue, then offer TransferRequest(direction=1)
                    let q = PeerMessage::PlaceInQueueResponse {
                        filename: filename.clone(),
                        place: 2,
                    }
                    .encode()
                    .unwrap();
                    p_sock.write_all(&q).unwrap();

                    let req = PeerMessage::TransferRequest {
                        direction: 1,
                        token: 424242,
                        filename,
                        file_size: Some(payload_for_peer.len() as u64),
                    }
                    .encode()
                    .unwrap();
                    p_sock.write_all(&req).unwrap();
                }
                PeerMessage::TransferResponse {
                    token: 424242,
                    allowed: true,
                    ..
                } => {
                    // Open inbound 'F' socket to downloader's listen port!
                    let mut f_sock =
                        TcpStream::connect((Ipv4Addr::LOCALHOST, client_port)).unwrap();
                    let f_init = PeerInitMessage::PeerInit {
                        username: "uploader_peer".to_string(),
                        conn_type: ConnectionType::File,
                        token: 0,
                    }
                    .encode();
                    f_sock.write_all(&f_init).unwrap();
                    f_sock
                        .write_all(&encode_file_transfer_init(424242))
                        .unwrap();
                    f_sock.flush().unwrap();

                    // Read downloader's 8-byte resume offset
                    let mut off_bytes = [0u8; 8];
                    f_sock.read_exact(&mut off_bytes).unwrap();
                    let offset = decode_file_offset(&off_bytes).unwrap() as usize;
                    assert_eq!(offset, 65_536, "expected resume from 64 KiB .part prefix");

                    // Stream remaining bytes
                    f_sock.write_all(&payload_for_peer[offset..]).unwrap();
                    f_sock.flush().unwrap();

                    // Wait for downloader to close F socket cleanly
                    let mut eof_check = [0u8; 1];
                    let _ = f_sock.read(&mut eof_check);
                    break;
                }
                _ => {}
            }
        }
    });

    client.set_logger(Some(Arc::new(move |ev| {
        logs_hook.lock().push(ev);
    })));

    // 1. Login
    let st = client
        .login("127.0.0.1", srv_port, "peer_user", "pass123")
        .unwrap();
    assert!(st.connected);
    assert!(st.logged_in);

    // Wait briefly for CheckPrivileges response to settle
    thread::sleep(Duration::from_millis(80));
    assert_eq!(client.state().privileges, 7200);

    // 2. Search
    let results = client.search("burial archangel", 250).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].username, "flac_peer");
    assert!(results[0].slots);
    assert_eq!(results[0].sample_rate, Some(44_100));
    assert_eq!(results[0].bit_depth, Some(16));
    assert_eq!(results[0].length_secs, Some(238));

    // 3. Browse
    let browsed = client.browse("uploader_peer").unwrap();
    assert_eq!(browsed.len(), 1);
    assert_eq!(
        browsed[0].filename,
        "@@vault\\PrivateDir\\SecretArtist\\01 - LosslessTrack.flac"
    );
    assert_eq!(browsed[0].sample_rate, Some(96_000));
    assert_eq!(browsed[0].bit_depth, Some(24));

    // 4. Download with pre-seeded 64 KiB `.part` file to prove resume works
    let out_dir = temp_dir("resume");
    let dest_file = out_dir.join("01 - LosslessTrack.flac");
    let part_file = part_path_for(&dest_file);
    fs::write(&part_file, &file_payload[..65_536]).unwrap();

    let progresses: Arc<Mutex<Vec<TransferProgress>>> = Arc::new(Mutex::new(Vec::new()));
    let prog_clone = Arc::clone(&progresses);

    let outcome = client
        .download(
            "uploader_peer",
            &browsed[0].filename,
            &dest_file,
            Some(Arc::new(move |p| {
                prog_clone.lock().push(p);
            })),
        )
        .unwrap();

    assert_eq!(outcome.path, dest_file);
    assert_eq!(outcome.size, file_payload.len() as u64);
    assert_eq!(outcome.resumed_from, 65_536);
    assert!(
        !part_file.exists(),
        ".part file must be renamed on completion"
    );

    let disk_bytes = fs::read(&dest_file).unwrap();
    assert_eq!(disk_bytes, file_payload);

    let recorded_prog = progresses.lock();
    assert!(
        recorded_prog.iter().any(|p| p.queue_place == Some(2)),
        "expected queue placement callback"
    );
    assert!(
        recorded_prog
            .iter()
            .any(|p| p.bytes_downloaded == file_payload.len() as u64),
        "expected completion progress callback"
    );

    // Verify peer full directory prefix was NOT logged at info/warn/error
    for ev in logs.lock().iter() {
        assert!(
            !ev.message.contains("PrivateDir\\SecretArtist"),
            "full peer path leaked in info log: {}",
            ev.message
        );
        assert!(
            !ev.message.contains("pass123"),
            "password leaked in log: {}",
            ev.message
        );
    }

    client.close();
    peer_thread.join().unwrap();
    srv_thread.join().unwrap();
    let _ = fs::remove_dir_all(&out_dir);
}

#[test]
fn server_kill_mid_search_reconnects_and_returns_hits() {
    let srv_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    let srv_thread = thread::spawn(move || {
        // Session 1: accept login, receive initial FileSearch, then immediately kill socket!
        let (mut sock1, _) = srv_listener.accept().unwrap();
        sock1
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let first_search_token = loop {
            let frame = read_frame_sync(&mut sock1).unwrap();
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    sock1
                        .write_all(&server_login_ok_frame(
                            "Session 1",
                            Ipv4Addr::LOCALHOST,
                            false,
                        ))
                        .unwrap();
                }
                server_code::CHECK_PRIVILEGES => {
                    sock1.write_all(&server_check_privs_frame(0)).unwrap();
                }
                server_code::FILE_SEARCH => {
                    let tok = r.read_u32().unwrap();
                    let query = r.read_string().unwrap();
                    assert_eq!(query, "aphex twin xtal");
                    break tok;
                }
                _ => {}
            }
        };
        // Drop server socket mid-search without delivering any peer results!
        drop(sock1);

        // Session 2: accept automatic reconnect, verify SetWaitPort + re-issued FileSearch(same token)
        let (mut sock2, _) = srv_listener.accept().unwrap();
        sock2
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut client_listen_port: u16 = 0;
        while let Ok(frame) = read_frame_sync(&mut sock2) {
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    sock2
                        .write_all(&server_login_ok_frame(
                            "Session 2",
                            Ipv4Addr::LOCALHOST,
                            false,
                        ))
                        .unwrap();
                }
                server_code::SET_WAIT_PORT => {
                    client_listen_port = r.read_u32().unwrap() as u16;
                }
                server_code::CHECK_PRIVILEGES => {
                    sock2.write_all(&server_check_privs_frame(120)).unwrap();
                }
                server_code::FILE_SEARCH => {
                    let reissued_token = r.read_u32().unwrap();
                    let query = r.read_string().unwrap();
                    assert_eq!(
                        reissued_token, first_search_token,
                        "re-dispatched search must preserve original token"
                    );
                    assert_eq!(query, "aphex twin xtal");
                    assert!(
                        client_listen_port > 0,
                        "SetWaitPort must be re-sent before search"
                    );

                    let mut p_sock =
                        TcpStream::connect((Ipv4Addr::LOCALHOST, client_listen_port)).unwrap();
                    let init = PeerInitMessage::PeerInit {
                        username: "ambient_peer".to_string(),
                        conn_type: ConnectionType::Peer,
                        token: 0,
                    }
                    .encode();
                    p_sock.write_all(&init).unwrap();

                    let resp = PeerMessage::FileSearchResponse {
                        username: "ambient_peer".to_string(),
                        token: reissued_token,
                        files: vec![WireFileEntry {
                            filename: "@@music\\SAW 85-92\\01 - Xtal.flac".to_string(),
                            size: 31_000_000,
                            extension: String::new(),
                            attrs: AudioAttributes {
                                bitrate: None,
                                length_secs: Some(294),
                                vbr: None,
                                sample_rate: Some(44_100),
                                bit_depth: Some(16),
                            },
                        }],
                        slot_free: true,
                        upload_speed: 1_800_000,
                        queue_length: 0,
                        private_files: Vec::new(),
                    }
                    .encode()
                    .unwrap();
                    p_sock.write_all(&resp).unwrap();
                    p_sock.flush().unwrap();
                }
                _ => {}
            }
        }
    });

    let logs: Arc<Mutex<Vec<LogEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_hook = Arc::clone(&logs);

    let client = SoulseekClient::with_options(ClientOptions {
        listen_port: 0,
        ping_interval: Duration::from_secs(30),
        server_read_timeout: Duration::from_secs(30),
        reconnect_backoff_min: Duration::from_millis(80),
        reconnect_backoff_max: Duration::from_millis(250),
        ..ClientOptions::default()
    });
    client.set_logger(Some(Arc::new(move |ev| {
        logs_hook.lock().push(ev);
    })));

    client
        .login("127.0.0.1", srv_port, "reconnect_user", "secret")
        .unwrap();

    let hits = client.search("aphex twin xtal", 900).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].username, "ambient_peer");
    assert!(hits[0].filename.ends_with("01 - Xtal.flac"));

    client.close();
    srv_thread.join().unwrap();

    let captured = logs.lock();
    assert!(
        captured
            .iter()
            .any(|e| e.event == "reconnected" && e.message.contains("re-issued 1 pending search")),
        "expected `reconnected` log carrying re-issued search count, got: {captured:?}"
    );
}

#[test]
fn dead_server_socket_detected_by_read_timeout_without_writes() {
    let srv_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    let srv_thread = thread::spawn(move || {
        // Session 1: accept login, send LoginSuccess, then hold the socket open in silence
        // (simulating a half-open / NAT-dropped TCP connection with neither FIN nor RST).
        let (mut stalled_sock, _) = srv_listener.accept().unwrap();
        stalled_sock
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        loop {
            let frame = read_frame_sync(&mut stalled_sock).unwrap();
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    stalled_sock
                        .write_all(&server_login_ok_frame(
                            "Silent session",
                            Ipv4Addr::LOCALHOST,
                            false,
                        ))
                        .unwrap();
                }
                server_code::CHECK_PRIVILEGES => {
                    // Do NOT answer CheckPrivileges — stay completely silent after login!
                    break;
                }
                _ => {}
            }
        }

        // Keep `stalled_sock` alive until Session 2 connects, proving detection needed neither
        // EOF nor a client write (`ping_interval` is 60s, far beyond the test duration).
        let (mut sock2, _) = srv_listener.accept().unwrap();
        drop(stalled_sock);
        sock2
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        while let Ok(frame) = read_frame_sync(&mut sock2) {
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    sock2
                        .write_all(&server_login_ok_frame(
                            "Recovered session",
                            Ipv4Addr::LOCALHOST,
                            false,
                        ))
                        .unwrap();
                }
                server_code::CHECK_PRIVILEGES => {
                    sock2.write_all(&server_check_privs_frame(3600)).unwrap();
                }
                _ => {}
            }
        }
    });

    let logs: Arc<Mutex<Vec<LogEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let logs_hook = Arc::clone(&logs);

    // Set ping_interval huge (60s) so zero keepalive writes occur; read timeout alone (200ms) must fire.
    let client = SoulseekClient::with_options(ClientOptions {
        listen_port: 0,
        ping_interval: Duration::from_secs(60),
        server_read_timeout: Duration::from_millis(200),
        reconnect_backoff_min: Duration::from_millis(80),
        reconnect_backoff_max: Duration::from_millis(200),
        ..ClientOptions::default()
    });
    client.set_logger(Some(Arc::new(move |ev| {
        logs_hook.lock().push(ev);
    })));

    client
        .login("127.0.0.1", srv_port, "timeout_user", "secret")
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut saw_read_timeout = false;
    let mut saw_reconnected = false;
    while std::time::Instant::now() < deadline {
        {
            let captured = logs.lock();
            saw_read_timeout = captured.iter().any(|e| e.event == "server_read_timeout");
            saw_reconnected = captured.iter().any(|e| e.event == "reconnected");
        }
        if saw_read_timeout && saw_reconnected && client.state().privileges == 3600 {
            break;
        }
        thread::sleep(Duration::from_millis(40));
    }

    assert!(saw_read_timeout, "expected `server_read_timeout` event");
    assert!(saw_reconnected, "expected automatic `reconnected` recovery");
    assert!(
        !logs.lock().iter().any(|e| e.event == "server_write_error"),
        "dead socket must be detected by read timeout without needing a write failure"
    );

    client.close();
    srv_thread.join().unwrap();
}

#[test]
fn disconnect_fails_inflight_peer_download_and_refreshes_watch_user_on_reconnect() {
    let srv_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    let watched_on_reconnect: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let watched_srv = Arc::clone(&watched_on_reconnect);

    let srv_thread = thread::spawn(move || {
        // Session 1: accept login, wait for download's ConnectToPeer + GetPeerAddress, then drop!
        let (mut sock1, _) = srv_listener.accept().unwrap();
        sock1
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut dropped_connect_token: Option<u32> = None;
        while let Ok(frame) = read_frame_sync(&mut sock1) {
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    sock1
                        .write_all(&server_login_ok_frame(
                            "Drop test",
                            Ipv4Addr::LOCALHOST,
                            false,
                        ))
                        .unwrap();
                }
                server_code::CONNECT_TO_PEER => {
                    dropped_connect_token = Some(r.read_u32().unwrap());
                    let _user = r.read_string().unwrap();
                }
                server_code::GET_PEER_ADDRESS => {
                    let _user = r.read_string().unwrap();
                    break;
                }
                _ => {}
            }
        }
        assert!(dropped_connect_token.is_some());
        drop(sock1);

        // Session 2: accept reconnect, record WatchUser refreshed for download queued while reconnecting,
        // then answer CantConnectToPeer so the second download terminates cleanly.
        let (mut sock2, _) = srv_listener.accept().unwrap();
        sock2
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        while let Ok(frame) = read_frame_sync(&mut sock2) {
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    sock2
                        .write_all(&server_login_ok_frame(
                            "Session 2",
                            Ipv4Addr::LOCALHOST,
                            false,
                        ))
                        .unwrap();
                }
                server_code::WATCH_USER => {
                    let u = r.read_string().unwrap();
                    watched_srv.lock().push(u);
                }
                server_code::CONNECT_TO_PEER => {
                    let tok = r.read_u32().unwrap();
                    let _u = r.read_string().unwrap();
                    let mut w = WireWriter::new();
                    w.write_u32(tok);
                    sock2
                        .write_all(&w.into_u32_frame(server_code::CANT_CONNECT_TO_PEER))
                        .unwrap();
                    break;
                }
                _ => {}
            }
        }
    });

    let client = Arc::new(SoulseekClient::with_options(ClientOptions {
        listen_port: 0,
        ping_interval: Duration::from_secs(30),
        server_read_timeout: Duration::from_secs(30),
        reconnect_backoff_min: Duration::from_millis(250),
        reconnect_backoff_max: Duration::from_millis(500),
        ..ClientOptions::default()
    }));

    client
        .login("127.0.0.1", srv_port, "drop_user", "secret")
        .unwrap();

    let out_dir = temp_dir("drop-dl");
    let dest = out_dir.join("track.flac");
    let start = std::time::Instant::now();
    let res = client.download("unreachable_peer", "@@music\\track.flac", &dest, None);
    let elapsed = start.elapsed();

    assert!(
        matches!(res, Err(ClientError::Disconnected(_))),
        "expected retryable ClientError::Disconnected on dropped session, got {res:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "pending download must fail promptly on disconnect instead of hanging ({elapsed:?})"
    );

    // Queue a retry download during the reconnect backoff window and verify WatchUser refreshes on reconnect
    let dest2 = out_dir.join("retry.flac");
    let res2 = client.download("watched_peer", "@@music\\retry.flac", &dest2, None);
    assert!(matches!(res2, Err(ClientError::Disconnected(_))));
    assert!(
        watched_on_reconnect
            .lock()
            .iter()
            .any(|u| u == "watched_peer"),
        "expected WatchUser refresh on reconnect for pending download target"
    );

    client.close();
    srv_thread.join().unwrap();
    let _ = fs::remove_dir_all(&out_dir);
}

/// Synthesize a valid minimal FLAC header (`fLaC` + 34-byte `STREAMINFO` last-metadata block)
/// followed by deterministic sample payload bytes.
fn make_synthetic_flac(
    sample_rate: u32,
    bit_depth: u8,
    total_samples: u64,
    body_len: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(42 + body_len);
    out.extend_from_slice(b"fLaC");
    // Metadata block header: last=1 (0x80) | type=0 (STREAMINFO), length = 34 (0x000022)
    out.extend_from_slice(&[0x80, 0x00, 0x00, 0x22]);
    let mut si = [0u8; 34];
    // min/max blocksize = 4096
    si[0..2].copy_from_slice(&4096u16.to_be_bytes());
    si[2..4].copy_from_slice(&4096u16.to_be_bytes());
    // Pack [20-bit sample_rate][3-bit (channels-1 = 1)][5-bit (bps-1)][36-bit total_samples] into si[10..18]
    let channels_minus_1: u64 = 1; // stereo
    let bps_minus_1 = u64::from(bit_depth - 1);
    let packed: u64 = ((u64::from(sample_rate) & 0xfffff) << 44)
        | ((channels_minus_1 & 0x7) << 41)
        | ((bps_minus_1 & 0x1f) << 36)
        | (total_samples & 0x0f_ffff_ffff);
    si[10..18].copy_from_slice(&packed.to_be_bytes());
    out.extend_from_slice(&si);
    for i in 0..body_len {
        out.push(((i * 53 + 19) & 0xff) as u8);
    }
    out
}

#[test]
fn advertises_disk_share_answers_browse_folder_contents_and_streams_upload_with_offset() {
    let share_dir = temp_dir("share-root");
    let album_dir = share_dir.join("Boards of Canada - Olson (1998)");
    fs::create_dir_all(&album_dir).unwrap();
    // Dot files and .part files must be excluded from share!
    fs::write(album_dir.join(".peartube-album.json"), b"{}\n").unwrap();
    fs::write(album_dir.join("incomplete.flac.part"), b"partial").unwrap();

    let track1_bytes = make_synthetic_flac(44_100, 16, 44_100 * 91, 192 * 1024);
    let track2_bytes = make_synthetic_flac(96_000, 24, 96_000 * 140, 64 * 1024);
    fs::write(album_dir.join("01 - Olson.flac"), &track1_bytes).unwrap();
    fs::write(
        album_dir.join("02 - Pete Standing Alone.flac"),
        &track2_bytes,
    )
    .unwrap();

    let peer_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer_port = peer_listener.local_addr().unwrap().port();

    let srv_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    let reported_share: Arc<Mutex<Vec<(u32, u32)>>> = Arc::new(Mutex::new(Vec::new()));
    let reported_share_srv = Arc::clone(&reported_share);
    let reported_speed: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));
    let reported_speed_srv = Arc::clone(&reported_speed);

    let srv_thread = thread::spawn(move || {
        let (mut sock, _) = srv_listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut cur_folders = 0u32;
        let mut cur_files = 0u32;
        while let Ok(frame) = read_frame_sync(&mut sock) {
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    sock.write_all(&server_login_ok_frame(
                        "Share test",
                        Ipv4Addr::LOCALHOST,
                        false,
                    ))
                    .unwrap();
                }
                server_code::SHARED_FOLDERS_FILES => {
                    cur_folders = r.read_u32().unwrap();
                    cur_files = r.read_u32().unwrap();
                    reported_share_srv.lock().push((cur_folders, cur_files));
                }
                server_code::GET_USER_STATS => {
                    let u = r.read_string().unwrap();
                    let mut w = WireWriter::new();
                    w.write_str(&u);
                    w.write_u32(128_000);
                    w.write_u32(3);
                    w.write_u32(0);
                    w.write_u32(cur_files);
                    w.write_u32(cur_folders);
                    sock.write_all(&w.into_u32_frame(server_code::GET_USER_STATS))
                        .unwrap();
                }
                server_code::CHECK_PRIVILEGES => {
                    sock.write_all(&server_check_privs_frame(600)).unwrap();
                }
                server_code::GET_PEER_ADDRESS => {
                    let target = r.read_string().unwrap();
                    sock.write_all(&server_peer_address_frame(
                        &target,
                        Ipv4Addr::LOCALHOST,
                        peer_port,
                    ))
                    .unwrap();
                }
                server_code::SEND_UPLOAD_SPEED => {
                    reported_speed_srv.lock().push(r.read_u32().unwrap());
                }
                _ => {}
            }
        }
    });

    let client = SoulseekClient::with_options(ClientOptions {
        listen_port: 0,
        share_dir: Some(share_dir.clone()),
        share_enabled: true,
        share_max_files: 2000,
        ..ClientOptions::default()
    });
    let relay_port = client.state().listen_port;

    client
        .login("127.0.0.1", srv_port, "relay_sharer", "secret")
        .unwrap();

    // 1. Verify GetUserStats reports our real non-zero folder/file counts (1 folder, 2 files)
    let stats = client
        .user_stats("relay_sharer", Duration::from_secs(5))
        .unwrap();
    assert_eq!(stats.folders, 1);
    assert_eq!(stats.files, 2);
    assert_eq!(reported_share.lock().as_slice(), &[(1, 2)]);

    // 2. Connect as a remote Soulseek peer to the relay's listener (`P` socket):
    //    - check UserInfoResponse (honest slots=2, queue=0, slot_free=true, description)
    //    - check SharedFileListResponse (matching folder + 2 FLACs + STREAMINFO attrs)
    //    - check FolderContentsRequest -> FolderContentsResponse
    //    - request QueueUpload for track 1 with 16 KiB resume offset and verify exact streamed bytes!
    let mut p_sock = TcpStream::connect((Ipv4Addr::LOCALHOST, relay_port)).unwrap();
    p_sock
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    p_sock
        .write_all(
            &PeerInitMessage::PeerInit {
                username: "remote_seeker".to_string(),
                conn_type: ConnectionType::Peer,
                token: 0,
            }
            .encode(),
        )
        .unwrap();

    // UserInfoRequest
    p_sock
        .write_all(&PeerMessage::UserInfoRequest.encode().unwrap())
        .unwrap();
    let info_msg = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    assert_eq!(
        info_msg,
        PeerMessage::UserInfoResponse {
            description: USER_INFO_DESCRIPTION.to_string(),
            picture: None,
            upload_slots: DEFAULT_UPLOAD_SLOTS,
            queue_length: 0,
            slot_free: true,
            upload_permission: Some(0),
        }
    );

    // SharedFileListRequest
    p_sock
        .write_all(&PeerMessage::SharedFileListRequest.encode().unwrap())
        .unwrap();
    let list_msg = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    let PeerMessage::SharedFileListResponse {
        folders,
        private_folders,
    } = list_msg
    else {
        panic!("expected SharedFileListResponse");
    };
    assert!(private_folders.is_empty());
    assert_eq!(folders.len(), 1);
    assert_eq!(
        folders[0].path,
        "@@peartube\\Boards of Canada - Olson (1998)"
    );
    assert_eq!(folders[0].files.len(), 2);
    assert_eq!(folders[0].files[0].filename, "01 - Olson.flac");
    assert_eq!(folders[0].files[0].size, track1_bytes.len() as u64);
    assert_eq!(folders[0].files[0].attrs.sample_rate, Some(44_100));
    assert_eq!(folders[0].files[0].attrs.bit_depth, Some(16));
    assert_eq!(folders[0].files[0].attrs.length_secs, Some(91));
    assert_eq!(folders[0].files[1].attrs.sample_rate, Some(96_000));
    assert_eq!(folders[0].files[1].attrs.bit_depth, Some(24));

    // FolderContentsRequest
    p_sock
        .write_all(
            &PeerMessage::FolderContentsRequest {
                token: 77,
                folder: "@@peartube\\Boards of Canada - Olson (1998)".to_string(),
            }
            .encode()
            .unwrap(),
        )
        .unwrap();
    let fc_msg = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    assert_eq!(
        fc_msg,
        PeerMessage::FolderContentsResponse {
            token: 77,
            root_folder: "@@peartube\\Boards of Canada - Olson (1998)".to_string(),
            folders: folders.clone(),
        }
    );

    // QueueUpload -> expect TransferRequest(direction=1) from relay!
    let wanted_vpath = "@@peartube\\Boards of Canada - Olson (1998)\\01 - Olson.flac".to_string();
    p_sock
        .write_all(
            &PeerMessage::QueueUpload {
                filename: wanted_vpath.clone(),
            }
            .encode()
            .unwrap(),
        )
        .unwrap();

    let offer = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    let PeerMessage::TransferRequest {
        direction: 1,
        token: transfer_token,
        filename: offered_name,
        file_size: Some(offered_size),
    } = offer
    else {
        panic!("expected TransferRequest(direction=1), got {offer:?}");
    };
    assert_eq!(offered_name, wanted_vpath);
    assert_eq!(offered_size, track1_bytes.len() as u64);

    // Spawn acceptor on `peer_listener` to receive the relay's outbound `F` connection!
    let expected_len = track1_bytes.len();
    let resume_offset: usize = 16 * 1024;
    let f_rx_handle = thread::spawn(move || {
        let (mut f_sock, _) = peer_listener.accept().unwrap();
        f_sock
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let f_init_raw = read_frame_sync(&mut f_sock).unwrap();
        let f_init = PeerInitMessage::decode(&f_init_raw).unwrap();
        assert_eq!(
            f_init,
            PeerInitMessage::PeerInit {
                username: "relay_sharer".to_string(),
                conn_type: ConnectionType::File,
                token: 0,
            }
        );
        let mut tok_buf = [0u8; 4];
        f_sock.read_exact(&mut tok_buf).unwrap();
        let rx_token = decode_file_transfer_init(&tok_buf).unwrap();
        assert_eq!(rx_token, transfer_token);

        // Send 8-byte FileOffset (16 KiB resume)
        f_sock
            .write_all(&encode_file_offset(resume_offset as u64))
            .unwrap();
        f_sock.flush().unwrap();

        let mut received = vec![0u8; expected_len - resume_offset];
        f_sock.read_exact(&mut received).unwrap();
        // Close F socket per SLSKPROTOCOL (downloader closes when complete)
        drop(f_sock);
        received
    });

    // Accept TransferRequest -> relay dials `F` socket and streams bytes[16384..]!
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

    let streamed_tail = f_rx_handle.join().unwrap();
    assert_eq!(streamed_tail, &track1_bytes[resume_offset..]);

    // Test runtime share toggle (`slskShare: false`) -> advertises (0, 0), UserInfo slots=0, slot_free=false
    let (folders_off, files_off) = client
        .configure_share(Some(share_dir.clone()), false, 2000)
        .unwrap();
    assert_eq!((folders_off, files_off), (0, 0));
    let stats_off = client
        .user_stats("relay_sharer", Duration::from_secs(5))
        .unwrap();
    assert_eq!((stats_off.folders, stats_off.files), (0, 0));

    p_sock
        .write_all(&PeerMessage::UserInfoRequest.encode().unwrap())
        .unwrap();
    let info_off = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    assert_eq!(
        info_off,
        PeerMessage::UserInfoResponse {
            description: USER_INFO_DESCRIPTION.to_string(),
            picture: None,
            upload_slots: 0,
            queue_length: 0,
            slot_free: false,
            upload_permission: Some(0),
        }
    );

    client.close();
    drop(p_sock);
    srv_thread.join().unwrap();
    let _ = fs::remove_dir_all(&share_dir);
}

#[test]
fn enforces_share_cap_upload_slots_queue_bound_and_concurrent_download() {
    let share_dir = temp_dir("share-cap");
    let album_dir = share_dir.join("Massive Boxset");
    fs::create_dir_all(&album_dir).unwrap();

    // Create 40 tracks on disk, but cap `share_max_files` at 35 (above queue_cap=32 + slots=2 = 34)
    let small_flac = make_synthetic_flac(44_100, 16, 44_100 * 10, 8 * 1024);
    for i in 1..=40 {
        fs::write(album_dir.join(format!("{i:02} - Track.flac")), &small_flac).unwrap();
    }

    // Also prepare a concurrent download source peer (`dl_source_peer`) with 256 KiB payload
    let dl_payload: Vec<u8> = (0..(256 * 1024)).map(|i| (i & 0xff) as u8).collect();
    let dl_payload_peer = dl_payload.clone();
    let dl_peer_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let dl_peer_port = dl_peer_listener.local_addr().unwrap().port();

    let srv_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    let srv_thread = thread::spawn(move || {
        let (mut sock, _) = srv_listener.accept().unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut cur_files = 0u32;
        let mut cur_folders = 0u32;
        while let Ok(frame) = read_frame_sync(&mut sock) {
            let mut r = WireReader::new(&frame);
            match r.read_u32().unwrap() {
                server_code::LOGIN => {
                    sock.write_all(&server_login_ok_frame("Bounds", Ipv4Addr::LOCALHOST, false))
                        .unwrap();
                }
                server_code::SHARED_FOLDERS_FILES => {
                    cur_folders = r.read_u32().unwrap();
                    cur_files = r.read_u32().unwrap();
                }
                server_code::GET_USER_STATS => {
                    let u = r.read_string().unwrap();
                    let mut w = WireWriter::new();
                    w.write_str(&u);
                    w.write_u32(0);
                    w.write_u32(0);
                    w.write_u32(0);
                    w.write_u32(cur_files);
                    w.write_u32(cur_folders);
                    sock.write_all(&w.into_u32_frame(server_code::GET_USER_STATS))
                        .unwrap();
                }
                server_code::GET_PEER_ADDRESS => {
                    let u = r.read_string().unwrap();
                    if u == "dl_source_peer" {
                        sock.write_all(&server_peer_address_frame(
                            &u,
                            Ipv4Addr::LOCALHOST,
                            dl_peer_port,
                        ))
                        .unwrap();
                    }
                }
                _ => {}
            }
        }
    });

    let client = Arc::new(SoulseekClient::with_options(ClientOptions {
        listen_port: 0,
        share_dir: Some(share_dir.clone()),
        share_enabled: true,
        share_max_files: 35,
        ..ClientOptions::default()
    }));
    let relay_port = client.state().listen_port;
    client
        .login("127.0.0.1", srv_port, "bounded_relay", "secret")
        .unwrap();

    // 1. Verify cap of 35 files enforced on 40-file folder
    let stats = client
        .user_stats("bounded_relay", Duration::from_secs(5))
        .unwrap();
    assert_eq!(stats.folders, 1);
    assert_eq!(stats.files, 35);

    // 2. Connect remote peer and queue 35 distinct files without answering TransferRequest yet:
    //    - First 2 take the 2 active upload slots (`TransferRequest` sent)
    //    - Next 32 enter the bounded queue (`PlaceInQueueResponse` 1..=32)
    //    - 35th exceeds `DEFAULT_UPLOAD_QUEUE_CAP` (32) -> rejected with `UploadDenied("Too many files")`!
    let mut p_sock = TcpStream::connect((Ipv4Addr::LOCALHOST, relay_port)).unwrap();
    p_sock
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    p_sock
        .write_all(
            &PeerInitMessage::PeerInit {
                username: "greedy_peer".to_string(),
                conn_type: ConnectionType::Peer,
                token: 0,
            }
            .encode(),
        )
        .unwrap();

    let total_requests = (DEFAULT_UPLOAD_SLOTS as usize) + DEFAULT_UPLOAD_QUEUE_CAP + 1; // 35
    for i in 1..=total_requests {
        let vpath = format!("@@peartube\\Massive Boxset\\{i:02} - Track.flac");
        p_sock
            .write_all(
                &PeerMessage::QueueUpload { filename: vpath }
                    .encode()
                    .unwrap(),
            )
            .unwrap();
    }

    let mut transfer_offers = 0usize;
    let mut max_place = 0u32;
    let mut saw_too_many = false;
    for _ in 0..total_requests {
        let msg = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
        match msg {
            PeerMessage::TransferRequest { direction: 1, .. } => transfer_offers += 1,
            PeerMessage::PlaceInQueueResponse { place, .. } => max_place = max_place.max(place),
            PeerMessage::UploadDenied { reason, .. } => {
                assert_eq!(reason, "Too many files");
                saw_too_many = true;
            }
            other => panic!("unexpected peer reply: {other:?}"),
        }
    }
    assert_eq!(transfer_offers, DEFAULT_UPLOAD_SLOTS as usize);
    assert_eq!(max_place, DEFAULT_UPLOAD_QUEUE_CAP as u32);
    assert!(
        saw_too_many,
        "35th request must be denied with 'Too many files'"
    );

    // Verify UserInfoResponse now honestly reports slot_free = false and queue_length = 32!
    p_sock
        .write_all(&PeerMessage::UserInfoRequest.encode().unwrap())
        .unwrap();
    let busy_info = PeerMessage::decode(&read_frame_sync(&mut p_sock).unwrap()).unwrap();
    assert_eq!(
        busy_info,
        PeerMessage::UserInfoResponse {
            description: USER_INFO_DESCRIPTION.to_string(),
            picture: None,
            upload_slots: DEFAULT_UPLOAD_SLOTS,
            queue_length: DEFAULT_UPLOAD_QUEUE_CAP as u32,
            slot_free: false,
            upload_permission: Some(0),
        }
    );

    // 3. Prove saturated upload slots + full upload queue NEVER block a concurrent download!
    let dl_peer_thread = thread::spawn(move || {
        let (mut s, _) = dl_peer_listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _init = PeerInitMessage::decode(&read_frame_sync(&mut s).unwrap()).unwrap();
        while let Ok(frame) = read_frame_sync(&mut s) {
            match PeerMessage::decode(&frame).unwrap() {
                PeerMessage::QueueUpload { filename } => {
                    s.write_all(
                        &PeerMessage::TransferRequest {
                            direction: 1,
                            token: 999_111,
                            filename,
                            file_size: Some(dl_payload_peer.len() as u64),
                        }
                        .encode()
                        .unwrap(),
                    )
                    .unwrap();
                }
                PeerMessage::TransferResponse {
                    token: 999_111,
                    allowed: true,
                    ..
                } => {
                    let mut f_sock = TcpStream::connect((Ipv4Addr::LOCALHOST, relay_port)).unwrap();
                    f_sock
                        .write_all(
                            &PeerInitMessage::PeerInit {
                                username: "dl_source_peer".to_string(),
                                conn_type: ConnectionType::File,
                                token: 0,
                            }
                            .encode(),
                        )
                        .unwrap();
                    f_sock
                        .write_all(&encode_file_transfer_init(999_111))
                        .unwrap();
                    let mut off = [0u8; 8];
                    f_sock.read_exact(&mut off).unwrap();
                    assert_eq!(decode_file_offset(&off).unwrap(), 0);
                    f_sock.write_all(&dl_payload_peer).unwrap();
                    f_sock.flush().unwrap();
                    let mut fin = [0u8; 1];
                    let _ = f_sock.read(&mut fin);
                    break;
                }
                _ => {}
            }
        }
    });

    let out_dir = temp_dir("concurrent-dl");
    let dl_dest = out_dir.join("downloaded.flac");
    let dl_outcome = client
        .download("dl_source_peer", "@@peer\\downloaded.flac", &dl_dest, None)
        .unwrap();
    assert_eq!(dl_outcome.size, dl_payload.len() as u64);
    assert_eq!(fs::read(&dl_dest).unwrap(), dl_payload);

    dl_peer_thread.join().unwrap();
    client.close();
    drop(p_sock);
    srv_thread.join().unwrap();
    let _ = fs::remove_dir_all(&share_dir);
    let _ = fs::remove_dir_all(&out_dir);
}

#[test]
fn sharing_defaults_off_advertising_zero_counts_and_zero_slots_until_explicitly_enabled() {
    let share_dir = temp_dir("default-off");
    let album_dir = share_dir.join("Private Artist - Home Recording (2025)");
    fs::create_dir_all(&album_dir).unwrap();
    let flac = make_synthetic_flac(44_100, 16, 44_100 * 30, 16 * 1024);
    fs::write(album_dir.join("01 - Unreleased Demo.flac"), &flac).unwrap();

    // Verify `ClientOptions::default()` keeps `share_enabled == false` when `PEARTUBE_SLSK_SHARE` is unset,
    // and that the startup JSON log line omits `dir` when disabled!
    if std::env::var("PEARTUBE_SLSK_SHARE").is_err() {
        let def = ClientOptions::default();
        assert!(
            !def.share_enabled,
            "sharing MUST default OFF when PEARTUBE_SLSK_SHARE is unset"
        );
        assert_eq!(
            format_share_decision_json(&def, 0),
            r#"{"msg":"soulseek share","enabled":false,"files":0}"#
        );
    }

    let srv_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let srv_port = srv_listener.local_addr().unwrap().port();

    let reported_shares: Arc<Mutex<Vec<(u32, u32)>>> = Arc::new(Mutex::new(Vec::new()));
    let reported_srv = Arc::clone(&reported_shares);

    let srv_thread = thread::spawn(move || {
        for _session in 0..2 {
            let Ok((mut sock, _)) = srv_listener.accept() else {
                break;
            };
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            while let Ok(frame) = read_frame_sync(&mut sock) {
                let mut r = WireReader::new(&frame);
                match r.read_u32().unwrap() {
                    server_code::LOGIN => {
                        sock.write_all(&server_login_ok_frame(
                            "Opt-in test",
                            Ipv4Addr::LOCALHOST,
                            false,
                        ))
                        .unwrap();
                    }
                    server_code::SHARED_FOLDERS_FILES => {
                        let folders = r.read_u32().unwrap();
                        let files = r.read_u32().unwrap();
                        reported_srv.lock().push((folders, files));
                    }
                    _ => {}
                }
            }
        }
    });

    // 1. Start with `share_enabled: false` (even when `share_dir` points at a populated folder):
    //    must advertise `SharedFoldersFiles { folders: 0, files: 0 }`, `upload_slots: 0`, `slot_free: false`,
    //    and empty `SharedFileListResponse`.
    let opts_off = ClientOptions {
        listen_port: 0,
        share_dir: Some(share_dir.clone()),
        share_enabled: false,
        ..ClientOptions::default()
    };
    assert_eq!(
        format_share_decision_json(&opts_off, 0),
        r#"{"msg":"soulseek share","enabled":false,"files":0}"#
    );
    let client_off = SoulseekClient::with_options(opts_off);
    let port_off = client_off.state().listen_port;
    client_off
        .login("127.0.0.1", srv_port, "private_relay", "secret")
        .unwrap();

    let mut p_off = TcpStream::connect((Ipv4Addr::LOCALHOST, port_off)).unwrap();
    p_off
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    p_off
        .write_all(
            &PeerInitMessage::PeerInit {
                username: "stranger".to_string(),
                conn_type: ConnectionType::Peer,
                token: 0,
            }
            .encode(),
        )
        .unwrap();
    p_off
        .write_all(&PeerMessage::UserInfoRequest.encode().unwrap())
        .unwrap();
    let info_off = PeerMessage::decode(&read_frame_sync(&mut p_off).unwrap()).unwrap();
    assert_eq!(
        info_off,
        PeerMessage::UserInfoResponse {
            description: USER_INFO_DESCRIPTION.to_string(),
            picture: None,
            upload_slots: 0,
            queue_length: 0,
            slot_free: false,
            upload_permission: Some(0),
        }
    );
    p_off
        .write_all(&PeerMessage::SharedFileListRequest.encode().unwrap())
        .unwrap();
    let list_off = PeerMessage::decode(&read_frame_sync(&mut p_off).unwrap()).unwrap();
    assert_eq!(
        list_off,
        PeerMessage::SharedFileListResponse {
            folders: Vec::new(),
            private_folders: Vec::new(),
        }
    );
    drop(p_off);
    client_off.close();

    // 2. Start with `share_enabled: true` pointing at the same temp dir:
    //    must advertise `SharedFoldersFiles { folders: 1, files: 1 }` and `upload_slots: 2`, `slot_free: true`.
    let opts_on = ClientOptions {
        listen_port: 0,
        share_dir: Some(share_dir.clone()),
        share_enabled: true,
        share_max_files: 2000,
        ..ClientOptions::default()
    };
    assert_eq!(
        format_share_decision_json(&opts_on, 1),
        format!(
            r#"{{"msg":"soulseek share","enabled":true,"files":1,"dir":"{}"}}"#,
            share_dir.to_string_lossy()
        )
    );
    let client_on = SoulseekClient::with_options(opts_on);
    let port_on = client_on.state().listen_port;
    client_on
        .login("127.0.0.1", srv_port, "public_relay", "secret")
        .unwrap();

    let mut p_on = TcpStream::connect((Ipv4Addr::LOCALHOST, port_on)).unwrap();
    p_on.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    p_on.write_all(
        &PeerInitMessage::PeerInit {
            username: "stranger".to_string(),
            conn_type: ConnectionType::Peer,
            token: 0,
        }
        .encode(),
    )
    .unwrap();
    p_on.write_all(&PeerMessage::UserInfoRequest.encode().unwrap())
        .unwrap();
    let info_on = PeerMessage::decode(&read_frame_sync(&mut p_on).unwrap()).unwrap();
    assert_eq!(
        info_on,
        PeerMessage::UserInfoResponse {
            description: USER_INFO_DESCRIPTION.to_string(),
            picture: None,
            upload_slots: DEFAULT_UPLOAD_SLOTS,
            queue_length: 0,
            slot_free: true,
            upload_permission: Some(0),
        }
    );
    drop(p_on);
    client_on.close();
    srv_thread.join().unwrap();

    assert_eq!(reported_shares.lock().as_slice(), &[(0, 0), (1, 1)]);
    let _ = fs::remove_dir_all(&share_dir);
}
