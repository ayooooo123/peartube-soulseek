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
use peartube_soulseek::client::{ClientError, ClientOptions, LogEvent, SoulseekClient};
use peartube_soulseek::proto::{
    AudioAttributes, ConnectionType, PeerInitMessage, PeerMessage, SharedFolder, WireFileEntry,
    WireReader, WireWriter, decode_file_offset, encode_file_transfer_init, read_frame_sync,
    server_code,
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
