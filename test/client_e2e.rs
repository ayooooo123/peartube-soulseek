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
use peartube_soulseek::client::{ClientError, LogEvent, SoulseekClient};
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
