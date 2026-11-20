//! Offline unit tests for every implemented Soulseek wire message using in-code hex fixtures.
//! No binary blobs committed; zero network access.

use std::net::Ipv4Addr;

use peartube_soulseek::proto::{
    AudioAttributes, ConnectionType, DEFAULT_MAJOR_VERSION, DEFAULT_MINOR_VERSION,
    DistributedMessage, FrameDecoder, LoginRejectReason, PeerInitMessage, PeerMessage, ProtoError,
    ServerRequest, ServerResponse, SharedFolder, WireFileEntry, WireWriter, decode_file_offset,
    decode_file_transfer_init, encode_file_offset, encode_file_transfer_init,
    flatten_shared_folders, login_checksum, md5_hex, server_code, zlib_compress,
};

fn unhex(hex: &str) -> Vec<u8> {
    let clean: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    assert_eq!(
        clean.len() % 2,
        0,
        "hex fixture must have even nibble count"
    );
    clean
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(s, 16).unwrap()
        })
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn strip_len_prefix(frame: &[u8]) -> &[u8] {
    let declared = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(declared + 4, frame.len(), "frame length prefix mismatch");
    &frame[4..]
}

#[test]
fn login_request_matches_nicotine_plus_hex_fixture() {
    // Verified byte-for-byte against SLSKPROTOCOL "Sending Login Example" & Nicotine+ Login:
    // username = "username", password = "password", major = 177 (0xb1), minor = 1
    // md5("usernamepassword") = "d51c9a7e9353746a6020f9602d452929"
    assert_eq!(
        login_checksum("username", "password"),
        "d51c9a7e9353746a6020f9602d452929"
    );

    let expected_hex = "\
        48000000\
        01000000\
        08000000757365726e616d65\
        0800000070617373776f7264\
        b1000000\
        200000006435316339613765393335333734366136303230663936303264343532393239\
        01000000";

    let encoded = ServerRequest::Login {
        username: "username".to_string(),
        password: "password".to_string(),
        major_version: DEFAULT_MAJOR_VERSION,
        minor_version: DEFAULT_MINOR_VERSION,
    }
    .encode();

    assert_eq!(to_hex(&encoded), expected_hex);
    assert_eq!(encoded, unhex(expected_hex));
}

#[test]
fn login_response_success_and_all_rejection_reasons() {
    // Server Login success fixture:
    // [len=57 (0x39)][code=1][ok=1][motd="Welcome"][ip 1.2.3.4 -> 04 03 02 01][md5="5f4dcc3b5aa765d61d8327deb882cf99"][supporter=1]
    let success_hex = "\
        39000000\
        01000000\
        01\
        0700000057656c636f6d65\
        04030201\
        200000003566346463633362356161373635643631643833323764656238383263663939\
        01";
    let frame = unhex(success_hex);
    let parsed = ServerResponse::decode(strip_len_prefix(&frame)).unwrap();
    assert_eq!(
        parsed,
        ServerResponse::LoginSuccess {
            motd: "Welcome".to_string(),
            own_ip: Ipv4Addr::new(1, 2, 3, 4),
            password_md5: md5_hex(b"password"),
            is_supporter: true,
        }
    );

    // Server Login rejection with detail (`INVALIDUSERNAME` + `"Nick too long."`)
    let mut w = WireWriter::new();
    w.write_bool(false);
    w.write_str("INVALIDUSERNAME");
    w.write_str("Nick too long.");
    let rej_frame = w.into_u32_frame(server_code::LOGIN);
    let rej_parsed = ServerResponse::decode(strip_len_prefix(&rej_frame)).unwrap();
    assert_eq!(
        rej_parsed,
        ServerResponse::LoginFailure {
            reason_code: LoginRejectReason::InvalidUsername,
            reason: "INVALIDUSERNAME".to_string(),
            detail: Some("Nick too long.".to_string()),
        }
    );

    // Verify every rejection reason mapping
    for (wire, expected) in [
        ("INVALIDUSERNAME", LoginRejectReason::InvalidUsername),
        ("EMPTYPASSWORD", LoginRejectReason::EmptyPassword),
        ("INVALIDPASS", LoginRejectReason::InvalidPass),
        ("INVALIDVERSION", LoginRejectReason::InvalidVersion),
        ("SVRFULL", LoginRejectReason::ServerFull),
        ("SVRPRIVATE", LoginRejectReason::ServerPrivate),
        ("SERVERPRIVATE", LoginRejectReason::ServerPrivate),
    ] {
        let mut rw = WireWriter::new();
        rw.write_bool(false);
        rw.write_str(wire);
        let rf = rw.into_u32_frame(server_code::LOGIN);
        assert_eq!(
            ServerResponse::decode(strip_len_prefix(&rf)).unwrap(),
            ServerResponse::LoginFailure {
                reason_code: expected,
                reason: wire.to_string(),
                detail: None,
            }
        );
    }
}

#[test]
fn server_requests_encode_exact_hex_fixtures() {
    // SetWaitPort(2234 = 0x08ba) -> len=8, code=2, port=0x08ba
    assert_eq!(
        to_hex(&ServerRequest::SetWaitPort { port: 2234 }.encode()),
        "0800000002000000ba080000"
    );

    // GetPeerAddress("alice") -> len=13, code=3, strlen=5, "alice"
    assert_eq!(
        to_hex(
            &ServerRequest::GetPeerAddress {
                username: "alice".to_string()
            }
            .encode()
        ),
        "0d0000000300000005000000616c696365"
    );

    // WatchUser("bob") & UnwatchUser("bob") & GetUserStatus("bob") & GetUserStats("bob")
    assert_eq!(
        to_hex(
            &ServerRequest::WatchUser {
                username: "bob".to_string()
            }
            .encode()
        ),
        "0b0000000500000003000000626f62"
    );
    assert_eq!(
        to_hex(
            &ServerRequest::UnwatchUser {
                username: "bob".to_string()
            }
            .encode()
        ),
        "0b0000000600000003000000626f62"
    );
    assert_eq!(
        to_hex(
            &ServerRequest::GetUserStatus {
                username: "bob".to_string()
            }
            .encode()
        ),
        "0b0000000700000003000000626f62"
    );
    assert_eq!(
        to_hex(
            &ServerRequest::GetUserStats {
                username: "bob".to_string()
            }
            .encode()
        ),
        "0b0000002400000003000000626f62"
    );

    // ConnectToPeer(token=0x12345678, username="dp", conn_type="P") -> code=18 (0x12)
    assert_eq!(
        to_hex(
            &ServerRequest::ConnectToPeer {
                token: 0x12345678,
                username: "dp".to_string(),
                conn_type: ConnectionType::Peer,
            }
            .encode()
        ),
        "1300000012000000785634120200000064700100000050"
    );

    // MessageAcked(42) -> code=23 (0x17)
    assert_eq!(
        to_hex(&ServerRequest::MessageAcked { message_id: 42 }.encode()),
        "08000000170000002a000000"
    );

    // FileSearch(token=99, query="aphex twin flac") -> code=26 (0x1a)
    assert_eq!(
        to_hex(
            &ServerRequest::FileSearch {
                token: 99,
                query: "flac".to_string(),
            }
            .encode()
        ),
        "100000001a0000006300000004000000666c6163"
    );

    // SetStatus(2 = Online), ServerPing(32), SharedFoldersFiles(3, 45)
    assert_eq!(
        to_hex(&ServerRequest::SetStatus { status: 2 }.encode()),
        "080000001c00000002000000"
    );
    assert_eq!(
        to_hex(&ServerRequest::ServerPing.encode()),
        "0400000020000000"
    );
    assert_eq!(
        to_hex(
            &ServerRequest::SharedFoldersFiles {
                folders: 3,
                files: 45
            }
            .encode()
        ),
        "0c00000023000000030000002d000000"
    );

    // HaveNoParent(true), CheckPrivileges, AcceptChildren(false), BranchLevel(1), BranchRoot("root"), CantConnectToPeer
    assert_eq!(
        to_hex(&ServerRequest::HaveNoParent { no_parent: true }.encode()),
        "050000004700000001"
    );
    assert_eq!(
        to_hex(&ServerRequest::CheckPrivileges.encode()),
        "040000005c000000"
    );
    assert_eq!(
        to_hex(&ServerRequest::AcceptChildren { accept: false }.encode()),
        "050000006400000000"
    );
    assert_eq!(
        to_hex(&ServerRequest::BranchLevel { level: 1 }.encode()),
        "080000007e00000001000000"
    );
    assert_eq!(
        to_hex(
            &ServerRequest::BranchRoot {
                username: "rt".to_string()
            }
            .encode()
        ),
        "0a0000007f000000020000007274"
    );
    assert_eq!(
        to_hex(
            &ServerRequest::CantConnectToPeer {
                token: 7,
                username: "dp".to_string()
            }
            .encode()
        ),
        "0e000000e903000007000000020000006470"
    );
}

#[test]
fn server_responses_decode_recorded_hex_fixtures() {
    // Recorded ConnectToPeer fixture from real Soulseek server:
    // user="dp", type="P", ip=45.37.231.27 (bytes: 1b e7 25 2d), port=2234, token=1658546
    let connect_to_peer_hex = "\
        24000000\
        12000000\
        020000006470\
        0100000050\
        1be7252d\
        ba080000\
        b24e1900\
        00\
        00000000\
        00000000";
    let ctp_raw = unhex(connect_to_peer_hex);
    // Note: header says 0x24 = 36 bytes; trim fixture to exact frame if needed
    let mut dec = FrameDecoder::new();
    dec.push(&ctp_raw);
    let ctp_payload = dec.next_frame().unwrap().unwrap();
    assert_eq!(
        ServerResponse::decode(&ctp_payload).unwrap(),
        ServerResponse::ConnectToPeer {
            username: "dp".to_string(),
            conn_type: ConnectionType::Peer,
            ip: Ipv4Addr::new(45, 37, 231, 27),
            port: 2234,
            token: 1_658_546,
            privileged: false,
            obfuscation_type: 0,
            obfuscated_port: 0,
        }
    );

    // GetPeerAddress response: code=3, user="alice", ip=192.168.1.50 (32 01 a8 c0), port=2234, obf_type=0, obf_port=0(u16)
    let gpa_hex = "\
        1b000000\
        03000000\
        05000000616c696365\
        3201a8c0\
        ba080000\
        00000000\
        0000";
    assert_eq!(
        ServerResponse::decode(strip_len_prefix(&unhex(gpa_hex))).unwrap(),
        ServerResponse::PeerAddress {
            username: "alice".to_string(),
            ip: Ipv4Addr::new(192, 168, 1, 50),
            port: 2234,
            obfuscation_type: 0,
            obfuscated_port: 0,
        }
    );

    // CheckPrivileges response (code=92, 86400s = 0x00015180)
    let priv_hex = "080000005c00000080510100";
    assert_eq!(
        ServerResponse::decode(strip_len_prefix(&unhex(priv_hex))).unwrap(),
        ServerResponse::CheckPrivileges {
            seconds_left: 86_400
        }
    );

    // Relogged (code=41 = 0x29)
    assert_eq!(
        ServerResponse::decode(strip_len_prefix(&unhex("0400000029000000"))).unwrap(),
        ServerResponse::Relogged
    );

    // CantConnectToPeer (code=1001 = 0x03e9, token=555)
    assert_eq!(
        ServerResponse::decode(strip_len_prefix(&unhex("08000000e90300002b020000"))).unwrap(),
        ServerResponse::CantConnectToPeer { token: 555 }
    );

    // GetUserStatus (code=7, user="dj", status=2, privileged=true)
    let status_hex = "0f0000000700000002000000646a0200000001";
    assert_eq!(
        ServerResponse::decode(strip_len_prefix(&unhex(status_hex))).unwrap(),
        ServerResponse::UserStatus {
            username: "dj".to_string(),
            status: 2,
            privileged: true,
        }
    );

    // ExcludedSearchPhrases (code=160 = 0xa0)
    let excl_hex = "10000000a0000000010000000400000074657374";
    assert_eq!(
        ServerResponse::decode(strip_len_prefix(&unhex(excl_hex))).unwrap(),
        ServerResponse::ExcludedSearchPhrases {
            phrases: vec!["test".to_string()],
        }
    );
}

#[test]
fn peer_init_messages_round_trip_hex() {
    // PierceFirewall(token = 0x00abcdef) -> len=5, code=0x00(u8), token
    let pf = PeerInitMessage::PierceFirewall { token: 0x00ab_cdef };
    let pf_bytes = pf.encode();
    assert_eq!(to_hex(&pf_bytes), "0500000000efcdab00");
    assert_eq!(
        PeerInitMessage::decode(strip_len_prefix(&pf_bytes)).unwrap(),
        pf
    );

    // PeerInit(username="ab", conn_type="P", token=0) -> len=16 (0x10), code=0x01(u8)
    let pi = PeerInitMessage::PeerInit {
        username: "ab".to_string(),
        conn_type: ConnectionType::Peer,
        token: 0,
    };
    let pi_bytes = pi.encode();
    assert_eq!(
        to_hex(&pi_bytes),
        "1000000001020000006162010000005000000000"
    );
    assert_eq!(
        PeerInitMessage::decode(strip_len_prefix(&pi_bytes)).unwrap(),
        pi
    );
}

#[test]
fn peer_search_and_browse_zlib_round_trip_and_lossless_attributes() {
    let flac_entry = WireFileEntry {
        filename: "@@music\\Boards of Canada\\1998 - Music Has the Right to Children\\01 - Wildlife Analysis.flac".to_string(),
        size: 8_421_376,
        extension: String::new(),
        attrs: AudioAttributes {
            bitrate: None,
            length_secs: Some(76),
            vbr: None,
            sample_rate: Some(44_100),
            bit_depth: Some(16),
        },
    };

    // FileSearchResponse (peer code 9)
    let search_msg = PeerMessage::FileSearchResponse {
        username: "archivist".to_string(),
        token: 777,
        files: vec![flac_entry.clone()],
        slot_free: true,
        upload_speed: 5_242_880,
        queue_length: 0,
        private_files: Vec::new(),
    };
    let encoded = search_msg.encode().unwrap();
    let decoded = PeerMessage::decode(strip_len_prefix(&encoded)).unwrap();
    assert_eq!(decoded, search_msg);

    let records = decoded.into_search_records();
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.username, "archivist");
    assert!(rec.slots);
    assert_eq!(rec.queue, 0);
    assert_eq!(rec.speed, 5_242_880);
    assert_eq!(rec.size, 8_421_376);
    assert_eq!(rec.sample_rate, Some(44_100));
    assert_eq!(rec.bit_depth, Some(16));
    assert_eq!(rec.length_secs, Some(76));
    // Derived lossless PCM bitrate: 44100 * 16 * 2 / 1000 = 1411 kbps
    assert_eq!(rec.bitrate, Some(1411));

    // SharedFileListResponse (peer code 5)
    let folder = SharedFolder {
        path: "@@music\\Boards of Canada".to_string(),
        files: vec![WireFileEntry {
            filename: "01 - Wildlife Analysis.flac".to_string(),
            ..flac_entry
        }],
    };
    let browse_msg = PeerMessage::SharedFileListResponse {
        folders: vec![folder.clone()],
        private_folders: Vec::new(),
    };
    let b_enc = browse_msg.encode().unwrap();
    let b_dec = PeerMessage::decode(strip_len_prefix(&b_enc)).unwrap();
    assert_eq!(b_dec, browse_msg);

    let flat = flatten_shared_folders("archivist", &[folder], true, 2, 100_000);
    assert_eq!(flat.len(), 1);
    assert_eq!(
        flat[0].filename,
        "@@music\\Boards of Canada\\01 - Wildlife Analysis.flac"
    );
    assert_eq!(flat[0].queue, 2);
}

#[test]
fn peer_transfer_queue_and_userinfo_messages_round_trip() {
    let cases = vec![
        PeerMessage::SharedFileListRequest,
        PeerMessage::UserInfoRequest,
        PeerMessage::UserInfoResponse {
            description: "FLAC library".to_string(),
            picture: Some(vec![0x89, 0x50, 0x4e, 0x47]),
            upload_slots: 4,
            queue_length: 1,
            slot_free: true,
            upload_permission: Some(1),
        },
        PeerMessage::FolderContentsRequest {
            token: 12,
            folder: "@@share\\Album".to_string(),
        },
        PeerMessage::FolderContentsResponse {
            token: 12,
            root_folder: "@@share\\Album".to_string(),
            folders: vec![SharedFolder {
                path: "@@share\\Album".to_string(),
                files: Vec::new(),
            }],
        },
        PeerMessage::QueueUpload {
            filename: "@@share\\Track01.flac".to_string(),
        },
        PeerMessage::PlaceInQueueRequest {
            filename: "@@share\\Track01.flac".to_string(),
        },
        PeerMessage::PlaceInQueueResponse {
            filename: "@@share\\Track01.flac".to_string(),
            place: 14,
        },
        PeerMessage::TransferRequest {
            direction: 1,
            token: 9001,
            filename: "@@share\\Track01.flac".to_string(),
            file_size: Some(42_000_000),
        },
        PeerMessage::TransferResponse {
            token: 9001,
            allowed: true,
            file_size: None,
            reason: None,
        },
        PeerMessage::TransferResponse {
            token: 9002,
            allowed: false,
            file_size: None,
            reason: Some("Queued".to_string()),
        },
        PeerMessage::UploadFailed {
            filename: "@@share\\Track01.flac".to_string(),
        },
        PeerMessage::UploadDenied {
            filename: "@@share\\Track01.flac".to_string(),
            reason: "File not shared.".to_string(),
        },
    ];

    for msg in cases {
        let frame = msg.encode().unwrap();
        let decoded = PeerMessage::decode(strip_len_prefix(&frame)).unwrap();
        assert_eq!(decoded, msg);
    }
}

#[test]
fn soulseek_ns_2gib_bug_workaround_and_latin1_fallback() {
    // Soulseek NS corrupts the upper 32 bits of >2 GiB file sizes with 0xffffffff:
    // Lower 32 bits = 3_000_000_000 (0xb2d05e00), upper 32 bits = 0xffffffff.
    let mut inner = WireWriter::new();
    inner.write_str("legacy_peer");
    inner.write_u32(55);
    inner.write_u32(1); // 1 file
    inner.write_u8(1);
    // Latin-1 filename bytes: "Caf\xe9.flac" (0xe9 is invalid standalone UTF-8)
    inner.write_bytes_prefixed(b"Caf\xe9.flac");
    inner.write_raw(&unhex("005ed0b2ffffffff"));
    inner.write_str("");
    inner.write_u32(0); // 0 attrs
    inner.write_bool(true);
    inner.write_u32(10_000);
    inner.write_u32(0);

    let compressed = zlib_compress(&inner.into_inner()).unwrap();
    let mut outer = WireWriter::new();
    outer.write_raw(&compressed);
    let frame = outer.into_u32_frame(9);

    let decoded = PeerMessage::decode(strip_len_prefix(&frame)).unwrap();
    let recs = decoded.into_search_records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].filename, "Café.flac");
    assert_eq!(recs[0].size, 3_000_000_000);
}

#[test]
fn file_connection_wire_and_distributed_messages() {
    let init = encode_file_transfer_init(0xdead_beef);
    assert_eq!(to_hex(&init), "efbeadde");
    assert_eq!(decode_file_transfer_init(&init).unwrap(), 0xdead_beef);

    let off = encode_file_offset(0x0000_0001_0203_0405);
    assert_eq!(to_hex(&off), "0504030201000000");
    assert_eq!(decode_file_offset(&off).unwrap(), 0x0000_0001_0203_0405);

    for dmsg in [
        DistributedMessage::Ping,
        DistributedMessage::Search {
            identifier: 49,
            username: "seeker".to_string(),
            token: 321,
            query: "autechre".to_string(),
        },
        DistributedMessage::BranchLevel { level: 2 },
        DistributedMessage::BranchRoot {
            username: "supernode".to_string(),
        },
    ] {
        let enc = dmsg.encode();
        let dec = DistributedMessage::decode(strip_len_prefix(&enc)).unwrap();
        assert_eq!(dec, dmsg);
    }
}

#[test]
fn hostile_frames_fail_safely_without_panicking() {
    let mut dec = FrameDecoder::new();
    // Claim 100 MiB frame (> MAX_FRAME_BYTES 32 MiB)
    dec.push(&unhex("00004006"));
    assert!(matches!(
        dec.next_frame(),
        Err(ProtoError::FrameTooLarge(_))
    ));

    // Claim 999_999 privileged users in an 8-byte payload
    let bogus = unhex("450000003f420f00");
    assert!(ServerResponse::decode(&bogus).is_err());
}
