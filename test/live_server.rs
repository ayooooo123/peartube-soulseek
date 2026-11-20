//! Live Soulseek server integration test (`#[ignore]` by default so `cargo test` runs 100% offline).
//!
//! Run manually only with a real pre-existing Soulseek account:
//! `SOULSEEK_USER=... SOULSEEK_PASS=... cargo test --test live_server -- --ignored`

use std::sync::Arc;

use parking_lot::Mutex;
use peartube_soulseek::client::{LogEvent, SoulseekClient};

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
