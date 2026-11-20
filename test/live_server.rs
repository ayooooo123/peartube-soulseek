//! Live Soulseek server integration test (`#[ignore]` by default so `cargo test` runs 100% offline).
//!
//! Run manually only with a real pre-existing Soulseek account:
//! `SOULSEEK_USER=... SOULSEEK_PASS=... cargo test --test live_server -- --ignored`

use peartube_soulseek::client::SoulseekClient;

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

    let client = SoulseekClient::new();
    let st = client
        .login(&server, port, &user, &pass)
        .expect("live Soulseek login failed");
    assert!(st.connected);
    assert!(st.logged_in);

    let results = client
        .search("flac", 4_000)
        .expect("live Soulseek search failed");
    eprintln!("live search returned {} file records", results.len());

    client.close();
}
