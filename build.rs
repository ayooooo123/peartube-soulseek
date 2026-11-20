use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("soulseek");
    println!("cargo:rerun-if-changed=soulseek/soulseek.h");
    println!("cargo:include={}", include_dir.display());
}
