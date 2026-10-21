//! Zero Trace 2.0 — engine CLI entry point.
//!
//! Phase C: the real implementation is Linux-only (the sole supported
//! backend; see `README.md` platform support table). Other targets get a
//! compile-only stub that refuses to run — they can never touch a disk.

#[cfg(target_os = "linux")]
#[path = "main_linux.rs"]
mod main_linux;

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    main_linux::run().await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("zt_engine: this platform is not supported (only Linux has a real backend)");
    std::process::exit(2);
}
