//! C5: Windows compile-only stub backend.
//!
//! Windows is **not supported yet** (platform support table in README): this
//! module exists so the crate compiles for `x86_64-pc-windows-gnu` and so the
//! platform selector has an explicit target for it. Every operation refuses
//! ([`UnsupportedBackend`]); `capabilities()` are all `false`. No code path
//! here can touch a disk.

use crate::backend::unsupported::UnsupportedBackend;

/// Windows stub: refuses every operation (`Unsupported`), capabilities off.
pub type WindowsBackend = UnsupportedBackend;

/// The Windows backend instance used by [`crate::backend::current_backend`].
pub fn windows_backend() -> WindowsBackend {
    UnsupportedBackend::new("windows", "windows")
}
