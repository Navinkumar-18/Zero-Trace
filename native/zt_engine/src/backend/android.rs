//! C5: Android compile-only stub backend.
//!
//! Android is **not supported yet** (platform support table in README): this
//! module exists so the crate compiles for an Android target and so the
//! platform selector has an explicit target for it. Every operation refuses
//! ([`UnsupportedBackend`]); `capabilities()` are all `false`. No code path
//! here can touch a disk.

use crate::backend::unsupported::UnsupportedBackend;

/// Android stub: refuses every operation (`Unsupported`), capabilities off.
pub type AndroidBackend = UnsupportedBackend;

/// The Android backend instance used by [`crate::backend::current_backend`].
pub fn android_backend() -> AndroidBackend {
    UnsupportedBackend::new("android", "android")
}
