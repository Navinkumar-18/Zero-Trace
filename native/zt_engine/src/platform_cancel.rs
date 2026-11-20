//! Step 1.4a: Windows console-control cancellation.
//!
//! `SetConsoleCtrlHandler` receives Ctrl+C, Ctrl+Break, window close, logoff
//! and shutdown. The handler does exactly one thing: store `true` into the
//! shared cancel flag. The wipe loop observes that flag, writes its
//! checkpoint and returns the same cancelled report as Linux
//! (`success: false`, `exit_code: 130`); the CLI then exits 130.
//!
//! The handler never touches a device and never panics (a panic across the
//! Win32 callback boundary would abort the process). The pure parts
//! ([`is_cancel_ctrl_event`], [`handle_ctrl_event`]) are cross-platform so
//! the cancel behaviour is unit-tested on every host without hardware.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// `CTRL_C_EVENT` (WinCon.h).
pub const CTRL_C_EVENT: u32 = 0;
/// `CTRL_BREAK_EVENT` (WinCon.h).
pub const CTRL_BREAK_EVENT: u32 = 1;
/// `CTRL_CLOSE_EVENT`: the console window is closing.
pub const CTRL_CLOSE_EVENT: u32 = 2;
/// `CTRL_LOGOFF_EVENT`.
pub const CTRL_LOGOFF_EVENT: u32 = 5;
/// `CTRL_SHUTDOWN_EVENT`.
pub const CTRL_SHUTDOWN_EVENT: u32 = 6;

static CANCEL_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// The process-wide cancel flag, created once so the console handler and the
/// wipe loop share the same `Arc`.
pub fn cancel_flag() -> Arc<AtomicBool> {
    CANCEL_FLAG
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// True for the console events that request a graceful cancellation.
pub fn is_cancel_ctrl_event(kind: u32) -> bool {
    matches!(
        kind,
        CTRL_C_EVENT
            | CTRL_BREAK_EVENT
            | CTRL_CLOSE_EVENT
            | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT
    )
}

/// Pure handler body: stores the flag and reports whether the event was
/// consumed as a cancellation. Unknown events are left to the next handler
/// (`false`), so they keep their default behaviour.
pub fn handle_ctrl_event(kind: u32) -> bool {
    if !is_cancel_ctrl_event(kind) {
        return false;
    }
    cancel_flag().store(true, Ordering::SeqCst);
    true
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn console_ctrl_handler(kind: u32) -> i32 {
    if handle_ctrl_event(kind) {
        1
    } else {
        0
    }
}

/// Installs the console handler and returns the shared cancel flag.
/// Windows-only; other targets report an error so a caller can fail closed
/// instead of running an uncancellable wipe.
#[cfg(target_os = "windows")]
pub fn install_console_handler() -> Result<Arc<AtomicBool>, String> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    let ok = unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), 1) };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "SetConsoleCtrlHandler failed (Win32 error {})",
            code
        ));
    }
    Ok(cancel_flag())
}

#[cfg(not(target_os = "windows"))]
pub fn install_console_handler() -> Result<Arc<AtomicBool>, String> {
    Err("console control handler is Windows-only".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_events_are_exactly_the_graceful_console_events() {
        for kind in [
            CTRL_C_EVENT,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT,
            CTRL_SHUTDOWN_EVENT,
        ] {
            assert!(is_cancel_ctrl_event(kind), "event {} must cancel", kind);
        }
        for kind in [3u32, 4, 7, 42, u32::MAX] {
            assert!(
                !is_cancel_ctrl_event(kind),
                "event {} must not cancel",
                kind
            );
        }
    }

    #[test]
    fn handler_sets_the_shared_flag_and_ignores_unknown_events() {
        let flag = cancel_flag();
        flag.store(false, Ordering::SeqCst);

        assert!(handle_ctrl_event(CTRL_C_EVENT));
        assert!(flag.load(Ordering::SeqCst), "Ctrl+C must set the flag");

        flag.store(false, Ordering::SeqCst);
        assert!(handle_ctrl_event(CTRL_BREAK_EVENT));
        assert!(flag.load(Ordering::SeqCst), "Ctrl+Break must set the flag");

        flag.store(false, Ordering::SeqCst);
        assert!(handle_ctrl_event(CTRL_CLOSE_EVENT));
        assert!(flag.load(Ordering::SeqCst), "close must set the flag");

        flag.store(false, Ordering::SeqCst);
        assert!(!handle_ctrl_event(999));
        assert!(
            !flag.load(Ordering::SeqCst),
            "an unknown event must not request cancellation"
        );
    }
}
