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
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("windows-facts") => run_windows_facts(),
        Some("windows-volumes") => run_windows_volumes(),
        Some("windows-validate") => run_windows_validate(&args),
        Some("sanitize") => run_windows_sanitize(&args),
        _ => {
            eprintln!("zt_engine: this platform is not supported (only Linux has a real backend)");
            eprintln!(
                "Windows read-only commands: windows-facts | windows-volumes | \
                 windows-validate <letter> [--confirm <token>] [--same-disk-confirm <token>]"
            );
            eprintln!(
                "Windows simulated sanitize: sanitize <letter> <method> <token> <serial> \
                 --dry-run [--same-disk-confirm <token>]"
            );
            std::process::exit(2);
        }
    }
}

/// Value of `flag` (`--flag value`), or `None` when absent/empty.
#[cfg(target_os = "windows")]
fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|pos| args.get(pos + 1))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Step 1.4a: read-only live validation. One `WINDOWS_VALIDATE:{json}` line;
/// exit 0 only when the full guard validation (including the typed
/// confirmation) passes, 3 for every typed refusal, 2 for usage/JSON errors.
#[cfg(target_os = "windows")]
fn run_windows_validate(args: &[String]) {
    let selector = match args.get(2) {
        Some(value) if !value.trim().is_empty() => value.clone(),
        _ => {
            eprintln!(
                "Usage: zt_engine windows-validate <drive-letter|volume-guid> \
                 [--confirm \"<token>\"] [--same-disk-confirm \"<token>\"]"
            );
            std::process::exit(2);
        }
    };
    let confirm = arg_value(args, "--confirm");
    let same_disk = arg_value(args, "--same-disk-confirm");

    let backend = zt_engine::backend::current_backend();
    let outcome = zt_engine::windows_validate::run_validation(
        backend.as_ref(),
        &selector,
        confirm.as_deref(),
        same_disk.as_deref(),
    );
    match serde_json::to_string(&outcome.report) {
        Ok(json) => println!("WINDOWS_VALIDATE:{}", json),
        Err(e) => {
            eprintln!("JSON serialization error: {}", e);
            std::process::exit(2);
        }
    }
    std::process::exit(outcome.exit_code);
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn run_windows_validate(_args: &[String]) {
    eprintln!("zt_engine: windows-validate is only available on Windows");
    std::process::exit(2);
}

/// Step 1.4a: Windows `sanitize --dry-run`. The positional arguments match
/// the Linux CLI (`<device> <method> <token> <serial>`), but a Windows
/// volume target is pinned by volume GUID + disk/partition identity, so the
/// serial argument is accepted and ignored. Real writes land in Step 1.4b.
#[cfg(target_os = "windows")]
fn run_windows_sanitize(args: &[String]) {
    if args.len() < 6 {
        eprintln!(
            "Usage: zt_engine sanitize <drive-letter> <method> <confirmation_token> \
             <device_serial> --dry-run [--same-disk-confirm \"<token>\"]"
        );
        std::process::exit(1);
    }
    let selector = args[2].clone();
    let method = args[3].clone();
    let token = args[4].clone();
    let _serial = args[5].clone();
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let same_disk = arg_value(args, "--same-disk-confirm");

    if !dry_run {
        eprintln!(
            "Refusing operation: real Windows volume writes are not enabled in this build \
             (Step 1.4b). Pass --dry-run for the full guard validation without writing."
        );
        std::process::exit(3);
    }

    let cancel_flag = match zt_engine::platform_cancel::install_console_handler() {
        Ok(flag) => flag,
        Err(e) => {
            eprintln!(
                "Refusing operation: cannot install the Windows cancel handler: {}",
                e
            );
            std::process::exit(3);
        }
    };

    let backend = zt_engine::backend::current_backend();
    match zt_engine::windows_sanitize::windows_volume_dry_run(
        backend.as_ref(),
        &selector,
        &method,
        &token,
        same_disk.as_deref(),
        cancel_flag,
    ) {
        Ok(outcome) => {
            for event in &outcome.events {
                if let Ok(json) = serde_json::to_string(event) {
                    println!("PROGRESS:{}", json);
                }
            }
            if let Ok(json) = serde_json::to_string(&outcome.report) {
                println!("REPORT:{}", json);
            }
            std::process::exit(zt_engine::wipe_core::report_exit_code(&outcome.report));
        }
        Err(err) => {
            eprintln!("Error executing sanitize: {:?}", err);
            std::process::exit(3);
        }
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn run_windows_sanitize(_args: &[String]) {
    eprintln!("zt_engine: sanitize is only available on Linux and Windows");
    std::process::exit(2);
}

/// Step 1.2: read-only Windows volume enumeration. Prints one line
/// `WINDOWS_VOLUMES:{json}` (a JSON array of `WindowsVolumeFacts`).
#[cfg(target_os = "windows")]
fn run_windows_volumes() {
    let backend = zt_engine::backend::current_backend();
    match backend.enumerate_volumes() {
        Ok(volumes) => match serde_json::to_string(&volumes) {
            Ok(json) => println!("WINDOWS_VOLUMES:{}", json),
            Err(e) => {
                eprintln!("JSON serialization error: {}", e);
                std::process::exit(2);
            }
        },
        Err(e) => {
            eprintln!("Error enumerating volumes: {}", e);
            std::process::exit(2);
        }
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "windows")))]
fn run_windows_volumes() {
    eprintln!("zt_engine: windows-volumes is only available on Windows");
    std::process::exit(2);
}

#[cfg(not(target_os = "linux"))]
fn run_windows_facts() {
    use std::collections::HashMap;
    use zt_engine::backend::WindowsBootFacts;

    let backend = zt_engine::backend::current_backend();
    let devices = match backend.enumerate_devices() {
        Ok(devs) => devs,
        Err(e) => {
            eprintln!("Error enumerating devices: {}", e);
            std::process::exit(1);
        }
    };

    let mut partitions = HashMap::new();
    for dev in &devices {
        match backend.enumerate_partitions(&dev.name) {
            Ok(parts) => {
                partitions.insert(dev.name.clone(), parts);
            }
            Err(e) => {
                eprintln!("Error enumerating partitions for {}: {}", dev.name, e);
                std::process::exit(1);
            }
        }
    }

    // D-a piece 2: boot/system facts and the shared per-disk refusal reason.
    let boot_facts = match backend.windows_boot_facts() {
        Ok(facts) => facts,
        Err(e) => {
            eprintln!("Error reading Windows boot facts: {}", e);
            std::process::exit(1);
        }
    };

    #[derive(serde::Serialize)]
    struct DiskRefusal {
        disk_number: u32,
        device: String,
        refusal_reason: Option<String>,
    }

    let mut disk_refusals = Vec::new();
    if let Some(facts) = &boot_facts {
        for dev in &devices {
            let Some(disk_number) = zt_engine::guard::windows_disk_number(&dev.name) else {
                continue;
            };
            disk_refusals.push(DiskRefusal {
                disk_number,
                device: dev.name.clone(),
                refusal_reason: zt_engine::guard::windows_boot_facts_disk_refusal(
                    facts,
                    disk_number,
                ),
            });
        }
        disk_refusals.sort_by_key(|r| r.disk_number);
    }
    let elevation_refusal = boot_facts
        .as_ref()
        .and_then(zt_engine::guard::windows_elevation_refusal);

    #[derive(serde::Serialize)]
    struct WindowsFactsOutput<'a> {
        devices: &'a [zt_engine::backend::DeviceInfo],
        partitions: &'a HashMap<String, Vec<zt_engine::backend::PartitionFacts>>,
        boot_facts: Option<&'a WindowsBootFacts>,
        elevation_refusal: Option<String>,
        disk_refusals: &'a [DiskRefusal],
    }

    let output = WindowsFactsOutput {
        devices: &devices,
        partitions: &partitions,
        boot_facts: boot_facts.as_ref(),
        elevation_refusal,
        disk_refusals: &disk_refusals,
    };

    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("JSON serialization error: {}", e);
            std::process::exit(1);
        }
    }
}
