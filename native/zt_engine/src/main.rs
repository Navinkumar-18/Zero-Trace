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
    if args.len() >= 2 && args[1] == "windows-facts" {
        run_windows_facts();
    } else {
        eprintln!("zt_engine: this platform is not supported (only Linux has a real backend)");
        std::process::exit(2);
    }
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
