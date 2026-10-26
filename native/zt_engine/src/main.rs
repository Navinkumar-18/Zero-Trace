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

    #[derive(serde::Serialize)]
    struct WindowsFactsOutput<'a> {
        devices: &'a [zt_engine::backend::DeviceInfo],
        partitions: &'a HashMap<String, Vec<zt_engine::backend::PartitionFacts>>,
    }

    let output = WindowsFactsOutput {
        devices: &devices,
        partitions: &partitions,
    };

    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("JSON serialization error: {}", e);
            std::process::exit(1);
        }
    }
}
