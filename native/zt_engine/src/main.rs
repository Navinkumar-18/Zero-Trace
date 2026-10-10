use std::env;
use std::path::Path;
use std::process;
use tokio::sync::mpsc;
use zt_engine::execute::{
    ata_sanitize, ata_secure_erase, emmc_sanitize, nvme_sanitize, opal_revert, software_overwrite,
    software_overwrite_partition, AtaSanitizeAction, EngineMethod, OverwritePattern, PartitionTargetParams,
    ProgressEvent, SanitizeAction,
};
use zt_engine::verify::{verify_device, verify_device_scoped};
use zt_engine::detect::probe_device;

fn is_partition_device(device: &str) -> bool {
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    let sys_part = format!("/sys/class/block/{}/partition", name);
    if Path::new(&sys_part).exists() {
        return true;
    }
    // Heuristic: check if name ends in digit after letters or 'p'
    if name.starts_with("nvme") || name.starts_with("mmcblk") || name.starts_with("loop") {
        if let Some(pos) = name.rfind('p') {
            let suffix = &name[pos + 1..];
            return !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit());
        }
    } else {
        let trimmed = name.trim_end_matches(|c: char| c.is_ascii_digit());
        if !trimmed.is_empty() && trimmed != name {
            return true;
        }
    }
    false
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: zt_engine <subcommand> [args]");
        eprintln!("Subcommands: sanitize, verify, detect");
        process::exit(1);
    }

    let subcommand = args[1].as_str();
    match subcommand {
        "sanitize" => {
            // Usage: zt_engine sanitize <device> <method> <confirmation_token> <device_serial> [--dry-run] [--psid <psid>] [--mode <whole-disk|partition>] ...
            if args.len() < 6 {
                eprintln!("Usage: zt_engine sanitize <device> <method> <confirmation_token> <device_serial> [--dry-run] [--psid <psid>] [--mode <partition>]");
                process::exit(1);
            }
            let device = &args[2];
            let method_raw = &args[3];
            let token = &args[4];
            let serial = &args[5];

            let engine_method = EngineMethod::from_str_opt(method_raw).unwrap_or_else(|| {
                eprintln!("Unknown method: {}", method_raw);
                process::exit(1);
            });

            let dry_run = args.iter().any(|arg| arg == "--dry-run");
            let psid = args.iter()
                .position(|arg| arg == "--psid")
                .and_then(|pos| args.get(pos + 1).map(|s| s.as_str()));

            let mode = args.iter()
                .position(|arg| arg == "--mode")
                .and_then(|pos| args.get(pos + 1).map(|s| s.as_str()));

            let is_part_mode = mode == Some("partition");
            let target_looks_like_part = is_partition_device(device);

            // Fail-closed CLI requirement: partition target without --mode partition refuses
            if target_looks_like_part && !is_part_mode {
                eprintln!(
                    "Refusing operation: target '{}' appears to be a partition, but --mode partition was not specified (fail closed)",
                    device
                );
                process::exit(1);
            }

            let (tx, mut rx) = mpsc::channel::<ProgressEvent>(100);

            // Spawn progress handler to print JSON lines to stdout in real-time
            let progress_handle = tokio::spawn(async move {
                use std::io::Write;
                let stdout = std::io::stdout();
                while let Some(event) = rx.recv().await {
                    if let Ok(json) = serde_json::to_string(&event) {
                        let mut handle = stdout.lock();
                        let _ = writeln!(handle, "PROGRESS:{}", json);
                        let _ = handle.flush();
                    }
                }
            });

            let res = if is_part_mode {
                // Fail-closed: partition mode requires allowlisted method
                if !engine_method.is_allowed_in_partition_mode() {
                    eprintln!(
                        "Refusing operation: method '{}' is not allowed in partition mode. Partition mode only allows overwrite methods (overwrite-zero, overwrite-random, overwrite-3pass)",
                        engine_method.as_str()
                    );
                    process::exit(1);
                }

                // Fail-closed: partition mode requires all expected flags
                let part_num = args.iter()
                    .position(|arg| arg == "--expected-part-num")
                    .and_then(|pos| args.get(pos + 1).and_then(|s| s.parse::<u32>().ok()));
                let start_sector = args.iter()
                    .position(|arg| arg == "--expected-start-sector")
                    .and_then(|pos| args.get(pos + 1).and_then(|s| s.parse::<u64>().ok()));
                let size_sectors = args.iter()
                    .position(|arg| arg == "--expected-size-sectors")
                    .and_then(|pos| args.get(pos + 1).and_then(|s| s.parse::<u64>().ok()));
                let table_fingerprint = args.iter()
                    .position(|arg| arg == "--expected-table-fingerprint")
                    .and_then(|pos| args.get(pos + 1).cloned());
                let partuuid = args.iter()
                    .position(|arg| arg == "--expected-partuuid")
                    .and_then(|pos| args.get(pos + 1).cloned());

                if part_num.is_none() || start_sector.is_none() || size_sectors.is_none() || table_fingerprint.is_none() {
                    eprintln!(
                        "Partition mode requires --expected-part-num, --expected-start-sector, --expected-size-sectors, and --expected-table-fingerprint"
                    );
                    process::exit(1);
                }

                let params = PartitionTargetParams {
                    expected_partition_num: part_num.unwrap(),
                    expected_start_sector: start_sector.unwrap(),
                    expected_size_sectors: size_sectors.unwrap(),
                    expected_partuuid: partuuid,
                    expected_table_fingerprint: table_fingerprint.unwrap(),
                };

                let (pattern, passes) = match engine_method {
                    EngineMethod::OverwriteZero => (OverwritePattern::Zeros, 1u8),
                    EngineMethod::OverwriteRandom => (OverwritePattern::Random, 1u8),
                    EngineMethod::Overwrite3Pass => (OverwritePattern::MultiPass3, 3u8),
                    _ => unreachable!(),
                };

                software_overwrite_partition(device, passes, pattern, token, serial, &params, dry_run, tx).await
            } else {
                match engine_method {
                    EngineMethod::AtaSecureErase => {
                        ata_secure_erase(device, false, token, serial, dry_run, tx).await
                    }
                    EngineMethod::AtaEnhancedSecureErase => {
                        ata_secure_erase(device, true, token, serial, dry_run, tx).await
                    }
                    EngineMethod::AtaSanitizeBlock => {
                        ata_sanitize(device, AtaSanitizeAction::BlockErase, token, serial, dry_run, tx).await
                    }
                    EngineMethod::AtaSanitizeCrypto => {
                        ata_sanitize(device, AtaSanitizeAction::CryptoScramble, token, serial, dry_run, tx).await
                    }
                    EngineMethod::NvmeSanitizeBlock => {
                        nvme_sanitize(device, SanitizeAction::BlockErase, token, serial, dry_run, tx).await
                    }
                    EngineMethod::NvmeSanitizeCrypto => {
                        nvme_sanitize(device, SanitizeAction::CryptoErase, token, serial, dry_run, tx).await
                    }
                    EngineMethod::OpalRevert => {
                        opal_revert(device, psid, token, serial, dry_run, tx).await
                    }
                    EngineMethod::EmmcSanitize => {
                        emmc_sanitize(device, token, serial, dry_run, tx).await
                    }
                    EngineMethod::OverwriteZero => {
                        software_overwrite(device, 1, OverwritePattern::Zeros, token, serial, dry_run, tx).await
                    }
                    EngineMethod::OverwriteRandom => {
                        software_overwrite(device, 1, OverwritePattern::Random, token, serial, dry_run, tx).await
                    }
                    EngineMethod::Overwrite3Pass => {
                        software_overwrite(device, 3, OverwritePattern::MultiPass3, token, serial, dry_run, tx).await
                    }
                }
            };

            // Wait for progress events to finish sending and printing
            let _ = progress_handle.await;

            match res {
                Ok(report) => {
                    if let Ok(json) = serde_json::to_string(&report) {
                        println!("REPORT:{}", json);
                    }
                    if !report.success {
                        process::exit(2);
                    }
                }
                Err(err) => {
                    eprintln!("Error executing sanitize: {:?}", err);
                    process::exit(3);
                }
            }
        }
        "verify" => {
            // Usage: zt_engine verify <device> <size> <serial> <method> <sample_count> <expect_zeros> [--device-size <total_device_size>]
            if args.len() < 8 {
                eprintln!("Usage: zt_engine verify <device> <size> <serial> <method> <sample_count> <expect_zeros> [--device-size <total_device_size>]");
                process::exit(1);
            }
            let device = &args[2];
            let size: u64 = args[3].parse().unwrap_or_else(|_| {
                eprintln!("Invalid size");
                process::exit(1);
            });
            let serial = &args[4];
            let method_raw = &args[5];
            let engine_method = EngineMethod::from_str_opt(method_raw).unwrap_or_else(|| {
                eprintln!("Unknown method: {}", method_raw);
                process::exit(1);
            });
            let sample_count: u32 = args[6].parse().unwrap_or_else(|_| {
                eprintln!("Invalid sample count");
                process::exit(1);
            });
            let expect_zeros: bool = args[7].parse().unwrap_or_else(|_| {
                eprintln!("Invalid expect_zeros (must be true/false)");
                process::exit(1);
            });
            let total_device_size = args.iter()
                .position(|arg| arg == "--device-size" || arg == "--total-device-size")
                .and_then(|pos| args.get(pos + 1).and_then(|s| s.parse::<u64>().ok()));

            let res = if let Some(total_size) = total_device_size {
                verify_device_scoped(device, size, total_size, serial, engine_method.as_str(), Some(sample_count), expect_zeros, None)
            } else {
                verify_device(device, size, serial, engine_method.as_str(), Some(sample_count), expect_zeros)
            };

            match res {
                Ok(report) => {
                    if let Ok(json) = serde_json::to_string(&report) {
                        println!("VERIFY_REPORT:{}", json);
                    }
                    if !report.pass {
                        process::exit(2);
                    }
                }
                Err(err) => {
                    eprintln!("Error executing verify: {:?}", err);
                    process::exit(3);
                }
            }
        }
        "detect" => {
            // Usage: zt_engine detect <device>
            if args.len() < 3 {
                eprintln!("Usage: zt_engine detect <device>");
                process::exit(1);
            }
            let device = &args[2];
            let capabilities = probe_device(device);
            if let Ok(json) = serde_json::to_string(&capabilities) {
                println!("DETECT_REPORT:{}", json);
            }
        }
        _ => {
            eprintln!("Unknown subcommand: {}", subcommand);
            process::exit(1);
        }
    }
}
