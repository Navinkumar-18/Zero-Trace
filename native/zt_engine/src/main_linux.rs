use std::env;
use std::path::Path;
use std::process;
use tokio::sync::mpsc;
use zt_engine::execute::{
    ata_sanitize_validated, ata_secure_erase_validated, discard_erase, discard_erase_partition,
    emmc_sanitize_validated, nvme_sanitize_validated, opal_revert_validated, software_overwrite,
    software_overwrite_partition, validate_whole_disk_flow_target_ctx, AtaSanitizeAction,
    EngineMethod, FsContext, OverwritePattern, PartitionTargetParams, ProgressEvent,
    SanitizeAction,
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

pub async fn run() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: zt_engine <subcommand> [args]");
        eprintln!("Subcommands: sanitize, verify, detect, partitions, probe-windows");
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
                        "Refusing operation: method '{}' is not allowed in partition mode. Partition mode only allows overwrite methods (overwrite-zero, overwrite-random, overwrite-3pass) and discard",
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

                match engine_method {
                    // A6: discard targets the partition range natively — no overwrite pattern.
                    EngineMethod::Discard => {
                        discard_erase_partition(device, token, serial, &params, dry_run, tx).await
                    }
                    _ => {
                        let (pattern, passes) = match engine_method {
                            EngineMethod::OverwriteZero => (OverwritePattern::Zeros, 1u8),
                            EngineMethod::OverwriteRandom => (OverwritePattern::Random, 1u8),
                            EngineMethod::Overwrite3Pass => (OverwritePattern::MultiPass3, 3u8),
                            _ => unreachable!(),
                        };

                        software_overwrite_partition(device, passes, pattern, token, serial, &params, dry_run, tx).await
                    }
                }
            } else {
                // P2: firmware methods take a guard-minted `ValidatedTarget`,
                // never a bare path. Mint once here in the historic check
                // order (boot-disk protection → confirmation token →
                // identity pinning); every destructive tool re-validates the
                // device identity immediately before it runs.
                if engine_method.is_firmware() {
                    let target = match validate_whole_disk_flow_target_ctx(
                        device,
                        token,
                        serial,
                        dry_run,
                        &FsContext::default(),
                    ) {
                        Ok(target) => target,
                        Err(err) => {
                            eprintln!("Error executing sanitize: {:?}", err);
                            process::exit(3);
                        }
                    };

                    match engine_method {
                        EngineMethod::AtaSecureErase => {
                            ata_secure_erase_validated(&target, false, dry_run, tx).await
                        }
                        EngineMethod::AtaEnhancedSecureErase => {
                            ata_secure_erase_validated(&target, true, dry_run, tx).await
                        }
                        EngineMethod::AtaSanitizeBlock => {
                            ata_sanitize_validated(&target, AtaSanitizeAction::BlockErase, dry_run, tx).await
                        }
                        EngineMethod::AtaSanitizeCrypto => {
                            ata_sanitize_validated(&target, AtaSanitizeAction::CryptoScramble, dry_run, tx).await
                        }
                        EngineMethod::NvmeSanitizeBlock => {
                            nvme_sanitize_validated(&target, SanitizeAction::BlockErase, dry_run, tx).await
                        }
                        EngineMethod::NvmeSanitizeCrypto => {
                            nvme_sanitize_validated(&target, SanitizeAction::CryptoErase, dry_run, tx).await
                        }
                        EngineMethod::OpalRevert => {
                            opal_revert_validated(&target, psid, dry_run, tx).await
                        }
                        EngineMethod::EmmcSanitize => {
                            emmc_sanitize_validated(&target, dry_run, tx).await
                        }
                        _ => unreachable!("is_firmware() matched above"),
                    }
                } else {
                    match engine_method {
                        // A6: removable-media discard (whole device)
                        EngineMethod::Discard => {
                            discard_erase(device, token, serial, dry_run, tx).await
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
                        _ => unreachable!("firmware methods handled above"),
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
            // C5: additive fields — "platform" and the backend's capability
            // flags ride alongside the historic payload; the Dart layer
            // ignores unknown fields, so every existing key is unchanged.
            let backend = zt_engine::backend::current_backend();
            let mut value = serde_json::to_value(&capabilities).unwrap_or(serde_json::Value::Null);
            if let serde_json::Value::Object(ref mut map) = value {
                map.insert(
                    "platform".to_string(),
                    serde_json::Value::String(backend.platform().to_string()),
                );
                map.insert(
                    "capabilities".to_string(),
                    serde_json::to_value(backend.capabilities()).unwrap_or(serde_json::Value::Null),
                );
            }
            println!("DETECT_REPORT:{}", value);
        }
        "partitions" => {
            // Usage: zt_engine partitions <disk>  (A2 enumeration)
            if args.len() < 3 {
                eprintln!("Usage: zt_engine partitions <disk>");
                process::exit(1);
            }
            let disk = &args[2];
            match zt_engine::partitions::enumerate_partitions_ctx(disk, &zt_engine::execute::FsContext::default()) {
                Ok(report) => {
                    if let Ok(json) = serde_json::to_string(&report) {
                        println!("PARTITIONS_REPORT:{}", json);
                    }
                }
                Err(e) => {
                    eprintln!("Error enumerating partitions: {}", e);
                    process::exit(1);
                }
            }
        }
        "probe-windows" => {
            // Usage: zt_engine probe-windows <device>  (B1 read-only probe)
            if args.len() < 3 {
                eprintln!("Usage: zt_engine probe-windows <device>");
                process::exit(1);
            }
            let device = &args[2];
            let probe = zt_engine::partitions::probe_windows_volume(device);
            if let Ok(json) = serde_json::to_string(&probe) {
                println!("WINDOWS_PROBE:{}", json);
            }
        }
        _ => {
            eprintln!("Unknown subcommand: {}", subcommand);
            process::exit(1);
        }
    }
}
