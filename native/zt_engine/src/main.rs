use std::env;
use std::process;
use tokio::sync::mpsc;
use zt_engine::execute::{
    ata_sanitize, ata_secure_erase, emmc_sanitize, nvme_sanitize, opal_revert, software_overwrite,
    AtaSanitizeAction, OverwritePattern, ProgressEvent, SanitizeAction,
};
use zt_engine::verify::verify_device;
use zt_engine::detect::probe_device;

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
            // Usage: zt_engine sanitize <device> <method> <confirmation_token> <device_serial> [--dry-run] [--psid <psid>]
            if args.len() < 6 {
                eprintln!("Usage: zt_engine sanitize <device> <method> <confirmation_token> <device_serial> [--dry-run] [--psid <psid>]");
                process::exit(1);
            }
            let device = &args[2];
            let method = &args[3];
            let token = &args[4];
            let serial = &args[5];

            let dry_run = args.iter().any(|arg| arg == "--dry-run");
            let psid = args.iter()
                .position(|arg| arg == "--psid")
                .and_then(|pos| args.get(pos + 1).map(|s| s.as_str()));

            let (tx, mut rx) = mpsc::channel::<ProgressEvent>(100);

            // Spawn progress handler to print JSON lines to stdout in real-time
            let progress_handle = tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    if let Ok(json) = serde_json::to_string(&event) {
                        println!("PROGRESS:{}", json);
                    }
                }
            });

            let res = match method.as_str() {
                "ata-secure-erase" => {
                    ata_secure_erase(device, false, token, serial, dry_run, tx).await
                }
                "ata-enhanced-secure-erase" => {
                    ata_secure_erase(device, true, token, serial, dry_run, tx).await
                }
                "ata-sanitize-block" => {
                    ata_sanitize(device, AtaSanitizeAction::BlockErase, token, serial, dry_run, tx).await
                }
                "ata-sanitize-crypto" => {
                    ata_sanitize(device, AtaSanitizeAction::CryptoScramble, token, serial, dry_run, tx).await
                }
                "nvme-sanitize-block" => {
                    nvme_sanitize(device, SanitizeAction::BlockErase, token, serial, dry_run, tx).await
                }
                "nvme-sanitize-crypto" => {
                    nvme_sanitize(device, SanitizeAction::CryptoErase, token, serial, dry_run, tx).await
                }
                "opal-revert" => {
                    opal_revert(device, psid, token, serial, dry_run, tx).await
                }
                "emmc-sanitize" => {
                    emmc_sanitize(device, token, serial, dry_run, tx).await
                }
                "overwrite-zero" => {
                    software_overwrite(device, 1, OverwritePattern::Zeros, token, serial, dry_run, tx).await
                }
                "overwrite-random" => {
                    software_overwrite(device, 1, OverwritePattern::Random, token, serial, dry_run, tx).await
                }
                "overwrite-3pass" => {
                    software_overwrite(device, 3, OverwritePattern::NistLegacy3Pass, token, serial, dry_run, tx).await
                }
                _ => {
                    eprintln!("Unknown method: {}", method);
                    process::exit(1);
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
            // Usage: zt_engine verify <device> <size> <serial> <method> <sample_count> <expect_zeros>
            if args.len() < 8 {
                eprintln!("Usage: zt_engine verify <device> <size> <serial> <method> <sample_count> <expect_zeros>");
                process::exit(1);
            }
            let device = &args[2];
            let size: u64 = args[3].parse().unwrap_or_else(|_| {
                eprintln!("Invalid size");
                process::exit(1);
            });
            let serial = &args[4];
            let method = &args[5];
            let sample_count: u32 = args[6].parse().unwrap_or_else(|_| {
                eprintln!("Invalid sample count");
                process::exit(1);
            });
            let expect_zeros: bool = args[7].parse().unwrap_or_else(|_| {
                eprintln!("Invalid expect_zeros (must be true/false)");
                process::exit(1);
            });

            match verify_device(device, size, serial, method, Some(sample_count), expect_zeros) {
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
