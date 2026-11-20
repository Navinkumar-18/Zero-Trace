//! Platform-neutral verification sampling shared by every backend.
//!
//! The core owns deterministic sample generation, sector hashing, entropy and
//! the evidence fingerprint. It never opens a device: callers implement
//! [`SectorReader`] over Linux O_DIRECT, a Windows volume handle, an Android
//! SCSI BOT channel, or an in-memory test fixture.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Failed to open device: {0}")]
    DeviceOpenFailed(String),
    #[error("Read error at offset {offset}: {message}")]
    ReadFailed { offset: u64, message: String },
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Verification cancelled by user")]
    Cancelled,
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleResult {
    pub offset: u64,
    pub is_zero: bool,
    pub sector_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub pass: bool,
    pub sample_count: u32,
    pub samples: Vec<SampleResult>,
    pub entropy_score: f64,
    pub fingerprint_hash: String,
    pub rng_seed: u64,
    #[serde(default)]
    pub bytes_overwritten: u64,
    #[serde(default)]
    pub total_device_bytes: u64,
}
/// Sector size for aligned O_DIRECT reads
pub const SECTOR_SIZE: usize = 512;

/// Default number of sample points across the device
const DEFAULT_SAMPLE_COUNT: u32 = 50;
/// Compute Shannon entropy of a byte buffer, normalized to [0.0, 1.0].
/// 0.0 = all identical bytes (e.g., all zeros)
/// 1.0 = perfectly uniform distribution (random data)
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    // Normalize: max entropy for 256 symbols = 8 bits
    entropy / 8.0
}
/// Generate pseudo-random sample offsets across a device of `device_size` bytes.
/// Uses a seeded PRNG so the exact offsets are reproducible for audit.
pub fn generate_sample_offsets(device_size: u64, sample_count: u32, seed: u64) -> Vec<u64> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut offsets = Vec::with_capacity(sample_count as usize);

    if device_size < SECTOR_SIZE as u64 {
        return offsets;
    }

    let max_sector = device_size / SECTOR_SIZE as u64;
    let step = max_sector / sample_count as u64;

    for i in 0..sample_count {
        let base = i as u64 * step;
        let jitter = if step > 1 {
            rng.gen_range(0..step.min(1024))
        } else {
            0
        };
        let sector = (base + jitter).min(max_sector - 1);
        let offset = sector * SECTOR_SIZE as u64;
        offsets.push(offset);
    }

    offsets
}

/// A sector source for verification sampling. Implementations own their
/// platform open/read primitives and map failures to [`VerifyError`] so the
/// evidence fingerprint text stays identical to the historic Linux path.
pub trait SectorReader {
    fn read_sector(&self, offset: u64) -> Result<Vec<u8>, VerifyError>;
}

pub fn verify_reader_with_cancel(
    reader: &dyn SectorReader,
    device_size: u64,
    device_serial: &str,
    method_used: &str,
    sample_count: Option<u32>,
    expect_zeros: bool,
    cancel_flag: Option<Arc<AtomicBool>>,
) -> Result<VerificationReport, VerifyError> {
    let count = sample_count.unwrap_or(DEFAULT_SAMPLE_COUNT);

    // Generate deterministic seed from device serial + method for audit reproducibility
    let seed_input = format!("{}:{}:{}", device_serial, method_used, device_size);
    let seed_hash = Sha256::digest(seed_input.as_bytes());
    let seed = u64::from_le_bytes(seed_hash[0..8].try_into().unwrap());

    let offsets = generate_sample_offsets(device_size, count, seed);

    let mut samples = Vec::with_capacity(offsets.len());
    let mut all_sector_data = Vec::new(); // concatenated for entropy calculation
    let mut all_pass = true;

    let is_crypto_mode = method_used.to_lowercase().contains("crypto")
        || method_used.to_lowercase().contains("revert")
        || method_used.to_lowercase().contains("opal");

    for &offset in &offsets {
        if let Some(ref flag) = cancel_flag {
            if flag.load(Ordering::SeqCst) {
                return Err(VerifyError::Cancelled);
            }
        }

        match reader.read_sector(offset) {
            Ok(sector_data) => {
                let is_zero = sector_data.iter().all(|&b| b == 0);
                let sector_hash = format!("{:x}", Sha256::digest(&sector_data));

                // Check pass condition
                let sample_pass = if expect_zeros {
                    is_zero
                } else if is_crypto_mode {
                    // For crypto erase: controllers can return all zeros (unmapped) or ciphertext
                    is_zero || shannon_entropy(&sector_data) > 0.5
                } else {
                    // For random software overwrite pass: sector must not be all zeros
                    !is_zero
                };

                if !sample_pass {
                    all_pass = false;
                }

                all_sector_data.extend_from_slice(&sector_data);

                samples.push(SampleResult {
                    offset,
                    is_zero,
                    sector_hash,
                });
            }
            Err(e) => {
                all_pass = false;
                samples.push(SampleResult {
                    offset,
                    is_zero: false,
                    sector_hash: format!("ERROR: {}", e),
                });
            }
        }
    }

    // Compute overall entropy across all sampled data
    let entropy_score = shannon_entropy(&all_sector_data);

    // Compute evidence fingerprint hash
    // SHA-256 over: [device_serial, method, seed, timestamp_placeholder, all_sample_hashes]
    let mut fingerprint_hasher = Sha256::new();
    fingerprint_hasher.update(device_serial.as_bytes());
    fingerprint_hasher.update(method_used.as_bytes());
    fingerprint_hasher.update(seed.to_le_bytes());
    for sample in &samples {
        fingerprint_hasher.update(sample.sector_hash.as_bytes());
    }
    let fingerprint_hash = format!("{:x}", fingerprint_hasher.finalize());

    // Item 3: Random-pass verification: no per-512B-sample 7.99 threshold.
    // Use aggregated samples or a statistical test, verified against real ChaCha output.
    let final_pass = if expect_zeros {
        all_pass
    } else if is_crypto_mode {
        // For crypto erase: require aggregated entropy > 0.95 or all zeros
        all_pass && (entropy_score > 0.95 || all_sector_data.iter().all(|&b| b == 0))
    } else {
        // For random overwrite pass: require aggregated entropy > 0.95
        all_pass && entropy_score > 0.95
    };

    Ok(VerificationReport {
        pass: final_pass,
        sample_count: samples.len() as u32,
        samples,
        entropy_score,
        fingerprint_hash,
        rng_seed: seed,
        bytes_overwritten: device_size,
        total_device_bytes: device_size,
    })
}
