//! Post-sanitization verification module.
//!
//! Reads raw disk sectors via O_DIRECT (bypassing page cache),
//! performs N-point pseudo-random LBA sampling, computes SHA-256
//! evidence fingerprints, and measures Shannon entropy.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rand::SeedableRng;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;

#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sector size for aligned O_DIRECT reads
const SECTOR_SIZE: usize = 512;

/// Default number of sample points across the device
const DEFAULT_SAMPLE_COUNT: u32 = 50;

// ---------------------------------------------------------------------------
// Entropy calculation
// ---------------------------------------------------------------------------

/// Compute Shannon entropy of a byte buffer, normalized to [0.0, 1.0].
/// 0.0 = all identical bytes (e.g., all zeros)
/// 1.0 = perfectly uniform distribution (random data)
fn shannon_entropy(data: &[u8]) -> f64 {
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

// ---------------------------------------------------------------------------
// Verification logic
// ---------------------------------------------------------------------------

/// Generate pseudo-random sample offsets across a device of `device_size` bytes.
/// Uses a seeded PRNG so the exact offsets are reproducible for audit.
fn generate_sample_offsets(device_size: u64, sample_count: u32, seed: u64) -> Vec<u64> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut offsets = Vec::with_capacity(sample_count as usize);

    if device_size < SECTOR_SIZE as u64 {
        return offsets;
    }

    let max_sector = device_size / SECTOR_SIZE as u64;
    let step = max_sector / sample_count as u64;

    for i in 0..sample_count {
        let base = i as u64 * step;
        let jitter = if step > 1 { rng.gen_range(0..step.min(1024)) } else { 0 };
        let sector = (base + jitter).min(max_sector - 1);
        let offset = sector * SECTOR_SIZE as u64;
        offsets.push(offset);
    }

    offsets
}

/// Read a single sector at the given offset from a file/device.
///
/// Uses O_DIRECT (opened through the backend) to bypass the page cache;
/// when O_DIRECT is unavailable (e.g. on regular fixture files) it falls
/// back to a buffered read opened through the backend as well. C2b: this
/// module never opens a device itself — every open helper lives in
/// `backend/linux`.
///
/// (The historic `#[cfg(not(target_os = "linux"))]` std-I/O branch was dead
/// code — the whole `verify` module compiles only on Linux (see `lib.rs`)
/// — and was removed so the C2b static scan needs no std-open exception
/// outside `backend/`.)
fn read_sector_at(path: &str, offset: u64) -> Result<Vec<u8>, VerifyError> {
    {
        use std::io::{Read, Seek, SeekFrom};

        // C2b: the device open lives in the backend — try O_DIRECT first
        // for the cache-bypass guarantee.
        let fd = crate::backend::linux::open_read_direct_fd(path);

        if fd >= 0 {
            let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

            // O_DIRECT requires aligned buffers
            // Allocate aligned buffer using posix_memalign
            let mut aligned_ptr: *mut libc::c_void = std::ptr::null_mut();
            let align_result = unsafe {
                libc::posix_memalign(&mut aligned_ptr, SECTOR_SIZE, SECTOR_SIZE)
            };

            if align_result != 0 || aligned_ptr.is_null() {
                return Err(VerifyError::ReadFailed {
                    offset,
                    message: "Failed to allocate aligned buffer".to_string(),
                });
            }

            let result = (|| -> Result<Vec<u8>, VerifyError> {
                file.seek(SeekFrom::Start(offset)).map_err(|e| VerifyError::ReadFailed {
                    offset,
                    message: format!("Seek failed: {}", e),
                })?;

                let buf_slice = unsafe {
                    std::slice::from_raw_parts_mut(aligned_ptr as *mut u8, SECTOR_SIZE)
                };

                file.read_exact(buf_slice).map_err(|e| VerifyError::ReadFailed {
                    offset,
                    message: format!("Read failed: {}", e),
                })?;

                Ok(buf_slice.to_vec())
            })();

            unsafe { libc::free(aligned_ptr) };
            return result;
        }

        // Fallback to standard I/O if O_DIRECT fails (e.g., on non-block devices)
        let mut file = crate::backend::linux::open_read_buffered(path)
            .map_err(|e| VerifyError::DeviceOpenFailed(format!("{}: {}", path, e)))?;
        {
            use std::os::unix::io::AsRawFd;
            crate::backend::linux::drop_cache_for_read(file.as_raw_fd());
        }
        file.seek(SeekFrom::Start(offset)).map_err(|e| VerifyError::ReadFailed {
            offset,
            message: format!("Seek failed: {}", e),
        })?;
        let mut buf = vec![0u8; SECTOR_SIZE];
        file.read_exact(&mut buf).map_err(|e| VerifyError::ReadFailed {
            offset,
            message: format!("Read failed: {}", e),
        })?;
        Ok(buf)
    }
}

/// Verify a device after sanitization by sampling sectors and checking for
/// expected patterns (zero-fill or high-entropy for crypto erase).
///
/// # Arguments
/// * `device_path` — Path to the block device (e.g., `/dev/sdb`)
/// * `device_size` — Size of device in bytes
/// * `device_serial` — For evidence fingerprint computation
/// * `method_used` — Sanitization method name (for fingerprint)
/// * `sample_count` — Number of LBA samples (default: 50)
/// * `expect_zeros` — If true, verify sectors are all-zero. If false, verify high entropy (crypto erase).
pub fn verify_device(
    device_path: &str,
    device_size: u64,
    device_serial: &str,
    method_used: &str,
    sample_count: Option<u32>,
    expect_zeros: bool,
) -> Result<VerificationReport, VerifyError> {
    verify_device_with_cancel(
        device_path,
        device_size,
        device_serial,
        method_used,
        sample_count,
        expect_zeros,
        None,
    )
}

pub fn verify_device_with_cancel(
    device_path: &str,
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

        match read_sector_at(device_path, offset) {
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

#[allow(clippy::too_many_arguments)]
pub fn verify_device_scoped(
    device_path: &str,
    partition_size: u64,
    total_device_size: u64,
    device_serial: &str,
    method_used: &str,
    sample_count: Option<u32>,
    expect_zeros: bool,
    cancel_flag: Option<Arc<AtomicBool>>,
) -> Result<VerificationReport, VerifyError> {
    let mut report = verify_device_with_cancel(
        device_path,
        partition_size,
        device_serial,
        method_used,
        sample_count,
        expect_zeros,
        cancel_flag,
    )?;
    report.bytes_overwritten = partition_size;
    report.total_device_bytes = total_device_size;
    Ok(report)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_all_zeros() {
        let data = vec![0u8; 512];
        let ent = shannon_entropy(&data);
        assert!(ent < 0.01, "All zeros should have near-zero entropy: {}", ent);
    }

    #[test]
    fn test_shannon_entropy_uniform_distribution() {
        // Create a buffer with all 256 byte values equally represented
        let mut data = Vec::with_capacity(256 * 4);
        for _ in 0..4 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let ent = shannon_entropy(&data);
        assert!(ent > 0.99, "Uniform distribution should have max entropy: {}", ent);
    }

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_generate_sample_offsets_count() {
        let offsets = generate_sample_offsets(1_000_000_000, 50, 12345);
        assert_eq!(offsets.len(), 50);
    }

    #[test]
    fn test_generate_sample_offsets_deterministic() {
        let a = generate_sample_offsets(1_000_000_000, 50, 42);
        let b = generate_sample_offsets(1_000_000_000, 50, 42);
        assert_eq!(a, b, "Same seed should produce identical offsets");
    }

    #[test]
    fn test_generate_sample_offsets_different_seeds() {
        let a = generate_sample_offsets(1_000_000_000, 50, 42);
        let b = generate_sample_offsets(1_000_000_000, 50, 99);
        assert_ne!(a, b, "Different seeds should produce different offsets");
    }

    #[test]
    fn test_generate_sample_offsets_aligned_to_sector() {
        let offsets = generate_sample_offsets(1_000_000_000, 50, 100);
        for offset in &offsets {
            assert_eq!(offset % SECTOR_SIZE as u64, 0, "Offset {} not aligned to sector size", offset);
        }
    }

    #[test]
    fn test_generate_sample_offsets_within_device() {
        let device_size = 1_000_000_000u64;
        let offsets = generate_sample_offsets(device_size, 50, 200);
        for offset in &offsets {
            assert!(*offset + SECTOR_SIZE as u64 <= device_size,
                "Offset {} + sector size exceeds device size {}", offset, device_size);
        }
    }

    #[test]
    fn test_generate_sample_offsets_tiny_device() {
        let offsets = generate_sample_offsets(256, 50, 300);
        assert!(offsets.is_empty(), "Device smaller than sector should produce no offsets");
    }

    #[test]
    fn test_verify_device_on_zero_filled_file() {
        use std::io::Write;

        // Create a temporary file filled with zeros
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero_test.img");
        let size = 64 * 1024u64; // 64KB

        let mut file = std::fs::File::create(&path).unwrap();
        let zeros = vec![0u8; size as usize];
        file.write_all(&zeros).unwrap();
        file.flush().unwrap();
        drop(file);

        let report = verify_device(
            path.to_str().unwrap(),
            size,
            "TEST_SERIAL",
            "Zero Fill",
            Some(10),
            true, // expect zeros
        ).unwrap();

        assert!(report.pass, "Zero-filled file should pass zero verification");
        assert_eq!(report.sample_count, 10);
        assert!(report.entropy_score < 0.01, "Zero data should have near-zero entropy");
        assert!(!report.fingerprint_hash.is_empty());
        assert!(report.samples.iter().all(|s| s.is_zero));
    }

    #[test]
    fn test_verify_device_on_random_filled_file() {
        use std::io::Write;
        use rand::RngCore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("random_test.img");
        let size = 64 * 1024u64;

        let mut file = std::fs::File::create(&path).unwrap();
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; size as usize];
        rng.fill_bytes(&mut data);
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        drop(file);

        let report = verify_device(
            path.to_str().unwrap(),
            size,
            "TEST_SERIAL",
            "Random Fill",
            Some(10),
            true, // expect zeros — should FAIL
        ).unwrap();

        assert!(!report.pass, "Random-filled file should fail zero verification");
        assert!(report.entropy_score > 0.5, "Random data should have high entropy");
    }

    #[test]
    fn test_verify_device_crypto_erase_mode_accepts_random() {
        use std::io::Write;
        use rand::RngCore;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crypto_test.img");
        let size = 64 * 1024u64;

        let mut file = std::fs::File::create(&path).unwrap();
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; size as usize];
        rng.fill_bytes(&mut data);
        file.write_all(&data).unwrap();
        file.flush().unwrap();
        drop(file);

        let report = verify_device(
            path.to_str().unwrap(),
            size,
            "TEST_SERIAL",
            "Crypto Erase",
            Some(10),
            false, // crypto mode: accept high-entropy data
        ).unwrap();

        assert!(report.pass, "Crypto erase mode should accept high-entropy data");
    }

    #[test]
    fn test_verification_report_serializes() {
        let report = VerificationReport {
            pass: true,
            sample_count: 50,
            samples: vec![SampleResult {
                offset: 0,
                is_zero: true,
                sector_hash: "abc123".to_string(),
            }],
            entropy_score: 0.001,
            fingerprint_hash: "deadbeef".to_string(),
            rng_seed: 42,
            bytes_overwritten: 25600,
            total_device_bytes: 25600,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"pass\":true"));
        assert!(json.contains("\"rng_seed\":42"));
    }

    #[test]
    fn test_fingerprint_is_deterministic() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("det_test.img");
        let size = 64 * 1024u64;

        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&vec![0u8; size as usize]).unwrap();
        file.flush().unwrap();
        drop(file);

        let r1 = verify_device(path.to_str().unwrap(), size, "SER", "Method", Some(5), true).unwrap();
        let r2 = verify_device(path.to_str().unwrap(), size, "SER", "Method", Some(5), true).unwrap();

        assert_eq!(r1.fingerprint_hash, r2.fingerprint_hash, "Same inputs should produce same fingerprint");
        assert_eq!(r1.rng_seed, r2.rng_seed);
    }
}
