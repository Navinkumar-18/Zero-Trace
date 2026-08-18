//! Certificate signing module.
//!
//! Provides HMAC-SHA256 and Ed25519 certificate signing for
//! sanitization audit certificates.

use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use rand::rngs::OsRng;

use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    #[error("Key storage error: {0}")]
    KeyStorageError(String),
    #[error("Key load error: {0}")]
    KeyLoadError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SigningMethod {
    HmacSha256,
    Ed25519,
}

impl std::fmt::Display for SigningMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningMethod::HmacSha256 => write!(f, "HMAC-SHA256"),
            SigningMethod::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCertificate {
    pub payload_json: String,
    pub signing_method: SigningMethod,
    pub signature_hex: String,
    pub public_key_hex: Option<String>,
}

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/// Default directory for Ed25519 key storage
fn default_key_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".zero_trace").join("keys")
}

/// Default path for the Ed25519 private key file
fn default_key_path() -> PathBuf {
    default_key_dir().join("ed25519.key")
}

/// Load an existing Ed25519 signing key from disk, or generate and persist a new one.
fn load_or_generate_key(key_path: Option<&str>) -> Result<SigningKey, CertificateError> {
    let path = key_path
        .map(PathBuf::from)
        .unwrap_or_else(default_key_path);

    // Try loading existing key
    if path.exists() {
        let key_bytes = fs::read(&path)
            .map_err(|e| CertificateError::KeyLoadError(format!("Cannot read {}: {}", path.display(), e)))?;

        if key_bytes.len() != 32 {
            return Err(CertificateError::KeyLoadError(format!(
                "Invalid key file size: expected 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key_bytes);
        return Ok(SigningKey::from_bytes(&key_array));
    }

    // Generate new keypair
    let signing_key = SigningKey::generate(&mut OsRng);

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CertificateError::KeyStorageError(format!("Cannot create key directory: {}", e)))?;
    }

    // Write private key bytes
    fs::write(&path, signing_key.to_bytes())
        .map_err(|e| CertificateError::KeyStorageError(format!("Cannot write key file: {}", e)))?;

    // Set file permissions to 0600 (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(&path, perms)
            .map_err(|e| CertificateError::KeyStorageError(format!("Cannot set key file permissions: {}", e)))?;
    }

    Ok(signing_key)
}

/// Get the public key hex string for an Ed25519 signing key.
fn public_key_hex(signing_key: &SigningKey) -> String {
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    hex::encode(&verifying_key.to_bytes())
}

// ---------------------------------------------------------------------------
// Hex encoding helper (to avoid adding hex crate dependency)
// ---------------------------------------------------------------------------

mod hex {
    /// Encode bytes as lowercase hex string.
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ---------------------------------------------------------------------------
// Signing functions
// ---------------------------------------------------------------------------

/// Sign a certificate payload using HMAC-SHA256.
/// The HMAC key is derived from a combination of the payload content
/// and a device-specific secret (serial number).
fn sign_hmac_sha256(payload: &str, device_serial: &str) -> Result<SignedCertificate, CertificateError> {
    // Derive HMAC key from device serial (in production, this would come from a secure key store)
    let key_material = format!("ZeroTrace-v2-HMAC-{}", device_serial);

    let mut mac = HmacSha256::new_from_slice(key_material.as_bytes())
        .map_err(|e| CertificateError::SigningFailed(format!("HMAC init failed: {}", e)))?;

    mac.update(payload.as_bytes());
    let result = mac.finalize();
    let signature = hex::encode(&result.into_bytes());

    Ok(SignedCertificate {
        payload_json: payload.to_string(),
        signing_method: SigningMethod::HmacSha256,
        signature_hex: signature,
        public_key_hex: None, // HMAC is symmetric, no public key
    })
}

/// Sign a certificate payload using Ed25519.
fn sign_ed25519(payload: &str, key_path: Option<&str>) -> Result<SignedCertificate, CertificateError> {
    let signing_key = load_or_generate_key(key_path)?;
    let pub_key_hex = public_key_hex(&signing_key);

    let signature = signing_key.sign(payload.as_bytes());
    let signature_hex = hex::encode(&signature.to_bytes());

    Ok(SignedCertificate {
        payload_json: payload.to_string(),
        signing_method: SigningMethod::Ed25519,
        signature_hex,
        public_key_hex: Some(pub_key_hex),
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign a certificate payload using the specified method.
///
/// # Arguments
/// * `payload` — JSON string of the certificate payload
/// * `method` — Signing method (HMAC-SHA256 or Ed25519)
/// * `key_path` — Optional path to Ed25519 key file (only used for Ed25519)
/// * `device_serial` — Device serial for HMAC key derivation (only used for HMAC)
pub fn sign_certificate(
    payload: &str,
    method: SigningMethod,
    key_path: Option<&str>,
    device_serial: &str,
) -> Result<SignedCertificate, CertificateError> {
    match method {
        SigningMethod::HmacSha256 => sign_hmac_sha256(payload, device_serial),
        SigningMethod::Ed25519 => sign_ed25519(payload, key_path),
    }
}

/// Verify an Ed25519 signature against a payload and public key.
pub fn verify_ed25519_signature(
    payload: &str,
    signature_hex: &str,
    public_key_hex_str: &str,
) -> Result<bool, CertificateError> {
    use ed25519_dalek::{Verifier, Signature};

    // Decode public key
    let pub_bytes = hex_decode(public_key_hex_str)
        .map_err(|e| CertificateError::SigningFailed(format!("Invalid public key hex: {}", e)))?;

    if pub_bytes.len() != 32 {
        return Err(CertificateError::SigningFailed(format!(
            "Invalid public key length: expected 32, got {}",
            pub_bytes.len()
        )));
    }

    let mut pub_array = [0u8; 32];
    pub_array.copy_from_slice(&pub_bytes);

    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| CertificateError::SigningFailed(format!("Invalid public key: {}", e)))?;

    // Decode signature
    let sig_bytes = hex_decode(signature_hex)
        .map_err(|e| CertificateError::SigningFailed(format!("Invalid signature hex: {}", e)))?;

    if sig_bytes.len() != 64 {
        return Err(CertificateError::SigningFailed(format!(
            "Invalid signature length: expected 64, got {}",
            sig_bytes.len()
        )));
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);

    match verifying_key.verify(payload.as_bytes(), &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Decode a hex string to bytes.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("Odd-length hex string".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PAYLOAD: &str = r#"{"certificateId":"ZT-TEST-001","deviceSerial":"SER123","method":"Test"}"#;

    #[test]
    fn test_hmac_sha256_signing() {
        let result = sign_certificate(TEST_PAYLOAD, SigningMethod::HmacSha256, None, "SER123").unwrap();
        assert_eq!(result.signing_method, SigningMethod::HmacSha256);
        assert!(!result.signature_hex.is_empty());
        assert_eq!(result.signature_hex.len(), 64, "HMAC-SHA256 should produce 32 bytes = 64 hex chars");
        assert!(result.public_key_hex.is_none(), "HMAC should not have a public key");
    }

    #[test]
    fn test_hmac_sha256_deterministic() {
        let r1 = sign_certificate(TEST_PAYLOAD, SigningMethod::HmacSha256, None, "SER123").unwrap();
        let r2 = sign_certificate(TEST_PAYLOAD, SigningMethod::HmacSha256, None, "SER123").unwrap();
        assert_eq!(r1.signature_hex, r2.signature_hex, "Same inputs should produce same HMAC");
    }

    #[test]
    fn test_hmac_sha256_different_serials_different_signature() {
        let r1 = sign_certificate(TEST_PAYLOAD, SigningMethod::HmacSha256, None, "SER123").unwrap();
        let r2 = sign_certificate(TEST_PAYLOAD, SigningMethod::HmacSha256, None, "SER456").unwrap();
        assert_ne!(r1.signature_hex, r2.signature_hex);
    }

    #[test]
    fn test_ed25519_signing_and_verification() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test_ed25519.key");
        let key_path_str = key_path.to_str().unwrap();

        let result = sign_certificate(
            TEST_PAYLOAD,
            SigningMethod::Ed25519,
            Some(key_path_str),
            "SER123",
        ).unwrap();

        assert_eq!(result.signing_method, SigningMethod::Ed25519);
        assert!(!result.signature_hex.is_empty());
        assert_eq!(result.signature_hex.len(), 128, "Ed25519 should produce 64 bytes = 128 hex chars");

        let pub_key = result.public_key_hex.as_ref().expect("Ed25519 should have public key");
        assert_eq!(pub_key.len(), 64, "Ed25519 public key should be 32 bytes = 64 hex chars");

        // Verify the signature
        let valid = verify_ed25519_signature(TEST_PAYLOAD, &result.signature_hex, pub_key).unwrap();
        assert!(valid, "Ed25519 signature should verify correctly");
    }

    #[test]
    fn test_ed25519_wrong_payload_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test_ed25519_wrong.key");
        let key_path_str = key_path.to_str().unwrap();

        let result = sign_certificate(
            TEST_PAYLOAD,
            SigningMethod::Ed25519,
            Some(key_path_str),
            "SER123",
        ).unwrap();

        let pub_key = result.public_key_hex.as_ref().unwrap();
        let valid = verify_ed25519_signature("tampered payload", &result.signature_hex, pub_key).unwrap();
        assert!(!valid, "Tampered payload should fail verification");
    }

    #[test]
    fn test_ed25519_key_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("persist_test.key");
        let key_path_str = key_path.to_str().unwrap();

        // First signing — generates key
        let r1 = sign_certificate(TEST_PAYLOAD, SigningMethod::Ed25519, Some(key_path_str), "SER").unwrap();

        // Second signing — reuses same key
        let r2 = sign_certificate(TEST_PAYLOAD, SigningMethod::Ed25519, Some(key_path_str), "SER").unwrap();

        // Same key → same public key
        assert_eq!(r1.public_key_hex, r2.public_key_hex, "Persisted key should produce same public key");

        // Same payload + same key → same signature (Ed25519 is deterministic)
        assert_eq!(r1.signature_hex, r2.signature_hex, "Same key + payload should produce same signature");
    }

    #[test]
    fn test_ed25519_key_file_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("perms_test.key");
        let key_path_str = key_path.to_str().unwrap();

        let _ = sign_certificate(TEST_PAYLOAD, SigningMethod::Ed25519, Some(key_path_str), "SER").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&key_path).unwrap();
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Key file should have 0600 permissions, got {:o}", mode);
        }
    }

    #[test]
    fn test_signed_certificate_serializes() {
        let cert = SignedCertificate {
            payload_json: TEST_PAYLOAD.to_string(),
            signing_method: SigningMethod::Ed25519,
            signature_hex: "abc123".to_string(),
            public_key_hex: Some("def456".to_string()),
        };
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("\"Ed25519\""));
        assert!(json.contains("\"def456\""));
    }

    #[test]
    fn test_hex_decode_valid() {
        let decoded = hex_decode("48656c6c6f").unwrap();
        assert_eq!(decoded, b"Hello");
    }

    #[test]
    fn test_hex_decode_odd_length_fails() {
        assert!(hex_decode("abc").is_err());
    }

    #[test]
    fn test_signing_method_display() {
        assert_eq!(format!("{}", SigningMethod::HmacSha256), "HMAC-SHA256");
        assert_eq!(format!("{}", SigningMethod::Ed25519), "Ed25519");
    }
}
