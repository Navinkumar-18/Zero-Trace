//! Parser unit tests using captured CLI output fixtures.
//!
//! These tests verify that detect.rs parsers correctly extract capabilities
//! from real-world CLI tool outputs without requiring any hardware.

#![cfg(target_os = "linux")]

use zt_engine::detect::*;

fn load_fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to load fixture '{}': {}", path, e))
}

// =========================================================================
// smartctl JSON parser tests
// =========================================================================

#[test]
fn test_smartctl_sata_ssd_health_passed() {
    let json = load_fixture("smartctl_sata_ssd.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.health_passed, Some(true));
}

#[test]
fn test_smartctl_sata_ssd_wear_level() {
    let json = load_fixture("smartctl_sata_ssd.json");
    let data = parse_smartctl_json(&json);
    // Wear Leveling Count attribute 177: value=98, so wear = 100-98 = 2%
    assert_eq!(data.wear_level_pct, Some(2));
}

#[test]
fn test_smartctl_sata_ssd_reallocated_sectors_zero() {
    let json = load_fixture("smartctl_sata_ssd.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.reallocated_sectors, 0);
}

#[test]
fn test_smartctl_sata_ssd_temperature() {
    let json = load_fixture("smartctl_sata_ssd.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.temperature, Some(29));
}

#[test]
fn test_smartctl_sata_ssd_power_on_hours() {
    let json = load_fixture("smartctl_sata_ssd.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.power_on_hours, Some(4521));
}

#[test]
fn test_smartctl_sata_ssd_device_type() {
    let json = load_fixture("smartctl_sata_ssd.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.device_type.as_deref(), Some("sat"));
}

#[test]
fn test_smartctl_sata_ssd_rotation_zero_is_ssd() {
    let json = load_fixture("smartctl_sata_ssd.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.rotation_rate, Some(0));
}

#[test]
fn test_smartctl_nvme_health_passed() {
    let json = load_fixture("smartctl_nvme.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.health_passed, Some(true));
}

#[test]
fn test_smartctl_nvme_percentage_used() {
    let json = load_fixture("smartctl_nvme.json");
    let data = parse_smartctl_json(&json);
    // NVMe percentage_used = 3
    assert_eq!(data.wear_level_pct, Some(3));
}

#[test]
fn test_smartctl_nvme_temperature() {
    let json = load_fixture("smartctl_nvme.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.temperature, Some(38));
}

#[test]
fn test_smartctl_nvme_device_type() {
    let json = load_fixture("smartctl_nvme.json");
    let data = parse_smartctl_json(&json);
    assert_eq!(data.device_type.as_deref(), Some("nvme"));
}

// =========================================================================
// hdparm output parser tests
// =========================================================================

#[test]
fn test_hdparm_security_supported() {
    let text = load_fixture("hdparm_sata_ssd.txt");
    let data = parse_hdparm_output(&text);
    assert!(data.security_supported);
}

#[test]
fn test_hdparm_security_not_enabled() {
    let text = load_fixture("hdparm_sata_ssd.txt");
    let data = parse_hdparm_output(&text);
    // "not  enabled" in fixture
    assert!(!data.security_enabled);
}

#[test]
fn test_hdparm_security_frozen() {
    let text = load_fixture("hdparm_sata_ssd.txt");
    let data = parse_hdparm_output(&text);
    // "frozen" (without "not") in fixture
    assert!(data.security_frozen);
}

#[test]
fn test_hdparm_security_not_locked() {
    let text = load_fixture("hdparm_sata_ssd.txt");
    let data = parse_hdparm_output(&text);
    // "not  locked" in fixture
    assert!(!data.security_locked);
}

#[test]
fn test_hdparm_enhanced_erase_supported() {
    let text = load_fixture("hdparm_sata_ssd.txt");
    let data = parse_hdparm_output(&text);
    assert!(data.enhanced_erase_supported);
}

#[test]
fn test_hdparm_erase_time() {
    let text = load_fixture("hdparm_sata_ssd.txt");
    let data = parse_hdparm_output(&text);
    assert_eq!(data.normal_erase_time_min, Some(2));
    assert_eq!(data.enhanced_erase_time_min, Some(2));
}

#[test]
fn test_hdparm_sanitize_supported() {
    let text = load_fixture("hdparm_sata_ssd.txt");
    let data = parse_hdparm_output(&text);
    assert!(data.sanitize_supported);
    assert!(data.sanitize_block_erase);
    assert!(data.sanitize_crypto_scramble);
    assert!(data.sanitize_overwrite);
}

// =========================================================================
// nvme id-ctrl parser tests
// =========================================================================

#[test]
fn test_nvme_id_ctrl_sanicap_0x3() {
    let text = load_fixture("nvme_id_ctrl.txt");
    let data = parse_nvme_id_ctrl(&text);
    // sanicap = 0x3 → bit 0 (crypto) + bit 1 (block) set
    assert!(data.sanitize_supported);
    assert!(data.crypto_erase_supported);
    assert!(data.block_erase_supported);
}

// =========================================================================
// sedutil-cli parser tests
// =========================================================================

#[test]
fn test_sedutil_opal_supported() {
    let text = load_fixture("sedutil_query_opal.txt");
    let data = parse_sedutil_query(&text);
    assert!(data.opal_supported);
}

#[test]
fn test_sedutil_not_locked() {
    let text = load_fixture("sedutil_query_opal.txt");
    let data = parse_sedutil_query(&text);
    // "Locked = N" in fixture
    assert!(!data.locked);
}

#[test]
fn test_sedutil_not_opal() {
    let text = load_fixture("sedutil_not_opal.txt");
    let data = parse_sedutil_query(&text);
    assert!(!data.opal_supported);
}

// =========================================================================
// mmc extcsd parser tests
// =========================================================================

#[test]
fn test_mmc_sanitize_supported() {
    let text = load_fixture("mmc_extcsd.txt");
    let data = parse_mmc_extcsd(&text);
    assert!(data.sanitize_supported);
}

// =========================================================================
// DeviceCapabilities struct tests
// =========================================================================

#[test]
fn test_device_capabilities_serializes_to_json() {
    let caps = DeviceCapabilities::new_unknown("/dev/sda");
    let json = serde_json::to_string(&caps).unwrap();
    assert!(json.contains("\"device_path\":\"/dev/sda\""));
    assert!(json.contains("\"bus_type\":\"Unknown\""));
}
