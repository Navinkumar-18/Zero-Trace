//! Device capability probing module.
//!
//! Shells out to Linux CLI tools (smartctl, hdparm, nvme, sedutil-cli, mmc)
//! and parses their output into a strongly-typed `DeviceCapabilities` struct.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum DetectError {
    #[error("Command execution failed: {0}")]
    CommandFailed(String),
    #[error("JSON parse error: {0}")]
    JsonParse(String),
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BusType {
    NVMe,
    SATA,
    USB,
    EMMC,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SmartHealth {
    Passed,
    Warning,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DurationClass {
    Seconds,
    Minutes,
    Hours,
    Unknown,
}

/// Strongly typed device capabilities gathered from real hardware probing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub device_path: String,
    pub bus_type: BusType,

    // SMART health
    pub smart_health: SmartHealth,
    pub wear_level_pct: Option<u8>,
    pub reallocated_sectors: u32,
    pub temperature_celsius: Option<u16>,
    pub power_on_hours: Option<u64>,

    // ATA Security feature set (hdparm -I)
    pub ata_security_supported: bool,
    pub ata_security_enabled: bool,
    pub ata_security_frozen: bool,
    pub ata_security_locked: bool,
    pub ata_enhanced_erase_supported: bool,
    pub ata_enhanced_erase_time_min: Option<u16>,
    pub ata_normal_erase_time_min: Option<u16>,

    // ATA Sanitize Device feature set
    pub ata_sanitize_supported: bool,
    pub ata_sanitize_crypto_scramble: bool,
    pub ata_sanitize_block_erase: bool,
    pub ata_sanitize_overwrite: bool,

    // NVMe Sanitize (nvme id-ctrl)
    pub nvme_sanitize_supported: bool,
    pub nvme_sanitize_crypto_erase: bool,
    pub nvme_sanitize_block_erase: bool,

    // TCG OPAL / SED (sedutil-cli)
    pub opal_supported: bool,
    pub opal_locked: bool,

    // eMMC (mmc extcsd)
    pub emmc_sanitize_supported: bool,

    // USB Link Speed (sysfs)
    #[serde(default)]
    pub usb_speed_mbps: Option<u32>,
    #[serde(default)]
    pub is_usb_2: bool,

    // Meta
    pub estimated_duration_class: DurationClass,
    pub probe_errors: Vec<String>,
}

impl DeviceCapabilities {
    /// Create a default capabilities struct with everything unknown/false.
    pub fn new_unknown(device_path: &str) -> Self {
        DeviceCapabilities {
            device_path: device_path.to_string(),
            bus_type: BusType::Unknown,
            smart_health: SmartHealth::Unknown,
            wear_level_pct: None,
            reallocated_sectors: 0,
            temperature_celsius: None,
            power_on_hours: None,
            ata_security_supported: false,
            ata_security_enabled: false,
            ata_security_frozen: false,
            ata_security_locked: false,
            ata_enhanced_erase_supported: false,
            ata_enhanced_erase_time_min: None,
            ata_normal_erase_time_min: None,
            ata_sanitize_supported: false,
            ata_sanitize_crypto_scramble: false,
            ata_sanitize_block_erase: false,
            ata_sanitize_overwrite: false,
            nvme_sanitize_supported: false,
            nvme_sanitize_crypto_erase: false,
            nvme_sanitize_block_erase: false,
            opal_supported: false,
            opal_locked: false,
            emmc_sanitize_supported: false,
            usb_speed_mbps: None,
            is_usb_2: false,
            estimated_duration_class: DurationClass::Unknown,
            probe_errors: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal parsed data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct SmartctlData {
    pub health_passed: Option<bool>,
    pub wear_level_pct: Option<u8>,
    pub reallocated_sectors: u32,
    pub temperature: Option<u16>,
    pub power_on_hours: Option<u64>,
    pub device_type: Option<String>,
    pub rotation_rate: Option<u32>,
}

#[derive(Debug, Default)]
pub struct HdparmData {
    pub security_supported: bool,
    pub security_enabled: bool,
    pub security_frozen: bool,
    pub security_locked: bool,
    pub enhanced_erase_supported: bool,
    pub enhanced_erase_time_min: Option<u16>,
    pub normal_erase_time_min: Option<u16>,
    pub sanitize_supported: bool,
    pub sanitize_crypto_scramble: bool,
    pub sanitize_block_erase: bool,
    pub sanitize_overwrite: bool,
}

#[derive(Debug, Default)]
pub struct NvmeIdData {
    pub sanitize_supported: bool,
    pub crypto_erase_supported: bool,
    pub block_erase_supported: bool,
}

#[derive(Debug, Default)]
pub struct SedutilData {
    pub opal_supported: bool,
    pub locked: bool,
}

#[derive(Debug, Default)]
pub struct MmcData {
    pub sanitize_supported: bool,
}

// ---------------------------------------------------------------------------
// Parser functions — pure functions parsing CLI output text
// ---------------------------------------------------------------------------

/// Parse smartctl JSON output (`smartctl -a <device> --json`)
pub fn parse_smartctl_json(stdout: &str) -> SmartctlData {
    let mut data = SmartctlData::default();

    let parsed: serde_json::Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => return data,
    };

    // Health status
    if let Some(smart_status) = parsed.get("smart_status") {
        if let Some(passed) = smart_status.get("passed").and_then(|v| v.as_bool()) {
            data.health_passed = Some(passed);
        }
    }

    // Device type / rotation rate
    if let Some(rot) = parsed.get("rotation_rate").and_then(|v| v.as_u64()) {
        data.rotation_rate = Some(rot as u32);
    }
    if let Some(dt) = parsed.get("device").and_then(|d| d.get("type")).and_then(|v| v.as_str()) {
        data.device_type = Some(dt.to_string());
    }

    // Temperature
    if let Some(temp_obj) = parsed.get("temperature") {
        if let Some(current) = temp_obj.get("current").and_then(|v| v.as_u64()) {
            data.temperature = Some(current as u16);
        }
    }

    // Power-on hours
    if let Some(poh) = parsed.get("power_on_time") {
        if let Some(hours) = poh.get("hours").and_then(|v| v.as_u64()) {
            data.power_on_hours = Some(hours);
        }
    }

    // ATA SMART attributes (id 5 = Reallocated Sectors, id 177/233 = Wear Leveling)
    if let Some(attrs) = parsed.get("ata_smart_attributes")
        .and_then(|a| a.get("table"))
        .and_then(|t| t.as_array())
    {
        for attr in attrs {
            let id = attr.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let raw_value = attr
                .get("raw")
                .and_then(|r| r.get("value"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            match id {
                5 => {
                    // Reallocated Sector Count
                    data.reallocated_sectors = raw_value as u32;
                }
                177 | 233 => {
                    // Wear Leveling Count (SSD)
                    // Value is typically 0-100 (100 = new, 0 = worn)
                    let current = attr.get("value").and_then(|v| v.as_u64()).unwrap_or(100);
                    data.wear_level_pct = Some((100u64.saturating_sub(current)) as u8);
                }
                _ => {}
            }
        }
    }

    // NVMe specific: percentage_used from nvme_smart_health_information_log
    if let Some(nvme_smart) = parsed.get("nvme_smart_health_information_log") {
        if let Some(pct_used) = nvme_smart.get("percentage_used").and_then(|v| v.as_u64()) {
            data.wear_level_pct = Some(pct_used.min(255) as u8);
        }
        if let Some(temp) = nvme_smart.get("temperature").and_then(|v| v.as_u64()) {
            data.temperature = Some(temp as u16);
        }
        if let Some(poh) = nvme_smart.get("power_on_hours").and_then(|v| v.as_u64()) {
            data.power_on_hours = Some(poh);
        }
    }

    data
}

/// Parse hdparm -I output (text format) for ATA Security feature set
pub fn parse_hdparm_output(stdout: &str) -> HdparmData {
    let mut data = HdparmData::default();
    let stdout_lower = stdout.to_lowercase();

    // Security section detection
    let in_security = stdout_lower.contains("security:");

    if in_security || stdout_lower.contains("security feature set") {
        // Master password capability
        data.security_supported = stdout_lower.contains("supported")
            && (stdout_lower.contains("security feature set")
                || stdout_lower.contains("security:"));

        // Check individual security states
        // hdparm outputs lines like:
        //   enabled
        //   not   locked
        //   frozen
        //   not   expired: security count
        for line in stdout.lines() {
            let trimmed = line.trim().to_lowercase();

            // "enabled" without "not" prefix on the same line
            if (trimmed == "enabled" || (trimmed.contains("enabled") && !trimmed.contains("not")))
                && !trimmed.contains("enhanced erase")
            {
                data.security_enabled = true;
            }

            if trimmed == "not\tenabled" || trimmed == "not\t enabled" || trimmed == "not enabled" {
                data.security_enabled = false;
            }

            if trimmed == "locked" || (trimmed.contains("locked") && !trimmed.contains("not")) {
                data.security_locked = true;
            }
            if trimmed.contains("not") && trimmed.contains("locked") {
                data.security_locked = false;
            }

            if trimmed == "frozen" || (trimmed.contains("frozen") && !trimmed.contains("not")) {
                data.security_frozen = true;
            }
            if trimmed.contains("not") && trimmed.contains("frozen") {
                data.security_frozen = false;
            }

            // Enhanced erase support and time
            if trimmed.contains("enhanced erase") {
                data.enhanced_erase_supported = true;
            }

            // Parse erase time estimates
            // "2min for SECURITY ERASE UNIT."
            // "2min for ENHANCED SECURITY ERASE UNIT."
            if trimmed.contains("min for security erase unit") {
                if let Some(min_str) = trimmed.split("min").next() {
                    if let Ok(mins) = min_str.trim().parse::<u16>() {
                        data.normal_erase_time_min = Some(mins);
                    }
                }
            }
            if trimmed.contains("min for enhanced security erase") {
                if let Some(min_str) = trimmed.split("min").next() {
                    if let Ok(mins) = min_str.trim().parse::<u16>() {
                        data.enhanced_erase_time_min = Some(mins);
                    }
                }
            }
        }
    }

    // Sanitize Device feature set
    if stdout_lower.contains("sanitize feature set") || stdout_lower.contains("sanitize device") {
        data.sanitize_supported = true;

        if stdout_lower.contains("crypto scramble") {
            data.sanitize_crypto_scramble = true;
        }
        if stdout_lower.contains("block erase") {
            data.sanitize_block_erase = true;
        }
        if stdout_lower.contains("overwrite") {
            data.sanitize_overwrite = true;
        }
    }

    data
}

/// Parse nvme id-ctrl output for sanitize capabilities
pub fn parse_nvme_id_ctrl(stdout: &str) -> NvmeIdData {
    let mut data = NvmeIdData::default();

    // Look for "sanicap" field (Sanitize Capabilities)
    // sanicap  : 0x3
    //   Bit 0 = Crypto Erase supported
    //   Bit 1 = Block Erase supported
    //   Bit 2 = Overwrite supported
    for line in stdout.lines() {
        let trimmed = line.trim().to_lowercase();

        if trimmed.starts_with("sanicap") {
            // Parse hex value after the colon
            if let Some(val_str) = trimmed.split(':').nth(1) {
                let val_str = val_str.trim().trim_start_matches("0x");
                if let Ok(val) = u32::from_str_radix(val_str, 16) {
                    data.sanitize_supported = val > 0;
                    data.crypto_erase_supported = (val & 0x1) != 0;
                    data.block_erase_supported = (val & 0x2) != 0;
                } else {
                    // Try decimal parse
                    if let Ok(val) = val_str.parse::<u32>() {
                        data.sanitize_supported = val > 0;
                        data.crypto_erase_supported = (val & 0x1) != 0;
                        data.block_erase_supported = (val & 0x2) != 0;
                    }
                }
            }
        }
    }

    // Alternative: JSON format from nvme id-ctrl --output-format=json
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(stdout) {
        if let Some(sanicap) = parsed.get("sanicap").and_then(|v| v.as_u64()) {
            data.sanitize_supported = sanicap > 0;
            data.crypto_erase_supported = (sanicap & 0x1) != 0;
            data.block_erase_supported = (sanicap & 0x2) != 0;
        }
    }

    data
}

/// Parse sedutil-cli --query output for TCG OPAL support
pub fn parse_sedutil_query(stdout: &str) -> SedutilData {
    let mut data = SedutilData::default();
    let stdout_lower = stdout.to_lowercase();

    // sedutil-cli --query outputs lines like:
    // "Locking function (0x0002)  Y"
    // "MBRDone     Y" etc.
    // Or "is NOT an Opal compliant drive"
    if stdout_lower.contains("is not an opal") || stdout_lower.contains("not opal") {
        data.opal_supported = false;
        return data;
    }

    // Look for OPAL SSC indicators
    if stdout_lower.contains("opal")
        && (stdout_lower.contains("ssc") || stdout_lower.contains("compliant"))
    {
        data.opal_supported = true;
    }

    // Check locked state
    if stdout_lower.contains("locked = y") || stdout_lower.contains("locking enabled") {
        data.locked = true;
    }

    data
}

/// Parse mmc extcsd read output for eMMC sanitize support
pub fn parse_mmc_extcsd(stdout: &str) -> MmcData {
    let mut data = MmcData::default();

    // SEC_FEATURE_SUPPORT [EXT_CSD field 231]:
    // Bit 6 = Sanitize Support
    for line in stdout.lines() {
        let trimmed = line.trim().to_lowercase();

        if trimmed.contains("sec_feature_support") {
            // Parse the hex value
            if let Some(val_str) = trimmed.split("0x").nth(1) {
                let val_str = val_str.split(|c: char| !c.is_ascii_hexdigit()).next().unwrap_or("");
                if let Ok(val) = u32::from_str_radix(val_str, 16) {
                    data.sanitize_supported = (val & (1 << 6)) != 0;
                }
            }
        }

        // Also check explicit "sanitize" mention
        if trimmed.contains("sanitize") && trimmed.contains("supported") {
            data.sanitize_supported = true;
        }
    }

    data
}

// ---------------------------------------------------------------------------
// High-level probe function — shells out to real CLI tools
// ---------------------------------------------------------------------------

/// Run a CLI command and capture stdout. Returns Ok(stdout) or Err with stderr.
fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            if output.status.success() || !output.stdout.is_empty() {
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            } else {
                Err(format!(
                    "{} exited with code {:?}: {}",
                    program,
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr)
                ))
            }
        }
        Err(e) => Err(format!("Failed to execute {}: {}", program, e)),
    }
}

/// Probe all capabilities of a device by shelling out to smartctl, hdparm, nvme, sedutil, mmc.
///
/// Gracefully handles missing tools — records errors in `probe_errors` rather than failing.
pub fn probe_device(device_path: &str) -> DeviceCapabilities {
    let mut caps = DeviceCapabilities::new_unknown(device_path);

    // 1. smartctl -a --json
    match run_command("smartctl", &["-a", device_path, "--json"]) {
        Ok(stdout) => {
            let smart = parse_smartctl_json(&stdout);
            caps.smart_health = match smart.health_passed {
                Some(true) => SmartHealth::Passed,
                Some(false) => SmartHealth::Failed,
                None => SmartHealth::Unknown,
            };
            caps.wear_level_pct = smart.wear_level_pct;
            caps.reallocated_sectors = smart.reallocated_sectors;
            caps.temperature_celsius = smart.temperature;
            caps.power_on_hours = smart.power_on_hours;

            // Determine bus type from smartctl device type
            if let Some(ref dt) = smart.device_type {
                let dt_lower = dt.to_lowercase();
                if dt_lower.contains("nvme") {
                    caps.bus_type = BusType::NVMe;
                } else if dt_lower.contains("sat") || dt_lower.contains("ata") {
                    if smart.rotation_rate.unwrap_or(0) > 0 {
                        caps.bus_type = BusType::SATA; // HDD or SATA SSD without rotation = SSD
                    } else {
                        caps.bus_type = BusType::SATA;
                    }
                } else if dt_lower.contains("usb") || dt_lower.contains("scsi") {
                    caps.bus_type = BusType::USB;
                }
            }
        }
        Err(e) => caps.probe_errors.push(format!("smartctl: {}", e)),
    }

    // Determine which additional probes to run based on bus type
    let is_nvme = caps.bus_type == BusType::NVMe
        || device_path.contains("nvme");
    let is_emmc = caps.bus_type == BusType::EMMC
        || device_path.contains("mmcblk");

    // 2. hdparm -I (for ATA/SATA devices)
    if !is_nvme && !is_emmc {
        match run_command("hdparm", &["-I", device_path]) {
            Ok(stdout) => {
                let hdp = parse_hdparm_output(&stdout);
                caps.ata_security_supported = hdp.security_supported;
                caps.ata_security_enabled = hdp.security_enabled;
                caps.ata_security_frozen = hdp.security_frozen;
                caps.ata_security_locked = hdp.security_locked;
                caps.ata_enhanced_erase_supported = hdp.enhanced_erase_supported;
                caps.ata_enhanced_erase_time_min = hdp.enhanced_erase_time_min;
                caps.ata_normal_erase_time_min = hdp.normal_erase_time_min;
                caps.ata_sanitize_supported = hdp.sanitize_supported;
                caps.ata_sanitize_crypto_scramble = hdp.sanitize_crypto_scramble;
                caps.ata_sanitize_block_erase = hdp.sanitize_block_erase;
                caps.ata_sanitize_overwrite = hdp.sanitize_overwrite;

                // Estimate duration
                if let Some(mins) = hdp.enhanced_erase_time_min.or(hdp.normal_erase_time_min) {
                    caps.estimated_duration_class = if mins <= 1 {
                        DurationClass::Seconds
                    } else if mins <= 60 {
                        DurationClass::Minutes
                    } else {
                        DurationClass::Hours
                    };
                }
            }
            Err(e) => caps.probe_errors.push(format!("hdparm: {}", e)),
        }
    }

    // 3. nvme id-ctrl (for NVMe devices)
    if is_nvme {
        caps.bus_type = BusType::NVMe;
        match run_command("nvme", &["id-ctrl", device_path]) {
            Ok(stdout) => {
                let nvme = parse_nvme_id_ctrl(&stdout);
                caps.nvme_sanitize_supported = nvme.sanitize_supported;
                caps.nvme_sanitize_crypto_erase = nvme.crypto_erase_supported;
                caps.nvme_sanitize_block_erase = nvme.block_erase_supported;

                // NVMe sanitize is typically fast
                caps.estimated_duration_class = DurationClass::Minutes;
            }
            Err(e) => caps.probe_errors.push(format!("nvme: {}", e)),
        }
    }

    // 4. sedutil-cli --query (for TCG OPAL / SED detection)
    if !is_emmc {
        match run_command("sedutil-cli", &["--query", device_path]) {
            Ok(stdout) => {
                let sed = parse_sedutil_query(&stdout);
                caps.opal_supported = sed.opal_supported;
                caps.opal_locked = sed.locked;
            }
            Err(e) => caps.probe_errors.push(format!("sedutil-cli: {}", e)),
        }
    }

    // 5. mmc extcsd read (for eMMC devices)
    if is_emmc {
        caps.bus_type = BusType::EMMC;
        match run_command("mmc", &["extcsd", "read", device_path]) {
            Ok(stdout) => {
                let mmc = parse_mmc_extcsd(&stdout);
                caps.emmc_sanitize_supported = mmc.sanitize_supported;
                caps.estimated_duration_class = DurationClass::Minutes;
            }
            Err(e) => caps.probe_errors.push(format!("mmc: {}", e)),
        }
    }

    // 6. USB Link speed detection via sysfs
    let (usb_speed, is_u2) = detect_usb_speed(device_path, "/sys");
    if let Some(spd) = usb_speed {
        caps.usb_speed_mbps = Some(spd);
        caps.is_usb_2 = is_u2;
        if caps.bus_type == BusType::Unknown {
            caps.bus_type = BusType::USB;
        }
    }

    caps
}

/// Detect USB link speed from sysfs by traversing parent directory nodes from the block device.
pub fn detect_usb_speed(device_path: &str, sys_root: &str) -> (Option<u32>, bool) {
    let dev_name = device_path.rsplit('/').next().unwrap_or(device_path);
    let block_dir = Path::new(sys_root).join("class/block").join(dev_name);
    if let Ok(canon) = fs::canonicalize(&block_dir) {
        let mut curr = canon.parent();
        while let Some(parent) = curr {
            let speed_file = parent.join("speed");
            if speed_file.exists() {
                if let Ok(content) = fs::read_to_string(&speed_file) {
                    if let Ok(speed_num) = content.trim().parse::<u32>() {
                        let is_usb2 = speed_num <= 480;
                        return (Some(speed_num), is_usb2);
                    }
                }
            }
            curr = parent.parent();
        }
    }
    (None, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_unknown_has_all_defaults() {
        let caps = DeviceCapabilities::new_unknown("/dev/sda");
        assert_eq!(caps.device_path, "/dev/sda");
        assert_eq!(caps.bus_type, BusType::Unknown);
        assert_eq!(caps.smart_health, SmartHealth::Unknown);
        assert!(!caps.ata_security_supported);
        assert!(!caps.nvme_sanitize_supported);
        assert!(!caps.opal_supported);
        assert!(!caps.emmc_sanitize_supported);
        assert!(caps.probe_errors.is_empty());
    }

    #[test]
    fn test_parse_smartctl_empty_json() {
        let data = parse_smartctl_json("{}");
        assert_eq!(data.health_passed, None);
        assert_eq!(data.reallocated_sectors, 0);
    }

    #[test]
    fn test_parse_smartctl_invalid_json() {
        let data = parse_smartctl_json("not json at all");
        assert_eq!(data.health_passed, None);
    }

    #[test]
    fn test_parse_hdparm_empty() {
        let data = parse_hdparm_output("");
        assert!(!data.security_supported);
        assert!(!data.security_frozen);
    }

    #[test]
    fn test_parse_nvme_id_ctrl_empty() {
        let data = parse_nvme_id_ctrl("");
        assert!(!data.sanitize_supported);
    }

    #[test]
    fn test_parse_sedutil_not_opal() {
        let data = parse_sedutil_query("This device is NOT an Opal compliant drive");
        assert!(!data.opal_supported);
    }

    #[test]
    fn test_parse_mmc_empty() {
        let data = parse_mmc_extcsd("");
        assert!(!data.sanitize_supported);
    }
}
