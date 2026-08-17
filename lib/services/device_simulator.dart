import '../models/device_profile.dart';

class DeviceSimulator {
  static final List<DeviceProfile> defaultProfiles = [
    const DeviceProfile(
      id: 'sim_hdd_01',
      name: 'Seagate Barracuda ST2000DM008',
      serialNumber: 'ZAC4891X',
      mediaType: MediaType.hdd,
      busType: 'SATA 6.0 Gb/s',
      capacityBytes: 2000398934016, // 2 TB
      rotationalRpm: 7200,
      isHardwareEncrypted: false,
      supportsAtaSecureErase: true,
      supportsAtaSanitize: false,
      supportsNvmeSanitize: false,
      supportsEmmcSanitize: false,
      supportsTrim: false,
      hpaDcoPresent: false,
      mountPoint: null,
      isSystemDisk: false,
      notes: 'Standard magnetic platter hard drive with ATA Secure Erase support.',
    ),
    const DeviceProfile(
      id: 'sim_sata_ssd_02',
      name: 'Samsung 870 EVO 500GB',
      serialNumber: 'S5YFNG0R102934',
      mediaType: MediaType.sataSsd,
      busType: 'SATA 6.0 Gb/s',
      capacityBytes: 500107862016, // 500 GB
      rotationalRpm: 0,
      isHardwareEncrypted: true,
      supportsAtaSecureErase: true,
      supportsAtaSanitize: true,
      supportsNvmeSanitize: false,
      supportsEmmcSanitize: false,
      supportsTrim: true,
      hpaDcoPresent: false,
      mountPoint: null,
      isSystemDisk: false,
      notes: 'SATA Solid State Drive with TCG OPAL 2.0 Encryption & ATA Sanitize Block Erase.',
    ),
    const DeviceProfile(
      id: 'sim_nvme_ssd_03',
      name: 'Western Digital Black SN850X 1TB',
      serialNumber: '213829801942',
      mediaType: MediaType.nvmeSsd,
      busType: 'PCIe Gen4 x4 NVMe',
      capacityBytes: 1000204886016, // 1 TB
      rotationalRpm: 0,
      isHardwareEncrypted: true,
      supportsAtaSecureErase: false,
      supportsAtaSanitize: false,
      supportsNvmeSanitize: true,
      supportsEmmcSanitize: false,
      supportsTrim: true,
      hpaDcoPresent: false,
      mountPoint: null,
      isSystemDisk: false,
      notes: 'High-speed NVMe 1.4 SSD with Block Erase & Cryptographic Erase support.',
    ),
    const DeviceProfile(
      id: 'sim_emmc_04',
      name: 'SanDisk DF4064 eMMC 64GB',
      serialNumber: 'EMMC64G-99A1',
      mediaType: MediaType.emmc,
      busType: 'eMMC 5.1',
      capacityBytes: 64424509440, // 64 GB
      rotationalRpm: 0,
      isHardwareEncrypted: false,
      supportsAtaSecureErase: false,
      supportsAtaSanitize: false,
      supportsNvmeSanitize: false,
      supportsEmmcSanitize: true,
      supportsTrim: true,
      hpaDcoPresent: false,
      mountPoint: null,
      isSystemDisk: false,
      notes: 'Embedded MultiMediaCard found in low-power laptop/thin-client board.',
    ),
    const DeviceProfile(
      id: 'sim_usb_unsupported_05',
      name: 'Generic Legacy USB Flash Drive 16GB',
      serialNumber: 'USB-LEGACY-007',
      mediaType: MediaType.usbFlash,
      busType: 'USB 2.0',
      capacityBytes: 16106127360, // 16 GB
      rotationalRpm: 0,
      isHardwareEncrypted: false,
      supportsAtaSecureErase: false,
      supportsAtaSanitize: false,
      supportsNvmeSanitize: false,
      supportsEmmcSanitize: false,
      supportsTrim: false,
      hpaDcoPresent: true, // Triggers security warning
      mountPoint: null,
      isSystemDisk: false,
      notes: 'Legacy controller without hardware sanitize primitives. Flagged for physical destruction under high risk.',
    ),
  ];

  List<DeviceProfile> _profiles = List.from(defaultProfiles);

  List<DeviceProfile> getDevices() {
    return List.unmodifiable(_profiles);
  }

  DeviceProfile? getDeviceById(String id) {
    try {
      return _profiles.firstWhere((p) => p.id == id);
    } catch (_) {
      return null;
    }
  }

  void resetProfiles() {
    _profiles = List.from(defaultProfiles);
  }

  void addCustomSimulatedDevice(DeviceProfile profile) {
    _profiles.add(profile);
  }
}
