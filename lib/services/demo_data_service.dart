/// Demo data service for Zero Trace 2.0
/// Provides mock recent operations, certificates, and stats for the Dashboard.
/// Used only in demo mode — no real device operations.

import '../models/device_profile.dart';

class DemoOperation {
  final String deviceName;
  final String mediaType;
  final String method;
  final String status; // 'Verified', 'Failed', 'Insufficient Assurance', 'Pending'
  final DateTime timestamp;
  final String? certificateId;

  const DemoOperation({
    required this.deviceName,
    required this.mediaType,
    required this.method,
    required this.status,
    required this.timestamp,
    this.certificateId,
  });
}

class DemoStats {
  final int totalDevices;
  final int readyDevices;
  final int attentionDevices;
  final int completedSanitizations;
  final int verifiedCount;
  final int certificatesGenerated;
  final int totalStorageGb;

  const DemoStats({
    required this.totalDevices,
    required this.readyDevices,
    required this.attentionDevices,
    required this.completedSanitizations,
    required this.verifiedCount,
    required this.certificatesGenerated,
    required this.totalStorageGb,
  });
}

class DemoDataService {
  List<DemoOperation> getRecentOperations() {
    final now = DateTime.now();
    return [
      DemoOperation(
        deviceName: 'Samsung 870 EVO 500GB',
        mediaType: 'SATA SSD',
        method: 'ATA Sanitize Block Erase',
        status: 'Verified',
        timestamp: now.subtract(const Duration(hours: 2)),
        certificateId: 'ZT-CERT-00142',
      ),
      DemoOperation(
        deviceName: 'Seagate Barracuda ST2000DM008',
        mediaType: 'HDD',
        method: 'ATA Secure Erase',
        status: 'Verified',
        timestamp: now.subtract(const Duration(hours: 5)),
        certificateId: 'ZT-CERT-00141',
      ),
      DemoOperation(
        deviceName: 'WD Black SN850X 1TB',
        mediaType: 'NVMe',
        method: 'NVMe Sanitize',
        status: 'Verified',
        timestamp: now.subtract(const Duration(days: 1)),
        certificateId: 'ZT-CERT-00140',
      ),
      DemoOperation(
        deviceName: 'Generic USB Flash Drive 16GB',
        mediaType: 'USB',
        method: 'N/A',
        status: 'Insufficient Assurance',
        timestamp: now.subtract(const Duration(days: 1, hours: 3)),
      ),
      DemoOperation(
        deviceName: 'SanDisk DF4064 eMMC 64GB',
        mediaType: 'eMMC',
        method: 'eMMC Sanitize',
        status: 'Verified',
        timestamp: now.subtract(const Duration(days: 2)),
        certificateId: 'ZT-CERT-00139',
      ),
    ];
  }

  DemoStats getStats(List<DeviceProfile> devices) {
    final totalCapacityBytes = devices.fold<int>(0, (sum, d) => sum + d.capacityBytes);
    final totalGb = (totalCapacityBytes / (1024 * 1024 * 1024)).round();
    final attention = devices.where((d) =>
        d.isSystemDisk ||
        d.hpaDcoPresent ||
        (!d.supportsAtaSanitize &&
            !d.supportsNvmeSanitize &&
            !d.supportsEmmcSanitize &&
            !d.supportsAtaSecureErase &&
            !d.isHardwareEncrypted)).length;

    return DemoStats(
      totalDevices: devices.length,
      readyDevices: devices.length - attention,
      attentionDevices: attention,
      completedSanitizations: 12,
      verifiedCount: 10,
      certificatesGenerated: 10,
      totalStorageGb: totalGb,
    );
  }
}
