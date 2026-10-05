import 'untrusted_text.dart';

/// Information about a single partition discovered on a storage device.
class PartitionInfo {
  final int partitionNumber;
  final String name; // e.g. "sdb1" or "nvme0n1p1"
  final String devicePath; // e.g. "/dev/sdb1"
  final int startSector; // 512-byte LBA sector offset
  final int sizeSectors; // Size in 512-byte sectors
  final int sizeBytes;
  final UntrustedText label; // Untrusted filesystem/partition label
  final String? partUuid;
  final String? fsType;
  final String? mountPoint;
  final bool isMounted;
  final bool isMountAllowed;
  final bool isProtected;
  final bool isActiveSwap;

  const PartitionInfo({
    required this.partitionNumber,
    required this.name,
    required this.devicePath,
    required this.startSector,
    required this.sizeSectors,
    required this.sizeBytes,
    required this.label,
    this.partUuid,
    this.fsType,
    this.mountPoint,
    this.isMounted = false,
    this.isMountAllowed = false,
    this.isProtected = false,
    this.isActiveSwap = false,
  });

  String get formattedSize {
    final double gb = sizeBytes / (1024 * 1024 * 1024);
    if (gb >= 1000) {
      final double tb = gb / 1024;
      return '${tb.toStringAsFixed(1)} TB';
    }
    if (gb >= 1.0) {
      return '${gb.toStringAsFixed(1)} GB';
    }
    final double mb = sizeBytes / (1024 * 1024);
    return '${mb.toStringAsFixed(0)} MB';
  }

  Map<String, dynamic> toJson() => {
    'partitionNumber': partitionNumber,
    'name': name,
    'devicePath': devicePath,
    'startSector': startSector,
    'sizeSectors': sizeSectors,
    'sizeBytes': sizeBytes,
    'label': label.rawValue,
    'partUuid': partUuid,
    'fsType': fsType,
    'mountPoint': mountPoint,
    'isMounted': isMounted,
    'isMountAllowed': isMountAllowed,
    'isProtected': isProtected,
    'isActiveSwap': isActiveSwap,
  };

  factory PartitionInfo.fromJson(Map<String, dynamic> json) {
    return PartitionInfo(
      partitionNumber: json['partitionNumber'] as int? ?? 1,
      name: json['name'] as String? ?? '',
      devicePath: json['devicePath'] as String? ?? '',
      startSector: (json['startSector'] as num? ?? 0).toInt(),
      sizeSectors: (json['sizeSectors'] as num? ?? 0).toInt(),
      sizeBytes: (json['sizeBytes'] as num? ?? 0).toInt(),
      label: UntrustedText(json['label'] as String? ?? ''),
      partUuid: json['partUuid'] as String?,
      fsType: json['fsType'] as String?,
      mountPoint: json['mountPoint'] as String?,
      isMounted: (json['isMounted'] as bool?) ?? false,
      isMountAllowed: (json['isMountAllowed'] as bool?) ?? false,
      isProtected: (json['isProtected'] as bool?) ?? false,
      isActiveSwap: (json['isActiveSwap'] as bool?) ?? false,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PartitionInfo &&
          runtimeType == other.runtimeType &&
          partitionNumber == other.partitionNumber &&
          name == other.name &&
          startSector == other.startSector &&
          sizeSectors == other.sizeSectors;

  @override
  int get hashCode => Object.hash(partitionNumber, name, startSector, sizeSectors);
}
