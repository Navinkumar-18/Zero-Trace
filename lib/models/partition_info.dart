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

  /// B1: partition type identifier from the table — canonical GPT type GUID
  /// ("c12a7328-…") or an MBR type token ("0x7").
  final String? partTypeGuid;

  /// B1: friendly partition type name — "EFI System", "Microsoft Reserved",
  /// "Microsoft Basic Data", "Windows Recovery", …
  final String? partTypeName;

  /// B1: stable role token — "efi_system" | "msr" | "windows_data" |
  /// "windows_recovery" | "linux" | "linux_swap" | "luks" | …
  final String? role;

  /// B2: "BitLocker" | "LUKS" when the volume carries an encryption
  /// signature. Wiping works regardless — the UI must tell the user.
  final String? encryptionKind;

  /// B1: used space in bytes when readable read-only (lsblk FSUSED for
  /// mounted volumes, engine probe otherwise).
  final int? usedBytes;

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
    this.partTypeGuid,
    this.partTypeName,
    this.role,
    this.encryptionKind,
    this.usedBytes,
  });

  /// Human-readable byte size (B1: shared by the friendly-name builder).
  static String formatBytes(int bytes) {
    final double gb = bytes / (1024 * 1024 * 1024);
    if (gb >= 1000) {
      final double tb = gb / 1024;
      return '${tb.toStringAsFixed(1)} TB';
    }
    if (gb >= 1.0) {
      return '${gb.toStringAsFixed(1)} GB';
    }
    final double mb = bytes / (1024 * 1024);
    return '${mb.toStringAsFixed(0)} MB';
  }

  String get formattedSize => formatBytes(sizeBytes);

  // -------------------------------------------------------------------------
  // B1: partition-type classification (Dart mirror of the Rust engine registry)
  // -------------------------------------------------------------------------

  /// GPT type GUID → friendly name. Mirrors `GPT_TYPE_REGISTRY` in the Rust
  /// engine (`native/zt_engine/src/partitions.rs`); used when the engine
  /// binary is unavailable so labels stay identical either way.
  static const Map<String, String> gptTypeNames = {
    'c12a7328-f81f-11d2-ba4b-00a0c93ec93b': 'EFI System',
    'e3c9e316-0b5c-4db8-817d-f92df00215ae': 'Microsoft Reserved',
    'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7': 'Microsoft Basic Data',
    'de94bba4-06d1-4d40-a16a-bfd50179d6ac': 'Windows Recovery',
    '0fc63daf-8483-4772-8e79-3d69d8477de4': 'Linux Filesystem',
    '0657fd6d-a4ab-43c4-84e5-0933c84b4f4f': 'Linux Swap',
    'e6d6d379-f507-44c2-a23c-238f2a3df928': 'Linux LVM',
    'a19d880f-05fc-4d3b-a006-743f0f84911e': 'Linux RAID',
    '7ffec5c9-2d00-49b7-8941-3ea10a5586b7': 'Linux dm-crypt',
    'ca7d7ccb-63ed-4c53-861c-1742536059cc': 'LUKS',
    '21686148-6449-6e6f-744e-656564454649': 'BIOS Boot',
  };

  /// GPT type GUID → role token (same keys as [gptTypeNames]).
  static const Map<String, String> gptTypeRoles = {
    'c12a7328-f81f-11d2-ba4b-00a0c93ec93b': 'efi_system',
    'e3c9e316-0b5c-4db8-817d-f92df00215ae': 'msr',
    'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7': 'windows_data',
    'de94bba4-06d1-4d40-a16a-bfd50179d6ac': 'windows_recovery',
    '0fc63daf-8483-4772-8e79-3d69d8477de4': 'linux',
    '0657fd6d-a4ab-43c4-84e5-0933c84b4f4f': 'linux_swap',
    'e6d6d379-f507-44c2-a23c-238f2a3df928': 'linux_lvm',
    'a19d880f-05fc-4d3b-a006-743f0f84911e': 'linux_raid',
    '7ffec5c9-2d00-49b7-8941-3ea10a5586b7': 'linux_crypt',
    'ca7d7ccb-63ed-4c53-861c-1742536059cc': 'luks',
    '21686148-6449-6e6f-744e-656564454649': 'bios_boot',
  };

  /// Rebuild the canonical dashed GUID from a 32-char hex string.
  static String dashGuid(String hex32) =>
      '${hex32.substring(0, 8)}-${hex32.substring(8, 12)}-${hex32.substring(12, 16)}'
      '-${hex32.substring(16, 20)}-${hex32.substring(20, 32)}';

  /// B1: derive `(type name, role)` from an lsblk PARTTYPE token — a GPT
  /// type GUID or an MBR type byte ("0x7") — refined by the filesystem
  /// signature. Mirrors the Rust engine's `classify_gpt_guid` /
  /// `classify_mbr_partition`. Returns `(null, null)` when unidentifiable.
  static (String?, String?) classifyTypeToken(String? rawType, {String? fsType}) {
    final fs = fsType?.trim().toLowerCase();
    final hasFs = fs != null && fs.isNotEmpty;

    final raw = rawType?.trim().toLowerCase() ?? '';
    if (raw.isEmpty) return _classifyFsOnly(fs);

    final token = raw.startsWith('0x') ? raw.substring(2) : raw;
    final hex32 = token.replaceAll('{', '').replaceAll('}', '').replaceAll('-', '');

    // GPT type GUID (32 hex chars, dashed or braced in some udev versions).
    if (RegExp(r'^[0-9a-f]{32}$').hasMatch(hex32)) {
      final guid = dashGuid(hex32);
      final name = gptTypeNames[guid];
      final role = gptTypeRoles[guid];
      if (name != null) return (name, role);
      // Unknown GUID: keep the raw identifier visible, role stays unknown.
      return (guid, 'unknown');
    }

    // MBR partition type byte — fs signature wins on contradiction
    // (a 0x07 entry actually holding ext4 is a Linux volume).
    final byte = int.tryParse(token, radix: 16);
    if (byte != null && byte <= 0xff) {
      if (hasFs &&
          (fs.startsWith('ext') ||
              fs == 'btrfs' ||
              fs == 'xfs' ||
              fs == 'f2fs')) {
        return ('Linux ($fs)', 'linux');
      }
      if (fs == 'swap') return ('Linux Swap', 'linux_swap');
      if (fs == 'ntfs' ||
          fs == 'exfat' ||
          fs == 'fat32' ||
          fs == 'fat16' ||
          fs == 'fat12') {
        final byByte = _mbrType(byte);
        if (byByte != null &&
            (byByte.$2 == 'windows_data' ||
                byByte.$2 == 'windows_recovery' ||
                byByte.$2 == 'efi_system')) {
          return byByte;
        }
        return ('Windows volume', 'windows_data');
      }
      return _mbrType(byte) ?? _classifyFsOnly(fs);
    }

    return _classifyFsOnly(fs);
  }

  /// MBR type byte → (name, role), mirroring `classify_mbr_type` in Rust.
  static (String, String)? _mbrType(int byte) {
    switch (byte) {
      case 0x07:
        return ('Windows NTFS/exFAT', 'windows_data');
      case 0x0b:
      case 0x0c:
        return ('Windows FAT32', 'windows_data');
      case 0x06:
      case 0x0e:
        return ('Windows FAT16', 'windows_data');
      case 0xef:
        return ('EFI System', 'efi_system');
      case 0x27:
        return ('Windows Recovery', 'windows_recovery');
      case 0x83:
        return ('Linux', 'linux');
      case 0x82:
        return ('Linux Swap', 'linux_swap');
      case 0x8e:
        return ('Linux LVM', 'linux_lvm');
      case 0xfd:
        return ('Linux dm-crypt', 'linux_crypt');
      case 0x05:
      case 0x0f:
        return ('Extended partition', 'extended');
      case 0xee:
        return ('Protective GPT', 'protective');
      default:
        return null;
    }
  }

  /// Filesystem-only fallback when the type token is missing/unreadable.
  static (String?, String?) _classifyFsOnly(String? fs) {
    switch (fs) {
      case 'ntfs':
      case 'exfat':
      case 'fat32':
      case 'fat16':
      case 'fat12':
        return ('Windows volume', 'windows_data');
      case 'swap':
        return ('Linux Swap', 'linux_swap');
      case 'bitlocker':
        return ('Windows volume', 'windows_data');
      case 'crypto_luks':
        return ('LUKS', 'luks');
      case null:
      case '':
        return (null, null);
    }
    if (fs.startsWith('ext') || fs == 'btrfs' || fs == 'xfs' || fs == 'f2fs') {
      return ('Linux ($fs)', 'linux');
    }
    return (null, null);
  }

  // -------------------------------------------------------------------------
  // B1/B2: display
  // -------------------------------------------------------------------------

  /// B1: Windows-friendly display name. Never invents drive letters — Linux
  /// cannot know them reliably. Volume label + size + fs stay visible in
  /// [detailLine] so C: vs D: stays recognizable.
  String get friendlyDisplayName {
    switch (role) {
      case 'efi_system':
        return 'EFI System';
      case 'msr':
        return 'Microsoft Reserved';
      case 'bios_boot':
        return 'BIOS Boot';
      case 'windows_recovery':
        return 'Recovery';
      case 'windows_data':
        final fs = fsType;
        if (fs != null && fs.isNotEmpty) {
          return 'Windows volume (${fs.toUpperCase()}, $formattedSize)';
        }
        return 'Windows volume ($formattedSize)';
      case 'luks':
      case 'linux_crypt':
        final enc = encryptionKind;
        if (enc != null) {
          return 'Encrypted volume ($enc, $formattedSize)';
        }
        return partTypeName ?? 'Partition $partitionNumber';
    }
    final lbl = label.sanitized;
    if (lbl.isNotEmpty) return lbl;
    final typeName = partTypeName;
    if (typeName != null && typeName.isNotEmpty && typeName != 'Unknown') {
      return typeName;
    }
    return 'Partition $partitionNumber';
  }

  /// B1/B2: secondary row text — label, filesystem, size, used space,
  /// encryption and mountpoint, minus whatever [friendlyDisplayName] already
  /// shows.
  String get detailLine {
    final bits = <String>[];
    final title = friendlyDisplayName;
    final lbl = label.sanitized;
    if (lbl.isNotEmpty && lbl != title) bits.add(lbl);
    final fs = fsType;
    if (fs != null && fs.isNotEmpty && !title.contains(fs.toUpperCase())) {
      bits.add(fs.toUpperCase());
    }
    if (!title.contains(formattedSize)) bits.add(formattedSize);
    final used = usedBytes;
    if (used != null) bits.add('${formatBytes(used)} used');
    final enc = encryptionKind;
    if (enc != null) bits.add('$enc (encrypted)');
    final mp = mountPoint;
    if (mp != null && mp.isNotEmpty) bits.add(mp);
    if (bits.isEmpty) return devicePath;
    return bits.join(' • ');
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
    if (partTypeGuid != null) 'partTypeGuid': partTypeGuid,
    if (partTypeName != null) 'partTypeName': partTypeName,
    if (role != null) 'role': role,
    if (encryptionKind != null) 'encryptionKind': encryptionKind,
    if (usedBytes != null) 'usedBytes': usedBytes,
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
      partTypeGuid: json['partTypeGuid'] as String?,
      partTypeName: json['partTypeName'] as String?,
      role: json['role'] as String?,
      encryptionKind: json['encryptionKind'] as String?,
      usedBytes: (json['usedBytes'] as num?)?.toInt(),
    );
  }

  /// A3: mount points that make a partition a system partition.
  static const Set<String> systemMountPoints = {
    '/', '/boot', '/boot/efi', '/usr', '/var', '/home',
  };

  /// Whether this partition holds a system path (/, /boot, /usr, ...).
  bool get isSystemPartition =>
      mountPoint != null && systemMountPoints.contains(mountPoint);

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
