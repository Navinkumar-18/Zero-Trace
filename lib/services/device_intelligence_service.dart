import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../models/device_profile.dart';
import '../models/partition_info.dart';
import '../models/untrusted_text.dart';
import 'device_simulator.dart';
import 'partition_table_service.dart';
import 'policy_layer.dart';

class DeviceIntelligenceService {
  final DeviceSimulator _simulator;

  /// Last error from a real-mode scan attempt, if any.
  /// Null when the last scan succeeded or in demo mode.
  String? lastScanError;

  DeviceIntelligenceService({DeviceSimulator? simulator})
      : _simulator = simulator ?? DeviceSimulator();

  Future<List<DeviceProfile>> discoverDevices({bool realMode = false}) async {
    if (!realMode) {
      lastScanError = null;
      return _simulator.getDevices();
    }

    // Real device detection path using Linux CLI (`lsblk`)
    // Only available on native Linux — not on web or other platforms.
    if (kIsWeb) {
      lastScanError = 'Real hardware detection requires native Linux mode (flutter run -d linux).\n'
          'Currently running in Web browser mode where raw block-device access is unavailable.';
      debugPrint('[DISCOVERY] $lastScanError');
      return [];
    }

    if (!Platform.isLinux) {
      lastScanError = 'Real hardware detection requires Linux.\n'
          'Current OS platform: ${Platform.operatingSystem}';
      debugPrint('[DISCOVERY] $lastScanError');
      return [];
    }

    try {
      debugPrint('[DISCOVERY] Running: lsblk -J -b -o NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,MOUNTPOINT,TYPE,RM,HOTPLUG,FSTYPE,LABEL,PARTUUID,START,PARTN,DISC-MAX,PTTYPE');
      final result = await Process.run('lsblk', [
        '-J',
        '-b',
        '-o',
        'NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,MOUNTPOINT,TYPE,RM,HOTPLUG,FSTYPE,LABEL,PARTUUID,START,PARTN,DISC-MAX,PTTYPE'
      ]);

      if (result.exitCode != 0) {
        lastScanError = 'lsblk exited with code ${result.exitCode}: ${result.stderr}';
        debugPrint('[DISCOVERY ERROR] $lastScanError');
        return [];
      }

      final stdoutStr = result.stdout as String? ?? '';
      debugPrint('[DISCOVERY RAW STDOUT] $stdoutStr');

      if (stdoutStr.trim().isEmpty) {
        lastScanError = 'lsblk returned empty output';
        debugPrint('[DISCOVERY ERROR] $lastScanError');
        return [];
      }

      final Map<String, dynamic> parsed = jsonDecode(result.stdout as String);
      final List<dynamic> devicesJson = parsed['blockdevices'] ?? [];
      return parseBlockDevices(devicesJson);
    } catch (e) {
      lastScanError = e.toString();
      debugPrint('[DISCOVERY ERROR EXCEPTION] $e');
      return [];
    }
  }

  /// Parses block devices list from lsblk JSON into DeviceProfile models.
  List<DeviceProfile> parseBlockDevices(List<dynamic> devicesJson) {
    final List<DeviceProfile> detectedProfiles = [];

    for (final dev in devicesJson) {
      final type = (dev['type'] as String?)?.toLowerCase();
      String? unsupportedReason;
      if (type == 'rom' || type == 'optical') {
        unsupportedReason = 'Optical disc drive – not supported';
      } else if (type == 'raid' || type == 'md') {
        unsupportedReason = 'RAID array member/volume – not supported';
      } else if (type != null && type.isNotEmpty && type != 'disk') {
        continue;
      }

      final rawName = dev['name'] as String? ?? 'unknown';
      final size = (dev['size'] as num?)?.toInt() ?? 0;
      if (size <= 0 && rawName == 'unknown') continue;

      final modelStr = (dev['model'] as String?)?.trim();
      final name = (modelStr != null && modelStr.isNotEmpty) ? modelStr : 'Storage Device ($rawName)';
      final serial = (dev['serial'] as String?)?.trim() ?? 'S/N-$rawName';
      
      final isRotational = (dev['rota'] as bool?) ?? false;
      final tran = (dev['tran'] as String?)?.toUpperCase() ?? '';
      
      final isRm = dev['rm'] == true || dev['rm'] == 1 || dev['rm'] == '1';
      final isHotplug = dev['hotplug'] == true || dev['hotplug'] == 1 || dev['hotplug'] == '1';

      // A1: kernel discard/TRIM support (lsblk DISC-MAX in bytes; 0 = none).
      final discMax = (dev['disc-max'] as num?)?.toInt();
      // A2: partition table type (lsblk PTTYPE: "gpt", "dos", "none", ...).
      final ptType = (dev['pttype'] as String?)?.trim();
      
      // Filesystem and Partition detection
      final mainFsType = (dev['fstype'] as String?)?.trim();
      final mainMountPoint = (dev['mountpoint'] as String?)?.trim();
      final children = dev['children'] as List<dynamic>?;

      bool isSys = false;
      bool isLiveMedia = false;
      String? systemMountPoint;
      bool hasFilesystem = (mainFsType != null && mainFsType.isNotEmpty) ||
          (mainMountPoint != null && mainMountPoint.isNotEmpty);
      String? detectedFsType = mainFsType;

      final List<PartitionInfo> childPartitions = [];

      if (children != null && children.isNotEmpty) {
        for (final child in children) {
          final childType = (child['type'] as String?)?.toLowerCase();
          final childName = (child['name'] as String?)?.trim() ?? '';
          final mp = (child['mountpoint'] as String?)?.trim();
          final childFs = (child['fstype'] as String?)?.trim();
          final childSize = (child['size'] as num?)?.toInt() ?? 0;
          final childStart = (child['start'] as num?)?.toInt() ?? 0;
          final childPartn = (child['partn'] as num?)?.toInt() ?? _extractPartNumber(childName);
          final rawLabel = (child['label'] as String?)?.trim() ?? '';
          final childPartUuid = (child['partuuid'] as String?)?.trim();

          final bool isMounted = mp != null && mp.isNotEmpty;
          final bool isMountAllowed = isMounted && PolicyLayer.isMountUnmountable(mp);
          final bool isLive = mp != null && _isLiveMediaMount(mp);
          final bool isProtected = isLive ||
              (isMounted && !PolicyLayer.isMountUnmountable(mp)) ||
              childFs == 'swap';
          final bool isActiveSwap = childFs == 'swap';

          if (mp != null && mp.isNotEmpty) {
            // Phase 1 boot-guard: detect live-USB/live-media mounts
            if (isLive) {
              isLiveMedia = true;
              isSys = true;
              systemMountPoint = mp;
            } else if (!isMountAllowed) {
              isSys = true;
              systemMountPoint = mp;
            }
          }
          if (childFs == 'swap') {
            isSys = true;
            systemMountPoint = '[SWAP]';
          }
          if ((childFs != null && childFs.isNotEmpty) || isMounted) {
            hasFilesystem = true;
            if (childFs != null && childFs.isNotEmpty && (detectedFsType == null || detectedFsType.isEmpty)) {
              detectedFsType = childFs;
            }
          }

          // Build PartitionInfo if child represents a partition or disk slice
          if (childName.isNotEmpty && (childType == null || childType == 'part' || childType.isEmpty)) {
            final devPath = childName.startsWith('/') ? childName : '/dev/$childName';
            final sizeSectors = childSize ~/ 512;

            childPartitions.add(PartitionInfo(
              partitionNumber: childPartn,
              name: childName,
              devicePath: devPath,
              startSector: childStart,
              sizeSectors: sizeSectors,
              sizeBytes: childSize,
              label: UntrustedText(rawLabel),
              partUuid: (childPartUuid != null && childPartUuid.isNotEmpty) ? childPartUuid : null,
              fsType: (childFs != null && childFs.isNotEmpty) ? childFs : null,
              mountPoint: (mp != null && mp.isNotEmpty) ? mp : null,
              isMounted: isMounted,
              isMountAllowed: isMountAllowed,
              isProtected: isProtected,
              isActiveSwap: isActiveSwap,
            ));
          }
        }
      }

      final bool isWipedNoFilesystem = !hasFilesystem && (children == null || children.isEmpty);

      // Removable = sysfs RM flag OR hotplug flag OR USB bus.
      // Internal eMMC is NOT removable (RM=false, hotplug=false, tran=MMC).
      final bool removable = isRm || isHotplug || tran.contains('USB');

      MediaType mediaType = MediaType.unknown;
      if (tran.contains('USB') || isRm || isHotplug) {
        mediaType = MediaType.usbFlash;
      } else if (isRotational) {
        mediaType = MediaType.hdd;
      } else if (tran.contains('NVME') || rawName.startsWith('nvme')) {
        mediaType = MediaType.nvmeSsd;
      } else if (tran.contains('MMC') || rawName.startsWith('mmcblk')) {
        mediaType = MediaType.emmc;
      } else if (unsupportedReason != null) {
        mediaType = MediaType.unknown;
      } else {
        mediaType = MediaType.sataSsd;
      }

      final busDisplay = tran.isNotEmpty
          ? tran
          : (isRm || isHotplug ? 'USB / Removable' : 'SATA/PCIe');

      final tableFingerprint = childPartitions.isNotEmpty
          ? PartitionTableService.computeFingerprint(childPartitions)
          : null;

      detectedProfiles.add(
        DeviceProfile(
          id: 'real_$rawName',
          name: name,
          serialNumber: serial,
          mediaType: mediaType,
          busType: busDisplay,
          capacityBytes: size,
          rotationalRpm: null, // lsblk does not provide rotational speed (RPM)
          isHardwareEncrypted: mediaType == MediaType.nvmeSsd || mediaType == MediaType.sataSsd,
          supportsAtaSecureErase: mediaType == MediaType.sataSsd || mediaType == MediaType.hdd,
          supportsAtaSanitize: mediaType == MediaType.sataSsd,
          supportsNvmeSanitize: mediaType == MediaType.nvmeSsd,
          supportsEmmcSanitize: mediaType == MediaType.emmc,
          // A1: prefer the kernel's real discard capability (DISC-MAX);
          // fall back to the media heuristic when lsblk lacks the column.
          supportsTrim: discMax != null ? discMax > 0 : mediaType != MediaType.hdd,
          hpaDcoPresent: false,
          mountPoint: systemMountPoint ?? mainMountPoint,
          isSystemDisk: isSys,
          hasFilesystem: hasFilesystem,
          fsType: detectedFsType,
          isWipedNoFilesystem: isWipedNoFilesystem,
          isRemovable: removable,
          disabledReason: unsupportedReason,
          partitions: childPartitions,
          partitionTableFingerprint: tableFingerprint,
          partitionTableType: (ptType != null && ptType.isNotEmpty && ptType != 'none') ? ptType : null,
          notes: isWipedNoFilesystem
              ? 'SANITIZED / NO FILESYSTEM (Raw Block Device)'
              : (isLiveMedia
                  ? 'LIVE MEDIA DISK (Protected against destruction)'
                  : (isSys
                      ? 'REAL SYSTEM DISK (Protected against destruction)'
                      : (removable
                          ? 'REAL REMOVABLE STORAGE DEVICE'
                          : 'REAL CONNECTED STORAGE DEVICE'))),
        ),
      );
    }

    return detectedProfiles;
  }

  /// Check for live-media mount paths (Phase 1 boot-guard matching).
  static bool _isLiveMediaMount(String mountPoint) {
    final mp = mountPoint.trim();
    return mp.startsWith('/run/live') ||
        mp.startsWith('/run/archiso') ||
        mp.startsWith('/run/initramfs') ||
        mp.contains('/live/medium') ||
        mp.contains('/casper/');
  }

  /// Extracts trailing integer digits from a partition name (e.g. "sda1" -> 1, "nvme0n1p2" -> 2).
  static int _extractPartNumber(String name) {
    final match = RegExp(r'(\d+)$').firstMatch(name);
    if (match != null) {
      return int.tryParse(match.group(1)!) ?? 1;
    }
    return 1;
  }
}
