import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';

import '../models/device_profile.dart';
import 'device_simulator.dart';

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
      debugPrint('[DISCOVERY] Running: lsblk -J -b -o NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,MOUNTPOINT,TYPE,RM,HOTPLUG');
      final result = await Process.run('lsblk', [
        '-J',
        '-b',
        '-o',
        'NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,MOUNTPOINT,TYPE,RM,HOTPLUG'
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
      final List<DeviceProfile> detectedProfiles = [];

      for (final dev in devicesJson) {
        final type = dev['type'] as String?;
        if (type == 'disk') {
          final rawName = dev['name'] as String? ?? 'unknown';
          final modelStr = (dev['model'] as String?)?.trim();
          final name = (modelStr != null && modelStr.isNotEmpty) ? modelStr : 'Storage Device ($rawName)';
          final serial = (dev['serial'] as String?)?.trim() ?? 'S/N-$rawName';
          
          // Safe size parsing (num cast to int)
          final size = (dev['size'] as num?)?.toInt() ?? 0;
          final isRotational = (dev['rota'] as bool?) ?? false;
          final tran = (dev['tran'] as String?)?.toUpperCase() ?? '';
          
          final isRm = dev['rm'] == true || dev['rm'] == 1 || dev['rm'] == '1';
          final isHotplug = dev['hotplug'] == true || dev['hotplug'] == 1 || dev['hotplug'] == '1';
          
          // Check if any partition matches system root / boot
          bool isSys = false;
          String? systemMountPoint;

          final children = dev['children'] as List<dynamic>?;
          if (children != null) {
            for (final child in children) {
              final mp = child['mountpoint'] as String?;
              if (mp == '/' || mp == '/boot' || mp == '/boot/efi') {
                isSys = true;
                systemMountPoint = mp;
                break;
              }
            }
          }

          MediaType mediaType = MediaType.unknown;
          if (tran.contains('USB') || isRm || isHotplug) {
            mediaType = MediaType.usbFlash;
          } else if (isRotational) {
            mediaType = MediaType.hdd;
          } else if (tran.contains('NVME') || rawName.startsWith('nvme')) {
            mediaType = MediaType.nvmeSsd;
          } else if (tran.contains('MMC') || rawName.startsWith('mmcblk')) {
            mediaType = MediaType.emmc;
          } else {
            mediaType = MediaType.sataSsd;
          }

          final busDisplay = tran.isNotEmpty
              ? tran
              : (isRm || isHotplug ? 'USB / Removable' : 'SATA/PCIe');

          detectedProfiles.add(
            DeviceProfile(
              id: 'real_$rawName',
              name: name,
              serialNumber: serial,
              mediaType: mediaType,
              busType: busDisplay,
              capacityBytes: size,
              rotationalRpm: isRotational ? 5400 : 0,
              isHardwareEncrypted: mediaType == MediaType.nvmeSsd || mediaType == MediaType.sataSsd,
              supportsAtaSecureErase: mediaType == MediaType.sataSsd || mediaType == MediaType.hdd,
              supportsAtaSanitize: mediaType == MediaType.sataSsd,
              supportsNvmeSanitize: mediaType == MediaType.nvmeSsd,
              supportsEmmcSanitize: mediaType == MediaType.emmc,
              supportsTrim: mediaType != MediaType.hdd,
              hpaDcoPresent: false,
              mountPoint: systemMountPoint,
              isSystemDisk: isSys,
              notes: isSys
                  ? 'REAL SYSTEM DISK (Protected against destruction)'
                  : (isRm || mediaType == MediaType.usbFlash
                      ? 'REAL REMOVABLE STORAGE DEVICE'
                      : 'REAL CONNECTED STORAGE DEVICE'),
            ),
          );
        }
      }

      lastScanError = null;
      return detectedProfiles;
    } catch (e) {
      lastScanError = 'Device scan failed: $e';
      return [];
    }
  }
}
