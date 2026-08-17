import 'dart:convert';
import 'dart:io';

import '../models/device_profile.dart';
import 'device_simulator.dart';

class DeviceIntelligenceService {
  final DeviceSimulator _simulator;

  DeviceIntelligenceService({DeviceSimulator? simulator})
      : _simulator = simulator ?? DeviceSimulator();

  Future<List<DeviceProfile>> discoverDevices({bool realMode = false}) async {
    if (!realMode) {
      return _simulator.getDevices();
    }

    // Real device detection path using Linux CLI (`lsblk`)
    if (Platform.isLinux) {
      try {
        final result = await Process.run('lsblk', [
          '-J',
          '-b',
          '-o',
          'NAME,MODEL,SERIAL,SIZE,ROTA,TRAN,MOUNTPOINT,TYPE'
        ]);

        if (result.exitCode == 0 && result.stdout != null) {
          final Map<String, dynamic> parsed = jsonDecode(result.stdout as String);
          final List<dynamic> devicesJson = parsed['blockdevices'] ?? [];
          final List<DeviceProfile> detectedProfiles = [];

          for (final dev in devicesJson) {
            final type = dev['type'] as String?;
            if (type == 'disk') {
              final name = (dev['model'] as String?)?.trim() ?? dev['name'] as String;
              final serial = (dev['serial'] as String?)?.trim() ?? 'UNKNOWN-${dev['name']}';
              final size = (dev['size'] as int?) ?? 0;
              final isRotational = (dev['rota'] as bool?) ?? false;
              final tran = (dev['tran'] as String?)?.toUpperCase() ?? 'SATA';
              
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
              if (isRotational) {
                mediaType = MediaType.hdd;
              } else if (tran.contains('NVME')) {
                mediaType = MediaType.nvmeSsd;
              } else if (tran.contains('USB')) {
                mediaType = MediaType.usbFlash;
              } else if (tran.contains('MMC') || dev['name'].toString().startsWith('mmcblk')) {
                mediaType = MediaType.emmc;
              } else {
                mediaType = MediaType.sataSsd;
              }

              detectedProfiles.add(
                DeviceProfile(
                  id: 'real_${dev['name']}',
                  name: name,
                  serialNumber: serial,
                  mediaType: mediaType,
                  busType: tran,
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
                      : 'REAL CONNECTED STORAGE DEVICE',
                ),
              );
            }
          }

          if (detectedProfiles.isNotEmpty) {
            return detectedProfiles;
          }
        }
      } catch (e) {
        // Fallback to simulated if real detection errors out
      }
    }

    return _simulator.getDevices();
  }
}
