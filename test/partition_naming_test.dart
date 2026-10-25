import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/models/partition_info.dart';
import 'package:zero_trace/models/untrusted_text.dart';

/// B1/B2: Windows-friendly partition naming, GPT/MBR type classification
/// and friendly-name formatting.
void main() {
  const espGuid = 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b';
  const msrGuid = 'e3c9e316-0b5c-4db8-817d-f92df00215ae';
  const basicGuid = 'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7';
  const recoveryGuid = 'de94bba4-06d1-4d40-a16a-bfd50179d6ac';
  const luksGuid = 'ca7d7ccb-63ed-4c53-861c-1742536059cc';

  PartitionInfo part({
    int partitionNumber = 1,
    String label = '',
    String? fsType,
    int sizeBytes = 500 * 1024 * 1024 * 1024,
    String? partTypeGuid,
    String? partTypeName,
    String? role,
    String? encryptionKind,
    int? usedBytes,
    String? mountPoint,
  }) =>
      PartitionInfo(
        partitionNumber: partitionNumber,
        name: 'sdb$partitionNumber',
        devicePath: '/dev/sdb$partitionNumber',
        startSector: 2048,
        sizeSectors: sizeBytes ~/ 512,
        sizeBytes: sizeBytes,
        label: UntrustedText(label),
        fsType: fsType,
        mountPoint: mountPoint,
        partTypeGuid: partTypeGuid,
        partTypeName: partTypeName,
        role: role,
        encryptionKind: encryptionKind,
        usedBytes: usedBytes,
      );

  group('B1 GPT type GUID classification', () {
    test('known Windows GUIDs map to canonical names and roles', () {
      expect(PartitionInfo.classifyTypeToken(espGuid),
          ('EFI System', 'efi_system'));
      expect(PartitionInfo.classifyTypeToken(msrGuid),
          ('Microsoft Reserved', 'msr'));
      expect(PartitionInfo.classifyTypeToken(basicGuid),
          ('Microsoft Basic Data', 'windows_data'));
      expect(PartitionInfo.classifyTypeToken(recoveryGuid),
          ('Windows Recovery', 'windows_recovery'));
      expect(PartitionInfo.classifyTypeToken(luksGuid), ('LUKS', 'luks'));
    });

    test('uppercase and braced GUIDs normalize like udev variants', () {
      expect(PartitionInfo.classifyTypeToken(espGuid.toUpperCase()),
          ('EFI System', 'efi_system'));
      expect(PartitionInfo.classifyTypeToken('{$espGuid}'),
          ('EFI System', 'efi_system'));
      expect(PartitionInfo.classifyTypeToken('{${basicGuid.toUpperCase()}}'),
          ('Microsoft Basic Data', 'windows_data'));
    });

    test('unknown GUID keeps the identifier visible with unknown role', () {
      final (name, role) = PartitionInfo
          .classifyTypeToken('12345678-1234-1234-1234-123456789abc');
      expect(name, '12345678-1234-1234-1234-123456789abc');
      expect(role, 'unknown');
    });
  });

  group('B1 MBR type byte classification', () {
    test('0x07 + NTFS stays a Windows label', () {
      expect(PartitionInfo.classifyTypeToken('0x7', fsType: 'ntfs'),
          ('Windows NTFS/exFAT', 'windows_data'));
    });

    test('fs signature contradicts a generic Windows byte → Linux wins', () {
      expect(PartitionInfo.classifyTypeToken('0x7', fsType: 'ext4'),
          ('Linux (ext4)', 'linux'));
    });

    test('FAT32 and Recovery bytes', () {
      expect(PartitionInfo.classifyTypeToken('0x0b', fsType: 'fat32'),
          ('Windows FAT32', 'windows_data'));
      expect(PartitionInfo.classifyTypeToken('0x27', fsType: 'ntfs'),
          ('Windows Recovery', 'windows_recovery'));
      expect(PartitionInfo.classifyTypeToken('0xef', fsType: null),
          ('EFI System', 'efi_system'));
    });

    test('bare hex bytes without 0x prefix work', () {
      expect(PartitionInfo.classifyTypeToken('83', fsType: null),
          ('Linux', 'linux'));
    });
  });

  group('B1 filesystem-only fallback', () {
    test('missing type token but known fs still classifies', () {
      expect(PartitionInfo.classifyTypeToken(null, fsType: 'ntfs'),
          ('Windows volume', 'windows_data'));
      expect(PartitionInfo.classifyTypeToken(null, fsType: 'ext4'),
          ('Linux (ext4)', 'linux'));
      expect(PartitionInfo.classifyTypeToken(null, fsType: 'swap'),
          ('Linux Swap', 'linux_swap'));
      expect(PartitionInfo.classifyTypeToken(null, fsType: 'crypto_LUKS'),
          ('LUKS', 'luks'));
      expect(PartitionInfo.classifyTypeToken(null, fsType: null),
          (null, null));
    });
  });

  group('B1 friendly display names (no invented drive letters)', () {
    test('EFI System, MSR and Recovery use short role names', () {
      expect(part(role: 'efi_system').friendlyDisplayName, 'EFI System');
      expect(part(role: 'msr').friendlyDisplayName, 'Microsoft Reserved');
      expect(part(role: 'windows_recovery').friendlyDisplayName, 'Recovery');
    });

    test('NTFS volume is labeled by filesystem, not by assumed OS', () {
      final p = part(
        role: 'windows_data',
        fsType: 'ntfs',
        sizeBytes: 237 * 1024 * 1024 * 1024,
        label: 'OS',
      );
      // P1: no Windows assumption from NTFS alone.
      expect(p.friendlyDisplayName, 'NTFS volume (237.0 GB)');
      // Label stays visible in the detail line — never a drive letter.
      expect(p.detailLine, contains('OS'));
      expect(p.friendlyDisplayName, isNot(contains('C:')));
    });

    test('probe-confirmed Windows install labels NTFS as Windows volume', () {
      final p = part(
        role: 'windows_data',
        fsType: 'ntfs',
        sizeBytes: 237 * 1024 * 1024 * 1024,
      );
      expect(p.displayName(windowsInstallDetected: true),
          'Windows volume (NTFS, 237.0 GB)');
      // The probe flag never affects non-NTFS volumes.
      final fat = part(role: 'windows_data', fsType: 'fat32');
      expect(fat.displayName(windowsInstallDetected: true),
          'FAT32 volume (500.0 GB)');
    });

    test('FAT32, exFAT and ext4 volumes use filesystem labels (P1)', () {
      expect(
          part(role: 'windows_data', fsType: 'fat32').friendlyDisplayName,
          'FAT32 volume (500.0 GB)');
      expect(
          part(role: 'windows_data', fsType: 'exfat').friendlyDisplayName,
          'exFAT volume (500.0 GB)');
      expect(part(role: 'linux', fsType: 'ext4').friendlyDisplayName,
          'ext4 volume (500.0 GB)');
      expect(part(role: 'linux', fsType: 'btrfs').friendlyDisplayName,
          'btrfs volume (500.0 GB)');
    });

    test('Windows volume without fs assumes no OS', () {
      final p = part(role: 'windows_data', fsType: null);
      expect(p.friendlyDisplayName, 'Partition 1 (500.0 GB)');
      expect(p.friendlyDisplayName, isNot(contains('Windows')));
    });

    test('encrypted volume names the encryption kind (B2)', () {
      final p = part(role: 'luks', encryptionKind: 'LUKS');
      expect(p.friendlyDisplayName, 'Encrypted volume (LUKS, 500.0 GB)');
    });

    test('plain partition falls back to label then number', () {
      expect(part(label: 'MYDATA').friendlyDisplayName, 'MYDATA');
      expect(part().friendlyDisplayName, 'Partition 1');
    });
  });

  group('B1/B2 detail line', () {
    test('filesystem, size, mountpoint and encryption are shown', () {
      final p = part(
        role: null,
        fsType: 'ext4',
        mountPoint: '/mnt/data',
        encryptionKind: null,
      );
      // P1: fs + size now live in the filesystem-based title
      // ("ext4 volume (500.0 GB)"); the detail line adds the mountpoint.
      expect(p.friendlyDisplayName, 'ext4 volume (500.0 GB)');
      expect(p.detailLine, '/mnt/data');
    });

    test('encrypted and used-space details appear', () {
      final p = part(
        fsType: 'ntfs',
        encryptionKind: 'BitLocker',
        usedBytes: 100 * 1024 * 1024 * 1024,
      );
      // P1: the filesystem is part of the title, not repeated below.
      expect(p.friendlyDisplayName, startsWith('NTFS volume'));
      expect(p.detailLine, contains('BitLocker (encrypted)'));
      expect(p.detailLine, contains('100.0 GB used'));
    });

    test('detail line does not repeat what the title shows', () {
      final p = part(
        role: 'windows_data',
        fsType: 'ntfs',
        sizeBytes: 100 * 1024 * 1024 * 1024,
      );
      // Title already has NTFS + size.
      expect(p.detailLine.contains('NTFS'), isFalse);
      expect(p.detailLine.contains('100.0 GB'), isFalse);
    });
  });

  group('B1/B2 JSON persistence', () {
    test('new fields round-trip through toJson/fromJson', () {
      final p = part(
        partTypeGuid: basicGuid,
        partTypeName: 'Microsoft Basic Data',
        role: 'windows_data',
        encryptionKind: 'BitLocker',
        usedBytes: 12345,
      );
      final back = PartitionInfo.fromJson(p.toJson());
      expect(back.partTypeGuid, basicGuid);
      expect(back.partTypeName, 'Microsoft Basic Data');
      expect(back.role, 'windows_data');
      expect(back.encryptionKind, 'BitLocker');
      expect(back.usedBytes, 12345);
    });

    test('legacy JSON without new fields stays parseable', () {
      final back = PartitionInfo.fromJson({
        'partitionNumber': 2,
        'name': 'sdc2',
        'devicePath': '/dev/sdc2',
        'startSector': 4096,
        'sizeSectors': 1000,
        'sizeBytes': 512000,
        'label': 'LEGACY',
        'fsType': 'ext4',
      });
      expect(back.partTypeGuid, isNull);
      expect(back.role, isNull);
      expect(back.encryptionKind, isNull);
      expect(back.usedBytes, isNull);
      expect(back.friendlyDisplayName, 'LEGACY');
    });
  });
}
