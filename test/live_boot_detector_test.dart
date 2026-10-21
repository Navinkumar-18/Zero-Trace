import 'package:flutter_test/flutter_test.dart';
import 'package:zero_trace/services/live_boot_detector.dart';

/// A3b: boot-environment detection with mocked /proc/cmdline + /proc/mounts
/// content for both modes (mirrors the Rust fixture tests in execute.rs).
/// Note: the mocked mount content uses /proc/MOUNTS format
/// (`source mountpoint fstype options dump pass`), which is what
/// [LiveBootDetector.classify] parses.
void main() {
  group('LiveBootDetector.classify (mocked mounts/cmdline)', () {
    // ── Normal mode ──────────────────────────────────────────────────────
    test('real ext4 root classifies as normal regardless of cmdline', () {
      const mounts = '/dev/sda1 / ext4 rw,relatime 0 0\n'
          '/dev/sda2 /boot ext4 rw,relatime 0 0\n';
      const cmdline = 'BOOT_IMAGE=/vmlinuz root=/dev/sda1 rw quiet';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.normal);
    });

    test('marker text on a real disk root does NOT downgrade protection', () {
      // The live marker only counts together with an overlay-style root; a
      // normal root keeps the installed-system rules (root disk protected).
      const mounts = '/dev/sda1 / ext4 rw,relatime 0 0\n';
      const cmdline = 'boot=live root=/dev/sda1 rw quiet';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.normal);
    });

    // ── Live mode ────────────────────────────────────────────────────────
    test('overlay root + boot=live marker classifies as live (Debian style)', () {
      const mounts = 'overlay / overlay rw,relatime,lowerdir=/run/live/medium 0 0\n'
          '/dev/sdb1 /cdrom iso9660 ro,relatime 0 0\n';
      const cmdline = 'boot=live findiso=/images/live.iso quiet';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.live);
    });

    test('overlay root + casper marker classifies as live (Ubuntu style)', () {
      const mounts = 'overlay / overlay rw,relatime,lowerdir=/cow 0 0\n';
      const cmdline = 'boot=casper findiso=/isos/live.iso quiet splash';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.live);
    });

    test('tmpfs root + archiso marker classifies as live (Arch style)', () {
      const mounts = 'tmpfs / tmpfs rw,relatime 0 0\n';
      const cmdline = 'archiso archisobasedir=arch archisolabel=ARCH_202601';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.live);
    });

    test('squashfs root + livecd marker classifies as live', () {
      const mounts = '/dev/sdb1 / squashfs ro,relatime 0 0\n';
      const cmdline = 'livecd root=/dev/sdb1 quiet';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.live);
    });

    // ── Container mode (fail closed) ─────────────────────────────────────
    test('overlay root without a live marker classifies as container', () {
      const mounts = 'overlay / overlay rw,relatime,lowerdir=/var/lib/docker 0 0\n';
      const cmdline = 'root=/dev/mapper/vg-root rw';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.container);
    });

    test('tmpfs root without a live marker fails closed to container', () {
      const mounts = 'tmpfs / tmpfs rw,relatime 0 0\n';
      const cmdline = 'root=/dev/mapper/vg-root rw';

      expect(LiveBootDetector.classify(cmdline, mounts), BootMode.container);
    });

    test('corrupt/short mount lines never classify as live', () {
      expect(LiveBootDetector.classify('boot=live', 'garbage'), BootMode.normal);
      expect(LiveBootDetector.classify('boot=live', ''), BootMode.normal);
      // A '/' line with an unrecognized fs type is not overlay-style:
      // installed-system (normal) rules apply.
      expect(
        LiveBootDetector.classify('boot=live', 'not / a mount line\n'),
        BootMode.normal,
      );
      expect(
        LiveBootDetector.classify('boot=live', 'overlay / overlay rw,relatime 0 0\n'),
        BootMode.live,
      );
    });
  });

  group('LiveBootDetector.describe (UI banner copy)', () {
    test('live mode banner promises internal-disk wipeability', () {
      expect(
        LiveBootDetector.describe(BootMode.live),
        'Running from live USB: internal disks can be wiped',
      );
    });

    test('container and normal descriptions are fail-safe', () {
      expect(
        LiveBootDetector.describe(BootMode.container),
        contains('destructive operations are disabled'),
      );
      expect(
        LiveBootDetector.describe(BootMode.normal),
        contains('boot disk and its partitions are protected'),
      );
    });
  });
}
