# Zero Trace Live Image (B3)

A minimal bootable Debian live image that auto-launches the Zero Trace app
with the sanitization engine (`zt_engine`) bundled in. Booting the target
machine from this medium is what makes its internal disks wipeable: the
engine's live-boot detection (A3b) only grants whole-disk scope when it sees
a live environment, and the certificate records the boot environment as a
signed field (B5).

## Build

On a networked Linux x86_64 host with `cargo`, `flutter` (Linux desktop
toolchain), `live-build` (`lb`), `xorriso` and `squashfs-tools` installed:

```sh
sudo ./scripts/build_live_image.sh
```

Outputs:

- `build/live-image/zero-trace-live-amd64.iso`
- `build/live-image/zero-trace-live-amd64.iso.sha256`

Verify the checksum before writing it anywhere:

```sh
sha256sum -c build/live-image/zero-trace-live-amd64.iso.sha256
```

## What the image contains

| Path on the live system            | Content                                    |
|------------------------------------|--------------------------------------------|
| `/opt/zero_trace/`                 | Flutter Linux release bundle (the app)     |
| `/usr/local/bin/zt_engine`         | Sanitization engine (release build)        |
| `/usr/local/bin/zero-trace-live`   | Launcher (starts X, runs the app as root)  |
| `/etc/systemd/system/getty@tty1.service.d/` | Root autologin on tty1             |

On boot the machine root-autologins on tty1 and starts the app
automatically; the session runs privileged because sanitization requires
raw block-device access. Trust comes from booting *your* verified medium —
the engine still validates every wipe (device family rules, guard chain,
typed confirmation upstream in the app).

## Writing the USB stick (operator step)

Pick the **whole device** (never a partition), e.g. `/dev/sdX` — double
check with `lsblk`:

```sh
lsblk                      # identify the USB stick by size/model
sudo dd if=build/live-image/zero-trace-live-amd64.iso \
        of=/dev/sdX bs=4M status=progress conv=fsync
```

Windows operators can use Rufus or balenaEtcher with the same ISO. The stick
is now a bootable Zero Trace medium; set the laptop's firmware boot order to
it (UEFI secure boot may need disabling — document this in your SOP).

## Safety rules

- **Never boot-test the live image on a real sanitization target during
  development.** Use a VM (VirtualBox/QEMU with a sacrificial virtual disk);
  no test in this repository writes to real hardware.
- The ISO build script refuses to run outside x86_64 and prints the
  checksum it produced so the artifact can be tracked.
- Wiping still requires the in-app confirmation flow (typed serial token,
  A5) — the live session being privileged does not skip the guard chain.
