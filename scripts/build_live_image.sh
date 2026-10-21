#!/usr/bin/env bash
#
# B3: build a minimal bootable Zero Trace live image (Debian live-build).
#
# The image boots on bare metal (a Windows laptop included), auto-logs-in
# root on tty1 and launches the Flutter app. The bundled zt_engine runs with
# the privileges of the live session; the engine's live-boot detection is the
# authoritative gate that makes internal disks wipeable only when booted from
# the live medium (A3b).
#
# Build host requirements:
#   - Linux x86_64 (or cross-capable host) with:
#       cargo (Rust, for zt_engine), flutter (Linux desktop toolchain),
#       live-build (`lb`), xorriso, squashfs-tools, syslinux-common, mtools
#   - root (or passwordless sudo): `lb build` needs chroot privileges
#   - network access for `lb build` (Debian package mirrors)
#
# NEVER run this against real target hardware in tests: boot-test the ISO in
# a VM only; writing it to a USB stick and booting bare metal is an operator
# action performed at sanitization time, not part of CI.
#
# Output: build/live-image/zero-trace-live-amd64.iso (+ .sha256)
#
# USB writing (operator step, see docs/LIVE_IMAGE.md):
#   sudo dd if=zero-trace-live-amd64.iso of=/dev/sdX bs=4M status=progress conv=fsync
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build/live-image"
CONFIG_DIR="$BUILD_DIR/config"
INCLUDES="$CONFIG_DIR/includes.chroot"
APP_DIR="$INCLUDES/opt/zero_trace"
BIN_DIR="$INCLUDES/usr/local/bin"
DISTRO="bookworm" # Debian release used for the live base

log() { printf '\033[1;33m[LIVE-BUILD]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[LIVE-BUILD ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Prerequisite checks -----------------------------------------------------

for cmd in cargo flutter lb xorriso mksquashfs; do
  command -v "$cmd" >/dev/null 2>&1 ||
    die "missing prerequisite '$cmd' (install live-build, flutter, cargo, xorriso, squashfs-tools)"
done
[ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1 ||
  die "building the live image needs root privileges (run as root or install sudo)"
[ "$(uname -m)" = "x86_64" ] ||
  die "this script targets amd64 live images (host is $(uname -m))"

# --- 1. Build the sanitization engine ----------------------------------------

log "Building zt_engine (release, x86_64-unknown-linux-gnu)..."
(
  cd "$REPO_ROOT/native/zt_engine"
  cargo build --release --target x86_64-unknown-linux-gnu
)
ENGINE_BIN="$REPO_ROOT/native/zt_engine/target/x86_64-unknown-linux-gnu/release/zt_engine"
[ -x "$ENGINE_BIN" ] || die "engine binary not produced at $ENGINE_BIN"

# --- 2. Build the Flutter Linux bundle ---------------------------------------

log "Building Flutter Linux release bundle..."
(
  cd "$REPO_ROOT"
  flutter build linux --release
)
BUNDLE_DIR="$REPO_ROOT/build/linux/x64/release/bundle"
[ -d "$BUNDLE_DIR" ] || die "Flutter bundle not produced at $BUNDLE_DIR"

# --- 3. Stage the live-build configuration -----------------------------------

log "Staging live-build configuration..."
rm -rf "$BUILD_DIR"
mkdir -p "$APP_DIR" "$BIN_DIR" \
  "$CONFIG_DIR/package-lists" \
  "$CONFIG_DIR/includes.chroot/etc/systemd/system/getty@tty1.service.d" \
  "$CONFIG_DIR/includes.chroot/root"

cp -a "$BUNDLE_DIR/." "$APP_DIR/"
install -m 0755 "$ENGINE_BIN" "$BIN_DIR/zt_engine"
install -m 0755 "$REPO_ROOT/scripts/live-image/launch.sh" "$BIN_DIR/zero-trace-live"
install -m 0644 "$REPO_ROOT/scripts/live-image/getty-autologin.conf" \
  "$CONFIG_DIR/includes.chroot/etc/systemd/system/getty@tty1.service.d/autologin.conf"
install -m 0644 "$REPO_ROOT/scripts/live-image/root-profile" \
  "$CONFIG_DIR/includes.chroot/root/.profile"

# Desktop-free base: X server + FLTK runtime for the Flutter Linux embedder.
cat > "$CONFIG_DIR/package-lists/zero-trace.list.chroot" <<'EOF'
xserver-xorg-core
xserver-xorg-input-libinput
xinit
x11-xserver-utils
openbox
libgl1
libglu1-mesa
libgtk-3-0
libnss3
libasound2
libblkid1
util-linux
fdisk
parted
dosfstools
e2fsprogs
ntfs-3g
smartmontools
EOF

# --- 4. Configure and build the ISO ------------------------------------------

log "Configuring live-build ($DISTRO, amd64)..."
cd "$BUILD_DIR"
lb config \
  --architectures amd64 \
  --distribution "$DISTRO" \
  --binary-images iso-hybrid \
  --bootloaders syslinux \
  --debian-installer live \
  --iso-application "Zero Trace Live" \
  --iso-publisher "Zero Trace" \
  --iso-volume "ZERO_TRACE_LIVE" \
  --apt-indices false \
  --clean

log "Building ISO (this downloads the Debian base and runs chroot hooks)..."
if [ "$(id -u)" -eq 0 ]; then
  lb build
else
  sudo lb build
fi

ISO="$(ls -1t live-image-amd64.hybrid.iso 2>/dev/null | head -1 || true)"
[ -n "$ISO" ] || die "lb build did not produce live-image-amd64.hybrid.iso"
OUT_ISO="$REPO_ROOT/build/live-image/zero-trace-live-amd64.iso"
mv "$ISO" "$OUT_ISO"
sha256sum "$OUT_ISO" > "$OUT_ISO.sha256"

log "Done."
log "ISO:  $OUT_ISO"
log "SHA:  $(cut -d' ' -f1 "$OUT_ISO.sha256")"
log "Write to USB with dd (see docs/LIVE_IMAGE.md). Boot-test only in a VM."
