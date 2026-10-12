# Manual Throttled Wipe Testing Guide

This guide documents how to manually test and verify Zero Trace's native Direct I/O overwrite engine and honest progress reporting without writing to physical production disks.

## Prerequisites
- Linux kernel 5.x+
- Root / sudo privileges for loopback device setup (`losetup`)
- Compiled `zt_engine` binary (`cargo build --manifest-path native/zt_engine/Cargo.toml --release`)

---

## 1. Create a File-Backed Loopback Device

Create a 1 GiB test file and attach it to a loopback block device:

```bash
# 1. Create 1 GiB test image
dd if=/dev/urandom of=/tmp/zt_test_1g.img bs=1M count=1024 status=progress

# 2. Attach to free loop device
sudo losetup -fP /tmp/zt_test_1g.img

# 3. Find the assigned loop device name
losetup -a | grep zt_test_1g.img
# Example output: /dev/loop7: [64770]:1234567 (/tmp/zt_test_1g.img)
```

---

## 2. (Optional) Throttle Write I/O via cgroups v2

To simulate a slow USB 2.0 stick (e.g. 5–10 MB/s) to observe the progress bar, heartbeats, and ETA:

```bash
# Get loop device major:minor
DEV_MAJ_MIN=$(lsblk -no MAJ:MIN /dev/loop7 | tr -d ' ')

# Create cgroup v2 for throttling
sudo mkdir -p /sys/fs/cgroup/zt_throttle
# Limit write speed to 8 MB/s (8388608 bytes/sec)
echo "$DEV_MAJ_MIN wbps=8388608" | sudo tee /sys/fs/cgroup/zt_throttle/io.max

# Run current shell or binary in the cgroup
echo $$ | sudo tee /sys/fs/cgroup/zt_throttle/cgroup.procs
```

---

## 3. Run Native Overwrite via `zt_engine`

Execute the native direct I/O overwrite directly from the command line:

```bash
# Generate dummy serial matching confirmation token
SERIAL="ZT_TEST_SERIAL_001"

# Run single-pass zero overwrite
./native/zt_engine/target/release/zt_engine sanitize /dev/loop7 overwrite-zero "$SERIAL" "$SERIAL"
```

### Observed Telemetry Lines
You will see JSON lines printed to standard output:

```text
PROGRESS:{"schema_version":2,"phase":"Preparing","bytes_done":0,"bytes_total":1073741824,"percent":null,"speed_bytes_per_sec":0.0,"eta_seconds":null,"message":"heartbeat","is_heartbeat":true}
PROGRESS:{"schema_version":2,"phase":"FirmwareCommand","bytes_done":2097152,"bytes_total":1073741824,"percent":0.001953125,"speed_bytes_per_sec":8342110.0,"eta_seconds":128,"message":"Pass 1 of 1: writing to media","is_heartbeat":false}
...
PROGRESS:{"schema_version":2,"phase":"Flushing","bytes_done":1073741824,"bytes_total":1073741824,"percent":null,"speed_bytes_per_sec":0.0,"eta_seconds":null,"message":"Finalizing, flushing to drive","is_heartbeat":false}
PROGRESS:{"schema_version":2,"phase":"Verification","bytes_done":1073741824,"bytes_total":1073741824,"percent":null,"speed_bytes_per_sec":0.0,"eta_seconds":null,"message":"Verifying sector erasure...","is_heartbeat":false}
REPORT:{"success":true,"method_used":"Software Overwrite (1-pass, Zeros)","command_log":["Native block overwrite (1 passes, mode: direct)"],"stdout":"Successfully overwritten 1073741824 bytes in 1 passes","stderr":"","exit_code":0,"duration_ms":128450,"dry_run":false,"bytes_written":1073741824,"io_mode":"direct"}
```

---

## 4. Test Cancellation Signal Handling

In a separate terminal, while `zt_engine` is writing:

```bash
kill -TERM $(pgrep -f zt_engine)
```

Expected behavior:
- Engine catches `SIGTERM` via `signal-hook`.
- Syncs remaining in-flight buffers to disk.
- Writes a checkpoint file `active_checkpoint.json` into the engine's checkpoint
  directory: `$ZT_CHECKPOINT_DIR` if set, otherwise
  `~/.local/state/zero_trace/` (or `/tmp/zero_trace` as a last resort). When the
  Flutter app launches the engine it sets `ZT_CHECKPOINT_DIR` to the app's state
  checkpoint directory, so the file does not live in `/tmp` in normal use.
- Exits cleanly with exit code `130`.
- Outputs `REPORT:{"success":false,...,"stderr":"Sanitization cancelled by user: partially wiped",...}` with exact `bytes_written`.

---

## 5. Clean Up Test Device

```bash
# Detach loopback device
sudo losetup -d /dev/loop7

# Remove test file
rm -f /tmp/zt_test_1g.img

# Clean up checkpoint file if present (uses the engine's checkpoint dir)
rm -f "${ZT_CHECKPOINT_DIR:-$HOME/.local/state/zero_trace}/active_checkpoint.json"
```
