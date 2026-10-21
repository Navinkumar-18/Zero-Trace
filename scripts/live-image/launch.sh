#!/bin/sh
# B3: live-session launcher for the Zero Trace app.
#
# Invoked twice by design:
#  1. From /root/.profile on the root tty1 autologin -> starts X.
#  2. As the xinit client inside the X session -> runs the app.
#
# The live session runs privileged; the Rust engine is the authoritative
# gate (live-boot detection, wipe guard chain) — the launcher only provides
# the environment the app expects.

export ZT_ENGINE_PATH=/usr/local/bin/zt_engine
APP_BIN=/opt/zero_trace/zero_trace

if [ -n "${DISPLAY:-}" ]; then
  # Inside the X session: minimal window manager, then the app (as root —
  # the live medium is trusted by design; the engine re-checks every wipe).
  command -v openbox >/dev/null 2>&1 && openbox >/dev/null 2>&1 &
  exec "$APP_BIN"
fi

# Bare tty1 login: bring up the display server with this script as client.
exec startx /usr/local/bin/zero-trace-live -- :0
