#!/usr/bin/env bash
#
# Move stale zero_trace scratch state out of the real state directory.
#
# Safety guarantees:
#   * Never deletes anything. Stale files are MOVED into a timestamped backup
#     folder; if the backup cannot be created, nothing happens.
#   * Refuses to run while zero_trace or zt_engine is running.
#   * Never reads or modifies the signing keys directory (keys/).
#   * Never touches audit_log.jsonl, certificates/ or reports/ unless you
#     explicitly confirm (and even then, only moves - never reads contents).
#   * Dry-run by default. Pass --apply to actually move files.
#
# Usage:
#   scripts/cleanup_test_state.sh [--apply] [--yes] [--state-dir DIR]

set -u

apply=0
assume_yes=0
state_dir="${ZT_DATA_DIR:-$HOME/.zero_trace}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --apply)     apply=1 ;;
    -y|--yes)    assume_yes=1 ;;
    --state-dir) shift; state_dir="${1:-}" ;;
    -h|--help)
      printf 'Usage: %s [--apply] [--yes] [--state-dir DIR]\n' "$0"
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      exit 2
      ;;
  esac
  shift
done

log() { printf '%s\n' "$*"; }
run() {
  if [ "$apply" -eq 1 ]; then
    "$@"
  else
    log "  [dry-run] $*"
  fi
}

# 1. Refuse to run while the app or engine is live.
if command -v pgrep >/dev/null 2>&1; then
  if pgrep -x zero_trace >/dev/null 2>&1 ||
     pgrep -x zt_engine >/dev/null 2>&1 ||
     pgrep -f '[z]t_engine' >/dev/null 2>&1; then
    log "Refusing to run: zero_trace or zt_engine is running. Close them first."
    exit 1
  fi
else
  log "Warning: pgrep not found; cannot verify the app/engine is stopped."
fi

if [ -z "$state_dir" ] || [ ! -d "$state_dir" ]; then
  log "Nothing to do: state dir '$state_dir' does not exist."
  exit 0
fi

backup_dir="$state_dir/backups/cleanup-$(date +%Y%m%d-%H%M%S)"
log "State dir:  $state_dir"
log "Backup dir: $backup_dir"
if [ "$apply" -eq 1 ]; then
  log "Mode:       APPLY (files will be moved)"
else
  log "Mode:       dry-run (nothing changes; pass --apply to move)"
fi
log ""

moved_any=0

# 2. Move clearly-stale scratch files. Back up (never delete).
move_file() {
  local src="$1"
  run mkdir -p "$backup_dir"
  run mv -v "$src" "$backup_dir/"
  moved_any=1
}

if [ -e "$state_dir/active_job.json" ]; then
  move_file "$state_dir/active_job.json"
fi

# Leftovers from interrupted atomic writes (*.tmp / *.tmp-*).
while IFS= read -r tmpfile; do
  [ -n "$tmpfile" ] && move_file "$tmpfile"
done < <(find "$state_dir" -maxdepth 1 -type f \( -name '*.tmp' -o -name '*.tmp-*' \) 2>/dev/null)

if [ "$moved_any" -eq 0 ]; then
  log "No stale scratch files found (active_job.json, *.tmp)."
fi

# 3. certificates/ and reports/ are listed and only moved on explicit consent.
for dirname in certificates reports; do
  dir="$state_dir/$dirname"
  if [ ! -d "$dir" ]; then
    continue
  fi
  log ""
  log "Found $dirname/ (listed, never read):"
  find "$dir" -mindepth 1 -maxdepth 1 -printf '  %p\n' 2>/dev/null || ls -1 "$dir" | sed 's/^/  /'

  do_move=0
  if [ "$apply" -eq 1 ]; then
    if [ "$assume_yes" -eq 1 ]; then
      do_move=1
    elif [ -t 0 ]; then
      printf 'Move %s/ into the backup folder? [y/N] ' "$dirname"
      read -r answer
      case "$answer" in
        y|Y|yes|YES) do_move=1 ;;
      esac
    else
      log "Skipping $dirname/ (no TTY for confirmation; use --yes to allow)."
    fi
  fi

  if [ "$do_move" -eq 1 ]; then
    run mkdir -p "$backup_dir"
    run mv -v "$dir" "$backup_dir/"
    moved_any=1
  elif [ "$apply" -eq 1 ]; then
    log "Keeping $dirname/ in place."
  fi
done

# 4. keys/ is off limits: never read, never modify, never move.
if [ -d "$state_dir/keys" ]; then
  log ""
  log "Leaving keys/ untouched (signing keys are never read or moved)."
fi

log ""
if [ "$apply" -eq 1 ] && [ "$moved_any" -eq 1 ]; then
  log "Done. Moved files are in: $backup_dir"
  log "Audit log left untouched (chain integrity is never tampered with)."
elif [ "$apply" -eq 1 ]; then
  log "Done. Nothing needed moving."
else
  log "Dry run complete. Re-run with --apply to move the files listed above."
fi
