#!/usr/bin/env bash
# Rate-floor watchdog for a running game-dump.
#
# Monitors the dump's log; when the sustained rate falls below the floor
# (or progress stalls, or the process died), it bounces the attach: kill +
# relaunch the same dump command. The dump's manifest resumes mid-file, and
# fresh attaches have consistently restored full throughput. Exits when the
# dump completes or fails for real.
#
# Usage: nohup tools/dump/dump-watchdog.sh <floor-KiB/s> <log> [dump args...] &
# Example:
#   nohup tools/dump/dump-watchdog.sh 2048 /tmp/game-dump-base.log \
#     0400c3f00006e000 --content base --section romfs >/tmp/dump-watchdog.log 2>&1 &
set -u
FLOOR_KIBS=${1:-2048}
LOG=${2:-/tmp/game-dump-base.log}
shift 2 || true
DUMP_ARGS=("$@")
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
MIN_INTERVAL=180       # seconds between bounces
GRACE=150              # seconds after launch before rate is judged
STALL_AFTER=900        # no progress line for this long = stall

LAUNCHED_AT=$(date +%s)
LAST_PROGRESS=$(date +%s)

log() { echo "[watchdog $(date +%H:%M:%S)] $*"; }

relaunch() {
  local pids waited=0
  pids=$(ps -eo pid,comm,args | awk '$2 ~ /^node/ && /game-dump\.cjs/ {print $1}')
  if [ -n "$pids" ]; then
    log "clean-stop signal to dump pids: $(echo $pids | tr '\n' ' ')"
    kill -INT $pids 2>/dev/null
    # the tool finishes the current chunk, closes handles, exits (resume-safe)
    while [ $waited -lt 45 ]; do
      sleep 3; waited=$((waited+3))
      pids=$(ps -eo pid,comm,args | awk '$2 ~ /^node/ && /game-dump\.cjs/ {print $1}')
      [ -z "$pids" ] && break
    done
    if [ -n "$pids" ]; then
      log "clean stop did not complete in 45s — SIGKILL (WARNING: a hard kill mid-RPC can kill the retained session)"
      kill -9 $pids 2>/dev/null
      sleep 4
    fi
  fi
  mv -f "$LOG" "$LOG.old" 2>/dev/null || true
  nohup sudo -n ip netns exec switchlab runuser -u nlight -- \
    node "$REPO/tools/dump/game-dump.cjs" "${DUMP_ARGS[@]}" \
    > "$LOG" 2>&1 < /dev/null &
  LAUNCHED_AT=$(date +%s); LAST_PROGRESS=$LAUNCHED_AT
  log "relaunched (args: ${DUMP_ARGS[*]})"
}

BOUNCES=0
MAX_BOUNCES=${MAX_BOUNCES:-2}
log "watchdog start: floor ${FLOOR_KIBS} KiB/s, log $LOG, max rate-bounces ${MAX_BOUNCES}, args: ${DUMP_ARGS[*]}"
while true; do
  sleep 60
  if tail -1 "$LOG" 2>/dev/null | grep -q "DUMP COMPLETE"; then log "dump complete — exiting"; exit 0; fi
  if tail -1 "$LOG" 2>/dev/null | grep -q "^FAILED"; then log "dump FAILED — exiting (needs attention)"; exit 1; fi
  now=$(date +%s)
  # progress freshness
  if [ -f "$LOG" ] && [ "$LOG" -nt /proc/self ] 2>/dev/null; then :; fi
  fresher=$(find "$LOG" -mmin -15 2>/dev/null)
  last=$(grep "KiB/s" "$LOG" 2>/dev/null | tail -1)
  # Any fresh log line (rate, header, verify) counts as progress while the
  # dump process is alive — the tool prints a rate line in BOTH phases
  # (small files + the romfs rest meter), so a silent log really is a stall.
  log_mtime=$(stat -c %Y "$LOG" 2>/dev/null || echo 0)
  if [ $((log_mtime + 60)) -ge "$now" ]; then LAST_PROGRESS=$now; fi
  alive=$(ps -eo pid,comm,args | awk '$2 ~ /^node/ && /game-dump\.cjs/ {print $1}' | wc -l)
  if [ "$alive" -eq 0 ]; then
    if [ $((now - LAUNCHED_AT)) -lt $GRACE ]; then continue; fi
    log "dump process not running — bouncing"
    relaunch; continue
  fi
  # rate-line freshness: only fatal if the LOG itself is silent (no line at
  # all in the stall window) — a healthy-but-slow phase still prints.
  if [ $((now - LAST_PROGRESS)) -gt $STALL_AFTER ]; then
    log "progress stalled (>$STALL_AFTER s without any log line) — bouncing"
    relaunch; continue
  fi
  # rate check only after the grace window
  if [ $((now - LAUNCHED_AT)) -lt $GRACE ]; then continue; fi
  rate=$(echo "$last" | sed -n 's/.* \([0-9]*\) KiB\/s.*/\1/p')
  if [ -z "$rate" ]; then continue; fi
  if [ "$rate" -lt "$FLOOR_KIBS" ]; then
    if [ $((now - LAUNCHED_AT)) -ge $MIN_INTERVAL ]; then
      if [ "$BOUNCES" -lt "$MAX_BOUNCES" ]; then
        BOUNCES=$((BOUNCES+1))
        log "rate ${rate} KiB/s < floor ${FLOOR_KIBS} — rate-bounce ${BOUNCES}/${MAX_BOUNCES}"
        relaunch
      else
        log "rate ${rate} KiB/s below floor but bounce cap reached — riding"
      fi
    fi
  else
    log "ok: ${rate} KiB/s"
  fi
done
