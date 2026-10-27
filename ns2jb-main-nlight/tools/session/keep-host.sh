#!/usr/bin/env bash
# Host lifeguard v4: keep exactly one session host listening so the console
# always dials straight into a valid host, and chain acquisition rolls.
#
# While a run is active: netwatch (carrier + console ping RTT, 2s) so a stall
# can be attributed to transport vs console.
#
# When the dial port is free, the next host is chosen by OUTCOME:
#   - SESSION READY in the last run dir (a session that lost its host):
#     session.sh resume (console retains state; GO2 PHASE 6 auto-redials).
#     A resume host that exits without attaching (HELLO mismatch = console
#     was rebooted) falls through to a fresh host.
#   - stall-resumable.json in the last run dir (a transport stall killed the
#     pipeline AFTER a memory-ready acquisition — P0.4): the console's
#     retained resources are intact, so offer session.sh resume FIRST with a
#     bounded window (~7 min) for the console's GO2 redial to re-attach if
#     its loop recovers; then fall back to a fresh host. Never re-offers
#     resume for the same run dir twice.
#   - otherwise (failed roll / no run yet): session.sh start immediately.
#
# Never more than one host listens at a time. Patterns live only in this
# file, never in process command lines.
cd "$(dirname "$0")"
state=/tmp/ns2-keeper-state.json
note() { echo "$(date +%H:%M:%S) $*" >> /tmp/ns2-host-keeper.log; }
last_start=none; started_at=0; resume_dir=''; resume_since=0; resume_tried=''
read_state() { resume_tried=$(python3 -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("resumeTriedDir",""))
except Exception: pass' "$state" 2>/dev/null); }
write_state() { printf '{"lastStart":"%s","startedAt":%s,"resumeTriedDir":"%s"}\n' \
  "$last_start" "$started_at" "$resume_tried" > "$state"; }
read_state
while :; do
  if pgrep -f "[r]un.cjs" >/dev/null 2>&1; then
    c=$(sudo -n ip netns exec switchlab cat /sys/class/net/enp17s0u6/carrier 2>/dev/null)
    rtt=$(sudo -n ip netns exec switchlab ping -c1 -W1 192.168.77.25 2>/dev/null | grep -oE 'time=[0-9.]+' | cut -d= -f2)
    echo "$(date +%H:%M:%S) carrier=${c:-?} ping=${rtt:-LOSS}" >> /tmp/ns2-netwatch.log
    sleep 2
    continue
  fi
  if sudo -n ip netns exec switchlab ss -ltn 2>/dev/null | grep -q 39380; then
    # Bounded stall-resume window: if the resume host we raised for a stalled
    # run has not been dialed within the window, reclaim the port and fall
    # back to a fresh host (the console loop is not recovering on its own).
    if [[ -n "$resume_dir" && $(date +%s) -ge $((resume_since + 420)) ]]; then
      conn=$(stat -c %Y "$resume_dir/connection.json" 2>/dev/null || echo 0)
      if (( conn <= resume_since )); then
        note "stall-resume window expired without a dial; falling back to fresh host"
        pkill -f "[r]un.cjs --resume" 2>/dev/null
        sleep 3
      else
        note "stall-resume window closed (a dial landed)"
      fi
      resume_dir=''; write_state
    fi
    sleep 5
    continue
  fi
  # Port free: pick the next host by the last run's outcome.
  ready=0; stalled=0; dir=''
  if [[ -s ../../latest-session.json ]]; then
    dir=$(python3 -c 'import json;print(json.load(open("../../latest-session.json")).get("directory",""))' 2>/dev/null)
    if [[ -n "$dir" && -f "$dir/run.log" ]] && grep -q "SESSION READY" "$dir/run.log" 2>/dev/null; then ready=1; fi
    if [[ -n "$dir" && -f "$dir/stall-resumable.json" ]]; then stalled=1; fi
  fi
  if (( ready )); then
    attached=0
    if [[ "$last_start" == resume && -n "$dir" && -f "$dir/connection.json" ]]; then
      m=$(stat -c %Y "$dir/connection.json" 2>/dev/null || echo 0)
      (( m > started_at )) && attached=1
    fi
    if (( attached )); then
      note "starting resume host (reattach after host loss)"
      nohup ./session.sh resume >> /tmp/ns2-resume.log 2>&1 &
      last_start=resume; started_at=$(date +%s); write_state
    elif [[ "$last_start" == resume ]]; then
      note "resume host bounced (console rebooted); starting fresh host"
      nohup ./session.sh start >> /tmp/ns2-start.log 2>&1 &
      last_start=fresh; started_at=$(date +%s); write_state
    else
      note "starting resume host (prior session was ready)"
      nohup ./session.sh resume >> /tmp/ns2-resume.log 2>&1 &
      last_start=resume; started_at=$(date +%s); write_state
    fi
  elif (( stalled )) && [[ "$resume_tried" != "$dir" ]]; then
    note "stall after memory-ready acquisition; offering resume host (bounded window)"
    resume_tried="$dir"; resume_dir="$dir"; resume_since=$(date +%s); write_state
    nohup ./session.sh resume >> /tmp/ns2-resume.log 2>&1 &
    last_start=resume; started_at=$(date +%s); write_state
  else
    note "starting fresh host (chain roll / fresh boot)"
    nohup ./session.sh start >> /tmp/ns2-start.log 2>&1 &
    last_start=fresh; started_at=$(date +%s); write_state
  fi
  sleep 10
done
