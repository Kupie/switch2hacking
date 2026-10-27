#!/bin/bash
# READY watcher: fires the SAFE runbook chain the moment SESSION READY lands.
# HIPC2 worker experiments are HALTED (5 console deaths — see FIRMWARE_FINDINGS
# 7.2d). The chain is now: identity check -> am-pid content-mount experiment
# (all proven op classes, the game-dumping track).
cd "$(dirname "$0")"
# Arm: record the time. Fire only when the log's mtime advances past the arm
# time AND it contains SESSION READY — the next host start truncates the log
# (mtime bump, old READY gone), so a later READY in a newer-than-arm file is
# always a NEW one. Immune to truncation, inode reuse, and count races.
rm -f /tmp/ready-chain-fired   # a stale latch from a previous boot must not eat this boot's event
ARM_TIME=$(date +%s)
for i in $(seq 1 720); do
  LOG_MTIME=$(stat -c %Y /tmp/ns2-start.log 2>/dev/null || echo 0)
  if [ "$LOG_MTIME" -gt "$ARM_TIME" ] && grep -q "SESSION READY" /tmp/ns2-start.log 2>/dev/null; then
    if [ -f /tmp/ready-chain-fired ]; then exit 0; fi
    echo "=== $(date +%H:%M:%S) SESSION READY detected — settling 90s first ==="
    # Post-READY settle window: the first seconds are fragile (0dSsB1/Jer6aO)
    sleep 90
    grep -q "SESSION READY" /tmp/ns2-start.log 2>/dev/null || exit 0
    touch /tmp/ready-chain-fired
    echo "=== $(date +%H:%M:%S) settle done — running safe chain ==="
    # Every chain command is time-boxed: a wedged request (the sm-deferral
    # class) costs at most 240s and the chain moves on; the 180s endpoint
    # deadline makes single requests fail fast; partial dump files bank
    # incrementally.
    timeout 240 sudo -n ip netns exec switchlab runuser -u nlight -- node fix-session-identity.cjs 2>&1 | tail -3
    timeout 240 sudo -n ip netns exec switchlab runuser -u nlight -- node am-mount.cjs 2>&1 | tail -30
    # THE BOOT-PARTITION PROBE (the patched 0037 policy = bits 62+63): a
    # clean-error op either way. Result 0 = package2/KTN unlocked -> run
    # bis-boot-dump.cjs manually.
    timeout 100 sudo -n ip netns exec switchlab runuser -u nlight -- node -e "
const fs=require('fs'),path=require('path');
const latest=JSON.parse(fs.readFileSync('../../latest-session.json'));
const {connect}=require(path.join(latest.directory,'switch2','tools','fs-memory.cjs'));
connect().then(m=>Promise.all([0,10].map(id=>m.request({command:'root-probe-bis', id}).then(r=>({id, result:r.result})))))
 .then(rs=>{for(const r of rs) console.log('BIS '+r.id+': 0x'+(r.result>>>0).toString(16)+(r.result===0?'  <<<*** BOOT PARTITION OPEN ***>>>':''));})
 .catch(e=>console.log('probe ERR:',e.message.slice(0,80)))" 2>&1 | tail -4
    # fs-dump stays MANUAL (sfIxbr death: the retained fetch of the rig
    # output is the bottleneck — needs per-chunk timing + resume first)
    exit 0
  fi
  sleep 10
done
echo "watcher: no READY within 2h"
