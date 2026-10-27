#!/bin/bash
# Bounded fs-dump slice runner. Kills the WHOLE process group at the
# deadline so no orphaned driver can keep hammering the memory server
# (the sfIxbr freeze lesson: timeout killed sudo, node survived).
set -u
cd "$(dirname "$0")"
DEADLINE=${1:-300}
shift || true
setsid sudo -n ip netns exec switchlab runuser -u nlight -- node fs-dump.cjs "$@" &
PID=$!
( sleep "$DEADLINE"; kill -TERM -- -$PID 2>/dev/null; sleep 3; kill -KILL -- -$PID 2>/dev/null ) &
WATCHDOG=$!
wait $PID; RC=$?
kill $WATCHDOG 2>/dev/null
exit $RC
