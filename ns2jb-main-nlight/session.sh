#!/usr/bin/env bash
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

kill_stale_hosts() {
  # A stale listener would accept the console's dial and close it, spamming
  # RPC STOP and leaking console sockets. Only one host may ever listen.
  local stale
  stale=$(pgrep -f "$project_dir/run.cjs|$project_dir/runs/.*/switch2/pipeline.cjs|$project_dir/runs/.*/switch2/memory/probe-reserved-gap.cjs" 2>/dev/null || true)
  if [[ -n "$stale" ]]; then
    echo "Killing stale session hosts: $stale" >&2
    for pid in $stale; do sudo -n kill -9 "$pid" 2>/dev/null || true; done
    sleep 1
  fi
  if sudo -n ip netns exec switchlab ss -tln 2>/dev/null | grep -q ':39380 '; then
    echo 'Refusing to continue: something still listens on 192.168.77.1:39380 in switchlab.' >&2
    exit 1
  fi
}

if [[ "${1:-}" == start ]]; then
  if sudo -n ip netns exec switchlab ip -4 route get 1.1.1.1 >/dev/null 2>&1; then
    echo 'Refusing to start: switchlab has an internet route.' >&2
    exit 1
  fi
  kill_stale_hosts
  exec sudo -n ip netns exec switchlab runuser -u nlight -- node "$project_dir/run.cjs" --session 192.168.77.1
fi
if [[ "${1:-}" == resume ]]; then
  if sudo -n ip netns exec switchlab ip -4 route get 1.1.1.1 >/dev/null 2>&1; then
    echo 'Refusing to resume: switchlab has an internet route.' >&2
    exit 1
  fi
  kill_stale_hosts
  exec sudo -n ip netns exec switchlab runuser -u nlight -- node "$project_dir/run.cjs" --resume
fi
exec sudo -n ip netns exec switchlab runuser -u nlight -- node "$project_dir/session.cjs" "${1:-status}"
