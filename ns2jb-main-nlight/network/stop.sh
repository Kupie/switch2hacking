#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.'; exit 1; }
systemctl stop switchlab-ap.service switchlab-dhcp.service switchlab-ctest.service
if [[ -n $(ip netns pids switchlab) ]]; then
 echo 'Other processes are still in switchlab. Stop them before removing the namespace.'
 exit 1
fi
ip -n switchlab link set wlp13s0 down
ip netns exec switchlab iw phy phy0 set netns 1
ip netns delete switchlab
networkctl reconfigure wlp13s0
