#!/usr/bin/env bash
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo.'; exit 1; }
ip netns list | grep -q '^switchlab\b' && { echo 'switchlab already exists; inspect it first.'; exit 1; }
install -d -m 711 /run/switchlab
install -d -o dnsmasq -g dnsmasq -m 700 /run/switchlab/dhcp
umask 077
python - <<'PY'
from pathlib import Path
p=Path('/run/switchlab')
password='12345678'
(p/'password').write_text(password+'\n')
(p/'hostapd.conf').write_text('''interface=wlp13s0
driver=nl80211
ssid=SwitchLab-Offline
hw_mode=g
channel=6
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase='''+password+'\n')
(p/'dnsmasq.conf').write_text('''interface=wlp13s0
bind-interfaces
listen-address=192.168.77.1
no-resolv
no-hosts
local=/#/
host-record=ctest.p01.ctest.srv.nintendo.net,192.168.77.1
log-queries
dhcp-range=192.168.77.20,192.168.77.30,255.255.255.0,1h
dhcp-option=3
dhcp-option=6,192.168.77.1
dhcp-leasefile=/run/switchlab/dhcp/leases
log-dhcp
''')
PY
ip netns add switchlab
ip link set wlp13s0 down
iw phy phy0 set netns name switchlab
ip -n switchlab link set lo up
ip netns exec switchlab sysctl -qw net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
ip netns exec switchlab nft -f - <<'NFT'
table inet isolation {
 chain input { type filter hook input priority 0; policy drop;
  iifname "lo" accept
  ct state established,related accept
  iifname "wlp13s0" udp dport { 53, 67 } accept
  iifname "wlp13s0" ip saddr 192.168.77.0/24 tcp dport { 53, 80, 39380 } accept
  iifname "wlp13s0" ip saddr 192.168.77.0/24 ip protocol icmp accept
 }
 chain forward { type filter hook forward priority 0; policy drop; }
 chain output { type filter hook output priority 0; policy drop;
  oifname "lo" accept
  oifname "wlp13s0" ip daddr 192.168.77.0/24 accept
  oifname "wlp13s0" udp sport 67 udp dport 68 accept
 }
}
NFT
ip -n switchlab address add 192.168.77.1/24 dev wlp13s0
systemd-run --unit=switchlab-ap --collect /usr/bin/ip netns exec switchlab /usr/bin/hostapd /run/switchlab/hostapd.conf
systemd-run --unit=switchlab-dhcp --collect /usr/bin/ip netns exec switchlab /usr/bin/dnsmasq --keep-in-foreground --conf-file=/run/switchlab/dnsmasq.conf

systemd-run --unit=switchlab-ctest --collect /usr/bin/ip netns exec switchlab /usr/bin/python "$SELF_DIR/connection_check.py"
