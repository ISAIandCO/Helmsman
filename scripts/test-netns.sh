#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run as root on an isolated CI runner'; exit 1; }
python_bin=${1:-python3}
export HELMSMAN_ENGINES=${HELMSMAN_ENGINES:?Set HELMSMAN_ENGINES}
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
server_pid=''
cleanup() {
  [[ -z $server_pid ]] || kill "$server_pid" 2>/dev/null || true
  ip netns del hm-client 2>/dev/null || true
  ip netns del hm-server 2>/dev/null || true
  rm -rf /etc/netns/hm-client /tmp/helmsman-netns-test
}
trap cleanup EXIT
id helmsman-engine &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin helmsman-engine
ip netns add hm-client
ip netns add hm-server
ip link add hm-vclient type veth peer name hm-vserver
ip link set hm-vclient netns hm-client
ip link set hm-vserver netns hm-server
ip -n hm-client link set lo up
ip -n hm-server link set lo up
ip -n hm-client addr add 10.90.0.2/24 dev hm-vclient
ip -n hm-server addr add 10.90.0.1/24 dev hm-vserver
ip -n hm-server addr add 198.51.100.2/32 dev lo
ip -n hm-server addr add 198.51.100.3/32 dev lo
ip -n hm-client link set hm-vclient up
ip -n hm-server link set hm-vserver up
ip -n hm-client route add default via 10.90.0.1
mkdir -p /etc/netns/hm-client
printf 'nameserver 203.0.113.53\noptions timeout:2 attempts:1\n' > /etc/netns/hm-client/resolv.conf
cd "$root"
ip netns exec hm-server "$python_bin" tests/netns_check.py server &
server_pid=$!
ip netns exec hm-client "$python_bin" tests/netns_check.py client
