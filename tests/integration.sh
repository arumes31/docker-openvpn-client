#!/usr/bin/env bash

# Integration tests for the kill switch and config checks.
# Starts the image against an unreachable VPN server (TEST-NET-1) so the tunnel
# never comes up, then verifies nothing can leave the container meanwhile.
#
# Usage: tests/integration.sh <image>

set -o errexit
set -o nounset
set -o pipefail

image="${1:?"usage: $0 <image>"}"
vpn_server=192.0.2.1
workdir=$(mktemp -d)
containers=()

cleanup() {
    for c in "${containers[@]}"; do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
    rm -rf "$workdir"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for c in "${containers[@]}"; do
        echo "--- logs of $c ---" >&2
        docker logs "$c" >&2 || true
    done
    exit 1
}

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=test-ca" \
    -keyout "$workdir/ca.key" -out "$workdir/ca.crt" 2>/dev/null
printf 'user\npass\n' > "$workdir/creds.txt"
chmod 644 "$workdir"/*

write_config() {
    cat > "$workdir/client.ovpn" <<EOF
client
dev tun
proto udp
remote $vpn_server 1194
nobind
ca ca.crt
auth-user-pass creds.txt
connect-retry 1
$1
EOF
}

# Starts a container and stores its name in $c
run_container() {
    c="vpn-test-$RANDOM"
    containers+=("$c")
    docker run --detach --name "$c" \
        --cap-add=NET_ADMIN --device=/dev/net/tun \
        --volume "$workdir:/data/vpn:ro" \
        "$@" "$image" >/dev/null
}

echo "== Kill switch is active before the tunnel is up"
write_config ""
run_container
for _ in $(seq 1 30); do
    docker exec "$c" pgrep openvpn >/dev/null 2>&1 && break
    sleep 1
done
docker exec "$c" pgrep openvpn >/dev/null 2>&1 || fail "openvpn is not running"

rules=$(docker exec "$c" iptables -S OUTPUT)
echo "$rules"
grep -qx -- '-P OUTPUT DROP' <<< "$rules" || fail "OUTPUT policy is not DROP"
grep -q -- "-d $vpn_server/32 -p udp -m udp --dport 1194 -j ACCEPT" <<< "$rules" || fail "no VPN server exception"
[[ $(tail -n 1 <<< "$rules") == '-A OUTPUT -j REJECT'* ]] || fail "REJECT is not the last rule"
if grep -q -- '--dport 53' <<< "$rules"; then fail "DNS is allowed outside the tunnel"; fi

docker exec "$c" ip link show tun0 >/dev/null 2>&1 && fail "tunnel unexpectedly up"
if docker exec "$c" curl -s --max-time 5 http://1.1.1.1 >/dev/null; then fail "HTTP egress outside the tunnel"; fi
if docker exec "$c" dig +time=2 +tries=1 @8.8.8.8 example.com >/dev/null; then fail "DNS egress outside the tunnel"; fi

echo "== Configs with script directives are refused"
write_config "up /bin/true"
run_container
docker wait "$c" >/dev/null
[[ $(docker inspect -f '{{.State.ExitCode}}' "$c") != 0 ]] || fail "config with 'up' was accepted"
docker logs "$c" 2>&1 | grep -q 'directives that execute external programs' || fail "missing refusal message"

echo "== ALLOW_CONFIG_SCRIPTS opts back in"
run_container --env ALLOW_CONFIG_SCRIPTS=on
sleep 5
docker exec "$c" pgrep openvpn >/dev/null 2>&1 || fail "openvpn not running with ALLOW_CONFIG_SCRIPTS=on"

echo "All integration tests passed"
