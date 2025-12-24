#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

cleanup() {
    [[ ${openvpn_pid:-} ]] && kill -TERM "$openvpn_pid" 2>/dev/null || true
    wait "$openvpn_pid" 2>/dev/null || true
}

is_enabled() {
    [[ ${1,,} =~ ^(true|t|yes|y|1|on|enable|enabled)$ ]]
}

# Find config file
if [[ -n ${VPN_CONFIG_FILE:-} ]]; then
    mapfile -t candidates < <(find /data/vpn -name "$VPN_CONFIG_FILE" 2>/dev/null | sort)
else
    mapfile -t candidates < <(find /data/vpn \( -name '*.ovpn' -o -name '*.conf' \) 2>/dev/null | sort)
fi

if [[ ${#candidates[@]} -eq 0 ]]; then
    echo "ERROR: No OpenVPN configuration file found in /data/vpn" >&2
    echo "   Expected: *.ovpn or *.conf (or set VPN_CONFIG_FILE env var)" >&2
    exit 1
fi

# Pick random one
config_file=$(shuf -n 1 -e "${candidates[@]}")

# CRITICAL: Double-check the file actually exists and is readable
if [[ ! -f "$config_file" || ! -r "$config_file" ]]; then
    echo "ERROR: Selected config file is not readable: $config_file" >&2
    exit 1
fi

echo "Using OpenVPN configuration: $config_file"

openvpn_args=(
    "--down-pre"
    "--script-security" "2"
    "--config" "$config_file"
    "--cd" "/data/vpn"
)

openvpn_args+=("--data-ciphers" "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC:AES-192-GCM:AES-128-CBC:AES-192-CBC")

openvpn_args+=("--verb" "${VPN_LOG_LEVEL:-3}")

if is_enabled "${KILL_SWITCH:-}"; then
    openvpn_args+=("--route-up" "/usr/local/bin/killswitch.sh ${KILL_SWITCH:-} ${ALLOWED_SUBNETS:-} $config_file")
fi

if [[ -n ${AUTH_SECRET:-} ]]; then
    auth_path="/run/secrets/$AUTH_SECRET"
    if [[ -f "$auth_path" ]]; then
        openvpn_args+=("--auth-user-pass" "$auth_path")
    else
        echo "WARNING: AUTH_SECRET specified but file not found: $auth_path" >&2
    fi
fi

# Final safety: print command (helpful for debugging)
echo "Starting OpenVPN with: openvpn ${openvpn_args[*]}"

openvpn "${openvpn_args[@]}" &
openvpn_pid=$!

trap cleanup TERM INT

wait "$openvpn_pid"