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

# OpenVPN directives in the config that execute external programs or load code.
# They run as root with NET_ADMIN in the network namespace shared with other
# containers, so they are refused unless explicitly allowed.
script_directive_regex='^[[:space:]]*(--)?(up|down|route-up|route-pre-down|ipchange|tls-verify|tls-crypt-v2-verify|auth-user-pass-verify|learn-address|client-connect|client-disconnect|plugin|iproute|script-security|config)([[:space:]]|$)'

if is_enabled "${ALLOW_CONFIG_SCRIPTS:-off}"; then
    echo "WARNING: ALLOW_CONFIG_SCRIPTS is enabled, script directives in $config_file will be executed" >&2
    script_security=2
else
    if script_lines=$(grep -nE "$script_directive_regex" "$config_file"); then
        echo "ERROR: $config_file contains directives that execute external programs:" >&2
        echo "$script_lines" >&2
        echo "   Remove them, or set ALLOW_CONFIG_SCRIPTS=on if you trust this config." >&2
        exit 1
    fi
    script_security=1
fi

openvpn_args=(
    "--down-pre"
    "--config" "$config_file"
    "--cd" "/data/vpn"
    "--script-security" "$script_security"
)

# Only AEAD ciphers by default; set VPN_DATA_CIPHERS if your provider requires CBC
openvpn_args+=("--data-ciphers" "${VPN_DATA_CIPHERS:-AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305}")

openvpn_args+=("--verb" "${VPN_LOG_LEVEL:-3}")

# Drop root privileges once the tunnel is set up
if is_enabled "${VPN_DROP_PRIVILEGES:-on}"; then
    openvpn_args+=("--user" "nobody" "--group" "nobody" "--persist-tun" "--persist-key")
fi

# Install the kill switch before OpenVPN starts so nothing leaks while connecting
if is_enabled "${KILL_SWITCH:-}"; then
    /usr/local/bin/killswitch.sh "$config_file"
else
    echo "KILL_SWITCH is disabled. Only IPv4 output policy will be ACCEPT."
    iptables -P OUTPUT ACCEPT
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