#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# This script is called by OpenVPN's --route-up option.
# It sets up iptables rules to act as a kill switch and adds static routes.

# Explicitly drop all outgoing IPv6 traffic, as requested.
ip6tables -F OUTPUT
ip6tables -P OUTPUT DROP

# Function to check if a variable represents an enabled state
is_enabled() {
    [[ ${1,,} =~ ^(true|t|yes|y|1|on|enable|enabled)$ ]]
}

# Configures IPv4 firewall rules
configure_ipv4_firewall() {
    local allowed_subnets="$1"
    
    echo "Configuring IPv4 firewall..."

    # Flush existing OUTPUT rules and set default policy to DROP for IPv4
    iptables -F OUTPUT
    iptables -P OUTPUT DROP

    # Allow established and related connections
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow all loopback traffic
    iptables -A OUTPUT -o lo -j ACCEPT

    # Allow traffic over the VPN tunnel
    iptables -A OUTPUT -o tun0 -j ACCEPT

    # Allow DNS (UDP/TCP port 53) traffic
    iptables -A OUTPUT -p udp --destination-port 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --destination-port 53 -j ACCEPT

    # Allow DHCP (UDP ports 67, 68) traffic
    iptables -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT

    # Block all outgoing IPv4 traffic that is not through tun0, except for local addresses
    # This rule is crucial for the kill switch functionality
    iptables -A OUTPUT \
        ! --out-interface tun0 \
        --match addrtype ! --dst-type LOCAL \
        ! --destination "$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)" \
        --jump REJECT

    # Create static routes for any ALLOWED_SUBNETS and punch holes in the firewall
    local default_gateway_ipv4
    default_gateway_ipv4=$(ip -4 route | awk '$1 == "default" { print $3; exit }')
    if [[ -z $default_gateway_ipv4 ]]; then
        echo "ERROR: IPv4 default gateway not found" >&2
        return 1
    fi
    for subnet in ${allowed_subnets//,/ }; do
        if [[ ! $subnet =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
            echo "ERROR: invalid ALLOWED_SUBNETS entry: $subnet" >&2
            return 1
        fi
        echo "Adding IPv4 allowed subnet: $subnet"
        ip route replace "$subnet" via "$default_gateway_ipv4"
        iptables -A OUTPUT --destination "$subnet" -j ACCEPT
    done
}

# Adds firewall exceptions for OpenVPN server addresses (IPv4)
add_vpn_server_exceptions_ipv4() {
    echo "Adding IPv4 VPN server exceptions..."
    local config_file="${1:?config file not provided to kill switch}"
    local global_port
    local global_protocol
    local remotes
    global_port=$(awk '$1 == "port" { print $2; exit }' "$config_file")
    global_protocol=$(awk '$1 == "proto" { print $2; exit }' "$config_file" | tr -d '\n')
    remotes=$(awk '$1 == "remote" { print $2, $3, $4 }' "$config_file")
    local ip_regex='^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$'

    while IFS= read -r line; do
        IFS=" " read -ra remote <<< "${line%%\#*}"
        local address=${remote[0]}
        local port
        local protocol
        port=$(printf '%s' "${remote[1]:-${global_port:-1194}}" | tr -d '[:space:]')
        protocol=$(printf '%s' "${remote[2]:-${global_protocol:-udp}}" | tr -d '[:space:]')
        if [[ ! $port =~ ^[0-9]{1,5}$ ]] || (( port < 1 || port > 65535 )); then
            echo "ERROR: invalid VPN remote port" >&2
            return 1
        fi
        if [[ $protocol != udp* && $protocol != tcp* ]]; then
            echo "ERROR: invalid VPN remote protocol" >&2
            return 1
        fi

        if [[ $address =~ $ip_regex ]]; then
            echo "Allowing IPv4 to VPN server: $address:$port (tcp)"
            iptables -A OUTPUT --destination "$address" --protocol tcp --destination-port "$port" -j ACCEPT
            echo "Allowing IPv4 to VPN server: $address:$port (udp)"
            iptables -A OUTPUT --destination "$address" --protocol udp --destination-port "$port" -j ACCEPT
        else
            # Resolve hostname to IP addresses
            for ip in $(dig +short -4 "$address"); do
                echo "Allowing IPv4 to VPN server ($address): $ip:$port (tcp)"
                iptables -A OUTPUT --destination "$ip" --protocol tcp --destination-port "$port" -j ACCEPT
                echo "Allowing IPv4 to VPN server ($address): $ip:$port (udp)"
                iptables -A OUTPUT --destination "$ip" --protocol udp --destination-port "$port" -j ACCEPT
            done
        fi
    done <<< "$remotes"
}

# Main execution
if is_enabled "${KILL_SWITCH:-}"; then
    allowed_subnets="${ALLOWED_SUBNETS:-}"
    config_file="${VPN_CONFIG_PATH:?VPN_CONFIG_PATH is required}"

    configure_ipv4_firewall "$allowed_subnets"
    add_vpn_server_exceptions_ipv4 "$config_file"
else
    echo "KILL_SWITCH is disabled. Only IPv4 output policy will be ACCEPT."
    iptables -P OUTPUT ACCEPT # If kill switch is off, allow all IPv4 traffic
fi
