#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# This script is called by OpenVPN's --route-up option.
# It sets up iptables rules to act as a kill switch and adds static routes.

# Explicitly drop all outgoing IPv6 traffic, as requested.
ip6tables -P OUTPUT DROP
ip6tables -F OUTPUT # Flush any existing rules

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
    local default_gateway_ipv4=$(ip -4 route | awk '$1 == "default" { print $3 }')
    for subnet in ${allowed_subnets//,/ }; do
        echo "Adding IPv4 allowed subnet: $subnet"
        ip route add "$subnet" via "$default_gateway_ipv4"
        iptables -A OUTPUT --destination "$subnet" -j ACCEPT
    done
}

# Adds firewall exceptions for OpenVPN server addresses (IPv4)
add_vpn_server_exceptions_ipv4() {
    echo "Adding IPv4 VPN server exceptions..."
    local config_file="${config:?"config file not found by kill switch"}"
    local global_port=$(awk '$1 == "port" { print $2 }' "$config_file")
    local global_protocol=$(awk '$1 == "proto" { print $2 }' "$config_file" | tr -d '\n')
    local remotes=$(awk '$1 == "remote" { print $2, $3, $4 }' "$config_file")
    local ip_regex='^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$'

    while IFS= read -r line; do
        IFS=" " read -ra remote <<< "${line%%\#*}"
        local address=${remote[0]}
        local port=$(echo ${remote[1]:-${global_port:-1194}} | tr -d '[:space:]')
        local protocol=$(echo ${remote[2]:-${global_protocol:-udp}} | tr -d '[:space:]')

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
                # Add to hosts to prevent DNS leaks for the server address itself, if not already
                grep -q "$ip $address" /etc/hosts || echo "$ip $address" >> /etc/hosts
            done
        fi
    done <<< "$remotes"
}

# Main execution
if is_enabled "${1:-}"; then
    kill_switch_status="${1:-}"
    allowed_subnets="${2:-}"
    config_file="${3:-}"

    configure_ipv4_firewall "$allowed_subnets"
    add_vpn_server_exceptions_ipv4 "$config_file"
else
    echo "KILL_SWITCH is disabled. Only IPv4 output policy will be ACCEPT."
    iptables -P OUTPUT ACCEPT # If kill switch is off, allow all IPv4 traffic
fi