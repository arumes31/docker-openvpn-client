#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

# This script is called by entry.sh *before* OpenVPN is started, so no traffic
# can leave the container outside the tunnel while it is connecting.
# It sets up iptables rules to act as a kill switch and adds static routes.
#
# Usage: killswitch.sh <openvpn config file>
# Allowed subnets are read from the ALLOWED_SUBNETS environment variable.

# Explicitly drop all outgoing IPv6 traffic, as requested.
ip6tables -P OUTPUT DROP
ip6tables -F OUTPUT # Flush any existing rules

ip_regex='^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$'

# Configures the base IPv4 firewall rules (default deny)
configure_ipv4_firewall() {
    echo "Configuring IPv4 firewall..."

    # Flush existing OUTPUT rules and set default policy to DROP for IPv4
    iptables -F OUTPUT
    iptables -P OUTPUT DROP

    # Allow established and related connections
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow all loopback traffic and traffic to the container's own addresses
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -m addrtype --dst-type LOCAL -j ACCEPT

    # Allow traffic over the VPN tunnel (this includes DNS; DNS is not
    # allowed on any other interface to prevent leaks)
    iptables -A OUTPUT -o tun+ -j ACCEPT
}

# Creates static routes for any ALLOWED_SUBNETS and punches holes in the firewall
add_allowed_subnets_ipv4() {
    local allowed_subnets="$1"
    local default_gateway_ipv4
    default_gateway_ipv4=$(ip -4 route | awk '$1 == "default" && !found { print $3; found = 1 }')

    for subnet in ${allowed_subnets//,/ }; do
        echo "Adding IPv4 allowed subnet: $subnet"
        if [[ -z $(ip -4 route show exact "$subnet") ]]; then
            ip route add "$subnet" via "$default_gateway_ipv4"
        fi
        iptables -A OUTPUT --destination "$subnet" -j ACCEPT
    done
}

# Adds firewall exceptions for OpenVPN server addresses (IPv4)
add_vpn_server_exceptions_ipv4() {
    echo "Adding IPv4 VPN server exceptions..."
    local config_file="${1:?"config file not passed to kill switch"}"
    local global_port global_protocol remotes
    global_port=$(awk '$1 == "port" { print $2 }' "$config_file" | tr -d '\r')
    global_protocol=$(awk '$1 == "proto" { print $2 }' "$config_file" | tr -d '\r\n')
    remotes=$(awk '$1 == "remote" { print $2, $3, $4 }' "$config_file" | tr -d '\r')

    while IFS= read -r line; do
        IFS=" " read -ra remote <<< "${line%%\#*}"
        [[ ${#remote[@]} -gt 0 ]] || continue
        local address=${remote[0]}
        local port=$(echo ${remote[1]:-${global_port:-1194}} | tr -d '[:space:]')
        local protocol=$(echo ${remote[2]:-${global_protocol:-udp}} | tr -d '[:space:]')

        if [[ $address =~ $ip_regex ]]; then
            echo "Allowing IPv4 to VPN server: $address:$port (tcp)"
            iptables -A OUTPUT --destination "$address" --protocol tcp --destination-port "$port" -j ACCEPT
            echo "Allowing IPv4 to VPN server: $address:$port (udp)"
            iptables -A OUTPUT --destination "$address" --protocol udp --destination-port "$port" -j ACCEPT
        else
            # Resolve hostname to IP addresses (dig may also print CNAMEs, skip those)
            for ip in $(dig +short -4 "$address" A); do
                [[ $ip =~ $ip_regex ]] || continue
                echo "Allowing IPv4 to VPN server ($address): $ip:$port (tcp)"
                iptables -A OUTPUT --destination "$ip" --protocol tcp --destination-port "$port" -j ACCEPT
                echo "Allowing IPv4 to VPN server ($address): $ip:$port (udp)"
                iptables -A OUTPUT --destination "$ip" --protocol udp --destination-port "$port" -j ACCEPT
                # Add to hosts so OpenVPN can resolve the server (on reconnects too)
                # without DNS outside the tunnel, if not already
                grep -qxF "$ip $address" /etc/hosts || echo "$ip $address" >> /etc/hosts
            done
        fi
    done <<< "$remotes"
}

# Main execution
config_file="${1:-}"

configure_ipv4_firewall
add_allowed_subnets_ipv4 "${ALLOWED_SUBNETS:-}"
add_vpn_server_exceptions_ipv4 "$config_file"

# Reject everything else that is not going through the tunnel. This must be the
# last rule so the exceptions above are evaluated first.
iptables -A OUTPUT -j REJECT
