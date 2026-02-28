#!/bin/bash
set -e

################################
# VARIABLES
################################
WAN_IF="eth1"
LAN_IF="eth2"

WAN_IP="10.0.0.2/24"
LAN_IP="192.168.10.1/24"
WAN_GW="10.0.0.1"

################################
# PORT → INTERNAL IP MAPPING
# Format: "PORT:IP"
################################
PORT_FORWARD_MAP=(
    "80:192.168.10.100"
    "443:192.168.10.101"
    "8080:192.168.10.102"
    "8443:192.168.10.103"
)

################################
# ENABLE IP FORWARDING
################################
sysctl -w net.ipv4.ip_forward=1
sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf || true

################################
# INTERFACE IP ADDRESSES
################################
ip addr flush dev $WAN_IF
ip addr flush dev $LAN_IF

ip addr add $WAN_IP dev $WAN_IF
ip addr add $LAN_IP dev $LAN_IF

ip link set $WAN_IF up
ip link set $LAN_IF up

################################
# DEFAULT ROUTE
################################
ip route flush default
ip route add default via $WAN_GW dev $WAN_IF

################################
# FLUSH IPTABLES
################################
iptables -F
iptables -t nat -F
iptables -X

################################
# DEFAULT POLICIES
################################
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

################################
# INPUT CHAIN
################################
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -i $LAN_IF -j ACCEPT
iptables -A INPUT -j DROP

################################
# FORWARD CHAIN
################################
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

# Allow LAN → Internet
iptables -A FORWARD -i $LAN_IF -o $WAN_IF -j ACCEPT

################################
# NAT MASQUERADE
################################
iptables -t nat -A POSTROUTING -o $WAN_IF -j MASQUERADE

################################
# PORT FORWARD LOOP
################################
for entry in "${PORT_FORWARD_MAP[@]}"; do
    PORT="${entry%%:*}"      # extract port before colon
    IP="${entry##*:}"        # extract IP after colon

    # DNAT for incoming WAN traffic
    iptables -t nat -A PREROUTING -i $WAN_IF -p tcp --dport $PORT \
        -j DNAT --to-destination $IP:$PORT

    # Allow forwarded traffic through FORWARD chain
    iptables -A FORWARD -p tcp -d $IP --dport $PORT \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
done

################################
# FINAL FORWARD DROP
################################
iptables -A FORWARD -j DROP

echo "Router config up"