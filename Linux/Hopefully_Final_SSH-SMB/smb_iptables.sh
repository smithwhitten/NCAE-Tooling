#!/bin/bash
# smb_iptables.sh — Shell/SMB node iptables ruleset
# Rocky Linux 9 | Team [TEAM_NUMBER]

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "Must be run as root."
    exit 1
fi

# --- CONFIGURABLE VARIABLES ---
COMP_DNS="[COMP_DNS_IP]"
JUMP_HOST="[JUMP_HOST_IP]"
SMB_SUBNET="[SMB_SOURCE_SUBNET]"
BACKUP_VM="[BACKUP_VM_IP]"
# ------------------------------

echo "[*] Disabling firewalld..."
systemctl disable --now firewalld 2>/dev/null || true

echo "[*] Loading conntrack module..."
modprobe ip_conntrack

echo "[*] Flushing existing rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

echo "[*] Setting default policies to ACCEPT temporarily..."
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

echo "[*] Applying INPUT rules..."
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s "$JUMP_HOST" --dport 22 -j ACCEPT
iptables -A INPUT -p tcp -s "$SMB_SUBNET" --dport 445 -j ACCEPT
iptables -A INPUT -p tcp -s "$SMB_SUBNET" --dport 139 -j ACCEPT
iptables -A INPUT -p udp -s "$SMB_SUBNET" --dport 137 -j ACCEPT
iptables -A INPUT -p udp -s "$SMB_SUBNET" --dport 138 -j ACCEPT
iptables -A INPUT -p icmp -s "$SMB_SUBNET" -j ACCEPT
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables-drop: " --log-level 4
iptables -A INPUT -j DROP

echo "[*] Applying OUTPUT rules..."
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p udp -d "$COMP_DNS" --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -d "$COMP_DNS" --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp -d "$BACKUP_VM" --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -j DROP

echo "[*] Locking down FORWARD..."
iptables -P FORWARD DROP

echo "[*] Locking down default INPUT/OUTPUT policies..."
iptables -P INPUT DROP
iptables -P OUTPUT DROP

echo "[*] Saving rules..."
dnf install -y iptables-services 2>/dev/null | tail -1
iptables-save > /etc/sysconfig/iptables
systemctl enable iptables

echo "[+] Done. Current ruleset:"
iptables -L -v -n --line-numbers
