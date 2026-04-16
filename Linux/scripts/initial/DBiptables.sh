#!/bin/bash
# TNTECH NCAE 2026 - Database Box "Smart Lockdown" V3
# Fixed: Syntax error with nftables curly braces using single quotes.

if [ "$EUID" -ne 0 ]; then
    echo "Fatal: Run as root!"
    exit 1
fi

# === CONFIG ===
T=10
WEB="192.168.$T.5"
DB_PORT=5432
DNS="192.168.$T.12"
BACKUP="192.168.$T.15"

# ============================================================
# UTILITIES
# ============================================================

check_integrity() {
    local bin="$1"
    local path
    path=$(command -v "$bin" 2>/dev/null)
    if [ -z "$path" ]; then return 1; fi
    if [ ! -x "$path" ]; then return 1; fi
    
    local size
    size=$(wc -c < "$path" 2>/dev/null)
    if [ "${size:-0}" -lt 100 ]; then return 1; fi
    return 0
}

detect_pkg() {
    if command -v apt-get &>/dev/null; then echo "apt"
    elif command -v dnf &>/dev/null; then echo "dnf"
    elif command -v yum &>/dev/null; then echo "yum"
    else echo "none"; fi
}

PKG_MGR=$(detect_pkg)

install_fix() {
    local pkg="$1"
    echo "  [!] Attempting repair: $pkg"
    case $PKG_MGR in
        apt) apt-get update &>/dev/null; apt-get install -y --reinstall "$pkg" &>/dev/null ;;
        dnf|yum) $PKG_MGR install -y "$pkg" &>/dev/null ;;
    esac
}

# ============================================================
# FIREWALL LOGIC
# ============================================================

try_nftables() {
    echo "[*] Trying nftables..."
    check_integrity nft || install_fix nftables || return 1

    nft flush ruleset
    nft add table inet filter
    
    # SINGLE QUOTES protect the curly braces from Bash
    nft 'add chain inet filter input { type filter hook input priority 0; policy drop; }'
    nft 'add chain inet filter output { type filter hook output priority 0; policy drop; }'
    
    nft add rule inet filter input iif lo accept
    nft "add rule inet filter input ip saddr $WEB tcp dport $DB_PORT accept"
    nft 'add rule inet filter input ct state established,related accept'
    
    nft add rule inet filter output oif lo accept
    nft "add rule inet filter output ip daddr $DNS udp dport 53 accept"
    nft "add rule inet filter output ip daddr $BACKUP accept"
    nft 'add rule inet filter output ct state established,related accept'
    
    nft list ruleset > /etc/nftables.conf
    systemctl enable --now nftables &>/dev/null
    return 0
}

try_iptables() {
    echo "[*] Trying iptables..."
    check_integrity iptables || install_fix iptables || return 1
    
    iptables -F
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p tcp -s "$WEB" --dport "$DB_PORT" -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -p udp -d "$DNS" --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$BACKUP" -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    return 0
}

# ============================================================
# EXECUTION
# ============================================================

echo "[*] Locking down management services..."
for svc in ufw firewalld; do
    systemctl stop "$svc" &>/dev/null
    systemctl disable "$svc" &>/dev/null
    systemctl mask "$svc" &>/dev/null
done

if try_nftables; then
    echo "SUCCESS: nftables applied."
    exit 0
elif try_iptables; then
    echo "SUCCESS: iptables applied."
    exit 0
else
    echo "FATAL: Could not apply any firewall."
    exit 1
fi
