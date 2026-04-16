#!/bin/bash
# TNTECH NCAE 2026 - Database Box "Smart Lockdown"
# Strategy: Find first working firewall -> Fix if broken -> Apply strict 1-inbound rule -> Exit.

if [ "$EUID" -ne 0 ]; then
    echo "This script must be ran as root!"
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
    [ -z "$path" ] && return 1
    [ ! -x "$path" ] && return 1
    # Check if binary is a dummy file (Red Team trick)
    local size
    size=$(stat -c '%s' "$path" 2>/dev/null)
    [ "${size:-0}" -lt 100 ] && return 1
    return 0
}

detect_pkg() {
    if command -v apt-get &>/dev/null; then echo "apt";
    elif command -v dnf &>/dev/null; then echo "dnf";
    elif command -v yum &>/dev/null; then echo "yum";
    else echo "none"; fi
}

PKG_MGR=$(detect_pkg)

install_fix() {
    local pkg="$1"
    echo "  [!] Attempting to repair/install $pkg..."
    case $PKG_MGR in
        apt) apt-get update &>/dev/null; apt-get install -y --reinstall "$pkg" &>/dev/null ;;
        dnf|yum) $PKG_MGR install -y "$pkg" &>/dev/null ;;
    esac
}

# ============================================================
# FIREWALL LOGIC
# ============================================================

try_iptables() {
    echo "[*] Checking iptables..."
    if ! check_integrity iptables; then
        install_fix iptables || return 1
    fi
    
    iptables -F
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    
    # Strict Inbound
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p tcp -s "$WEB" --dport "$DB_PORT" -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    
    # Strict Outbound
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A OUTPUT -p udp -d "$DNS" --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$BACKUP" -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    return 0
}

try_nftables() {
    echo "[*] Checking nftables..."
    if ! check_integrity nft; then
        install_fix nftables || return 1
    fi

    nft flush ruleset
    nft add table inet filter
    nft add chain inet filter input { type filter hook input priority 0; policy drop; }
    nft add chain inet filter output { type filter hook output priority 0; policy drop; }
    
    nft add rule inet filter input iif lo accept
    nft add rule inet filter input ip saddr "$WEB" tcp dport "$DB_PORT" accept
    nft add rule inet filter input ct state established,related accept
    
    nft add rule inet filter output oif lo accept
    nft add rule inet filter output ip daddr "$DNS" udp dport 53 accept
    nft add rule inet filter output ip daddr "$BACKUP" accept
    nft add rule inet filter output ct state established,related accept
    
    nft list ruleset > /etc/nftables.conf
    systemctl enable --now nftables &>/dev/null
    return 0
}

try_ufw() {
    echo "[*] Checking ufw..."
    if ! check_integrity ufw; then
        install_fix ufw || return 1
    fi
    
    ufw --force reset &>/dev/null
    ufw default deny incoming
    ufw default deny outgoing
    ufw allow from "$WEB" to any port "$DB_PORT" proto tcp
    ufw allow out to "$DNS" port 53 proto udp
    ufw allow out to "$BACKUP"
    ufw --force enable &>/dev/null
    return 0
}

try_firewalld() {
    echo "[*] Checking firewalld..."
    if ! check_integrity firewall-cmd; then
        install_fix firewalld || return 1
    fi
    
    systemctl start firewalld &>/dev/null
    firewall-cmd --set-default-zone=drop &>/dev/null
    firewall-cmd --permanent --zone=drop --add-rich-rule="rule family=ipv4 source address=$WEB port port=$DB_PORT protocol=tcp accept" &>/dev/null
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -d "$DNS" -p udp --dport 53 -j ACCEPT &>/dev/null
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -d "$BACKUP" -j ACCEPT &>/dev/null
    firewall-cmd --reload &>/dev/null
    return 0
}

# ============================================================
# MAIN EXECUTION loop
# ============================================================

# Disable conflicting services first
systemctl stop ufw firewalld nftables &>/dev/null

for method in try_nftables try_iptables try_ufw try_firewalld; do
    if $method; then
        echo "------------------------------------------------"
        echo " SUCCESS: $method applied strict lockdown."
        echo " 1 Inbound Allowed: $WEB -> Port $DB_PORT"
        echo " No SSH. No Ping. Console access only."
        echo "------------------------------------------------"
        exit 0
    fi
    echo "  [-] $method failed or unavailable. Trying next..."
done

echo " [!!!] FATAL: All firewall attempts failed. Box is UNPROTECTED."
exit 1
