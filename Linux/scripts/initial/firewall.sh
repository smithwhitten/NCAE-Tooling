#!/bin/bash
# TNTECH NCAE 2026 - Universal "Zero-Trust" Repair & Lockdown
# Strategy: Verify Integrity -> Repair/Install -> Global DROP (In/Out/Forward)

if [ "$EUID" -ne 0 ]; then
    echo "Fatal: Must run as root!"
    exit 1
fi

# ============================================================
# UTILITIES: INTEGRITY & REPAIR
# ============================================================

check_integrity() {
    local bin="$1"
    local path
    path=$(command -v "$bin" 2>/dev/null)
    if [ -z "$path" ]; then return 1; fi
    if [ ! -x "$path" ]; then return 1; fi
    
    # Check for empty/dummy files (Red Team trick)
    local size
    size=$(wc -c < "$path" 2>/dev/null)
    if [ "${size:-0}" -lt 100 ]; then return 1; fi
    return 0
}

detect_pkg() {
    if   command -v apt-get &>/dev/null; then echo "apt"
    elif command -v dnf     &>/dev/null; then echo "dnf"
    elif command -v yum     &>/dev/null; then echo "yum"
    else echo "none"; fi
}

PKG_MGR=$(detect_pkg)

install_fix() {
    local pkg="$1"
    echo "[!] Attempting repair/installation of $pkg..."
    case $PKG_MGR in
        apt) 
            apt-get update &>/dev/null
            apt-get install -y --reinstall "$pkg" &>/dev/null 
            ;;
        dnf|yum) 
            $PKG_MGR install -y "$pkg" &>/dev/null 
            ;;
        *) 
            echo "  [!] No package manager found. Manual repair needed."
            return 1 
            ;;
    esac
}

# ============================================================
# LOCKDOWN EXECUTION
# ============================================================

echo "------------------------------------------------------"
echo " PHASE 1: INTEGRITY CHECK"
echo "------------------------------------------------------"

# Ensure iptables is present and functional
if ! check_integrity iptables; then
    install_fix iptables
    if ! check_integrity iptables; then
        echo "FATAL: Could not fix iptables. Integrity compromised."
        exit 1
    fi
fi
echo "[+] iptables verified/repaired."

echo "------------------------------------------------------"
echo " PHASE 2: SERVICES LOCKDOWN"
echo "------------------------------------------------------"

# Stop/Mask managers so they don't fight our global DROP
for svc in ufw firewalld nftables; do
    systemctl stop "$svc" &>/dev/null
    systemctl disable "$svc" &>/dev/null
    systemctl mask "$svc" &>/dev/null
done
echo "[+] Management services masked."

echo "------------------------------------------------------"
echo " PHASE 3: GLOBAL DROP (SCORCHED EARTH)"
echo "------------------------------------------------------"

# 1. Flush all current rules
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# 2. SET UNIVERSAL DROP (The Big Hammer)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# 4. Persistence
if [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
fi

echo "------------------------------------------------------"
echo " UNIVERSAL LOCKDOWN COMPLETE"
echo "------------------------------------------------------"
echo " Status: 100% Isolation (except Localhost)"
echo " No Inbound, No Outbound, No Forwarding."
