#!/bin/bash
# Clauded By Yours Truly
# King Snowball
# TNTECH NCAE 2026 - Database Box Firewall Script
# Installs and applies ALL available firewalls simultaneously.
# If one is blocked/broken, the others still hold.

echo "======================================================"
echo " TNTECH NCAE 2026 - Database Firewall (Team 10)"
echo " Strategy: Install + apply ALL firewalls in parallel"
echo "======================================================"
echo

if [ "$EUID" -ne 0 ]; then
    echo "This script must be ran as root!"
    exit 1
fi

# === HARDCODED CONFIG ===
T=10
ROUTER="192.168.$T.1"
BACKUP="192.168.$T.15"
DNS="192.168.$T.12"
WEB="192.168.$T.5"
DATABASE="192.168.$T.7"

# Track what succeeded
APPLIED=()
FAILED=()

# ============================================================
# UTILITIES
# ============================================================

check_binary_integrity() {
    local bin="$1"
    local path
    path=$(command -v "$bin" 2>/dev/null)
    [ -z "$path" ]       && return 1
    [ ! -x "$path" ]     && echo "  [!] $bin NOT executable — possible tamper!" && return 1
    local size
    size=$(stat -c '%s' "$path" 2>/dev/null)
    [ "${size:-0}" -lt 100 ] && echo "  [!] $bin suspiciously small (${size}B) — possible broken binary!" && return 1
    return 0
}

detect_pkg_manager() {
    if   command -v apt-get  &>/dev/null; then echo "apt"
    elif command -v dnf      &>/dev/null; then echo "dnf"
    elif command -v yum      &>/dev/null; then echo "yum"
    else echo "none"
    fi
}

PKG=$(detect_pkg_manager)

install_pkg() {
    # $1 = apt name, $2 = dnf/yum name (optional, defaults to $1)
    local apt_name="$1"
    local rpm_name="${2:-$1}"
    case $PKG in
        apt) apt-get install -y "$apt_name" &>/dev/null ;;
        dnf) dnf install -y "$rpm_name"     &>/dev/null ;;
        yum) yum install -y "$rpm_name"     &>/dev/null ;;
        *)   return 1 ;;
    esac
}

# ============================================================
# IPTABLES
# ============================================================

apply_iptables() {
    echo "[*] iptables — checking / installing..."

    if ! check_binary_integrity iptables; then
        echo "  [-] iptables not found or broken. Attempting install..."
        install_pkg iptables iptables || { echo "  [!] iptables install failed."; return 1; }
        case $PKG in
            apt) install_pkg iptables-persistent iptables-services ;;
            dnf|yum)
                install_pkg iptables-services iptables-services
                systemctl enable --now iptables &>/dev/null
                ;;
        esac
    fi

    check_binary_integrity iptables || { echo "  [!] iptables still broken after install attempt."; return 1; }

    echo "  [+] iptables healthy. Applying DB rules..."

    modprobe ip_conntrack 2>/dev/null || true

    # Flush everything
    iptables -F
    iptables -X
    iptables -t nat -F; iptables -t nat -X
    iptables -t mangle -F; iptables -t mangle -X

    # Default DROP
    iptables -P INPUT   DROP
    iptables -P OUTPUT  DROP
    iptables -P FORWARD DROP

    # Loopback
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Established / related
    iptables -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # SSH from router only (management)
    iptables -A INPUT -s "$ROUTER" -p tcp --dport 22 -j ACCEPT

    # ICMP from internal LAN only
    iptables -A INPUT  -s 192.168.$T.0/24 -p icmp -j ACCEPT
    iptables -A OUTPUT -d 192.168.$T.0/24 -p icmp -j ACCEPT

    # DNS outbound (name resolution)
    iptables -A OUTPUT -d "$DNS" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$DNS" -p tcp --dport 53 -j ACCEPT

    # PostgreSQL from web server ONLY — no other inbound
    iptables -A INPUT -s "$WEB" -p tcp --dport 5432 -j ACCEPT

    # Outbound to backup
    iptables -A OUTPUT -d "$BACKUP" -j ACCEPT

    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4

    # Persist on boot
    case $PKG in
        apt)
            # iptables-persistent / netfilter-persistent
            if command -v netfilter-persistent &>/dev/null; then
                netfilter-persistent save &>/dev/null
            fi
            ;;
        dnf|yum)
            systemctl enable --now iptables &>/dev/null
            service iptables save &>/dev/null
            ;;
    esac

    echo "  [+] iptables DB rules applied and saved."
    return 0
}

# ============================================================
# NFTABLES
# ============================================================

apply_nftables() {
    echo "[*] nftables — checking / installing..."

    if ! check_binary_integrity nft; then
        echo "  [-] nft not found or broken. Attempting install..."
        install_pkg nftables nftables || { echo "  [!] nftables install failed."; return 1; }
        systemctl enable --now nftables &>/dev/null
    fi

    check_binary_integrity nft || { echo "  [!] nft still broken after install attempt."; return 1; }

    echo "  [+] nftables healthy. Applying DB rules..."

    # Flush all existing nftables rules
    nft flush ruleset

    nft add table inet filter

    nft add chain inet filter input   '{ type filter hook input   priority 0; policy drop; }'
    nft add chain inet filter output  '{ type filter hook output  priority 0; policy drop; }'
    nft add chain inet filter forward '{ type filter hook forward priority 0; policy drop; }'

    # Loopback
    nft add rule inet filter input  iif lo accept
    nft add rule inet filter output oif lo accept

    # Established / related
    nft add rule inet filter input  ct state related,established accept
    nft add rule inet filter output ct state related,established accept

    # SSH from router only
    nft add rule inet filter input ip saddr "$ROUTER" tcp dport 22 accept

    # ICMP internal only
    nft add rule inet filter input  ip saddr 192.168.$T.0/24 icmp type echo-request accept
    nft add rule inet filter output ip daddr 192.168.$T.0/24 icmp type echo-reply   accept

    # DNS outbound
    nft add rule inet filter output ip daddr "$DNS" udp dport 53 accept
    nft add rule inet filter output ip daddr "$DNS" tcp dport 53 accept

    # PostgreSQL from web server ONLY
    nft add rule inet filter input ip saddr "$WEB" tcp dport 5432 accept

    # Outbound to backup
    nft add rule inet filter output ip daddr "$BACKUP" accept

    # Save rules
    mkdir -p /etc/nftables
    nft list ruleset > /etc/nftables/rules.nft

    # Persist on boot
    systemctl enable --now nftables &>/dev/null
    if [ -f /etc/nftables.conf ]; then
        cp /etc/nftables/rules.nft /etc/nftables.conf
    fi

    echo "  [+] nftables DB rules applied and saved."
    return 0
}

# ============================================================
# UFW
# ============================================================

apply_ufw() {
    echo "[*] ufw — checking / installing..."

    if ! check_binary_integrity ufw; then
        echo "  [-] ufw not found or broken. Attempting install..."
        install_pkg ufw ufw || { echo "  [!] ufw install failed."; return 1; }
    fi

    check_binary_integrity ufw || { echo "  [!] ufw still broken after install attempt."; return 1; }

    echo "  [+] ufw healthy. Applying DB rules..."

    # Full reset to known state
    ufw --force reset &>/dev/null

    ufw default deny incoming  &>/dev/null
    ufw default deny outgoing  &>/dev/null

    # Loopback (ufw handles implicitly, but be explicit)
    ufw allow in  on lo &>/dev/null
    ufw allow out on lo &>/dev/null

    # SSH from router only
    ufw allow from "$ROUTER" to any port 22 proto tcp &>/dev/null

    # ICMP from internal (ufw doesn't expose a simple rule; tweak before.rules)
    # We insert an ICMP allow into ufw's before.rules for internal LAN
    BEFORE_RULES="/etc/ufw/before.rules"
    if [ -f "$BEFORE_RULES" ] && ! grep -q "NCAE_ICMP" "$BEFORE_RULES"; then
        sed -i "/^# don't delete the 'COMMIT'/i \
# NCAE_ICMP — allow ICMP from internal LAN\n\
-A ufw-before-input -s 192.168.$T.0/24 -p icmp --icmp-type echo-request -j ACCEPT\n\
-A ufw-before-output -d 192.168.$T.0/24 -p icmp --icmp-type echo-reply -j ACCEPT" \
            "$BEFORE_RULES" 2>/dev/null || true
    fi

    # DNS outbound
    ufw allow out to "$DNS" port 53 proto udp &>/dev/null
    ufw allow out to "$DNS" port 53 proto tcp &>/dev/null

    # PostgreSQL from web server ONLY
    ufw allow from "$WEB" to any port 5432 proto tcp &>/dev/null

    # Outbound to backup
    ufw allow out to "$BACKUP" &>/dev/null

    ufw --force enable &>/dev/null

    echo "  [+] ufw DB rules applied and saved."
    return 0
}

# ============================================================
# FIREWALLD
# ============================================================

apply_firewalld() {
    echo "[*] firewalld — checking / installing..."

    if ! check_binary_integrity firewall-cmd; then
        echo "  [-] firewall-cmd not found or broken. Attempting install..."
        install_pkg firewalld firewalld || { echo "  [!] firewalld install failed."; return 1; }
        systemctl enable --now firewalld &>/dev/null
    fi

    check_binary_integrity firewall-cmd || { echo "  [!] firewall-cmd still broken after install."; return 1; }

    systemctl start firewalld &>/dev/null || { echo "  [!] firewalld failed to start."; return 1; }

    echo "  [+] firewalld healthy. Applying DB rules..."

    # Set default zone to drop (block everything not explicitly allowed)
    firewall-cmd --set-default-zone=drop &>/dev/null

    # Remove any lingering services from drop zone
    for svc in $(firewall-cmd --zone=drop --list-services 2>/dev/null); do
        firewall-cmd --zone=drop --remove-service="$svc" &>/dev/null
    done

    # SSH from router only
    firewall-cmd --zone=drop --add-rich-rule=\
"rule family=ipv4 source address=$ROUTER service name=ssh accept" &>/dev/null

    # ICMP from internal LAN only
    firewall-cmd --zone=drop --add-rich-rule=\
"rule family=ipv4 source address=192.168.$T.0/24 icmp-type name=echo-request accept" &>/dev/null

    # DNS outbound — firewalld direct rules for output
    firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 \
        -d "$DNS" -p udp --dport 53 -j ACCEPT &>/dev/null
    firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 \
        -d "$DNS" -p tcp --dport 53 -j ACCEPT &>/dev/null

    # PostgreSQL from web server ONLY
    firewall-cmd --zone=drop --add-rich-rule=\
"rule family=ipv4 source address=$WEB port protocol=tcp port=5432 accept" &>/dev/null

    # Outbound to backup
    firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 \
        -d "$BACKUP" -j ACCEPT &>/dev/null

    # Make all rules permanent
    firewall-cmd --runtime-to-permanent &>/dev/null
    systemctl enable firewalld &>/dev/null

    echo "  [+] firewalld DB rules applied and made permanent."
    return 0
}

# ============================================================
# RUN ALL FIREWALLS
# ============================================================

echo "--- Attempting all four firewalls on DB box (192.168.$T.7) ---"
echo

apply_iptables  && APPLIED+=("iptables")  || FAILED+=("iptables")
echo
apply_nftables  && APPLIED+=("nftables")  || FAILED+=("nftables")
echo
apply_ufw       && APPLIED+=("ufw")       || FAILED+=("ufw")
echo
apply_firewalld && APPLIED+=("firewalld") || FAILED+=("firewalld")
echo

# ============================================================
# SUMMARY
# ============================================================

echo "======================================================"
echo " RESULTS"
echo "======================================================"
if [ ${#APPLIED[@]} -gt 0 ]; then
    echo " [+] Successfully applied: ${APPLIED[*]}"
else
    echo " [!!!] NO firewalls were successfully applied!"
    echo "       The DB box may be unprotected. Investigate immediately."
    exit 1
fi

if [ ${#FAILED[@]} -gt 0 ]; then
    echo " [-] Failed / unavailable:  ${FAILED[*]}"
fi

echo
echo " DB POLICY ENFORCED:"
echo "   Inbound  — PostgreSQL (5432) from $WEB ONLY"
echo "   Inbound  — SSH (22) from $ROUTER ONLY"
echo "   Inbound  — ICMP from 192.168.$T.0/24 only"
echo "   Outbound — DNS to $DNS only"
echo "   Outbound — Backup to $BACKUP only"
echo "   Everything else: DROP"
echo "======================================================"
echo
echo "Done!"
