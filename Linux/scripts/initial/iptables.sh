# Clauded By Yours Truly
# King Snowball

#!/bin/bash

echo "TNTECH NCAE 2026 - Universal iptables Script"
echo

if [ "$EUID" -ne 0 ]; then
    echo "This script must be ran as root!"
    exit 1
fi

# === TEAM NUMBER ===
read -p "Enter your team number: " T
if ! [[ "$T" =~ ^[0-9]+$ ]]; then
    echo "Invalid team number!"; exit 1
fi

# === ADDRESSES ===
ROUTER="192.168.$T.1"
BACKUP="192.168.$T.15"
DNS="192.168.$T.12"
WEB="192.168.$T.5"
DATABASE="192.168.$T.7"
SHELL="192.168.$T.14"

COMP_DNS="172.18.0.12"
COMP_ROUTER="172.18.0.1"

# === BOX SELECTION ===
echo
echo "Select your box:"
echo "  1) Web Server   (192.168.$T.5)  - Ubuntu 24.04"
echo "  2) Database     (192.168.$T.7)  - Ubuntu 24.04"
echo "  3) DNS          (192.168.$T.12) - Rocky Linux 9"
echo "  4) Shell/SMB    (192.168.$T.14) - Rocky Linux 9"
echo "  5) Backup       (192.168.$T.15)"
echo
read -p "Enter choice [1-5]: " ROLE

case $ROLE in
    1|2|3|4|5) ;;
    *) echo "Invalid choice!"; exit 1 ;;
esac

# === ACTION SELECTION ===
echo
echo "Select action:"
echo "  1) Apply iptables rules"
echo "  2) Reset/flush iptables (open all)"
echo "  3) Save current iptables"
echo "  4) Restore saved iptables"
echo
read -p "Enter choice [1-4]: " ACTION

# === FLUSH FUNCTION ===
flush_rules() {
    echo "Flushing existing rules..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    echo "Rules flushed — all traffic now open."
}

# === COMMON BASE RULES ===
apply_base_rules() {
    modprobe ip_conntrack

    flush_rules

    # Default DROP everything
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP

    # Loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    # Established/related
    iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    # SSH from router only
    iptables -A INPUT -s $ROUTER -p tcp --dport 22 -j ACCEPT

    # ICMP from internal LAN only
    iptables -A INPUT -s 192.168.$T.0/24 -p icmp -j ACCEPT
    iptables -A OUTPUT -d 192.168.$T.0/24 -p icmp -j ACCEPT

    # DNS outbound (for name resolution)
    iptables -A OUTPUT -d $DNS -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d $DNS -p tcp --dport 53 -j ACCEPT
}

# === BOX-SPECIFIC RULES ===

apply_web_rules() {
    echo "Applying Web Server rules..."
    apply_base_rules

    # HTTP and HTTPS from anywhere (scoring engine hits these)
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    # Outbound to DB (PostgreSQL only)
    iptables -A OUTPUT -d $DATABASE -p tcp --dport 5432 -j ACCEPT

    # Outbound to backup
    iptables -A OUTPUT -d $BACKUP -j ACCEPT

    echo "Web Server rules applied."
}

apply_db_rules() {
    echo "Applying Database rules..."
    apply_base_rules

    # PostgreSQL from web server only
    iptables -A INPUT -s $WEB -p tcp --dport 5432 -j ACCEPT

    # Outbound to backup
    iptables -A OUTPUT -d $BACKUP -j ACCEPT

    echo "Database rules applied."
}

apply_dns_rules() {
    echo "Applying DNS rules..."
    apply_base_rules

    # Accept DNS queries from internal LAN
    iptables -A INPUT -s 192.168.$T.0/24 -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -s 192.168.$T.0/24 -p tcp --dport 53 -j ACCEPT

    # Accept DNS queries forwarded from router (external scoring)
    iptables -A INPUT -s $ROUTER -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -s $ROUTER -p tcp --dport 53 -j ACCEPT

    # Forward DNS queries upstream to competition DNS
    iptables -A OUTPUT -d $COMP_DNS -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d $COMP_DNS -p tcp --dport 53 -j ACCEPT

    # Outbound to backup
    iptables -A OUTPUT -d $BACKUP -j ACCEPT

    echo "DNS rules applied."
}

apply_shell_rules() {
    echo "Applying Shell/SMB rules..."
    apply_base_rules

    # SSH from anywhere — scoring engine tests this with keys
    # Locked down to key-only auth in /etc/ssh/sshd_config
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    # SMB from internal LAN only (445)
    iptables -A INPUT -s 192.168.$T.0/24 -p tcp --dport 445 -j ACCEPT

    # SMB also needs these ports for full functionality
    iptables -A INPUT -s 192.168.$T.0/24 -p tcp --dport 139 -j ACCEPT
    iptables -A INPUT -s 192.168.$T.0/24 -p udp --dport 137 -j ACCEPT
    iptables -A INPUT -s 192.168.$T.0/24 -p udp --dport 138 -j ACCEPT

    # Outbound to backup
    iptables -A OUTPUT -d $BACKUP -j ACCEPT

    echo "Shell/SMB rules applied."
    echo
    echo "*** REMINDER: Ensure /etc/ssh/sshd_config has:"
    echo "    PasswordAuthentication no"
    echo "    PermitRootLogin no"
    echo "    PubkeyAuthentication yes"
}

apply_backup_rules() {
    echo "Applying Backup rules..."
    apply_base_rules

    # Accept inbound from all internal boxes
    iptables -A INPUT -s 192.168.$T.0/24 -j ACCEPT

    echo "Backup rules applied."
}

# === SAVE / RESTORE ===
save_rules() {
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    echo "Rules saved to /etc/iptables/rules.v4"
}

restore_rules() {
    if [ -f /etc/iptables/rules.v4 ]; then
        iptables-restore < /etc/iptables/rules.v4
        echo "Rules restored from /etc/iptables/rules.v4"
    else
        echo "No saved rules found at /etc/iptables/rules.v4!"
        exit 1
    fi
}

# === MAIN LOGIC ===
case $ACTION in
    1)
        case $ROLE in
            1) apply_web_rules ;;
            2) apply_db_rules ;;
            3) apply_dns_rules ;;
            4) apply_shell_rules ;;
            5) apply_backup_rules ;;
        esac
        save_rules
        ;;
    2)
        flush_rules
        ;;
    3)
        save_rules
        ;;
    4)
        restore_rules
        ;;
esac

echo
echo "Done!"