#!/bin/bash
# NCAE - CosmicGrace
# Author - Claude (Anthropic) / CosmicGrace
# =============================================================================
# setup_ssh.sh — SSH Service Configuration and Hardening
# =============================================================================
# PURPOSE : Installs OpenSSH, writes a hardened sshd_config, configures
#           fail2ban (brute-force protection), and opens the firewall.
#
# DOES NOT: Create users. Run create_ssh_users.sh for that.
#
# USAGE   : sudo ./setup_ssh.sh [users_file]
#           Default users file: users.txt
# =============================================================================

set -uo pipefail  # -u = error on undefined vars | -o pipefail = catch pipe errors

USERS_FILE="${1:-users.txt}"    # First argument OR default to users.txt
BACKUP_DIR="/root/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ── COLOR CODES FOR READABLE OUTPUT ──────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── SANITY CHECKS ─────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { error "Run as root (sudo)."; exit 1; }
[[ ! -f "$USERS_FILE" ]] && { error "Users file '$USERS_FILE' not found."; exit 1; }

mkdir -p "$BACKUP_DIR"

# =============================================================================
# DETECT SERVICE NAME: sshd vs ssh
# =============================================================================
# On most RHEL/Rocky systems the daemon unit is called "sshd".
# Some minimal installs or alternate setups call it "ssh".
# We auto-detect so the script works either way.
# NOTE: The FIREWALL service name is ALWAYS "ssh" (not "sshd").
#       firewalld service names ≠ systemd unit names.
# =============================================================================
if systemctl list-unit-files sshd.service &>/dev/null 2>&1 | grep -q sshd; then
    SSH_SERVICE="sshd"      # Standard RHEL/Rocky/CentOS name
else
    SSH_SERVICE="ssh"       # Debian/Ubuntu or minimal install name
fi
info "Detected SSH daemon unit: $SSH_SERVICE"

# ── DEPENDENCIES ─────────────────────────────────────────────────────────────
info "Checking/installing dependencies..."

# openssh-server provides the sshd daemon
if ! rpm -q openssh-server &>/dev/null; then
    info "Installing openssh-server..."
    dnf install -y openssh-server
fi

# EPEL (Extra Packages for Enterprise Linux) is required to install fail2ban
# on Rocky/RHEL — it's not in the base repos
if ! rpm -q epel-release &>/dev/null; then
    info "Installing EPEL repo (required for fail2ban)..."
    dnf install -y epel-release
fi

# fail2ban reads auth logs and bans IPs that fail too many times
if ! rpm -q fail2ban &>/dev/null; then
    info "Installing fail2ban..."
    dnf install -y fail2ban
fi

# ── BACKUP EXISTING CONFIG ────────────────────────────────────────────────────
info "Backing up existing sshd_config..."
[[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$TIMESTAMP"

# ── BUILD AllowUsers LIST FROM users.txt ─────────────────────────────────────
# AllowUsers is a whitelist: ONLY users listed here can SSH in.
# Anyone not on this list is rejected, even with valid credentials.
info "Building AllowUsers list from $USERS_FILE..."
ALLOW_USERS=""
while IFS= read -r user || [[ -n "$user" ]]; do
    [[ -z "$user" || "$user" == \#* ]] && continue        # Skip blanks and comments
    user="$(echo "$user" | tr -d '[:space:]')"            # Strip any whitespace
    ALLOW_USERS="$ALLOW_USERS $user"
done < "$USERS_FILE"

[[ -z "$ALLOW_USERS" ]] && { error "No users found in $USERS_FILE. Aborting."; exit 1; }
info "AllowUsers will be:$ALLOW_USERS"

# ── WRITE HARDENED sshd_config ────────────────────────────────────────────────
info "Writing hardened sshd_config..."
chattr -i /etc/ssh/sshd_config 2>/dev/null || true   # Remove immutable flag if set

cat > /etc/ssh/sshd_config << 'SSHD_EOF'
# =============================================================================
# sshd_config — Hardened for NCAE Cyber Games Competition
# =============================================================================

# ── PORT AND NETWORK ──────────────────────────────────────────────────────────
Port 22
# Change this if competition specifies a different port.
# If changed, update firewall: firewall-cmd --permanent --add-port=XXXX/tcp

AddressFamily inet
# inet  = IPv4 only  (reduces attack surface)
# inet6 = IPv6 only
# any   = both IPv4 and IPv6

ListenAddress 0.0.0.0
# 0.0.0.0 = listen on ALL network interfaces
# Change to specific IP if you only want to listen on one interface

# ── AUTHENTICATION ────────────────────────────────────────────────────────────
PubkeyAuthentication yes
# yes = allow SSH key-based login (REQUIRED for competition scoring)
# no  = disable key auth (never set this to no in competition)

AuthorizedKeysFile .ssh/authorized_keys
# Where the server looks for allowed public keys.
# .ssh/authorized_keys = relative to each user's home dir
# e.g. /home/alice/.ssh/authorized_keys for user alice

PasswordAuthentication yes
# yes = users can also log in with a password
# no  = ONLY key-based auth allowed (more secure, but risky if keys break)
# Keep yes during competition unless you're 100% sure keys work for scoring

PermitRootLogin no
# no            = root CANNOT SSH in at all (recommended)
# yes           = root can SSH with password or key (dangerous)
# prohibit-password = root can only use key auth (still risky)

PermitEmptyPasswords no
# no  = accounts with blank passwords cannot log in via SSH
# yes = empty passwords allowed (never set this in competition)

# AuthenticationMethods publickey
# Uncomment to REQUIRE key auth only and reject ALL password attempts.
# Only enable once you've confirmed keys work perfectly for scoring.

# ── SESSION SECURITY ──────────────────────────────────────────────────────────
MaxAuthTries 3
# Max number of authentication attempts per connection before disconnect.
# 3 = after 3 wrong attempts, the connection is dropped
# Lower = harder to brute force, but also locks out legitimate users faster

MaxSessions 5
# Maximum concurrent sessions multiplexed over a single connection.
# 5 = allows up to 5 simultaneous sessions per connection

LoginGraceTime 30
# How many seconds a user has to authenticate before being disconnected.
# 30 = 30 seconds to log in or get dropped (default is 120)

ClientAliveInterval 300
# Send a keepalive packet to client every 300 seconds (5 minutes).
# Detects dead connections and broken networks.

ClientAliveCountMax 2
# Drop connection after this many missed keepalives.
# Total idle timeout = 300 * 2 = 600 seconds (10 minutes)

# ── DISABLE UNNECESSARY FEATURES (attack surface reduction) ──────────────────
X11Forwarding no
# no  = disable GUI application forwarding (not needed in competition)
# yes = allows remote GUI apps to display locally — unnecessary risk

AllowAgentForwarding no
# no  = prevent forwarding of SSH agent to remote host
# yes = allows lateral movement through the network via your SSH keys

AllowTcpForwarding no
# no  = disable TCP tunneling through SSH
# yes = red team could use your SSH session to tunnel traffic to other systems

PermitTunnel no
# no  = disable VPN-like tunnels over SSH
# yes = allows full network layer tunneling

GatewayPorts no
# no  = forwarded ports only bind to loopback (127.0.0.1)
# yes = forwarded ports bind to all interfaces (used for pivoting attacks)

# ── LOGGING ───────────────────────────────────────────────────────────────────
SyslogFacility AUTHPRIV
# AUTHPRIV = logs to /var/log/secure on RHEL/Rocky
# AUTH     = logs to /var/log/auth.log (Debian/Ubuntu)

LogLevel VERBOSE
# QUIET   = almost nothing logged
# ERROR   = only errors
# INFO    = standard info (default)
# VERBOSE = includes key fingerprints on auth — good for detecting key injection
# DEBUG   = very noisy, use only for troubleshooting one specific issue

# ── CRYPTOGRAPHY (modern algorithms only) ─────────────────────────────────────
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256
# KEX = Key Exchange Algorithm (how client and server establish a shared secret)
# curve25519-sha256       = modern elliptic curve, fast, no known weaknesses
# diffie-hellman-group14  = RSA-based, 2048-bit, SHA-256 (acceptable fallback)
# EXCLUDED: diffie-hellman-group1-sha1 (1024-bit, SHA-1, BROKEN)

Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr
# Ciphers = symmetric encryption used after key exchange
# aes256-gcm = AES 256-bit Galois/Counter Mode (authenticated encryption)
# aes128-gcm = AES 128-bit GCM (slightly faster, still strong)
# aes256-ctr = AES 256-bit Counter Mode (no authentication, but good fallback)
# EXCLUDED: aes128-cbc, 3des-cbc (CBC mode has padding oracle vulnerabilities)

MACs hmac-sha2-512,hmac-sha2-256
# MAC = Message Authentication Code (ensures data wasn't tampered in transit)
# hmac-sha2-512 = HMAC with SHA-512 (strongest)
# hmac-sha2-256 = HMAC with SHA-256 (strong, slightly faster)
# EXCLUDED: hmac-md5, hmac-sha1 (MD5 and SHA-1 are cryptographically broken)

HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256
# How the SERVER proves its identity to the client
# ssh-ed25519   = Ed25519 elliptic curve (preferred, fastest, most modern)
# rsa-sha2-512  = RSA with SHA-512 (strong)
# rsa-sha2-256  = RSA with SHA-256 (acceptable)
# EXCLUDED: ssh-rsa (uses SHA-1, deprecated as of OpenSSH 8.8)

SSHD_EOF

# Append the AllowUsers line — built dynamically from users.txt
echo "AllowUsers$ALLOW_USERS" >> /etc/ssh/sshd_config
info "AllowUsers set to:$ALLOW_USERS"

# ── VALIDATE CONFIG BEFORE RESTARTING ─────────────────────────────────────────
# CRITICAL: Always test config BEFORE restarting. A bad config + restart = lockout.
info "Testing sshd_config syntax..."
if ! sshd -t; then
    error "sshd_config test FAILED. Restoring backup to prevent lockout."
    cp "$BACKUP_DIR/sshd_config.$TIMESTAMP" /etc/ssh/sshd_config
    exit 1
fi
info "Config test passed."

# ── FAIL2BAN CONFIGURATION ────────────────────────────────────────────────────
# fail2ban monitors /var/log/secure and bans IPs after repeated auth failures
info "Configuring fail2ban..."

# jail.local overrides jail.conf (never edit jail.conf directly — it gets
# overwritten on package updates)
[[ ! -f /etc/fail2ban/jail.local ]] && cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

mkdir -p /etc/fail2ban/jail.d

# Create a competition-specific SSH jail
cat > /etc/fail2ban/jail.d/sshd-competition.conf << 'F2B_EOF'
[sshd]
enabled  = true          # true = this jail is active
port     = ssh           # which port to block (ssh = port 22)
filter   = sshd          # which filter pattern file to use (/etc/fail2ban/filter.d/sshd.conf)
logpath  = /var/log/secure  # where to watch for failed attempts (RHEL/Rocky log location)
maxretry = 3             # ban after 3 failed attempts
bantime  = 3600          # keep IP banned for 1 hour (3600 seconds)
findtime = 600           # count failures within this window (600 seconds = 10 min)
F2B_EOF

# ── FIREWALL ──────────────────────────────────────────────────────────────────
# IMPORTANT: firewalld service names ≠ systemd unit names.
#   systemd unit = "sshd"   (the process/daemon)
#   firewalld service = "ssh"  (the firewall rule definition)
# Using --add-service=sshd would FAIL with "INVALID_SERVICE" and the firewall
# would NOT open port 22, causing connection refused for all users.
info "Configuring firewall..."
systemctl is-active firewalld &>/dev/null || systemctl start firewalld

firewall-cmd --permanent --add-service=ssh   # Opens TCP port 22
# Rate limit: max 5 new SSH connections per minute per source IP
firewall-cmd --permanent --add-rich-rule='rule service name="ssh" limit value="5/m" accept'
firewall-cmd --reload

# ── START / RESTART SERVICES ──────────────────────────────────────────────────
info "Enabling and starting services..."
systemctl enable --now "$SSH_SERVICE"    # enable = start at boot | --now = start immediately
systemctl restart "$SSH_SERVICE"
systemctl enable --now fail2ban
systemctl restart fail2ban

# ── LOCK CONFIG FILE ──────────────────────────────────────────────────────────
# chattr +i makes the file IMMUTABLE — not even root can modify/delete it
# without first running: chattr -i /etc/ssh/sshd_config
# This stops red team from modifying the config even with root access.
info "Locking sshd_config with chattr +i..."
chattr +i /etc/ssh/sshd_config

# ── FINAL STATUS ──────────────────────────────────────────────────────────────
echo ""
info "SSH setup complete. Backup: $BACKUP_DIR/sshd_config.$TIMESTAMP"
warn "NEXT STEP: Run create_ssh_users.sh to set up user accounts and .ssh dirs"
warn "To edit sshd_config later: chattr -i /etc/ssh/sshd_config"
echo ""
systemctl status "$SSH_SERVICE" --no-pager -l
