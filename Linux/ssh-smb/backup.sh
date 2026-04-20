#!/bin/bash
# NCAE - CosmicGrace
# Author - Claude (Anthropic) / CosmicGrace
# backup.sh — Backs up SSH configs, SMB configs, user databases, and share contents
# Usage: sudo ./backup.sh

set -uo pipefail

BACKUP_BASE="/root/.cache"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_BASE/$TIMESTAMP"
SHARE_PATH="/srv/samba/compshare"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root."; exit 1; }

mkdir -p "$BACKUP_DIR"
info "Backup directory: $BACKUP_DIR"

# ── DEPENDENCY: TAR ───────────────────────────────────────────────────────────
if ! command -v tar &>/dev/null; then
    warn "tar not found. Installing..."
    dnf install -y tar || { error "Failed to install tar."; exit 1; }
fi

# ── SSH ───────────────────────────────────────────────────────────────────────
info "Backing up SSH configuration..."
[[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config"
[[ -d /etc/ssh ]] && tar -czf "$BACKUP_DIR/ssh_keys.tar.gz" -C /etc/ssh/ssh_host_* 2>/dev/null || true

# ── SMB CONFIG ────────────────────────────────────────────────────────────────
info "Backing up Samba configuration..."
[[ -f /etc/samba/smb.conf ]] && cp /etc/samba/smbd.conf "$BACKUP_DIR/smbd.conf"

# ── SYSTEM USER DATABASES ─────────────────────────────────────────────────────
info "Backing up user databases..."
cp /etc/passwd  "$BACKUP_DIR/passwd"
cp /etc/shadow  "$BACKUP_DIR/shadow"
cp /etc/group   "$BACKUP_DIR/group"
cp /etc/gshadow "$BACKUP_DIR/gshadow" 2>/dev/null || true
chmod 600 "$BACKUP_DIR/shadow" "$BACKUP_DIR/gshadow" 2>/dev/null || true

# ── SAMBA USER DATABASE ───────────────────────────────────────────────────────
info "Backing up Samba user database..."
if command -v pdbedit &>/dev/null; then
    pdbedit -L -e "$BACKUP_DIR/samba_users.tdb" 2>/dev/null || true
fi
[[ -f /var/lib/samba/private/passdb.tdb ]] && \
    cp /var/lib/samba/private/passdb.tdb "$BACKUP_DIR/passdb.tdb"

# ── /MTN/FILES ────────────────────────────────────────────────────────────────
if [[ -d "/mnt/files" ]]; then
    info "Backing up /mnt/files..."
    tar -czf "$BACKUP_DIR/mnt_files.tar.gz" -C /mnt files
    info "/mnt/files backup: $BACKUP_DIR/mnt_files.tar.gz"
else
    warn "Path /mnt/files not found. Skipping."
fi

# ── AUTHORIZED_KEYS ───────────────────────────────────────────────────────────
info "Backing up authorized_keys for all users..."
mkdir -p "$BACKUP_DIR/authorized_keys"
while IFS=: read -r username _ uid _ _ homedir _; do
    [[ $uid -ge 1000 && -f "$homedir/.ssh/authorized_keys" ]] && \
        cp "$homedir/.ssh/authorized_keys" "$BACKUP_DIR/authorized_keys/${username}_authorized_keys"
done < /etc/passwd

# ── SMB SHARE CONTENTS ────────────────────────────────────────────────────────
if [[ -d "$SHARE_PATH" ]]; then
    info "Backing up SMB share contents..."
    tar -czf "$BACKUP_DIR/compshare.tar.gz" -C /srv/samba/compshare
    info "Share backup: $BACKUP_DIR/compshare.tar.gz"
else
    warn "Share path $SHARE_PATH not found. Skipping."
fi

# ── FIREWALL RULES ────────────────────────────────────────────────────────────
info "Backing up firewall rules..."
firewall-cmd --list-all > "$BACKUP_DIR/firewall_rules.txt" 2>/dev/null || true

# ── FAIL2BAN CONFIG ───────────────────────────────────────────────────────────
info "Backing up fail2ban config..."
[[ -d /etc/fail2ban/jail.d ]] && \
    tar -czf "$BACKUP_DIR/fail2ban_jails.tar.gz" -C /etc fail2ban/jail.d 2>/dev/null || true

# ── MANIFEST ─────────────────────────────────────────────────────────────────
info "Writing backup manifest..."
{
    echo "Backup Timestamp: $TIMESTAMP"
    echo "Backup Directory: $BACKUP_DIR"
    echo ""
    echo "Files:"
    ls -lh "$BACKUP_DIR"
} > "$BACKUP_DIR/MANIFEST.txt"

echo ""
info "Backup complete: $BACKUP_DIR"
ls -lh "$BACKUP_DIR"