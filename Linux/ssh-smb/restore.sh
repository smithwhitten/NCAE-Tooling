#!/bin/bash
# NCAE - CosmicGrace
# Author - Claude (Anthropic) / CosmicGrace
# restore.sh — Restore SSH and/or SMB from a timestamped backup
# Usage: sudo ./restore.sh [backup_timestamp]
# If no timestamp given, lists available backups and prompts.

set -uo pipefail

BACKUP_BASE="/root/.cache"
SHARE_PATH="/srv/samba/compshare"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

[[ $EUID -ne 0 ]] && { error "Run as root."; exit 1; }

# ── SELECT BACKUP ─────────────────────────────────────────────────────────────
if [[ -n "${1:-}" ]]; then
    BACKUP_DIR="$BACKUP_BASE/$1"
else
    echo ""
    info "Available backups:"
    ls -1 "$BACKUP_BASE" 2>/dev/null | grep -E '^[0-9]{8}_[0-9]{6}$' || \
        { error "No backups found in $BACKUP_BASE"; exit 1; }
    echo ""
    read -rp "Enter backup timestamp to restore: " SELECTED
    BACKUP_DIR="$BACKUP_BASE/$SELECTED"
fi

[[ ! -d "$BACKUP_DIR" ]] && { error "Backup directory not found: $BACKUP_DIR"; exit 1; }
info "Restoring from: $BACKUP_DIR"

# ── SELECT WHAT TO RESTORE ────────────────────────────────────────────────────
echo ""
echo "What would you like to restore?"
echo "  1) SSH only"
echo "  2) SMB only"
echo "  3) Both SSH and SMB"
echo "  4) Full restore (SSH + SMB + share contents + users)"
read -rp "Choice [1-4]: " CHOICE

restore_ssh() {
    if [[ -f "$BACKUP_DIR/sshd_config" ]]; then
        info "Restoring sshd_config..."
        chattr -i /etc/ssh/sshd_config 2>/dev/null || true
        cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
        if sshd -t; then
            systemctl restart sshd
            info "sshd restarted successfully."
        else
            error "sshd config test failed after restore. Investigate manually."
        fi
    else
        warn "No sshd_config found in backup."
    fi

    if [[ -d "$BACKUP_DIR/authorized_keys" ]]; then
        info "Restoring authorized_keys..."
        for keyfile in "$BACKUP_DIR/authorized_keys/"*; do
            [[ -f "$keyfile" ]] || continue
            username="$(basename "$keyfile" | sed 's/_authorized_keys$//')"
            homedir="$(getent passwd "$username" | cut -d: -f6)"
            if [[ -n "$homedir" && -d "$homedir" ]]; then
                mkdir -p "$homedir/.ssh"
                cp "$keyfile" "$homedir/.ssh/authorized_keys"
                chmod 700 "$homedir/.ssh"
                chmod 600 "$homedir/.ssh/authorized_keys"
                chown -R "$username:$username" "$homedir/.ssh"
                info "Restored authorized_keys for: $username"
            fi
        done
    fi
}

restore_smb() {
    if [[ -f "$BACKUP_DIR/smbd.conf" ]]; then
        info "Restoring smbd.conf..."
        chattr -i /etc/samba/smbd.conf 2>/dev/null || true
        cp "$BACKUP_DIR/smb.conf" /etc/samba/smbd.conf
        if testparm -s /etc/samba/smbd.conf &>/dev/null; then
            systemctl restart smbd nmbd
            info "smbd/nmbd restarted successfully."
        else
            error "smbd.conf test failed after restore. Run: testparm"
        fi
    else
        warn "No smbd.conf found in backup."
    fi
}

restore_share() {
    if [[ -f "$BACKUP_DIR/compshare.tar.gz" ]]; then
        info "Restoring SMB share contents..."

        if ! command -v tar &>/dev/null; then
            dnf install -y tar
        fi

        mkdir -p /srv/samba
        tar -xzf "$BACKUP_DIR/compshare.tar.gz" -C /srv/samba
        chown -R root:smbgroup "$SHARE_PATH" 2>/dev/null || true
        chmod -R 0770 "$SHARE_PATH"
        restorecon -Rv "$SHARE_PATH" 2>/dev/null || true
        info "Share contents restored."
    else
        warn "No share backup found."
    fi
}

restore_users() {
    warn "Restoring system user databases. THIS IS DESTRUCTIVE — confirm."
    read -rp "  Type YES to confirm: " CONFIRM
    if [[ "$CONFIRM" == "YES" ]]; then
        [[ -f "$BACKUP_DIR/passwd"  ]] && cp "$BACKUP_DIR/passwd"  /etc/passwd
        [[ -f "$BACKUP_DIR/shadow"  ]] && cp "$BACKUP_DIR/shadow"  /etc/shadow
        [[ -f "$BACKUP_DIR/group"   ]] && cp "$BACKUP_DIR/group"   /etc/group
        [[ -f "$BACKUP_DIR/gshadow" ]] && cp "$BACKUP_DIR/gshadow" /etc/gshadow 2>/dev/null || true
        [[ -f "$BACKUP_DIR/passdb.tdb" ]] && \
            cp "$BACKUP_DIR/passdb.tdb" /var/lib/samba/private/passdb.tdb
        info "User databases restored."
    else
        warn "User restore skipped."
    fi
}

restore_firewall() {
    info "Re-applying firewall rules..."
    firewall-cmd --permanent --add-service=sshd  2>/dev/null || true
    firewall-cmd --permanent --add-service=smbd 2>/dev/null || true
    firewall-cmd --reload
    info "Firewall rules applied."
}

case "$CHOICE" in
    1) restore_ssh ;;
    2) restore_smb ;;
    3) restore_ssh; restore_smb ;;
    4) restore_ssh; restore_smb; restore_share; restore_users ;;
    *) error "Invalid choice."; exit 1 ;;
esac

restore_firewall

# ── RE-LOCK CONFIGS ───────────────────────────────────────────────────────────
info "Re-locking config files..."
[[ -f /etc/ssh/sshd_config ]] && chattr +i /etc/ssh/sshd_config
[[ -f /etc/samba/smb.conf ]] && chattr +i /etc/samba/smbd.conf

echo ""
info "Restore complete."
systemctl status sshd smbd nmbd --no-pager -l 2>/dev/null || true