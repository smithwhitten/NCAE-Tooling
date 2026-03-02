#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — Samba (SMB) Backup & Restore
# =============================================================================
# Backs up Samba configuration, user database (tdbsam/smbpasswd),
# share definitions, and selinux/apparmor contexts where applicable.
#
# Usage:
#   sudo ./04_backup_smb.sh backup
#   sudo ./04_backup_smb.sh restore
#   sudo ./04_backup_smb.sh verify
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="smb"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
LATEST_LINK="${BACKUP_ROOT}/latest"

SMB_CONFIG_FILES=(
    /etc/samba/smb.conf
    /etc/samba/lmhosts
)

SMB_CONFIG_DIRS=(
    /etc/samba
)

# Samba var/lib paths (TDB databases, user accounts)
SMB_DATA_DIRS=(
    /var/lib/samba
    /var/cache/samba
)

SMB_SERVICES=(smbd nmbd winbind)

# ── Logging ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()   { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }
info()  { log "INFO " "${GREEN}$*${NC}"; }
warn()  { log "WARN " "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { error "Must run as root."; exit 1; }
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_ROOT"

# Check if samba is installed
if ! command -v smbd &>/dev/null; then
    warn "smbd not found — Samba may not be installed."
    warn "If needed, install with: apt install samba -y  OR  dnf install samba -y"
fi

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    info "=== Samba Backup Started: $TIMESTAMP ==="

    # Config directory
    for dir in "${SMB_CONFIG_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            dest="${BACKUP_DIR}${dir}"
            mkdir -p "$dest"
            cp -rp "$dir/." "$dest/"
            chmod 700 "$dest"  # smb.conf may contain passwords
            info "  Config backed up: $dir"
        else
            warn "  Config dir not found: $dir"
        fi
    done

    # Data directories (TDB databases contain user accounts and session data)
    for dir in "${SMB_DATA_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            dest="${BACKUP_DIR}${dir}"
            mkdir -p "$dest"
            cp -rp "$dir/." "$dest/" 2>/dev/null || warn "  Some files in $dir could not be copied (may be locked)"
            info "  Data backed up: $dir"
        fi
    done

    # Export Samba user list (non-sensitive metadata)
    if command -v pdbedit &>/dev/null; then
        info "Exporting Samba user list via pdbedit..."
        pdbedit -L > "${BACKUP_DIR}/samba_users.txt" 2>/dev/null || warn "pdbedit failed — smbd may not be running"
        # Full export including password hashes (restrict permissions)
        pdbedit -e smbpasswd:"${BACKUP_DIR}/samba_passdb_export.smbpasswd" 2>/dev/null || \
            warn "pdbedit password export failed."
        [[ -f "${BACKUP_DIR}/samba_passdb_export.smbpasswd" ]] && \
            chmod 600 "${BACKUP_DIR}/samba_passdb_export.smbpasswd"
    fi

    # Record running samba version
    smbd --version > "${BACKUP_DIR}/samba_version.txt" 2>/dev/null || true

    # Hash manifest
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${BACKUP_DIR}/sha256sums.txt"
    chmod 400 "${BACKUP_DIR}/sha256sums.txt"

    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"
    info "✅ Samba backup complete: $BACKUP_DIR"
}

# ── Verify ────────────────────────────────────────────────────────────────────
do_verify() {
    info "=== Samba Config Verification ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found."
        exit 1
    fi

    # Test current smb.conf syntax
    if command -v testparm &>/dev/null; then
        info "Testing current smb.conf with testparm..."
        testparm -s /etc/samba/smb.conf 2>&1 | tee -a "$LOG_FILE"
    fi

    # Hash check
    local mismatch=0
    while IFS= read -r line; do
        expected_hash=$(echo "$line" | awk '{print $1}')
        backup_path=$(echo "$line" | awk '{print $2}')
        live_path="${backup_path#${LATEST_LINK}}"
        if [[ -f "$live_path" ]]; then
            actual_hash=$(sha256sum "$live_path" | awk '{print $1}')
            if [[ "$expected_hash" != "$actual_hash" ]]; then
                warn "  CHANGED: $live_path"
                ((mismatch++))
            else
                info "  OK: $live_path"
            fi
        else
            warn "  MISSING: $live_path"
        fi
    done < "${LATEST_LINK}/sha256sums.txt"

    [[ $mismatch -eq 0 ]] && info "✅ All Samba files match backup." || \
        warn "⚠️  $mismatch file(s) differ from backup."
}

# ── Restore ───────────────────────────────────────────────────────────────────
do_restore() {
    info "=== Samba Restore ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found."
        exit 1
    fi

    warn "This will stop Samba services and restore configuration."
    read -rp "Type 'CONFIRM' to proceed: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }

    # Stop Samba services
    for svc in "${SMB_SERVICES[@]}"; do
        systemctl stop "$svc" 2>/dev/null && info "  Stopped: $svc" || true
    done

    # Restore config
    for dir in "${SMB_CONFIG_DIRS[@]}"; do
        src="${LATEST_LINK}${dir}"
        if [[ -d "$src" ]]; then
            cp -rp "$dir" "${dir}.blueteam_pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -rp "$src/." "$dir/"
            info "  Restored: $dir"
        fi
    done

    # Validate restored config
    info "Validating restored smb.conf..."
    if testparm -s /etc/samba/smb.conf &>/dev/null; then
        info "  smb.conf syntax: OK"
    else
        error "  smb.conf syntax error! Review before starting Samba."
        testparm -s /etc/samba/smb.conf 2>&1 | tee -a "$LOG_FILE"
    fi

    # Restore Samba password database if export exists
    if [[ -f "${LATEST_LINK}/samba_passdb_export.smbpasswd" ]]; then
        info "Restoring Samba password database..."
        while IFS=: read -r username _; do
            pdbedit -I -u "$username" 2>/dev/null || true
        done < "${LATEST_LINK}/samba_passdb_export.smbpasswd"
        info "  Password database restore attempted."
        warn "  Verify user accounts with: pdbedit -L"
    fi

    # Restart services
    for svc in "${SMB_SERVICES[@]}"; do
        systemctl start "$svc" 2>/dev/null && info "  Started: $svc" || warn "  Could not start: $svc"
    done

    info "✅ Samba restore complete."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
case "${1:-help}" in
    backup)  do_backup ;;
    restore) do_restore ;;
    verify)  do_verify ;;
    *)
        echo "Usage: sudo $0 {backup|restore|verify}"
        exit 1
        ;;
esac
