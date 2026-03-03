#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — Linux Binary Backup & Restore
# =============================================================================
# Backs up critical system binaries that are common targets for replacement
# by attackers (e.g., netcat, bash, ls, ss, ps, find, etc.)
#
# Usage:
#   sudo ./01_backup_binaries.sh backup
#   sudo ./01_backup_binaries.sh restore
#   sudo ./01_backup_binaries.sh verify   — Hash check without restoring
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="binaries"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
HASH_FILE="${BACKUP_DIR}/sha256sums.txt"
LATEST_LINK="${BACKUP_ROOT}/latest"

# Binaries to protect — extend this list as needed
CRITICAL_BINARIES=(
    /bin/bash
    /bin/sh
    /bin/ls
    /bin/ps
    /bin/ss
    /bin/netstat
    /usr/bin/find
    /usr/bin/who
    /usr/bin/w
    /usr/bin/last
    /usr/bin/id
    /usr/bin/awk
    /usr/bin/sed
    /usr/bin/grep
    /usr/bin/curl
    /usr/bin/wget
    /usr/bin/nc
    /usr/bin/ncat
    /usr/bin/ssh
    /usr/bin/scp
    /usr/sbin/sshd
    /usr/bin/sudo
    /usr/bin/passwd
    /usr/bin/su
    /sbin/iptables
    /sbin/ip6tables
    /usr/sbin/iptables
)

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

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    info "=== Binary Backup Started: $TIMESTAMP ==="
    local backed_up=0
    local skipped=0

    for bin in "${CRITICAL_BINARIES[@]}"; do
        if [[ -f "$bin" ]]; then
            # Preserve directory structure inside backup
            dest_dir="${BACKUP_DIR}/$(dirname "$bin")"
            mkdir -p "$dest_dir"
            cp -p "$bin" "$dest_dir/"
            info "  Backed up: $bin"
            ((backed_up++))
        else
            warn "  Not found (skipped): $bin"
            ((skipped++))
        fi
    done

    # Generate SHA-256 hashes for integrity verification
    info "Generating SHA-256 manifest..."
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "$HASH_FILE"
    chmod 400 "$HASH_FILE"

    # Symlink latest
    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"

    info "✅ Backup complete. Backed up: $backed_up | Skipped: $skipped"
    info "   Location: $BACKUP_DIR"
    info "   Hash manifest: $HASH_FILE"
}

# ── Verify ────────────────────────────────────────────────────────────────────
do_verify() {
    info "=== Binary Integrity Verification ==="
    local target="${1:-live}"   # 'live' = check current system binaries

    if [[ "$target" == "live" ]]; then
        if [[ ! -L "$LATEST_LINK" ]]; then
            error "No latest backup found at $LATEST_LINK. Run backup first."
            exit 1
        fi
        local ref_hash_file="${LATEST_LINK}/sha256sums.txt"
        info "Comparing live binaries against backup manifest: $ref_hash_file"
        local mismatch=0

        while IFS= read -r line; do
            expected_hash=$(echo "$line" | awk '{print $1}')
            backup_path=$(echo "$line" | awk '{print $2}')
            # Convert backup path back to live path
            live_path="${backup_path#${LATEST_LINK}}"
            if [[ -f "$live_path" ]]; then
                actual_hash=$(sha256sum "$live_path" | awk '{print $1}')
                if [[ "$expected_hash" != "$actual_hash" ]]; then
                    error "  HASH MISMATCH: $live_path"
                    error "    Expected: $expected_hash"
                    error "    Actual:   $actual_hash"
                    ((mismatch++))
                else
                    info "  OK: $live_path"
                fi
            else
                warn "  MISSING on live system: $live_path"
                ((mismatch++))
            fi
        done < "$ref_hash_file"

        if [[ $mismatch -eq 0 ]]; then
            info "✅ All binaries match backup hashes. No tampering detected."
        else
            error "❌ $mismatch binary/binaries differ from backup. Investigate immediately."
            exit 2
        fi
    fi
}

# ── Restore ───────────────────────────────────────────────────────────────────
do_restore() {
    info "=== Binary Restore ==="

    # List available backups
    echo "Available backup snapshots:"
    local i=1
    declare -a snapshots
    for snap in "$BACKUP_ROOT"/[0-9]*/; do
        snapshots+=("$snap")
        echo "  $i) $(basename "$snap")"
        ((i++))
    done

    if [[ ${#snapshots[@]} -eq 0 ]]; then
        error "No backups found in $BACKUP_ROOT"
        exit 1
    fi

    read -rp "Select snapshot number (or 'latest'): " sel
    local chosen_backup
    if [[ "$sel" == "latest" ]]; then
        chosen_backup="$LATEST_LINK"
    elif [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#snapshots[@]} )); then
        chosen_backup="${snapshots[$((sel-1))]}"
    else
        error "Invalid selection."
        exit 1
    fi

    warn "⚠️  This will overwrite live binaries with backup from: $(basename "$chosen_backup")"
    read -rp "Type 'CONFIRM' to proceed: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Restore cancelled."; exit 0; }

    # Stop services that may hold binaries open
    warn "Stopping potentially affected services..."
    systemctl stop ssh sshd 2>/dev/null || true

    local restored=0
    while IFS= read -r -d '' backup_file; do
        # Reconstruct live path by stripping backup prefix
        live_path="${backup_file#${chosen_backup}}"
        if [[ -f "$live_path" ]]; then
            # Save current (possibly compromised) binary
            cp -p "$live_path" "${live_path}.blueteam_pre_restore_${TIMESTAMP}" 2>/dev/null || true
        fi
        cp -p "$backup_file" "$live_path"
        chown root:root "$live_path" 2>/dev/null || true
        info "  Restored: $live_path"
        ((restored++))
    done < <(find "$chosen_backup" -type f ! -name "sha256sums.txt" -print0)

    # Restart services
    info "Restarting SSH..."
    systemctl start ssh sshd 2>/dev/null || true

    info "✅ Restore complete. $restored binaries restored."
    info "   Pre-restore copies saved with suffix: .blueteam_pre_restore_${TIMESTAMP}"
    warn "   Run '$0 verify' to confirm hashes match."
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
