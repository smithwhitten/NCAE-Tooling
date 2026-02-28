#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — Linux Master Backup & Restore Orchestrator
# =============================================================================
# Usage:
#   sudo ./00_master.sh backup    — Run ALL backup scripts
#   sudo ./00_master.sh restore   — Interactive restore menu
#   sudo ./00_master.sh status    — Show latest backup inventory
#
# Requires: root / sudo
# Compatible: Ubuntu 20.04+, Debian 11+, RHEL/CentOS 8+
# =============================================================================

set -euo pipefail

# ── Global Configuration ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="/opt/blueteam/backups"
LOG_FILE="/var/log/blueteam_master.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

# ── Logging ───────────────────────────────────────────────────────────────────
log() { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }
info()    { log "INFO " "${GREEN}$*${NC}"; }
warn()    { log "WARN " "${YELLOW}$*${NC}"; }
error()   { log "ERROR" "${RED}$*${NC}"; }
section() { echo -e "\n${BOLD}${CYAN}━━━  $*  ━━━${NC}\n"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
preflight() {
    if [[ $EUID -ne 0 ]]; then
        error "Must be run as root. Use: sudo $0 $*"
        exit 1
    fi
    mkdir -p "$BACKUP_ROOT" /var/log
    chmod 700 "$BACKUP_ROOT"
    info "Backup root: $BACKUP_ROOT"
}

# ── Backup All ────────────────────────────────────────────────────────────────
run_all_backups() {
    section "STARTING FULL BLUE TEAM BACKUP — $TIMESTAMP"
    local scripts=(
        "01_backup_binaries.sh"
        "02_backup_pam.sh"
        "03_backup_sshd.sh"
        "04_backup_smb.sh"
        "05_backup_webserver.sh"
        "06_backup_webcontent.sh"
    )
    local failed=()
    for script in "${scripts[@]}"; do
        if [[ -f "$SCRIPT_DIR/$script" ]]; then
            info "Running: $script"
            bash "$SCRIPT_DIR/$script" backup || { warn "FAILED: $script"; failed+=("$script"); }
        else
            warn "Script not found: $SCRIPT_DIR/$script"
        fi
    done

    echo ""
    if [[ ${#failed[@]} -eq 0 ]]; then
        info "✅ All backups completed successfully."
    else
        error "❌ The following scripts failed: ${failed[*]}"
        exit 1
    fi
}

# ── Restore Menu ──────────────────────────────────────────────────────────────
restore_menu() {
    section "RESTORE MENU"
    echo "Select a service to restore:"
    echo "  1) Binaries"
    echo "  2) PAM"
    echo "  3) SSHD Config"
    echo "  4) Samba (SMB)"
    echo "  5) Web Server Config"
    echo "  6) Web Content"
    echo "  7) ALL (full restore)"
    echo "  0) Exit"
    echo ""
    read -rp "Choice: " choice
    case "$choice" in
        1) bash "$SCRIPT_DIR/01_backup_binaries.sh" restore ;;
        2) bash "$SCRIPT_DIR/02_backup_pam.sh" restore ;;
        3) bash "$SCRIPT_DIR/03_backup_sshd.sh" restore ;;
        4) bash "$SCRIPT_DIR/04_backup_smb.sh" restore ;;
        5) bash "$SCRIPT_DIR/05_backup_webserver.sh" restore ;;
        6) bash "$SCRIPT_DIR/06_backup_webcontent.sh" restore ;;
        7)
            for s in 01 02 03 04 05 06; do
                bash "$SCRIPT_DIR/${s}_backup_"*.sh restore 2>/dev/null || true
            done
            ;;
        0) exit 0 ;;
        *) error "Invalid choice." ;;
    esac
}

# ── Status ────────────────────────────────────────────────────────────────────
show_status() {
    section "BACKUP INVENTORY — $BACKUP_ROOT"
    if [[ ! -d "$BACKUP_ROOT" ]]; then
        warn "No backups found."
        return
    fi
    du -sh "$BACKUP_ROOT"/*/  2>/dev/null || warn "No service backup directories found."
    echo ""
    info "Latest backup timestamps per service:"
    for dir in "$BACKUP_ROOT"/*/; do
        svc=$(basename "$dir")
        latest=$(ls -t "$dir" 2>/dev/null | head -1)
        echo "  ${CYAN}${svc}${NC}: ${latest:-none}"
    done
}

# ── Entry Point ───────────────────────────────────────────────────────────────
preflight "$@"
case "${1:-help}" in
    backup)  run_all_backups ;;
    restore) restore_menu ;;
    status)  show_status ;;
    *)
        echo "Usage: sudo $0 {backup|restore|status}"
        exit 1
        ;;
esac
