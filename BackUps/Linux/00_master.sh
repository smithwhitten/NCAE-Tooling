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
#
# Scripts managed:
#   01_backup_binaries.sh    — Critical system binaries
#   02_backup_pam.sh         — PAM configuration & libraries
#   03_backup_sshd.sh        — SSH server config & keys
#   04_backup_smb.sh         — Samba configuration
#   05_backup_webserver.sh   — Web server config (Apache/Nginx/Lighttpd)
#   06_backup_webcontent.sh  — Web root content
#   07_backup_mysql.sh       — MySQL / MariaDB databases
#   08_backup_postgres.sh    — PostgreSQL databases
# =============================================================================

set -euo pipefail

# ── Global Configuration ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_ROOT="/opt/blueteam/backups"
LOG_FILE="/var/log/blueteam_master.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

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
    info "Script dir:  $SCRIPT_DIR"
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
        "07_backup_mysql.sh"
        "08_backup_postgres.sh"
    )

    local failed=()
    local skipped=()

    for script in "${scripts[@]}"; do
        local script_path="$SCRIPT_DIR/$script"
        if [[ -f "$script_path" ]]; then
            info "Running: $script"
            if bash "$script_path" backup; then
                info "  ✅ Completed: $script"
            else
                warn "  ❌ FAILED: $script"
                failed+=("$script")
            fi
        else
            warn "  ⚠️  Not found (skipped): $script_path"
            skipped+=("$script")
        fi
    done

    echo ""
    section "BACKUP SUMMARY"
    info "Timestamp: $TIMESTAMP"
    info "Location:  $BACKUP_ROOT"
    [[ ${#skipped[@]} -gt 0 ]] && warn "Skipped: ${skipped[*]}"

    if [[ ${#failed[@]} -eq 0 ]]; then
        info "✅ All present scripts completed successfully."
    else
        error "❌ Failed: ${failed[*]}"
        error "Check log: $LOG_FILE"
        exit 1
    fi
}

# ── Restore Menu ──────────────────────────────────────────────────────────────
restore_menu() {
    section "RESTORE MENU"
    echo "Select a service to restore:"
    echo ""
    echo "  ── System ──────────────────────────"
    echo "  1) Binaries"
    echo "  2) PAM"
    echo "  3) SSHD Config"
    echo "  4) Samba (SMB)"
    echo ""
    echo "  ── Web ─────────────────────────────"
    echo "  5) Web Server Config"
    echo "  6) Web Content"
    echo ""
    echo "  ── Databases ───────────────────────"
    echo "  7) MySQL / MariaDB"
    echo "  8) PostgreSQL"
    echo ""
    echo "  ── All ─────────────────────────────"
    echo "  9) ALL services (full restore)"
    echo ""
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
        7) bash "$SCRIPT_DIR/07_backup_mysql.sh" restore ;;
        8) bash "$SCRIPT_DIR/08_backup_postgres.sh" restore ;;
        9)
            warn "Full restore will interactively prompt for each service."
            read -rp "Type 'CONFIRM' to proceed: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }
            for script in \
                "01_backup_binaries.sh" \
                "02_backup_pam.sh" \
                "03_backup_sshd.sh" \
                "04_backup_smb.sh" \
                "05_backup_webserver.sh" \
                "06_backup_webcontent.sh" \
                "07_backup_mysql.sh" \
                "08_backup_postgres.sh"; do
                [[ -f "$SCRIPT_DIR/$script" ]] && bash "$SCRIPT_DIR/$script" restore || true
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

    local found=0
    for dir in "$BACKUP_ROOT"/*/; do
        [[ -d "$dir" ]] || continue
        local svc
        svc=$(basename "$dir")
        local latest
        latest=$(ls -t "$dir" 2>/dev/null | head -1)
        local size
        size=$(du -sh "$dir" 2>/dev/null | awk '{print $1}')
        printf "  ${CYAN}%-20s${NC} Latest: %-22s Size: %s\n" "$svc" "${latest:-none}" "${size:-?}"
        ((found++))
    done

    if [[ $found -eq 0 ]]; then
        warn "No service backups found. Run: sudo $0 backup"
    else
        echo ""
        info "$found service(s) have backups."
    fi
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
