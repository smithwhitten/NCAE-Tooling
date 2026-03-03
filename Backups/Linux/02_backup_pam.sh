#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — Linux PAM (Pluggable Authentication Modules) Backup & Restore
# =============================================================================
# PAM is a critical authentication framework. Attackers may modify PAM configs
# to create backdoors (e.g., pam_unix.so patches, rogue pam_exec entries).
#
# This script:
#   - Backs up all PAM configuration files and shared libraries
#   - Detects package manager (apt / dnf / yum) for reinstallation
#   - Can fully reinstall PAM packages to known-good state
#
# Usage:
#   sudo ./02_backup_pam.sh backup
#   sudo ./02_backup_pam.sh restore
#   sudo ./02_backup_pam.sh reinstall   — Package-manager reinstall (nuclear option)
#   sudo ./02_backup_pam.sh verify      — Hash check PAM libs vs backup
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="pam"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
LATEST_LINK="${BACKUP_ROOT}/latest"

# PAM paths to backup
PAM_CONFIG_DIRS=(
    /etc/pam.d
    /etc/security
)

PAM_LIB_PATHS=(
    /lib/x86_64-linux-gnu/security
    /lib64/security
    /usr/lib/x86_64-linux-gnu/security
    /usr/lib64/security
    /lib/aarch64-linux-gnu/security  # ARM64
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

# Detect package manager
detect_pkg_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo "unknown"
    fi
}

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    info "=== PAM Backup Started: $TIMESTAMP ==="

    # Backup PAM config directories
    for dir in "${PAM_CONFIG_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            dest="${BACKUP_DIR}${dir}"
            mkdir -p "$dest"
            cp -rp "$dir/." "$dest/"
            info "  Config backed up: $dir"
        else
            warn "  Config dir not found: $dir"
        fi
    done

    # Backup PAM shared libraries
    for lib_dir in "${PAM_LIB_PATHS[@]}"; do
        if [[ -d "$lib_dir" ]]; then
            dest="${BACKUP_DIR}${lib_dir}"
            mkdir -p "$dest"
            cp -rp "$lib_dir/." "$dest/"
            info "  Libraries backed up: $lib_dir"
        fi
    done

    # Record installed PAM package versions
    local pkg_manager
    pkg_manager=$(detect_pkg_manager)
    local pkg_list_file="${BACKUP_DIR}/installed_pam_packages.txt"

    info "Recording installed PAM package versions (pkg manager: $pkg_manager)..."
    case "$pkg_manager" in
        apt)
            dpkg -l | grep -iE 'libpam|pam' > "$pkg_list_file" || true
            ;;
        dnf|yum)
            rpm -qa | grep -iE 'pam' > "$pkg_list_file" || true
            ;;
        *)
            warn "Unknown package manager — skipping package list."
            ;;
    esac

    # Generate SHA-256 hashes
    info "Generating SHA-256 manifest..."
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" ! -name "installed_pam_packages.txt" \
        -exec sha256sum {} \; > "${BACKUP_DIR}/sha256sums.txt"
    chmod 400 "${BACKUP_DIR}/sha256sums.txt"

    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"

    info "✅ PAM backup complete: $BACKUP_DIR"
}

# ── Verify ────────────────────────────────────────────────────────────────────
do_verify() {
    info "=== PAM Integrity Verification ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No latest backup. Run backup first."
        exit 1
    fi

    local hash_file="${LATEST_LINK}/sha256sums.txt"
    local mismatch=0

    while IFS= read -r line; do
        expected_hash=$(echo "$line" | awk '{print $1}')
        backup_path=$(echo "$line" | awk '{print $2}')
        live_path="${backup_path#${LATEST_LINK}}"

        if [[ -f "$live_path" ]]; then
            actual_hash=$(sha256sum "$live_path" | awk '{print $1}')
            if [[ "$expected_hash" != "$actual_hash" ]]; then
                error "  HASH MISMATCH: $live_path"
                ((mismatch++))
            else
                info "  OK: $live_path"
            fi
        else
            warn "  MISSING: $live_path"
            ((mismatch++))
        fi
    done < "$hash_file"

    if [[ $mismatch -eq 0 ]]; then
        info "✅ All PAM files match backup. No tampering detected."
    else
        error "❌ $mismatch PAM file(s) differ. POSSIBLE BACKDOOR — investigate immediately."
        exit 2
    fi
}

# ── Restore from Backup ───────────────────────────────────────────────────────
do_restore() {
    info "=== PAM Restore from Backup ==="
    warn "⚠️  WARNING: Incorrect PAM config can lock ALL users out of the system."
    warn "   Consider 'reinstall' option for a cleaner recovery."

    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found. Run backup first."
        exit 1
    fi

    read -rp "Type 'CONFIRM' to restore PAM from latest backup: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Restore cancelled."; exit 0; }

    # Restore config directories
    for dir in "${PAM_CONFIG_DIRS[@]}"; do
        src="${LATEST_LINK}${dir}"
        if [[ -d "$src" ]]; then
            # Backup current state first
            cp -rp "$dir" "${dir}.blueteam_pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -rp "$src/." "$dir/"
            info "  Restored: $dir"
        fi
    done

    # Restore libraries
    for lib_dir in "${PAM_LIB_PATHS[@]}"; do
        src="${LATEST_LINK}${lib_dir}"
        if [[ -d "$src" ]]; then
            cp -rp "$lib_dir" "${lib_dir}.blueteam_pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -rp "$src/." "$lib_dir/"
            info "  Restored libraries: $lib_dir"
        fi
    done

    info "✅ PAM restore complete."
    info "   Pre-restore config saved with suffix: .blueteam_pre_restore_${TIMESTAMP}"

    # Test PAM is functional (non-destructive)
    info "Testing PAM functionality..."
    if pamtester login root authenticate 2>/dev/null; then
        info "  PAM login module: OK"
    else
        warn "  pamtester not available or test inconclusive. Manually verify login."
    fi
}

# ── Reinstall PAM Packages ────────────────────────────────────────────────────
do_reinstall() {
    info "=== PAM Package Reinstall (Nuclear Option) ==="
    warn "This will reinstall PAM packages from the distribution repository."
    warn "Requires internet/repo access and will overwrite all PAM libraries and defaults."

    local pkg_manager
    pkg_manager=$(detect_pkg_manager)

    read -rp "Type 'REINSTALL' to proceed with $pkg_manager reinstall: " confirm
    [[ "$confirm" != "REINSTALL" ]] && { info "Cancelled."; exit 0; }

    # Backup current state before reinstall
    do_backup

    case "$pkg_manager" in
        apt)
            info "Reinstalling PAM via apt..."
            DEBIAN_FRONTEND=noninteractive apt-get install --reinstall -y \
                libpam-runtime \
                libpam-modules \
                libpam-modules-bin \
                libpam0g \
                passwd
            info "Running pam-auth-update to restore defaults..."
            pam-auth-update --force
            ;;
        dnf)
            info "Reinstalling PAM via dnf..."
            dnf reinstall -y pam
            ;;
        yum)
            info "Reinstalling PAM via yum..."
            yum reinstall -y pam
            ;;
        *)
            error "Unknown package manager. Manual reinstall required."
            error "Packages needed: libpam, pam (distribution-specific names)"
            exit 1
            ;;
    esac

    info "✅ PAM reinstall complete."
    warn "   Verify /etc/pam.d/common-* (Debian) or /etc/pam.d/system-auth (RHEL) are correct."
    warn "   Open a NEW terminal and test login BEFORE closing this session."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
case "${1:-help}" in
    backup)    do_backup ;;
    restore)   do_restore ;;
    reinstall) do_reinstall ;;
    verify)    do_verify ;;
    *)
        echo "Usage: sudo $0 {backup|restore|reinstall|verify}"
        exit 1
        ;;
esac
