#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — SSHD Configuration Backup & Restore
# =============================================================================
# Backs up sshd_config, authorized_keys, known_hosts, host keys, and
# related SSH configuration. Detects and warns about common backdoor indicators.
#
# Usage:
#   sudo ./03_backup_sshd.sh backup
#   sudo ./03_backup_sshd.sh restore
#   sudo ./03_backup_sshd.sh audit     — Check for suspicious config entries
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="sshd"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
LATEST_LINK="${BACKUP_ROOT}/latest"

SSH_CONFIG_FILES=(
    /etc/ssh/sshd_config
    /etc/ssh/ssh_config
)

SSH_HOST_KEY_PATTERNS=(
    /etc/ssh/ssh_host_*
)

SSH_CONFIG_DIRS=(
    /etc/ssh/sshd_config.d
    /etc/ssh/ssh_config.d
)

# ── Logging ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()   { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }
info()  { log "INFO " "${GREEN}$*${NC}"; }
warn()  { log "WARN " "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
alert() { log "ALERT" "${RED}⚠️  $*${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { error "Must run as root."; exit 1; }
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_ROOT"

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    info "=== SSHD Backup Started: $TIMESTAMP ==="

    # Main config files
    for f in "${SSH_CONFIG_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            dest="${BACKUP_DIR}$(dirname "$f")"
            mkdir -p "$dest"
            cp -p "$f" "$dest/"
            info "  Backed up: $f"
        else
            warn "  Not found: $f"
        fi
    done

    # Config drop-in directories
    for dir in "${SSH_CONFIG_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            dest="${BACKUP_DIR}${dir}"
            mkdir -p "$dest"
            cp -rp "$dir/." "$dest/"
            info "  Backed up dir: $dir"
        fi
    done

    # Host keys (public only — private keys are sensitive)
    # We backup public keys for reference; private keys are regenerable
    mkdir -p "${BACKUP_DIR}/etc/ssh"
    for key in /etc/ssh/ssh_host_*.pub; do
        [[ -f "$key" ]] && cp -p "$key" "${BACKUP_DIR}/etc/ssh/" && info "  Backed up host pubkey: $key"
    done
    # Private host keys — store in backup but restrict permissions hard
    for key in /etc/ssh/ssh_host_*; do
        if [[ -f "$key" && "$key" != *.pub ]]; then
            cp -p "$key" "${BACKUP_DIR}/etc/ssh/"
            chmod 600 "${BACKUP_DIR}/etc/ssh/$(basename "$key")"
            info "  Backed up host privkey: $key (permissions: 600)"
        fi
    done

    # Per-user authorized_keys (all home dirs)
    info "Backing up authorized_keys for all users..."
    while IFS=: read -r username _ uid _ _ homedir _; do
        if (( uid >= 1000 )) || [[ "$username" == "root" ]]; then
            local auth_keys="${homedir}/.ssh/authorized_keys"
            if [[ -f "$auth_keys" ]]; then
                dest="${BACKUP_DIR}${homedir}/.ssh"
                mkdir -p "$dest"
                cp -p "$auth_keys" "$dest/"
                info "    $username: $auth_keys"
            fi
        fi
    done < /etc/passwd

    # Also backup root's
    if [[ -f /root/.ssh/authorized_keys ]]; then
        mkdir -p "${BACKUP_DIR}/root/.ssh"
        cp -p /root/.ssh/authorized_keys "${BACKUP_DIR}/root/.ssh/"
        info "  Backed up root authorized_keys"
    fi

    # Hash manifest
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${BACKUP_DIR}/sha256sums.txt"
    chmod 400 "${BACKUP_DIR}/sha256sums.txt"

    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"
    info "✅ SSHD backup complete: $BACKUP_DIR"

    # Run audit automatically after backup
    do_audit
}

# ── Audit / Backdoor Detection ────────────────────────────────────────────────
do_audit() {
    info "=== SSHD Security Audit ==="
    local issues=0
    local config="/etc/ssh/sshd_config"
    [[ ! -f "$config" ]] && { error "sshd_config not found."; return; }

    # Check for dangerous settings
    declare -A checks=(
        ["PermitRootLogin yes"]="Root login enabled — should be 'no' or 'prohibit-password'"
        ["PermitEmptyPasswords yes"]="Empty passwords allowed — critical risk"
        ["PasswordAuthentication yes"]="Password auth enabled — prefer key-only"
        ["ChallengeResponseAuthentication yes"]="Challenge-response auth enabled"
        ["X11Forwarding yes"]="X11 forwarding enabled — attack surface"
        ["AllowTcpForwarding yes"]="TCP forwarding enabled — tunneling risk"
        ["GatewayPorts yes"]="Gateway ports enabled — remote forwarding risk"
    )

    for pattern in "${!checks[@]}"; do
        if grep -qiE "^\s*${pattern}" "$config" 2>/dev/null; then
            warn "  [FINDING] $pattern → ${checks[$pattern]}"
            ((issues++))
        fi
    done

    # Check for suspicious AuthorizedKeysFile paths
    if grep -qiE "AuthorizedKeysFile.*(tmp|proc|dev|run)" "$config" 2>/dev/null; then
        alert "SUSPICIOUS AuthorizedKeysFile path pointing to /tmp, /proc, /dev, or /run"
        ((issues++))
    fi

    # Check for ForceCommand bypasses
    if grep -qiE "^\s*ForceCommand" "$config" 2>/dev/null; then
        warn "  [INFO] ForceCommand directive found — verify it is expected:"
        grep -iE "^\s*ForceCommand" "$config" | tee -a "$LOG_FILE"
    fi

    # Check for suspicious AcceptEnv
    if grep -qiE "AcceptEnv\s+.*\*" "$config" 2>/dev/null; then
        warn "  [FINDING] AcceptEnv wildcard — environment variable injection risk"
        ((issues++))
    fi

    # Check for extra/unexpected Match blocks (common backdoor location)
    local match_count
    match_count=$(grep -ciE "^\s*Match\s+" "$config" 2>/dev/null || echo 0)
    if (( match_count > 0 )); then
        warn "  [REVIEW] $match_count 'Match' block(s) found in sshd_config — verify all are expected:"
        grep -nE "^\s*Match\s+" "$config" | tee -a "$LOG_FILE"
    fi

    # Check authorized_keys for unusual entries
    info "Checking authorized_keys for command= restrictions and unusual keys..."
    for auth_file in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [[ ! -f "$auth_file" ]] && continue
        owner=$(stat -c '%U' "$auth_file")
        # Check for command= restrictions (could be backdoor or legitimate)
        if grep -qE '^command=' "$auth_file" 2>/dev/null; then
            warn "  [REVIEW] command= restriction in $auth_file (user: $owner) — verify all entries"
            grep -n 'command=' "$auth_file" | tee -a "$LOG_FILE"
        fi
        # Check permissions
        perms=$(stat -c '%a' "$auth_file")
        if [[ "$perms" != "600" && "$perms" != "640" ]]; then
            warn "  [FINDING] $auth_file has loose permissions: $perms (expected 600)"
            ((issues++))
        fi
    done

    if [[ $issues -eq 0 ]]; then
        info "✅ No critical SSHD configuration issues detected."
    else
        warn "⚠️  $issues issue(s) found. Review findings above."
    fi
}

# ── Restore ───────────────────────────────────────────────────────────────────
do_restore() {
    info "=== SSHD Restore ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found. Run backup first."
        exit 1
    fi

    warn "This will restore sshd_config and related files from: $(readlink "$LATEST_LINK")"
    read -rp "Type 'CONFIRM' to proceed: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }

    # Restore config files
    for f in "${SSH_CONFIG_FILES[@]}"; do
        src="${LATEST_LINK}${f}"
        if [[ -f "$src" ]]; then
            cp -p "$f" "${f}.blueteam_pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -p "$src" "$f"
            chmod 600 "$f"
            chown root:root "$f"
            info "  Restored: $f"
        fi
    done

    # Restore config drop-in dirs
    for dir in "${SSH_CONFIG_DIRS[@]}"; do
        src="${LATEST_LINK}${dir}"
        if [[ -d "$src" ]]; then
            cp -rp "$src/." "$dir/"
            info "  Restored dir: $dir"
        fi
    done

    # Validate config syntax before restarting
    info "Validating sshd_config syntax..."
    if sshd -t 2>&1 | tee -a "$LOG_FILE"; then
        info "  Config syntax: OK"
        info "Restarting SSHD..."
        systemctl restart sshd || systemctl restart ssh
        info "✅ SSHD restored and restarted."
    else
        error "Config syntax error! NOT restarting SSHD."
        error "Fix /etc/ssh/sshd_config before restarting SSH."
        exit 1
    fi
}

# ── Entry Point ───────────────────────────────────────────────────────────────
case "${1:-help}" in
    backup)  do_backup ;;
    restore) do_restore ;;
    audit)   do_audit ;;
    *)
        echo "Usage: sudo $0 {backup|restore|audit}"
        exit 1
        ;;
esac
