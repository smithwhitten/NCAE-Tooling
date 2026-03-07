#!/bin/bash
# ==============================================================================
# smb_threat_hunt.sh
# Samba Threat Hunting Script — Detect guest access, unauthorized users,
# suspicious share file drops, and service tampering
#
# Run as root: sudo bash smb_threat_hunt.sh
# Run repeatedly: watch -n 120 sudo bash smb_threat_hunt.sh
# ==============================================================================

SMB_CONF="/etc/samba/smb.conf"
LOG_FILE="/var/log/ncae_smb_hunt.log"

log() {
    local msg="[$(date '+%H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "[ERROR] Run as root: sudo bash $0"
        exit 1
    fi
}

# ── Hunt 1: Guest / anonymous access ─────────────────────────────────────────
hunt_guest_access() {
    log ""
    log "=== [1] Guest / Anonymous Access Audit ==="

    if grep -iE "^\s*guest ok\s*=\s*yes" "$SMB_CONF" 2>/dev/null; then
        log "  [WARN] 'guest ok = yes' found — anonymous share access enabled!"
    else
        log "  [OK] No 'guest ok = yes' found"
    fi

    if grep -iE "^\s*map to guest\s*=\s*(bad user|bad password)" "$SMB_CONF" 2>/dev/null; then
        log "  [WARN] 'map to guest' allows anonymous fallback!"
    else
        log "  [OK] map to guest is not permissive"
    fi

    local restrict; restrict=$(grep -iE "^\s*restrict anonymous\s*=" "$SMB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$restrict" == "2" ]]; then
        log "  [OK] restrict anonymous = 2"
    else
        log "  [WARN] restrict anonymous = '${restrict:-not set}' — should be 2"
    fi
}

# ── Hunt 2: Samba user database ────────────────────────────────────────────────
hunt_samba_users() {
    log ""
    log "=== [2] Samba User Audit ==="
    log "  [*] Current Samba users:"
    pdbedit -L 2>/dev/null | while IFS= read -r line; do log "    $line"; done \
        || log "    (pdbedit unavailable)"

    log "  [*] Disabled accounts (Account Flags contain D):"
    pdbedit -Lv 2>/dev/null | grep -E "^Unix username:|^Account Flags:" | paste - - \
        | grep "\[D" | while IFS= read -r line; do log "    $line"; done || true

    log "  [*] Accounts with no password required (Flag N — dangerous):"
    pdbedit -Lv 2>/dev/null | grep -E "^Unix username:|^Account Flags:" | paste - - \
        | grep "\[N" | while IFS= read -r line; do log "    [WARN] $line"; done || true
}

# ── Hunt 3: Active connections ────────────────────────────────────────────────
hunt_connections() {
    log ""
    log "=== [3] Active Samba Connections ==="

    log "  [*] Current share connections:"
    smbstatus --shares 2>/dev/null | while IFS= read -r line; do log "    $line"; done \
        || log "    (smbstatus unavailable)"

    log "  [*] Connected users:"
    smbstatus --users 2>/dev/null | while IFS= read -r line; do log "    $line"; done \
        || log "    (smbstatus unavailable)"
}

# ── Hunt 4: Recently modified share files ─────────────────────────────────────
hunt_share_files() {
    log ""
    log "=== [4] Recently Modified Share Files (last 60 min) ==="

    local share_found=0
    while IFS= read -r line; do
        if [[ "$line" =~ path[[:space:]]*=[[:space:]]*(.+) ]]; then
            local path="${BASH_REMATCH[1]// /}"
            [[ ! -d "$path" ]] && continue
            share_found=1
            log "  [*] Share path: $path"
            local file_count=0
            find "$path" -mmin -60 -type f 2>/dev/null | while IFS= read -r f; do
                log "    MODIFIED: $(ls -la "$f")"
                ((file_count++))
            done
            [[ $file_count -eq 0 ]] && log "    (no files modified in last 60 min)"
        fi
    done < "$SMB_CONF"

    [[ $share_found -eq 0 ]] && log "  (no share paths found in $SMB_CONF)"
}

# ── Hunt 5: Service status ───────────────────────────────────────────────────
hunt_service_status() {
    log ""
    log "=== [5] Samba Service Status ==="

    systemctl is-active --quiet smbd \
        && log "  [OK] smbd is RUNNING" \
        || log "  [CRITICAL] smbd is NOT RUNNING — Samba file sharing is down!"

    local masked; masked=$(systemctl is-enabled smbd 2>/dev/null)
    [[ "$masked" == "masked" ]] && log "  [CRITICAL] smbd is MASKED — cannot be restarted!" \
        || log "  [OK] smbd enabled status: $masked"

    ss -tlnp 2>/dev/null | grep -q 445 \
        && log "  [OK] Port 445 is listening" \
        || log "  [CRITICAL] Port 445 is NOT listening — SMB service is unreachable!"
}

# ── Hunt 6: SMB protocol version ─────────────────────────────────────────────
hunt_protocol_version() {
    log ""
    log "=== [6] SMB Protocol Version Check ==="

    local min_proto; min_proto=$(grep -iE "^\s*server min protocol\s*=" "$SMB_CONF" 2>/dev/null \
        | awk -F= '{print $2}' | tr -d ' \t')

    if [[ -z "$min_proto" ]]; then
        log "  [WARN] server min protocol not set — SMB1 may be allowed (default behavior varies)"
    else
        case "$min_proto" in
            SMB1|CORE|LANMAN1|LANMAN2|NT1)
                log "  [CRITICAL] server min protocol = $min_proto — SMB1 is ENABLED (EternalBlue risk)!"
                ;;
            SMB2|SMB2_02|SMB2_10|SMB2_22|SMB2_24|SMB3|SMB3_00|SMB3_02|SMB3_11)
                log "  [OK] server min protocol = $min_proto (SMB1 disabled)"
                ;;
            *)
                log "  [INFO] server min protocol = $min_proto (verify this is correct)"
                ;;
        esac
    fi
}

# ── Hunt 7: Recently modified smb.conf ───────────────────────────────────────
hunt_config_changes() {
    log ""
    log "=== [7] Samba Config File Changes ==="

    find /etc/samba -mmin -120 -type f 2>/dev/null | while IFS= read -r f; do
        log "  [WARN] RECENTLY MODIFIED: $f ($(stat -c '%y' "$f"))"
    done

    find /etc/samba -mmin -120 -type f 2>/dev/null | grep -q . \
        || log "  [OK] No Samba config files modified in last 2 hours"
}

main() {
    check_root
    mkdir -p "$(dirname "$LOG_FILE")"

    echo "=============================="
    echo " SMB Threat Hunt"
    echo " $(date)"
    echo "=============================="

    log "=============================="
    log " SMB Threat Hunt — $(date)"
    log "=============================="

    hunt_guest_access
    hunt_samba_users
    hunt_connections
    hunt_share_files
    hunt_service_status
    hunt_protocol_version
    hunt_config_changes

    log ""
    log "=============================="
    log " Hunt complete. Log: $LOG_FILE"
    log "=============================="
    echo ""
    echo "Log saved to: $LOG_FILE"
}

main
