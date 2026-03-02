#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — Web Server Configuration Backup & Restore
# =============================================================================
# Auto-detects installed web server: Apache2, Nginx, or Lighttpd
# Backs up all server configs, virtual hosts, SSL/TLS certs, and modules.
#
# Usage:
#   sudo ./05_backup_webserver.sh backup
#   sudo ./05_backup_webserver.sh restore
#   sudo ./05_backup_webserver.sh audit    — Check for dangerous misconfigs
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="webserver"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
LATEST_LINK="${BACKUP_ROOT}/latest"

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

# ── Auto-detect Web Server ────────────────────────────────────────────────────
detect_webserver() {
    if command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then
        echo "apache"
    elif command -v nginx &>/dev/null; then
        echo "nginx"
    elif command -v lighttpd &>/dev/null; then
        echo "lighttpd"
    else
        echo "none"
    fi
}

get_webserver_config() {
    local ws="$1"
    case "$ws" in
        apache)
            # Debian/Ubuntu uses apache2, RHEL uses httpd
            if [[ -d /etc/apache2 ]]; then
                CONFIG_DIRS=(/etc/apache2)
                SERVICE_NAME="apache2"
                TEST_CMD="apache2ctl -t"
                RELOAD_CMD="systemctl reload apache2"
            else
                CONFIG_DIRS=(/etc/httpd)
                SERVICE_NAME="httpd"
                TEST_CMD="httpd -t"
                RELOAD_CMD="systemctl reload httpd"
            fi
            ;;
        nginx)
            CONFIG_DIRS=(/etc/nginx)
            SERVICE_NAME="nginx"
            TEST_CMD="nginx -t"
            RELOAD_CMD="systemctl reload nginx"
            ;;
        lighttpd)
            CONFIG_DIRS=(/etc/lighttpd)
            SERVICE_NAME="lighttpd"
            TEST_CMD="lighttpd -t -f /etc/lighttpd/lighttpd.conf"
            RELOAD_CMD="systemctl reload lighttpd"
            ;;
    esac
}

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    local ws
    ws=$(detect_webserver)

    if [[ "$ws" == "none" ]]; then
        warn "No supported web server detected (apache2/nginx/lighttpd)."
        warn "If installed under a different name, add CONFIG_DIRS manually."
        exit 0
    fi

    get_webserver_config "$ws"
    info "=== Web Server Backup: $ws — $TIMESTAMP ==="

    # Record which web server we backed up
    echo "$ws" > "${BACKUP_DIR}/webserver_type.txt"

    for dir in "${CONFIG_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            dest="${BACKUP_DIR}${dir}"
            mkdir -p "$dest"
            cp -rp "$dir/." "$dest/"
            info "  Backed up: $dir"
        else
            warn "  Not found: $dir"
        fi
    done

    # Backup SSL certificates if present
    SSL_DIRS=(/etc/ssl /etc/letsencrypt /etc/pki/tls)
    for ssl_dir in "${SSL_DIRS[@]}"; do
        if [[ -d "$ssl_dir" ]]; then
            dest="${BACKUP_DIR}${ssl_dir}"
            mkdir -p "$dest"
            cp -rp "$ssl_dir/." "$dest/"
            chmod 700 "${dest}"
            info "  SSL/TLS backed up: $ssl_dir"
        fi
    done

    # Record version
    case "$ws" in
        apache) apache2 -v 2>/dev/null || httpd -v > "${BACKUP_DIR}/version.txt" 2>/dev/null || true ;;
        nginx)  nginx -v > "${BACKUP_DIR}/version.txt" 2>/dev/null || true ;;
        lighttpd) lighttpd -v > "${BACKUP_DIR}/version.txt" 2>/dev/null || true ;;
    esac

    # Hash manifest
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; > "${BACKUP_DIR}/sha256sums.txt"
    chmod 400 "${BACKUP_DIR}/sha256sums.txt"

    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"
    info "✅ Web server backup complete: $BACKUP_DIR"

    do_audit
}

# ── Audit ─────────────────────────────────────────────────────────────────────
do_audit() {
    local ws
    ws=$(detect_webserver)
    [[ "$ws" == "none" ]] && { warn "No web server detected for audit."; return; }
    get_webserver_config "$ws"

    info "=== Web Server Security Audit ($ws) ==="
    local issues=0

    case "$ws" in
        apache)
            local conf_dir="${CONFIG_DIRS[0]}"

            # Check for directory listing
            if grep -rqiE "Options\s+.*Indexes" "$conf_dir" 2>/dev/null; then
                alert "Directory listing (Options Indexes) enabled — information disclosure risk"
                grep -rnE "Options\s+.*Indexes" "$conf_dir" | tee -a "$LOG_FILE"
                ((issues++))
            fi

            # Check ServerTokens
            if ! grep -rqiE "ServerTokens\s+Prod" "$conf_dir" 2>/dev/null; then
                warn "  ServerTokens not set to 'Prod' — server version may be disclosed"
                ((issues++))
            fi

            # Check ServerSignature
            if grep -rqiE "ServerSignature\s+On" "$conf_dir" 2>/dev/null; then
                warn "  ServerSignature is On — disclose server info in error pages"
                ((issues++))
            fi

            # Check for .htaccess overrides
            if grep -rqiE "AllowOverride\s+All" "$conf_dir" 2>/dev/null; then
                warn "  AllowOverride All — .htaccess can override security settings"
            fi

            # Check mod_status exposure
            if grep -rqiE "SetHandler\s+server-status" "$conf_dir" 2>/dev/null; then
                if ! grep -rqiE "Require\s+(local|ip\s+127)" "$conf_dir" 2>/dev/null; then
                    alert "mod_status may be exposed publicly — check access controls"
                    ((issues++))
                fi
            fi
            ;;

        nginx)
            local conf_dir="${CONFIG_DIRS[0]}"

            # Check server_tokens
            if ! grep -rqiE "server_tokens\s+off" "$conf_dir" 2>/dev/null; then
                warn "  server_tokens not disabled — Nginx version may be disclosed"
                ((issues++))
            fi

            # Check for autoindex
            if grep -rqiE "autoindex\s+on" "$conf_dir" 2>/dev/null; then
                alert "autoindex on — directory listing enabled"
                grep -rnE "autoindex\s+on" "$conf_dir" | tee -a "$LOG_FILE"
                ((issues++))
            fi

            # Check for stub_status exposure
            if grep -rqiE "stub_status" "$conf_dir" 2>/dev/null; then
                warn "  stub_status found — verify access is restricted to localhost"
            fi
            ;;
    esac

    # Common: check for non-TLS vhosts serving sensitive paths
    info "Checking for HTTP (non-HTTPS) virtual host configurations..."
    if grep -rqiE "listen\s+80[^0-9]" "${CONFIG_DIRS[0]}" 2>/dev/null; then
        warn "  Plaintext HTTP (port 80) listener found — ensure redirect to HTTPS is configured"
    fi

    if [[ $issues -eq 0 ]]; then
        info "✅ No critical web server misconfigurations detected."
    else
        warn "⚠️  $issues issue(s) found. Review findings above."
    fi
}

# ── Restore ───────────────────────────────────────────────────────────────────
do_restore() {
    info "=== Web Server Restore ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found."
        exit 1
    fi

    local ws
    if [[ -f "${LATEST_LINK}/webserver_type.txt" ]]; then
        ws=$(cat "${LATEST_LINK}/webserver_type.txt")
    else
        ws=$(detect_webserver)
    fi
    get_webserver_config "$ws"

    warn "This will restore $ws configuration from: $(readlink "$LATEST_LINK")"
    read -rp "Type 'CONFIRM' to proceed: " confirm
    [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }

    for dir in "${CONFIG_DIRS[@]}"; do
        src="${LATEST_LINK}${dir}"
        if [[ -d "$src" ]]; then
            cp -rp "$dir" "${dir}.blueteam_pre_restore_${TIMESTAMP}" 2>/dev/null || true
            cp -rp "$src/." "$dir/"
            info "  Restored: $dir"
        fi
    done

    # Restore SSL
    for ssl_dir in /etc/ssl /etc/letsencrypt /etc/pki/tls; do
        src="${LATEST_LINK}${ssl_dir}"
        if [[ -d "$src" ]]; then
            cp -rp "$src/." "$ssl_dir/"
            info "  Restored SSL: $ssl_dir"
        fi
    done

    # Test config before reload
    info "Testing restored configuration..."
    if eval "$TEST_CMD" 2>&1 | tee -a "$LOG_FILE"; then
        info "  Config test passed."
        eval "$RELOAD_CMD" && info "  Service reloaded: $SERVICE_NAME" || \
            systemctl restart "$SERVICE_NAME" && info "  Service restarted: $SERVICE_NAME"
    else
        error "Config test FAILED. Service NOT reloaded. Fix errors and manually restart."
        exit 1
    fi

    info "✅ Web server restore complete."
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
