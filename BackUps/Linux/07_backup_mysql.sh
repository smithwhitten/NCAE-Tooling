#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — MySQL / MariaDB Backup & Restore (Linux)
# =============================================================================
# Performs per-database and full-instance dumps using mysqldump.
# Supports credential file auth (.my.cnf), binary log position capture,
# and integrity verification via checksum tables.
#
# Usage:
#   sudo ./07_backup_mysql.sh backup    — Dump all databases
#   sudo ./07_backup_mysql.sh restore   — Interactive restore menu
#   sudo ./07_backup_mysql.sh verify    — Verify dump files are valid SQL
#   sudo ./07_backup_mysql.sh audit     — Check for dangerous config/user issues
#
# Requirements: mysqldump, mysql client, gzip
# Compatible: MySQL 5.7+, MySQL 8.x, MariaDB 10.3+
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="mysql"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
LATEST_LINK="${BACKUP_ROOT}/latest"

# MySQL connection — prefer .my.cnf credential file over plaintext passwords
# Create /root/.my.cnf with:
#   [client]
#   user=root
#   password=yourpassword
MYSQL_DEFAULTS_FILE="/root/.my.cnf"
MYSQL_HOST="${MYSQL_HOST:-localhost}"
MYSQL_PORT="${MYSQL_PORT:-3306}"

# Compression (gzip by default)
COMPRESS=true

# Databases to SKIP (system databases — backed up separately via --all-databases)
SKIP_DBS=("information_schema" "performance_schema" "sys")

# ── Logging ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
log()   { echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$1] $2" | tee -a "$LOG_FILE"; }
info()  { log "INFO " "${GREEN}$*${NC}"; }
warn()  { log "WARN " "${YELLOW}$*${NC}"; }
error() { log "ERROR" "${RED}$*${NC}"; }
alert() { log "ALERT" "${RED}⚠️  $*${NC}"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { error "Must run as root."; exit 1; }

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_ROOT"

# Check required tools
for tool in mysqldump mysql gzip; do
    command -v "$tool" &>/dev/null || { error "Required tool not found: $tool"; exit 1; }
done

# Build MySQL connection arguments
build_mysql_args() {
    local args=()
    if [[ -f "$MYSQL_DEFAULTS_FILE" ]]; then
        args+=("--defaults-file=${MYSQL_DEFAULTS_FILE}")
        info "  Using credentials from: $MYSQL_DEFAULTS_FILE"
    else
        warn "  No .my.cnf found at $MYSQL_DEFAULTS_FILE"
        warn "  Attempting passwordless connection (socket auth)."
        warn "  To set credentials: create /root/.my.cnf with [client] user/password"
    fi
    args+=("-h" "$MYSQL_HOST" "-P" "$MYSQL_PORT")
    echo "${args[@]}"
}

# Test connectivity
test_connection() {
    local args
    read -ra args <<< "$(build_mysql_args)"
    if mysql "${args[@]}" -e "SELECT 1;" &>/dev/null; then
        info "MySQL connection: OK"
        return 0
    else
        error "Cannot connect to MySQL. Check credentials in $MYSQL_DEFAULTS_FILE"
        error "Or set MYSQL_HOST / MYSQL_PORT environment variables."
        return 1
    fi
}

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    info "=== MySQL Backup Started: $TIMESTAMP ==="
    test_connection || exit 1

    local args
    read -ra args <<< "$(build_mysql_args)"

    # 1. Full instance dump (all databases in one file — for complete restore)
    info "Dumping full instance (all databases)..."
    local full_dump="${BACKUP_DIR}/full_instance_${TIMESTAMP}.sql"
    mysqldump "${args[@]}" \
        --all-databases \
        --single-transaction \
        --flush-logs \
        --master-data=2 \
        --routines \
        --triggers \
        --events \
        --add-drop-database \
        --comments \
        2>>"$LOG_FILE" > "$full_dump"

    if $COMPRESS; then
        gzip -f "$full_dump"
        full_dump="${full_dump}.gz"
        info "  Full dump (compressed): $full_dump"
    else
        info "  Full dump: $full_dump"
    fi

    # 2. Per-database dumps (for surgical restore)
    info "Dumping individual databases..."
    local db_list
    db_list=$(mysql "${args[@]}" -N -e "SHOW DATABASES;" 2>/dev/null)

    local db_dir="${BACKUP_DIR}/per_database"
    mkdir -p "$db_dir"
    local dumped=0

    while IFS= read -r db; do
        # Skip system databases
        local skip=false
        for skip_db in "${SKIP_DBS[@]}"; do
            [[ "$db" == "$skip_db" ]] && skip=true && break
        done
        $skip && continue

        [[ -z "$db" ]] && continue

        local dump_file="${db_dir}/${db}_${TIMESTAMP}.sql"
        info "  Dumping: $db"

        mysqldump "${args[@]}" \
            --single-transaction \
            --routines \
            --triggers \
            --events \
            --add-drop-table \
            --add-drop-database \
            --databases "$db" \
            2>>"$LOG_FILE" > "$dump_file"

        if $COMPRESS; then
            gzip -f "$dump_file"
            dump_file="${dump_file}.gz"
        fi

        # Record file hash
        sha256sum "$dump_file" >> "${BACKUP_DIR}/sha256sums.txt"
        ((dumped++))
    done <<< "$db_list"

    info "  Per-database dumps complete: $dumped database(s)"

    # 3. Dump MySQL user accounts and grants
    info "Exporting user accounts and GRANT statements..."
    local users_file="${BACKUP_DIR}/mysql_users_grants_${TIMESTAMP}.sql"
    mysql "${args[@]}" -N -e "
        SELECT CONCAT('SHOW GRANTS FOR \'',user,'\'@\'',host,'\';')
        FROM mysql.user
        WHERE user != '';" 2>/dev/null | \
    while IFS= read -r grant_cmd; do
        mysql "${args[@]}" -N -e "$grant_cmd" 2>/dev/null | \
            sed 's/$/;/'
        echo ""
    done > "$users_file" 2>>"$LOG_FILE" || warn "Could not export all grants."

    if $COMPRESS; then
        gzip -f "$users_file"
    fi
    info "  User/grants export: ${users_file}.gz"

    # 4. Capture binary log position (for point-in-time recovery reference)
    info "Capturing binary log position..."
    mysql "${args[@]}" -e "SHOW MASTER STATUS\G" 2>/dev/null > \
        "${BACKUP_DIR}/binlog_position_${TIMESTAMP}.txt" || \
        warn "Could not capture binary log position (may not be enabled)."

    # 5. Record MySQL version and configuration
    mysql "${args[@]}" -e "SELECT VERSION();" 2>/dev/null > "${BACKUP_DIR}/mysql_version.txt" || true
    mysql "${args[@]}" -e "SHOW VARIABLES;" 2>/dev/null > "${BACKUP_DIR}/mysql_variables.txt" || true

    # 6. Backup my.cnf
    for cnf in /etc/mysql/my.cnf /etc/my.cnf /etc/mysql/mysql.conf.d/mysqld.cnf \
                /etc/mysql/mariadb.conf.d/50-server.cnf; do
        if [[ -f "$cnf" ]]; then
            dest="${BACKUP_DIR}/config$(dirname "$cnf")"
            mkdir -p "$dest"
            cp -p "$cnf" "$dest/"
            info "  MySQL config backed up: $cnf"
        fi
    done

    # Final hash manifest
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; >> "${BACKUP_DIR}/sha256sums.txt"
    sort -u "${BACKUP_DIR}/sha256sums.txt" -o "${BACKUP_DIR}/sha256sums.txt"
    chmod 400 "${BACKUP_DIR}/sha256sums.txt"
    chmod 600 "${BACKUP_DIR}/"*.sql* 2>/dev/null || true
    chmod 600 "${BACKUP_DIR}/per_database/"*.sql* 2>/dev/null || true

    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"
    info "✅ MySQL backup complete: $BACKUP_DIR"
}

# ── Verify ────────────────────────────────────────────────────────────────────
do_verify() {
    info "=== MySQL Dump Verification ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found. Run backup first."
        exit 1
    fi

    local issues=0

    # Verify SQL dump files are valid (check header and basic structure)
    while IFS= read -r -d '' dumpfile; do
        local basename
        basename=$(basename "$dumpfile")
        info "  Checking: $basename"

        local content
        if [[ "$dumpfile" == *.gz ]]; then
            content=$(zcat "$dumpfile" 2>/dev/null | head -20)
        else
            content=$(head -20 "$dumpfile" 2>/dev/null)
        fi

        if echo "$content" | grep -qE "^-- MySQL dump|^-- MariaDB dump"; then
            info "    Header: OK (valid mysqldump format)"
        else
            warn "    Header: UNEXPECTED — file may be corrupt or truncated"
            ((issues++))
        fi

        # Check for dump completion marker
        local tail_content
        if [[ "$dumpfile" == *.gz ]]; then
            tail_content=$(zcat "$dumpfile" 2>/dev/null | tail -5)
        else
            tail_content=$(tail -5 "$dumpfile" 2>/dev/null)
        fi

        if echo "$tail_content" | grep -q "Dump completed"; then
            info "    Completion marker: OK"
        else
            warn "    Completion marker: MISSING — dump may be incomplete"
            ((issues++))
        fi

    done < <(find "$LATEST_LINK" -name "*.sql" -o -name "*.sql.gz" -print0 2>/dev/null)

    # SHA-256 verification
    info "Verifying file hashes..."
    local mismatch=0
    while IFS= read -r line; do
        local expected_hash file_path
        expected_hash=$(echo "$line" | awk '{print $1}')
        file_path=$(echo "$line" | awk '{print $2}')
        if [[ -f "$file_path" ]]; then
            local actual_hash
            actual_hash=$(sha256sum "$file_path" | awk '{print $1}')
            if [[ "$expected_hash" != "$actual_hash" ]]; then
                error "  HASH MISMATCH: $file_path"
                ((mismatch++))
            fi
        fi
    done < "${LATEST_LINK}/sha256sums.txt"

    if [[ $issues -eq 0 && $mismatch -eq 0 ]]; then
        info "✅ All MySQL dumps verified successfully."
    else
        warn "⚠️  $issues dump issue(s), $mismatch hash mismatch(es) found."
    fi
}

# ── Audit ─────────────────────────────────────────────────────────────────────
do_audit() {
    info "=== MySQL Security Audit ==="
    test_connection || { warn "Cannot connect — skipping live audit checks."; return; }

    local args
    read -ra args <<< "$(build_mysql_args)"
    local issues=0

    # Check for anonymous users
    info "Checking for anonymous user accounts..."
    local anon_users
    anon_users=$(mysql "${args[@]}" -N -e \
        "SELECT user, host FROM mysql.user WHERE user='';" 2>/dev/null)
    if [[ -n "$anon_users" ]]; then
        alert "Anonymous MySQL user(s) exist — should be removed:"
        echo "$anon_users" | tee -a "$LOG_FILE"
        echo "  Fix: DROP USER ''@'localhost'; DROP USER ''@'%';"
        ((issues++))
    else
        info "  No anonymous users: OK"
    fi

    # Check for users with empty passwords
    info "Checking for accounts with empty passwords..."
    local empty_pass
    # MySQL 5.7+ uses authentication_string; older uses Password
    empty_pass=$(mysql "${args[@]}" -N -e \
        "SELECT user, host FROM mysql.user
         WHERE (authentication_string='' OR authentication_string IS NULL)
         AND user != '';" 2>/dev/null || \
        mysql "${args[@]}" -N -e \
        "SELECT user, host FROM mysql.user
         WHERE Password='' AND user != '';" 2>/dev/null)
    if [[ -n "$empty_pass" ]]; then
        alert "Users with EMPTY passwords:"
        echo "$empty_pass" | tee -a "$LOG_FILE"
        ((issues++))
    else
        info "  No empty-password accounts: OK"
    fi

    # Check for root accounts accessible from any host
    info "Checking root account host restrictions..."
    local root_any
    root_any=$(mysql "${args[@]}" -N -e \
        "SELECT user, host FROM mysql.user WHERE user='root' AND host='%';" 2>/dev/null)
    if [[ -n "$root_any" ]]; then
        alert "root account allows connection from ANY host ('%') — restrict to localhost"
        ((issues++))
    else
        info "  root host restriction: OK"
    fi

    # Check for accounts with ALL PRIVILEGES
    info "Checking for overprivileged accounts..."
    local all_privs
    all_privs=$(mysql "${args[@]}" -N -e \
        "SELECT user, host FROM mysql.user
         WHERE Super_priv='Y' AND user NOT IN ('root','mysql.sys','mysql.session');" \
        2>/dev/null)
    if [[ -n "$all_privs" ]]; then
        warn "  Non-root accounts with SUPER privilege:"
        echo "$all_privs" | tee -a "$LOG_FILE"
        ((issues++))
    fi

    # Check if bind-address is 0.0.0.0 (exposed to network)
    info "Checking network binding..."
    local bind_addr
    bind_addr=$(mysql "${args[@]}" -N -e \
        "SHOW VARIABLES LIKE 'bind_address';" 2>/dev/null | awk '{print $2}')
    if [[ "$bind_addr" == "0.0.0.0" || "$bind_addr" == "*" ]]; then
        alert "MySQL bound to 0.0.0.0 — accessible from all interfaces"
        alert "  Consider: bind-address = 127.0.0.1 in my.cnf if only local access needed"
        ((issues++))
    else
        info "  bind-address: $bind_addr"
    fi

    # Check FILE privilege (can read/write OS files)
    info "Checking FILE privilege..."
    local file_privs
    file_privs=$(mysql "${args[@]}" -N -e \
        "SELECT user, host FROM mysql.user
         WHERE File_priv='Y' AND user NOT IN ('root');" 2>/dev/null)
    if [[ -n "$file_privs" ]]; then
        alert "Non-root users have FILE privilege (can read/write OS files via LOAD DATA):"
        echo "$file_privs" | tee -a "$LOG_FILE"
        ((issues++))
    fi

    # Check secure_file_priv
    local sfp
    sfp=$(mysql "${args[@]}" -N -e "SHOW VARIABLES LIKE 'secure_file_priv';" 2>/dev/null | awk '{print $2}')
    if [[ -z "$sfp" || "$sfp" == "NULL" ]]; then
        warn "  secure_file_priv is not set — LOAD DATA INFILE unrestricted"
        ((issues++))
    else
        info "  secure_file_priv: $sfp"
    fi

    if [[ $issues -eq 0 ]]; then
        info "✅ No critical MySQL security issues detected."
    else
        warn "⚠️  $issues issue(s) found. Review alerts above."
    fi
}

# ── Restore ───────────────────────────────────────────────────────────────────
do_restore() {
    info "=== MySQL Restore ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found. Run backup first."
        exit 1
    fi

    test_connection || exit 1
    local args
    read -ra args <<< "$(build_mysql_args)"

    echo ""
    echo "Restore options:"
    echo "  1) Full instance restore (all databases)"
    echo "  2) Single database restore"
    echo "  3) Restore users/grants only"
    echo "  0) Cancel"
    read -rp "Choice: " choice

    case "$choice" in
        1)
            warn "⚠️  FULL RESTORE will overwrite ALL databases on this server."
            warn "   This is destructive. Ensure you have stopped dependent applications."
            read -rp "Type 'FULL RESTORE' to proceed: " confirm
            [[ "$confirm" != "FULL RESTORE" ]] && { info "Cancelled."; exit 0; }

            local full_dump
            full_dump=$(find "$LATEST_LINK" -maxdepth 1 -name "full_instance_*.sql.gz" \
                -o -name "full_instance_*.sql" 2>/dev/null | head -1)

            if [[ -z "$full_dump" ]]; then
                error "Full dump not found in $LATEST_LINK"
                exit 1
            fi

            info "Restoring from: $(basename "$full_dump")"
            if [[ "$full_dump" == *.gz ]]; then
                zcat "$full_dump" | mysql "${args[@]}" 2>>"$LOG_FILE"
            else
                mysql "${args[@]}" < "$full_dump" 2>>"$LOG_FILE"
            fi
            info "✅ Full restore complete."
            ;;

        2)
            local db_dir="${LATEST_LINK}/per_database"
            if [[ ! -d "$db_dir" ]]; then
                error "Per-database backup directory not found."
                exit 1
            fi

            echo "Available database dumps:"
            local i=1
            declare -a dump_files
            while IFS= read -r -d '' f; do
                dump_files+=("$f")
                echo "  $i) $(basename "$f")"
                ((i++))
            done < <(find "$db_dir" -name "*.sql.gz" -o -name "*.sql" -print0 2>/dev/null | sort -z)

            read -rp "Select dump number: " sel
            if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#dump_files[@]} )); then
                local chosen="${dump_files[$((sel-1))]}"
                local db_name
                db_name=$(basename "$chosen" | sed 's/_[0-9]\{8\}_[0-9]\{6\}\.sql.*$//')
                warn "This will overwrite database: $db_name"
                read -rp "Type 'CONFIRM' to proceed: " confirm
                [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }

                if [[ "$chosen" == *.gz ]]; then
                    zcat "$chosen" | mysql "${args[@]}" 2>>"$LOG_FILE"
                else
                    mysql "${args[@]}" < "$chosen" 2>>"$LOG_FILE"
                fi
                info "✅ Database '$db_name' restored."
            else
                error "Invalid selection."
                exit 1
            fi
            ;;

        3)
            local grants_file
            grants_file=$(find "$LATEST_LINK" -maxdepth 1 \
                -name "mysql_users_grants_*.sql.gz" -o -name "mysql_users_grants_*.sql" \
                2>/dev/null | head -1)
            if [[ -z "$grants_file" ]]; then
                error "Grants file not found."
                exit 1
            fi
            warn "Restoring user accounts and GRANT statements..."
            read -rp "Type 'CONFIRM' to proceed: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }

            if [[ "$grants_file" == *.gz ]]; then
                zcat "$grants_file" | mysql "${args[@]}" 2>>"$LOG_FILE"
            else
                mysql "${args[@]}" < "$grants_file" 2>>"$LOG_FILE"
            fi
            mysql "${args[@]}" -e "FLUSH PRIVILEGES;" 2>>"$LOG_FILE"
            info "✅ Users and grants restored. Privileges flushed."
            ;;

        0) exit 0 ;;
        *) error "Invalid choice."; exit 1 ;;
    esac
}

# ── Entry Point ───────────────────────────────────────────────────────────────
case "${1:-help}" in
    backup)  do_backup ;;
    restore) do_restore ;;
    verify)  do_verify ;;
    audit)   do_audit ;;
    *)
        echo "Usage: sudo $0 {backup|restore|verify|audit}"
        exit 1
        ;;
esac
