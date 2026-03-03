#!/usr/bin/env bash
# =============================================================================
# BLUE TEAM — PostgreSQL Backup & Restore (Linux)
# =============================================================================
# Performs per-database pg_dump and full-cluster pg_dumpall backups.
# Backs up pg_hba.conf, postgresql.conf, and role/user definitions.
# Supports both plain SQL and custom format (-Fc) dumps.
#
# Usage:
#   sudo ./08_backup_postgres.sh backup
#   sudo ./08_backup_postgres.sh restore
#   sudo ./08_backup_postgres.sh verify
#   sudo ./08_backup_postgres.sh audit
#
# Requirements: pg_dump, pg_dumpall, pg_restore, psql
# Compatible: PostgreSQL 12+
# =============================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
SERVICE="postgres"
BACKUP_ROOT="/opt/blueteam/backups/${SERVICE}"
LOG_FILE="/var/log/blueteam_${SERVICE}.log"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/${TIMESTAMP}"
LATEST_LINK="${BACKUP_ROOT}/latest"

# PostgreSQL connection settings
PG_HOST="${PGHOST:-localhost}"
PG_PORT="${PGPORT:-5432}"
PG_SUPERUSER="${PGUSER:-postgres}"  # Must be a superuser for full backup

# Dump format: 'custom' (-Fc, compressed, pg_restore only) or 'plain' (-Fp, .sql)
# 'custom' is recommended — supports parallel restore and selective table restore
DUMP_FORMAT="custom"

# Databases to skip
SKIP_DBS=("template0")  # template0 cannot be connected to; template1 is backed up

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

for tool in pg_dump pg_dumpall pg_restore psql; do
    command -v "$tool" &>/dev/null || { error "Required tool not found: $tool"; exit 1; }
done

# Build psql connection args (uses peer auth for postgres user when run as root→sudo -u postgres)
run_as_postgres() {
    sudo -u "$PG_SUPERUSER" "$@"
}

pg_exec() {
    run_as_postgres psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --no-password -t -A -c "$1" 2>/dev/null
}

test_connection() {
    if run_as_postgres psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --no-password -c "SELECT 1;" &>/dev/null; then
        info "PostgreSQL connection: OK"
        return 0
    else
        error "Cannot connect to PostgreSQL as user '$PG_SUPERUSER'."
        error "Ensure the postgres system user exists and PostgreSQL is running."
        error "Alternatively, set PGUSER, PGHOST, PGPORT environment variables."
        return 1
    fi
}

# ── Backup ────────────────────────────────────────────────────────────────────
do_backup() {
    info "=== PostgreSQL Backup Started: $TIMESTAMP ==="
    test_connection || exit 1

    # Determine file extension based on format
    local ext
    [[ "$DUMP_FORMAT" == "custom" ]] && ext=".dump" || ext=".sql"

    # 1. Full cluster dump (globals: roles, tablespaces — no data)
    info "Dumping cluster globals (roles, tablespaces)..."
    local globals_file="${BACKUP_DIR}/globals_${TIMESTAMP}.sql"
    run_as_postgres pg_dumpall \
        -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --globals-only \
        --no-password \
        2>>"$LOG_FILE" > "$globals_file"
    gzip -f "$globals_file"
    info "  Globals dump: ${globals_file}.gz"

    # 2. Full cluster dump (all databases — for complete recovery)
    info "Dumping full cluster (all databases)..."
    local full_dump="${BACKUP_DIR}/full_cluster_${TIMESTAMP}.sql"
    run_as_postgres pg_dumpall \
        -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
        --no-password \
        --clean \
        --if-exists \
        2>>"$LOG_FILE" > "$full_dump"
    gzip -f "$full_dump"
    info "  Full cluster dump (compressed): ${full_dump}.gz"

    # 3. Per-database dumps
    info "Dumping individual databases..."
    local db_dir="${BACKUP_DIR}/per_database"
    mkdir -p "$db_dir"
    local dumped=0

    local db_list
    db_list=$(pg_exec "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname;")

    while IFS= read -r db; do
        [[ -z "$db" ]] && continue

        # Skip configured databases
        local skip=false
        for skip_db in "${SKIP_DBS[@]}"; do
            [[ "$db" == "$skip_db" ]] && skip=true && break
        done
        $skip && continue

        local dump_file="${db_dir}/${db}_${TIMESTAMP}${ext}"
        info "  Dumping: $db"

        if [[ "$DUMP_FORMAT" == "custom" ]]; then
            run_as_postgres pg_dump \
                -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                --no-password \
                --format=custom \
                --compress=9 \
                --blobs \
                --schema-only=false \
                --verbose \
                --dbname="$db" \
                2>>"$LOG_FILE" > "$dump_file"
        else
            run_as_postgres pg_dump \
                -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                --no-password \
                --format=plain \
                --clean \
                --if-exists \
                --blobs \
                --dbname="$db" \
                2>>"$LOG_FILE" > "$dump_file"
            gzip -f "$dump_file"
            dump_file="${dump_file}.gz"
        fi

        sha256sum "$dump_file" >> "${BACKUP_DIR}/sha256sums.txt"
        info "    Done: $(basename "$dump_file")"
        ((dumped++))
    done <<< "$db_list"

    info "  Per-database dumps: $dumped database(s)"

    # 4. Backup PostgreSQL configuration files
    info "Backing up PostgreSQL configuration..."
    local pg_conf_dirs=(
        "/etc/postgresql"
        "/var/lib/postgresql"
    )
    # Also detect config from running instance
    local pg_data_dir
    pg_data_dir=$(pg_exec "SHOW data_directory;" 2>/dev/null || echo "")
    if [[ -n "$pg_data_dir" && -d "$pg_data_dir" ]]; then
        pg_conf_dirs+=("$pg_data_dir")
    fi

    for conf_dir in "${pg_conf_dirs[@]}"; do
        if [[ -d "$conf_dir" ]]; then
            local dest="${BACKUP_DIR}/config${conf_dir}"
            mkdir -p "$dest"
            # Only copy config files, not WAL/data files (too large)
            find "$conf_dir" -maxdepth 4 \
                \( -name "*.conf" -o -name "*.conf.d" -o -name "pg_hba.conf" \
                   -o -name "pg_ident.conf" -o -name "pg_ctl.conf" \) \
                -exec cp -p --parents {} "${BACKUP_DIR}/config/" \; 2>/dev/null || true
            info "  Config backed up from: $conf_dir"
        fi
    done

    # 5. Record PostgreSQL version and settings
    pg_exec "SELECT version();" > "${BACKUP_DIR}/pg_version.txt" 2>/dev/null || true
    pg_exec "SELECT name, setting, unit, context FROM pg_settings ORDER BY name;" \
        > "${BACKUP_DIR}/pg_settings.txt" 2>/dev/null || true

    # 6. Record table sizes per database (useful for triage)
    info "Recording database sizes..."
    pg_exec "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size
             FROM pg_database ORDER BY pg_database_size(datname) DESC;" \
        > "${BACKUP_DIR}/database_sizes.txt" 2>/dev/null || true

    # Final hash manifest
    find "$BACKUP_DIR" -type f ! -name "sha256sums.txt" \
        -exec sha256sum {} \; >> "${BACKUP_DIR}/sha256sums.txt"
    sort -u "${BACKUP_DIR}/sha256sums.txt" -o "${BACKUP_DIR}/sha256sums.txt"
    chmod 400 "${BACKUP_DIR}/sha256sums.txt"
    chmod 600 "${BACKUP_DIR}/"*_${TIMESTAMP}* 2>/dev/null || true
    chmod 600 "${BACKUP_DIR}/per_database/"* 2>/dev/null || true

    ln -sfn "$BACKUP_DIR" "$LATEST_LINK"
    info "✅ PostgreSQL backup complete: $BACKUP_DIR"
}

# ── Verify ────────────────────────────────────────────────────────────────────
do_verify() {
    info "=== PostgreSQL Dump Verification ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found."
        exit 1
    fi

    local issues=0

    # Verify custom format dumps with pg_restore --list (non-destructive)
    while IFS= read -r -d '' dumpfile; do
        local basename
        basename=$(basename "$dumpfile")
        info "  Verifying: $basename"

        if [[ "$dumpfile" == *.dump ]]; then
            # Custom format — use pg_restore to check table of contents
            if run_as_postgres pg_restore --list "$dumpfile" &>/dev/null; then
                info "    pg_restore table-of-contents: OK"
            else
                warn "    pg_restore FAILED to read dump — file may be corrupt"
                ((issues++))
            fi
        elif [[ "$dumpfile" == *.sql.gz ]]; then
            # Plain SQL — check header
            if zcat "$dumpfile" 2>/dev/null | head -5 | grep -q "PostgreSQL database dump"; then
                info "    SQL header: OK"
                # Check completion marker
                if zcat "$dumpfile" 2>/dev/null | tail -5 | grep -q "PostgreSQL database dump complete"; then
                    info "    Completion marker: OK"
                else
                    warn "    Completion marker missing — dump may be truncated"
                    ((issues++))
                fi
            else
                warn "    Unexpected header — not a standard pg_dump output"
                ((issues++))
            fi
        fi
    done < <(find "$LATEST_LINK/per_database" -type f \( -name "*.dump" -o -name "*.sql.gz" \) -print0 2>/dev/null)

    if [[ $issues -eq 0 ]]; then
        info "✅ All PostgreSQL dumps verified."
    else
        warn "⚠️  $issues dump verification issue(s) found."
    fi
}

# ── Audit ─────────────────────────────────────────────────────────────────────
do_audit() {
    info "=== PostgreSQL Security Audit ==="
    test_connection || { warn "Cannot connect — skipping live audit."; return; }

    local issues=0

    # Check for superuser accounts (non-postgres)
    info "Checking for unexpected superuser accounts..."
    local superusers
    superusers=$(pg_exec "SELECT rolname FROM pg_roles
                          WHERE rolsuper = true AND rolname NOT IN ('postgres');")
    if [[ -n "$superusers" ]]; then
        alert "Non-default superuser accounts found:"
        echo "$superusers" | tee -a "$LOG_FILE"
        ((issues++))
    else
        info "  Superusers: only 'postgres' (OK)"
    fi

    # Check for roles with LOGIN and no password
    info "Checking for login roles without passwords..."
    local no_pass
    no_pass=$(pg_exec "SELECT rolname FROM pg_authid
                       WHERE rolcanlogin = true
                       AND rolpassword IS NULL
                       AND rolname NOT IN ('postgres');")
    if [[ -n "$no_pass" ]]; then
        alert "Login roles with NO password set:"
        echo "$no_pass" | tee -a "$LOG_FILE"
        ((issues++))
    else
        info "  All login roles have passwords set: OK"
    fi

    # Check pg_hba.conf for trust authentication
    info "Checking pg_hba.conf for 'trust' authentication..."
    local hba_file
    hba_file=$(pg_exec "SHOW hba_file;" 2>/dev/null)
    if [[ -f "$hba_file" ]]; then
        local trust_lines
        trust_lines=$(grep -vE '^\s*#|^\s*$' "$hba_file" | grep -E '\btrust\b' || true)
        if [[ -n "$trust_lines" ]]; then
            alert "pg_hba.conf has 'trust' auth entries — anyone can connect without password:"
            echo "$trust_lines" | tee -a "$LOG_FILE"
            ((issues++))
        else
            info "  No 'trust' auth in pg_hba.conf: OK"
        fi

        # Check for md5 (deprecated, prefer scram-sha-256 in PG14+)
        if grep -qE '\bmd5\b' "$hba_file" 2>/dev/null; then
            warn "  pg_hba.conf uses 'md5' — consider upgrading to 'scram-sha-256' (PG10+)"
        fi
    else
        warn "  Could not locate pg_hba.conf"
    fi

    # Check listen_addresses
    info "Checking listen_addresses..."
    local listen
    listen=$(pg_exec "SHOW listen_addresses;")
    if [[ "$listen" == "*" ]]; then
        alert "listen_addresses='*' — PostgreSQL accepts connections on ALL interfaces"
        alert "  Consider: listen_addresses = 'localhost' if only local access needed"
        ((issues++))
    else
        info "  listen_addresses: $listen"
    fi

    # Check SSL status
    local ssl_on
    ssl_on=$(pg_exec "SHOW ssl;")
    if [[ "$ssl_on" != "on" ]]; then
        warn "  SSL is OFF — connections are unencrypted"
        ((issues++))
    else
        info "  SSL: on (OK)"
    fi

    # Check for tables with PUBLIC insert/write access
    info "Checking for tables with excessive PUBLIC grants..."
    local public_grants
    public_grants=$(pg_exec "SELECT table_catalog, table_schema, table_name, privilege_type
                              FROM information_schema.role_table_grants
                              WHERE grantee = 'PUBLIC'
                              AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')
                              LIMIT 20;" 2>/dev/null || echo "")
    if [[ -n "$public_grants" ]]; then
        alert "Tables with PUBLIC write privileges (first 20):"
        echo "$public_grants" | tee -a "$LOG_FILE"
        ((issues++))
    else
        info "  No PUBLIC write grants found: OK"
    fi

    if [[ $issues -eq 0 ]]; then
        info "✅ No critical PostgreSQL security issues detected."
    else
        warn "⚠️  $issues issue(s) found. Review alerts above."
    fi
}

# ── Restore ───────────────────────────────────────────────────────────────────
do_restore() {
    info "=== PostgreSQL Restore ==="
    if [[ ! -L "$LATEST_LINK" ]]; then
        error "No backup found."
        exit 1
    fi

    test_connection || exit 1

    echo ""
    echo "Restore options:"
    echo "  1) Full cluster restore (globals + all databases)"
    echo "  2) Single database restore"
    echo "  3) Restore globals (roles/tablespaces) only"
    echo "  0) Cancel"
    read -rp "Choice: " choice

    case "$choice" in
        1)
            warn "⚠️  FULL CLUSTER RESTORE will drop and recreate all databases."
            warn "   Stop all applications before proceeding."
            read -rp "Type 'FULL RESTORE' to proceed: " confirm
            [[ "$confirm" != "FULL RESTORE" ]] && { info "Cancelled."; exit 0; }

            # Restore globals first
            local globals_file
            globals_file=$(find "$LATEST_LINK" -maxdepth 1 -name "globals_*.sql.gz" | head -1)
            if [[ -n "$globals_file" ]]; then
                info "Restoring globals..."
                zcat "$globals_file" | run_as_postgres psql \
                    -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                    --no-password -f - 2>>"$LOG_FILE" || warn "Some globals restore errors (may be harmless)"
            fi

            # Restore full cluster dump
            local full_dump
            full_dump=$(find "$LATEST_LINK" -maxdepth 1 -name "full_cluster_*.sql.gz" | head -1)
            if [[ -n "$full_dump" ]]; then
                info "Restoring full cluster..."
                zcat "$full_dump" | run_as_postgres psql \
                    -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                    --no-password -f - 2>>"$LOG_FILE"
                info "✅ Full cluster restore complete."
            else
                error "Full cluster dump not found."
                exit 1
            fi
            ;;

        2)
            local db_dir="${LATEST_LINK}/per_database"
            echo "Available database dumps:"
            local i=1
            declare -a dump_files
            while IFS= read -r -d '' f; do
                dump_files+=("$f")
                echo "  $i) $(basename "$f")"
                ((i++))
            done < <(find "$db_dir" -type f \( -name "*.dump" -o -name "*.sql.gz" \) -print0 2>/dev/null | sort -z)

            if [[ ${#dump_files[@]} -eq 0 ]]; then
                error "No per-database dumps found."
                exit 1
            fi

            read -rp "Select dump number: " sel
            if [[ "$sel" =~ ^[0-9]+$ ]] && (( sel >= 1 && sel <= ${#dump_files[@]} )); then
                local chosen="${dump_files[$((sel-1))]}"
                local db_name
                db_name=$(basename "$chosen" | sed 's/_[0-9]\{8\}_[0-9]\{6\}.*$//')

                warn "This will restore database: $db_name"
                warn "The database will be DROPPED and recreated."
                read -rp "Type 'CONFIRM' to proceed: " confirm
                [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }

                # Create database if it doesn't exist
                run_as_postgres psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                    --no-password -c "DROP DATABASE IF EXISTS \"${db_name}\";" 2>>"$LOG_FILE" || true
                run_as_postgres psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                    --no-password -c "CREATE DATABASE \"${db_name}\";" 2>>"$LOG_FILE"

                if [[ "$chosen" == *.dump ]]; then
                    # Custom format restore
                    run_as_postgres pg_restore \
                        -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                        --no-password \
                        --dbname="$db_name" \
                        --verbose \
                        --clean \
                        --if-exists \
                        "$chosen" 2>>"$LOG_FILE"
                else
                    # Plain SQL restore
                    zcat "$chosen" | run_as_postgres psql \
                        -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                        --no-password -d "$db_name" -f - 2>>"$LOG_FILE"
                fi
                info "✅ Database '$db_name' restored."
            else
                error "Invalid selection."
                exit 1
            fi
            ;;

        3)
            local globals_file
            globals_file=$(find "$LATEST_LINK" -maxdepth 1 -name "globals_*.sql.gz" | head -1)
            if [[ -z "$globals_file" ]]; then
                error "Globals dump not found."
                exit 1
            fi
            read -rp "Type 'CONFIRM' to restore roles/tablespaces: " confirm
            [[ "$confirm" != "CONFIRM" ]] && { info "Cancelled."; exit 0; }
            zcat "$globals_file" | run_as_postgres psql \
                -h "$PG_HOST" -p "$PG_PORT" -U "$PG_SUPERUSER" \
                --no-password -f - 2>>"$LOG_FILE"
            info "✅ Globals restored."
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
