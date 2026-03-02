#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — PostgreSQL Backup & Restore (Windows)
# =============================================================================
# Performs per-database pg_dump and full-cluster pg_dumpall backups.
# Backs up pg_hba.conf, postgresql.conf, and role definitions.
# Supports PostgreSQL 12+ on Windows Server.
#
# Usage (as Administrator):
#   .\07_Backup-Postgres.ps1 -Action backup
#   .\07_Backup-Postgres.ps1 -Action restore
#   .\07_Backup-Postgres.ps1 -Action verify
#   .\07_Backup-Postgres.ps1 -Action audit
#
# Requirements: PostgreSQL client tools in PATH or set $PGBinPaths
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","verify","audit")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Configuration ─────────────────────────────────────────────────────────────
$Service    = "postgres"
$BackupRoot = "C:\BlueteamBackups\$Service"
$LogFile    = "C:\BlueteamBackups\Logs\${Service}_$(Get-Date -f 'yyyyMMdd').log"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir  = Join-Path $BackupRoot $Timestamp
$LatestFile = Join-Path $BackupRoot "latest.txt"

# PostgreSQL binary paths — script auto-detects common install locations
$PGBinPaths = @(
    "C:\Program Files\PostgreSQL\17\bin"
    "C:\Program Files\PostgreSQL\16\bin"
    "C:\Program Files\PostgreSQL\15\bin"
    "C:\Program Files\PostgreSQL\14\bin"
    "C:\Program Files\PostgreSQL\13\bin"
    "C:\Program Files\PostgreSQL\12\bin"
)

# Connection settings
$PGHost    = $env:PGHOST   ?? "localhost"
$PGPort    = $env:PGPORT   ?? "5432"
$PGUser    = $env:PGUSER   ?? "postgres"

# Password via PGPASSWORD environment variable OR pgpass.conf
# Recommended: Set PGPASSWORD before running, or create pgpass.conf at:
# %APPDATA%\postgresql\pgpass.conf  with line: localhost:5432:*:postgres:yourpassword
# Then: icacls pgpass.conf /inheritance:r /grant %USERNAME%:F
$PGPassword = $env:PGPASSWORD ?? ""

# Dump format: 'custom' (.dump) or 'plain' (.sql)
$DumpFormat = "custom"

$SkipDbs = @("template0")

# Common PostgreSQL data directory locations
$PGDataPaths = @(
    "C:\Program Files\PostgreSQL\17\data"
    "C:\Program Files\PostgreSQL\16\data"
    "C:\Program Files\PostgreSQL\15\data"
    "C:\Program Files\PostgreSQL\14\data"
    "C:\Program Files\PostgreSQL\13\data"
    "C:\Program Files\PostgreSQL\12\data"
    "$env:ProgramData\PostgreSQL"
)

# ── Logging ───────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path (Split-Path $LogFile -Parent), $BackupRoot -Force | Out-Null
function Write-Log {
    param([string]$Level, [string]$Message)
    $entry = "{0} [{1}] {2}" -f (Get-Date -f "yyyy-MM-dd HH:mm:ss"), $Level.PadRight(5), $Message
    Add-Content -Path $LogFile -Value $entry -ErrorAction SilentlyContinue
    $color = switch ($Level.Trim()) {
        "ERROR" {"Red"} "WARN" {"Yellow"} "ALERT" {"Magenta"} default {"Green"}
    }
    Write-Host $entry -ForegroundColor $color
}
function Write-Info  { Write-Log "INFO"  $args[0] }
function Write-Warn  { Write-Log "WARN"  $args[0] }
function Write-Err   { Write-Log "ERROR" $args[0] }
function Write-Alert { Write-Log "ALERT" $args[0] }

# ── Tool Discovery ────────────────────────────────────────────────────────────
function Find-PGBin {
    param([string]$Tool)
    $found = Get-Command $Tool -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    foreach ($path in $PGBinPaths) {
        $full = Join-Path $path "$Tool.exe"
        if (Test-Path $full) { return $full }
    }
    Write-Err "$Tool not found. Add PostgreSQL bin dir to PATH or set `$PGBinPaths."
    return $null
}

$pgdump    = Find-PGBin "pg_dump"
$pgdumpall = Find-PGBin "pg_dumpall"
$pgrestore = Find-PGBin "pg_restore"
$psql      = Find-PGBin "psql"

# ── Connection Helpers ────────────────────────────────────────────────────────
function Get-PGEnv {
    # Set environment variables for pg tools
    $env:PGHOST     = $PGHost
    $env:PGPORT     = $PGPort
    $env:PGUSER     = $PGUser
    if ($PGPassword) { $env:PGPASSWORD = $PGPassword }
}

function Invoke-PSql {
    param([string]$Query, [string]$Database = "postgres")
    Get-PGEnv
    $result = & $psql -h $PGHost -p $PGPort -U $PGUser -d $Database `
        -t -A -c $Query 2>$null
    return $result
}

function Test-PGConnection {
    if (-not $psql) { return $false }
    Get-PGEnv
    $result = & $psql -h $PGHost -p $PGPort -U $PGUser -d "postgres" `
        -c "SELECT 1;" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Info "PostgreSQL connection: OK"
        return $true
    } else {
        Write-Err "Cannot connect to PostgreSQL."
        Write-Err "Set PGPASSWORD environment variable or configure pgpass.conf"
        Write-Err "pgpass.conf location: $env:APPDATA\postgresql\pgpass.conf"
        Write-Err "Error: $($result | Select-Object -Last 3 | Out-String)"
        return $false
    }
}

# Find active PostgreSQL data directory
function Get-PGDataDir {
    # Try from running instance
    try {
        $dataDir = Invoke-PSql "SHOW data_directory;"
        if ($dataDir -and (Test-Path $dataDir.Trim())) {
            return $dataDir.Trim()
        }
    } catch {}
    # Fall back to known paths
    foreach ($path in $PGDataPaths) {
        if (Test-Path (Join-Path $path "postgresql.conf")) {
            return $path
        }
    }
    return $null
}

# ── GZip Helpers ─────────────────────────────────────────────────────────────
function Compress-ToGzip {
    param([string]$InputPath, [switch]$DeleteSource)
    $outputPath = "${InputPath}.gz"
    try {
        $inputStream  = [System.IO.File]::OpenRead($InputPath)
        $outputStream = [System.IO.File]::Create($outputPath)
        $gzStream     = [System.IO.Compression.GZipStream]::new(
            $outputStream, [System.IO.Compression.CompressionMode]::Compress)
        $inputStream.CopyTo($gzStream)
        $gzStream.Close(); $outputStream.Close(); $inputStream.Close()
        if ($DeleteSource) { Remove-Item $InputPath -Force }
    } catch { Write-Warn "Compression error: $_" }
}

function Expand-FromGzip {
    param([string]$InputPath, [string]$OutputPath)
    $inputStream  = [System.IO.File]::OpenRead($InputPath)
    $gzStream     = [System.IO.Compression.GZipStream]::new(
        $inputStream, [System.IO.Compression.CompressionMode]::Decompress)
    $outputStream = [System.IO.File]::Create($OutputPath)
    $gzStream.CopyTo($outputStream)
    $outputStream.Close(); $gzStream.Close(); $inputStream.Close()
}

# ── Backup ────────────────────────────────────────────────────────────────────
function Invoke-Backup {
    Write-Info "=== PostgreSQL Backup: $Timestamp ==="
    if (-not $pgdump -or -not $pgdumpall -or -not $psql) { exit 1 }
    if (-not (Test-PGConnection)) { exit 1 }

    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    icacls $BackupDir /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" 2>$null | Out-Null

    Get-PGEnv

    # 1. Globals dump (roles, tablespaces)
    Write-Info "Dumping cluster globals (roles, tablespaces)..."
    $globalsFile = Join-Path $BackupDir "globals_${Timestamp}.sql"
    & $pgdumpall -h $PGHost -p $PGPort -U $PGUser --globals-only --clean `
        -f $globalsFile 2>>"$LogFile"
    if (Test-Path $globalsFile) {
        Compress-ToGzip -InputPath $globalsFile -DeleteSource
        Write-Info "  Globals: ${globalsFile}.gz"
    }

    # 2. Full cluster dump
    Write-Info "Dumping full cluster (all databases)..."
    $fullDump = Join-Path $BackupDir "full_cluster_${Timestamp}.sql"
    & $pgdumpall -h $PGHost -p $PGPort -U $PGUser --clean --if-exists `
        -f $fullDump 2>>"$LogFile"
    if (Test-Path $fullDump) {
        Compress-ToGzip -InputPath $fullDump -DeleteSource
        Write-Info "  Full cluster: ${fullDump}.gz"
    }

    # 3. Per-database dumps
    Write-Info "Dumping individual databases..."
    $dbDir = Join-Path $BackupDir "per_database"
    New-Item -ItemType Directory -Path $dbDir -Force | Out-Null

    $dbList = Invoke-PSql "SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname;" |
        Where-Object { $_ -notin $SkipDbs -and $_.Trim() -ne "" }

    $dumped = 0
    foreach ($db in $dbList) {
        $db = $db.Trim()
        if (-not $db) { continue }

        Write-Info "  Dumping: $db"

        if ($DumpFormat -eq "custom") {
            $dumpFile = Join-Path $dbDir "${db}_${Timestamp}.dump"
            & $pgdump -h $PGHost -p $PGPort -U $PGUser `
                --format=custom --compress=9 --blobs `
                -f $dumpFile $db 2>>"$LogFile"
        } else {
            $dumpFile = Join-Path $dbDir "${db}_${Timestamp}.sql"
            & $pgdump -h $PGHost -p $PGPort -U $PGUser `
                --format=plain --clean --if-exists --blobs `
                -f $dumpFile $db 2>>"$LogFile"
            if (Test-Path $dumpFile) {
                Compress-ToGzip -InputPath $dumpFile -DeleteSource
                $dumpFile = "${dumpFile}.gz"
            }
        }

        if (Test-Path $dumpFile) {
            Write-Info "    Saved: $(Split-Path $dumpFile -Leaf)"
            $dumped++
        } else {
            Write-Warn "    Dump failed or empty: $db"
        }
    }
    Write-Info "  Per-database dumps: $dumped"

    # 4. Backup PostgreSQL config files
    Write-Info "Backing up PostgreSQL config files..."
    $dataDir = Get-PGDataDir
    if ($dataDir) {
        $configDest = Join-Path $BackupDir "config"
        New-Item -ItemType Directory -Path $configDest -Force | Out-Null
        @("postgresql.conf", "pg_hba.conf", "pg_ident.conf", "postgresql.auto.conf") |
            ForEach-Object {
                $src = Join-Path $dataDir $_
                if (Test-Path $src) {
                    Copy-Item $src $configDest -Force
                    Write-Info "  Config backed up: $_"
                }
            }
    } else {
        Write-Warn "  PostgreSQL data directory not found — config backup skipped"
    }

    # 5. Record PG settings and version
    Invoke-PSql "SELECT version();" | Set-Content (Join-Path $BackupDir "pg_version.txt") -Encoding UTF8
    Invoke-PSql "SELECT name, setting, unit FROM pg_settings ORDER BY name;" |
        Set-Content (Join-Path $BackupDir "pg_settings.txt") -Encoding UTF8

    # 6. Database sizes
    Invoke-PSql "SELECT datname, pg_size_pretty(pg_database_size(datname)) FROM pg_database ORDER BY pg_database_size(datname) DESC;" |
        Set-Content (Join-Path $BackupDir "database_sizes.txt") -Encoding UTF8

    # 7. Hash manifest
    $manifest = @{}
    Get-ChildItem $BackupDir -Recurse -File |
        Where-Object { $_.Name -ne "sha256_manifest.json" } |
        ForEach-Object {
            $manifest[$_.FullName] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    $manifest | ConvertTo-Json -Compress |
        Set-Content (Join-Path $BackupDir "sha256_manifest.json") -Encoding UTF8

    $BackupDir | Set-Content $LatestFile -Encoding UTF8
    Write-Info "PostgreSQL backup complete: $BackupDir"
}

# ── Verify ────────────────────────────────────────────────────────────────────
function Invoke-Verify {
    Write-Info "=== PostgreSQL Dump Verification ==="
    if (-not (Test-Path $LatestFile)) { Write-Err "No backup found."; exit 1 }
    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    $issues = 0

    # Custom format dumps — use pg_restore --list
    Get-ChildItem (Join-Path $latestBackup "per_database") -Filter "*.dump" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Info "  Verifying (custom): $($_.Name)"
            Get-PGEnv
            $tocOutput = & $pgrestore --list $_.FullName 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Info "    pg_restore TOC read: OK"
            } else {
                Write-Warn "    pg_restore failed to read TOC — file may be corrupt"
                $issues++
            }
        }

    # Plain SQL dumps
    Get-ChildItem (Join-Path $latestBackup "per_database") -Filter "*.sql.gz" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Write-Info "  Verifying (plain SQL): $($_.Name)"
            $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
            try {
                Expand-FromGzip $_.FullName $tmpSql
                $header = Get-Content $tmpSql -TotalCount 5
                if ($header -match "PostgreSQL database dump") {
                    Write-Info "    Header: OK"
                } else {
                    Write-Warn "    Unexpected header — possible corruption"
                    $issues++
                }
            } finally {
                Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue
            }
        }

    if ($issues -eq 0) { Write-Info "All PostgreSQL dumps verified." }
    else { Write-Warn "$issues verification issue(s) found." }
}

# ── Audit ─────────────────────────────────────────────────────────────────────
function Invoke-Audit {
    Write-Info "=== PostgreSQL Security Audit ==="
    if (-not (Test-PGConnection)) { return }
    $issues = 0

    # Superuser accounts
    $superusers = Invoke-PSql "SELECT rolname FROM pg_roles WHERE rolsuper = true AND rolname <> 'postgres';"
    if ($superusers -and $superusers.Trim()) {
        Write-Alert "Unexpected superuser accounts:"
        $superusers | ForEach-Object { if ($_.Trim()) { Write-Alert "  $_" } }
        $issues++
    } else { Write-Info "  Superusers: only 'postgres' (OK)" }

    # Login roles with no password
    $noPass = Invoke-PSql "SELECT rolname FROM pg_authid WHERE rolcanlogin = true AND rolpassword IS NULL AND rolname <> 'postgres';"
    if ($noPass -and $noPass.Trim()) {
        Write-Alert "Login roles with NO password:"
        $noPass | ForEach-Object { if ($_.Trim()) { Write-Alert "  $_" } }
        $issues++
    } else { Write-Info "  All login roles have passwords (OK)" }

    # Trust authentication in pg_hba.conf
    $dataDir = Get-PGDataDir
    if ($dataDir) {
        $hbaFile = Join-Path $dataDir "pg_hba.conf"
        if (Test-Path $hbaFile) {
            $trustLines = Get-Content $hbaFile |
                Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\btrust\b' }
            if ($trustLines) {
                Write-Alert "pg_hba.conf has 'trust' auth entries (no password required):"
                $trustLines | ForEach-Object { Write-Alert "  $_" }
                $issues++
            } else { Write-Info "  No 'trust' auth entries: OK" }

            # Check for md5 (prefer scram-sha-256)
            if (Select-String -Path $hbaFile -Pattern '\bmd5\b' -Quiet) {
                Write-Warn "  pg_hba.conf uses 'md5' — consider upgrading to 'scram-sha-256'"
            }
        }
    }

    # listen_addresses
    $listen = Invoke-PSql "SHOW listen_addresses;"
    if ($listen -eq "*") {
        Write-Alert "listen_addresses='*' — PostgreSQL accessible on all interfaces"
        $issues++
    } else { Write-Info "  listen_addresses: $($listen.Trim())" }

    # SSL status
    $ssl = Invoke-PSql "SHOW ssl;"
    if ($ssl.Trim() -ne "on") {
        Write-Warn "  SSL is OFF — connections are unencrypted"
        $issues++
    } else { Write-Info "  SSL: on (OK)" }

    # PUBLIC write grants
    $publicGrants = Invoke-PSql "SELECT table_schema, table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee = 'PUBLIC' AND privilege_type IN ('INSERT','UPDATE','DELETE') LIMIT 10;"
    if ($publicGrants -and $publicGrants.Trim()) {
        Write-Alert "Tables with PUBLIC write grants:"
        $publicGrants | ForEach-Object { if ($_.Trim()) { Write-Alert "  $_" } }
        $issues++
    } else { Write-Info "  No PUBLIC write grants: OK" }

    if ($issues -eq 0) { Write-Info "No critical PostgreSQL security issues detected." }
    else { Write-Warn "$issues issue(s) found. Review above." }
}

# ── Restore ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Info "=== PostgreSQL Restore ==="
    if (-not (Test-Path $LatestFile)) { Write-Err "No backup found."; exit 1 }
    if (-not (Test-PGConnection)) { exit 1 }

    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    Get-PGEnv

    Write-Host "`nRestore options:" -ForegroundColor Cyan
    Write-Host "  1) Full cluster restore (globals + all databases)"
    Write-Host "  2) Single database restore"
    Write-Host "  3) Restore globals (roles) only"
    Write-Host "  4) Restore PostgreSQL config files only"
    Write-Host "  0) Cancel"
    $choice = Read-Host "Choice"

    switch ($choice) {
        "1" {
            Write-Host "WARNING: FULL RESTORE will overwrite ALL databases." -ForegroundColor Red
            $confirm = Read-Host "Type 'FULL RESTORE' to proceed"
            if ($confirm -ne "FULL RESTORE") { Write-Info "Cancelled."; return }

            # Globals first
            $globalsGz = Get-ChildItem $latestBackup -Filter "globals_*.sql.gz" | Select-Object -First 1
            if ($globalsGz) {
                $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
                try {
                    Expand-FromGzip $globalsGz.FullName $tmpSql
                    & $psql -h $PGHost -p $PGPort -U $PGUser -d postgres -f $tmpSql 2>>"$LogFile"
                    Write-Info "  Globals restored."
                } finally { Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue }
            }

            # Full cluster
            $fullGz = Get-ChildItem $latestBackup -Filter "full_cluster_*.sql.gz" | Select-Object -First 1
            if ($fullGz) {
                $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
                try {
                    Expand-FromGzip $fullGz.FullName $tmpSql
                    & $psql -h $PGHost -p $PGPort -U $PGUser -d postgres -f $tmpSql 2>>"$LogFile"
                    Write-Info "Full cluster restore complete."
                } finally { Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue }
            } else {
                Write-Err "Full cluster dump not found."
            }
        }
        "2" {
            $dumps = Get-ChildItem (Join-Path $latestBackup "per_database") |
                Where-Object { $_.Extension -in @(".dump",".gz") } | Sort-Object Name
            for ($i = 0; $i -lt $dumps.Count; $i++) {
                Write-Host "  $($i+1)) $($dumps[$i].Name)"
            }
            $sel = Read-Host "Select number"
            if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $dumps.Count) {
                $chosen = $dumps[[int]$sel - 1]
                $dbName = $chosen.Name -replace '_\d{8}_\d{6}\.(dump|sql\.gz)$',''
                $confirm = Read-Host "Type 'CONFIRM' to restore '$dbName' (will DROP and recreate)"
                if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; return }

                # Drop and recreate database
                & $psql -h $PGHost -p $PGPort -U $PGUser -d postgres `
                    -c "DROP DATABASE IF EXISTS `"$dbName`";" 2>>"$LogFile"
                & $psql -h $PGHost -p $PGPort -U $PGUser -d postgres `
                    -c "CREATE DATABASE `"$dbName`";" 2>>"$LogFile"

                if ($chosen.Extension -eq ".dump") {
                    & $pgrestore -h $PGHost -p $PGPort -U $PGUser `
                        -d $dbName --verbose --clean --if-exists $chosen.FullName 2>>"$LogFile"
                } else {
                    $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
                    try {
                        Expand-FromGzip $chosen.FullName $tmpSql
                        & $psql -h $PGHost -p $PGPort -U $PGUser -d $dbName -f $tmpSql 2>>"$LogFile"
                    } finally { Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue }
                }
                Write-Info "Database '$dbName' restored."
            }
        }
        "3" {
            $globalsGz = Get-ChildItem $latestBackup -Filter "globals_*.sql.gz" | Select-Object -First 1
            if (-not $globalsGz) { Write-Err "Globals file not found."; return }
            $confirm = Read-Host "Type 'CONFIRM' to restore globals"
            if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; return }
            $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
            try {
                Expand-FromGzip $globalsGz.FullName $tmpSql
                & $psql -h $PGHost -p $PGPort -U $PGUser -d postgres -f $tmpSql 2>>"$LogFile"
                Write-Info "Globals restored."
            } finally { Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue }
        }
        "4" {
            $configBackup = Join-Path $latestBackup "config"
            $dataDir = Get-PGDataDir
            if (-not $dataDir) { Write-Err "PostgreSQL data directory not found."; return }
            if (-not (Test-Path $configBackup)) { Write-Err "Config backup not found."; return }
            $confirm = Read-Host "Type 'CONFIRM' to restore config files to $dataDir"
            if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; return }

            # Stop PostgreSQL service
            $pgSvc = Get-Service -Name "postgresql*" | Select-Object -First 1
            if ($pgSvc) {
                Stop-Service $pgSvc.Name -Force
                Write-Info "  Stopped: $($pgSvc.Name)"
            }

            @("postgresql.conf", "pg_hba.conf", "pg_ident.conf", "postgresql.auto.conf") |
                ForEach-Object {
                    $src = Join-Path $configBackup $_
                    $dst = Join-Path $dataDir $_
                    if (Test-Path $src) {
                        if (Test-Path $dst) {
                            Copy-Item $dst "${dst}.prerestore_${Timestamp}" -Force
                        }
                        Copy-Item $src $dst -Force
                        Write-Info "  Restored: $_"
                    }
                }

            # Restart PostgreSQL
            if ($pgSvc) {
                Start-Service $pgSvc.Name
                Write-Info "  Started: $($pgSvc.Name)"
            }
            Write-Info "Config restore complete."
        }
        "0" { return }
        default { Write-Err "Invalid choice." }
    }
}

# ── Entry Point ───────────────────────────────────────────────────────────────
switch ($Action) {
    "backup"  { Invoke-Backup }
    "restore" { Invoke-Restore }
    "verify"  { Invoke-Verify }
    "audit"   { Invoke-Audit }
}
