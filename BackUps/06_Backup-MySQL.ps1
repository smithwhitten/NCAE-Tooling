#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — MySQL / MariaDB Backup & Restore (Windows)
# =============================================================================
# Performs per-database and full-instance mysqldump backups.
# Supports MySQL 5.7/8.x and MariaDB 10.x on Windows Server.
# Credentials stored securely via .mylogin.cnf or options file.
#
# Usage (as Administrator):
#   .\06_Backup-MySQL.ps1 -Action backup
#   .\06_Backup-MySQL.ps1 -Action restore
#   .\06_Backup-MySQL.ps1 -Action verify
#   .\06_Backup-MySQL.ps1 -Action audit
#
# Requirements: MySQL client tools in PATH or set $MySQLBinPath
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","verify","audit")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Configuration ─────────────────────────────────────────────────────────────
$Service    = "mysql"
$BackupRoot = "C:\BlueteamBackups\$Service"
$LogFile    = "C:\BlueteamBackups\Logs\${Service}_$(Get-Date -f 'yyyyMMdd').log"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir  = Join-Path $BackupRoot $Timestamp
$LatestFile = Join-Path $BackupRoot "latest.txt"

# MySQL binary paths — script auto-detects common install locations
$MySQLBinPaths = @(
    "C:\Program Files\MySQL\MySQL Server 8.0\bin"
    "C:\Program Files\MySQL\MySQL Server 5.7\bin"
    "C:\Program Files\MariaDB 10.6\bin"
    "C:\Program Files\MariaDB 10.11\bin"
    "C:\xampp\mysql\bin"
    "C:\wamp64\bin\mysql\mysql8.0\bin"
)

# Connection settings — override with environment variables if preferred
$MySQLHost = $env:MYSQL_HOST ?? "localhost"
$MySQLPort = $env:MYSQL_PORT ?? "3306"

# Credentials options file path — RECOMMENDED over plaintext password
# Format: [client]\nuser=root\npassword=yourpassword
$MySQLOptionsFile = "C:\ProgramData\blueteam\mysql_backup.cnf"

# Databases to always skip
$SkipDbs = @("information_schema", "performance_schema", "sys")

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
function Find-MySQLBin {
    param([string]$Tool)

    # Check PATH first
    $found = Get-Command $Tool -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }

    # Check known install paths
    foreach ($path in $MySQLBinPaths) {
        $full = Join-Path $path "$Tool.exe"
        if (Test-Path $full) { return $full }
    }

    Write-Err "$Tool not found. Add MySQL bin directory to PATH or set `$MySQLBinPaths."
    return $null
}

$mysqldump = Find-MySQLBin "mysqldump"
$mysql     = Find-MySQLBin "mysql"

# ── Connection Arguments ──────────────────────────────────────────────────────
function Get-MySQLArgs {
    $args = [System.Collections.ArrayList]@()
    if (Test-Path $MySQLOptionsFile) {
        $args.Add("--defaults-extra-file=`"$MySQLOptionsFile`"") | Out-Null
        Write-Info "  Using credentials from: $MySQLOptionsFile"
    } else {
        Write-Warn "  No credentials file at $MySQLOptionsFile"
        Write-Warn "  Create it with: [client]`nuser=root`npassword=yourpassword"
        Write-Warn "  Then restrict permissions: icacls $MySQLOptionsFile /inheritance:r /grant Administrators:F"
    }
    $args.Add("-h $MySQLHost") | Out-Null
    $args.Add("-P $MySQLPort") | Out-Null
    return $args -join " "
}

function Test-MySQLConnection {
    if (-not $mysql) { return $false }
    $connArgs = Get-MySQLArgs
    $result = & cmd /c "`"$mysql`" $connArgs -e `"SELECT 1;`" 2>&1"
    if ($LASTEXITCODE -eq 0) {
        Write-Info "MySQL connection: OK"
        return $true
    } else {
        Write-Err "MySQL connection failed. Check credentials in: $MySQLOptionsFile"
        Write-Err "Error: $result"
        return $false
    }
}

function Invoke-MySQL {
    param([string]$Query)
    $connArgs = Get-MySQLArgs
    $result = & cmd /c "`"$mysql`" $connArgs -N -e `"$Query`" 2>&1"
    return $result
}

# ── Backup ────────────────────────────────────────────────────────────────────
function Invoke-Backup {
    Write-Info "=== MySQL Backup: $Timestamp ==="
    if (-not $mysqldump -or -not $mysql) { exit 1 }
    if (-not (Test-MySQLConnection)) { exit 1 }

    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    # Restrict backup dir to Administrators only
    icacls $BackupDir /inheritance:r /grant "Administrators:(OI)(CI)F" /grant "SYSTEM:(OI)(CI)F" 2>$null | Out-Null

    $connArgs = Get-MySQLArgs

    # 1. Full instance dump
    Write-Info "Dumping full instance (all databases)..."
    $fullDump = Join-Path $BackupDir "full_instance_${Timestamp}.sql"
    $dumpArgs = "$connArgs --all-databases --single-transaction --flush-logs " +
                "--master-data=2 --routines --triggers --events " +
                "--add-drop-database --result-file=`"$fullDump`""

    & cmd /c "`"$mysqldump`" $dumpArgs 2>>`"$LogFile`""
    if ($LASTEXITCODE -eq 0 -and (Test-Path $fullDump)) {
        # Compress with built-in .NET GZip
        Compress-ToGzip -InputPath $fullDump -DeleteSource
        Write-Info "  Full dump: ${fullDump}.gz"
    } else {
        Write-Warn "  Full dump may have errors — check $LogFile"
    }

    # 2. Per-database dumps
    Write-Info "Dumping individual databases..."
    $dbDir = Join-Path $BackupDir "per_database"
    New-Item -ItemType Directory -Path $dbDir -Force | Out-Null

    $dbList = Invoke-MySQL "SHOW DATABASES;" | Where-Object { $_ -notin $SkipDbs -and $_ -ne "" }
    $dumped = 0

    foreach ($db in $dbList) {
        $db = $db.Trim()
        if (-not $db.Trim()) { continue }

        Write-Info "  Dumping: $db"
        $dumpFile = Join-Path $dbDir "${db}_${Timestamp}.sql"
        $perDbArgs = "$connArgs --single-transaction --routines --triggers --events " +
                     "--add-drop-table --add-drop-database " +
                     "--databases `"$db`" --result-file=`"$dumpFile`""

        & cmd /c "`"$mysqldump`" $perDbArgs 2>>`"$LogFile`""
        if ($LASTEXITCODE -eq 0 -and (Test-Path $dumpFile)) {
            Compress-ToGzip -InputPath $dumpFile -DeleteSource
            $dumped++
        } else {
            Write-Warn "    Dump may have errors for: $db"
        }
    }
    Write-Info "  Per-database dumps: $dumped"

    # 3. Export user grants
    Write-Info "Exporting user accounts and grants..."
    $grantsFile = Join-Path $BackupDir "mysql_users_grants_${Timestamp}.sql"
    $grantQueries = Invoke-MySQL "SELECT CONCAT('SHOW GRANTS FOR \`'',user,'\`'@\`'',host,'\`';') FROM mysql.user WHERE user != '';"

    $grantOutput = foreach ($q in $grantQueries) {
        if ($q.Trim()) {
            Invoke-MySQL $q.Trim()
            ""
        }
    }
    $grantOutput | Set-Content $grantsFile -Encoding UTF8
    Compress-ToGzip -InputPath $grantsFile -DeleteSource
    Write-Info "  Grants exported: ${grantsFile}.gz"

    # 4. Backup MySQL config files (my.ini)
    $myCnfPaths = @(
        "C:\ProgramData\MySQL\MySQL Server 8.0\my.ini"
        "C:\ProgramData\MySQL\MySQL Server 5.7\my.ini"
        "$env:SystemRoot\my.ini"
        "C:\my.ini"
    )
    foreach ($cnf in $myCnfPaths) {
        if (Test-Path $cnf) {
            $destCnf = Join-Path $BackupDir "config\$(Split-Path $cnf -Parent | Split-Path -Leaf)"
            New-Item -ItemType Directory -Path $destCnf -Force | Out-Null
            Copy-Item $cnf $destCnf -Force
            Write-Info "  MySQL config backed up: $cnf"
        }
    }

    # 5. Hash manifest
    Write-Info "Generating SHA-256 manifest..."
    $manifest = @{}
    Get-ChildItem $BackupDir -Recurse -File |
        Where-Object { $_.Name -ne "sha256_manifest.json" } |
        ForEach-Object {
            $manifest[$_.FullName] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    $manifest | ConvertTo-Json -Compress |
        Set-Content (Join-Path $BackupDir "sha256_manifest.json") -Encoding UTF8

    $BackupDir | Set-Content $LatestFile -Encoding UTF8
    Write-Info "MySQL backup complete: $BackupDir"
}

# ── GZip Helper ───────────────────────────────────────────────────────────────
function Compress-ToGzip {
    param([string]$InputPath, [switch]$DeleteSource)
    $outputPath = "${InputPath}.gz"
    try {
        $inputStream  = [System.IO.File]::OpenRead($InputPath)
        $outputStream = [System.IO.File]::Create($outputPath)
        $gzStream     = [System.IO.Compression.GZipStream]::new(
            $outputStream, [System.IO.Compression.CompressionMode]::Compress)
        $inputStream.CopyTo($gzStream)
        $gzStream.Close()
        $outputStream.Close()
        $inputStream.Close()
        if ($DeleteSource) { Remove-Item $InputPath -Force }
    } catch {
        Write-Warn "Compression failed for ${InputPath}: $_"
    }
}

function Expand-FromGzip {
    param([string]$InputPath, [string]$OutputPath)
    try {
        $inputStream  = [System.IO.File]::OpenRead($InputPath)
        $gzStream     = [System.IO.Compression.GZipStream]::new(
            $inputStream, [System.IO.Compression.CompressionMode]::Decompress)
        $outputStream = [System.IO.File]::Create($OutputPath)
        $gzStream.CopyTo($outputStream)
        $outputStream.Close()
        $gzStream.Close()
        $inputStream.Close()
    } catch {
        Write-Err "Decompression failed for ${InputPath}: $_"
        throw
    }
}

# ── Verify ────────────────────────────────────────────────────────────────────
function Invoke-Verify {
    Write-Info "=== MySQL Dump Verification ==="
    if (-not (Test-Path $LatestFile)) { Write-Err "No backup found."; exit 1 }
    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }

    $issues = 0
    Get-ChildItem $latestBackup -Recurse -Filter "*.sql.gz" | ForEach-Object {
        Write-Info "  Checking: $($_.Name)"
        $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
        try {
            Expand-FromGzip -InputPath $_.FullName -OutputPath $tmpSql
            $header = Get-Content $tmpSql -TotalCount 5 -ErrorAction SilentlyContinue
            if ($header -match "MySQL dump|MariaDB dump") {
                Write-Info "    Header: OK"
            } else {
                Write-Warn "    Unexpected header — possible corruption"
                $issues++
            }
            $tail = Get-Content $tmpSql -Tail 5 -ErrorAction SilentlyContinue
            if ($tail -match "Dump completed") {
                Write-Info "    Completion marker: OK"
            } else {
                Write-Warn "    Completion marker missing — dump may be truncated"
                $issues++
            }
        } finally {
            Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue
        }
    }

    if ($issues -eq 0) {
        Write-Info "All MySQL dumps verified successfully."
    } else {
        Write-Warn "$issues issue(s) found in dump verification."
    }
}

# ── Audit ─────────────────────────────────────────────────────────────────────
function Invoke-Audit {
    Write-Info "=== MySQL Security Audit ==="
    if (-not (Test-MySQLConnection)) { return }
    $issues = 0

    # Anonymous users
    $anon = Invoke-MySQL "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='';"
    if ($anon) {
        Write-Alert "Anonymous MySQL user(s) found:"
        $anon | ForEach-Object { Write-Alert "  $_" }
        $issues++
    } else { Write-Info "  Anonymous users: none (OK)" }

    # Empty passwords
    $emptyPass = Invoke-MySQL "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND user != '';" 2>$null
    if (-not $emptyPass) {
        $emptyPass = Invoke-MySQL "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Password='' AND user != '';" 2>$null
    }
    if ($emptyPass) {
        Write-Alert "Users with EMPTY passwords:"
        $emptyPass | ForEach-Object { Write-Alert "  $_" }
        $issues++
    } else { Write-Info "  Empty passwords: none (OK)" }

    # Root from any host
    $rootAny = Invoke-MySQL "SELECT host FROM mysql.user WHERE user='root' AND host='%';"
    if ($rootAny) {
        Write-Alert "root accessible from ANY host (%) — restrict to localhost"
        $issues++
    } else { Write-Info "  root@% restriction: OK" }

    # FILE privilege
    $filePriv = Invoke-MySQL "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE File_priv='Y' AND user NOT IN ('root');"
    if ($filePriv) {
        Write-Alert "Non-root users with FILE privilege:"
        $filePriv | ForEach-Object { Write-Alert "  $_" }
        $issues++
    }

    # Bind address
    $bindAddr = Invoke-MySQL "SHOW VARIABLES LIKE 'bind_address';" | ForEach-Object { ($_ -split '\s+')[1] }
    if ($bindAddr -eq "0.0.0.0" -or $bindAddr -eq "*") {
        Write-Alert "MySQL bound to all interfaces (bind-address=$bindAddr)"
        $issues++
    } else { Write-Info "  bind-address: $bindAddr" }

    if ($issues -eq 0) { Write-Info "No critical MySQL issues detected." }
    else { Write-Warn "$issues issue(s) found. Review above." }
}

# ── Restore ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Info "=== MySQL Restore ==="
    if (-not (Test-Path $LatestFile)) { Write-Err "No backup found."; exit 1 }
    if (-not (Test-MySQLConnection)) { exit 1 }

    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    $connArgs = Get-MySQLArgs

    Write-Host "`nRestore options:" -ForegroundColor Cyan
    Write-Host "  1) Full instance restore"
    Write-Host "  2) Single database restore"
    Write-Host "  3) Users/grants only"
    Write-Host "  0) Cancel"
    $choice = Read-Host "Choice"

    switch ($choice) {
        "1" {
            Write-Host "WARNING: Full restore will overwrite ALL databases." -ForegroundColor Red
            $confirm = Read-Host "Type 'FULL RESTORE' to proceed"
            if ($confirm -ne "FULL RESTORE") { Write-Info "Cancelled."; return }

            $fullDump = Get-ChildItem $latestBackup -Filter "full_instance_*.sql.gz" |
                Select-Object -First 1
            if (-not $fullDump) { Write-Err "Full dump not found."; return }

            $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
            try {
                Expand-FromGzip $fullDump.FullName $tmpSql
                & cmd /c "`"$mysql`" $connArgs < `"$tmpSql`" 2>>`"$LogFile`""
                Write-Info "Full restore complete."
            } finally {
                Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue
            }
        }
        "2" {
            $dumps = Get-ChildItem (Join-Path $latestBackup "per_database") -Filter "*.sql.gz" |
                Sort-Object Name
            for ($i = 0; $i -lt $dumps.Count; $i++) {
                Write-Host "  $($i+1)) $($dumps[$i].Name)"
            }
            $sel = Read-Host "Select number"
            if ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $dumps.Count) {
                $chosen = $dumps[[int]$sel - 1]
                $dbName = $chosen.Name -replace '_\d{8}_\d{6}\.sql\.gz$',''
                $confirm = Read-Host "Type 'CONFIRM' to restore '$dbName'"
                if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; return }

                $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
                try {
                    Expand-FromGzip $chosen.FullName $tmpSql
                    & cmd /c "`"$mysql`" $connArgs < `"$tmpSql`" 2>>`"$LogFile`""
                    Write-Info "Database '$dbName' restored."
                } finally {
                    Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue
                }
            }
        }
        "3" {
            $grantsFile = Get-ChildItem $latestBackup -Filter "mysql_users_grants_*.sql.gz" |
                Select-Object -First 1
            if (-not $grantsFile) { Write-Err "Grants file not found."; return }
            $confirm = Read-Host "Type 'CONFIRM' to restore users/grants"
            if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; return }

            $tmpSql = [System.IO.Path]::GetTempFileName() + ".sql"
            try {
                Expand-FromGzip $grantsFile.FullName $tmpSql
                & cmd /c "`"$mysql`" $connArgs < `"$tmpSql`" 2>>`"$LogFile`""
                & cmd /c "`"$mysql`" $connArgs -e `"FLUSH PRIVILEGES;`" 2>>`"$LogFile`""
                Write-Info "Users/grants restored."
            } finally {
                Remove-Item $tmpSql -Force -ErrorAction SilentlyContinue
            }
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
