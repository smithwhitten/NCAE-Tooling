#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — Windows Critical Binaries Backup & Restore
# =============================================================================
# Backs up critical Windows system binaries that are common attack targets:
# cmd.exe, powershell.exe, net.exe, sc.exe, etc. with hash verification.
#
# Usage:
#   .\01_Backup-Binaries.ps1 -Action backup
#   .\01_Backup-Binaries.ps1 -Action restore
#   .\01_Backup-Binaries.ps1 -Action verify
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","verify")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"  # Don't stop on individual file errors

# ── Configuration ─────────────────────────────────────────────────────────────
$Service    = "binaries"
$BackupRoot = "C:\BlueteamBackups\$Service"
$LogFile    = "C:\BlueteamBackups\Logs\${Service}_$(Get-Date -f 'yyyyMMdd').log"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir  = Join-Path $BackupRoot $Timestamp
$LatestFile = Join-Path $BackupRoot "latest.txt"

# System32 and SysWOW64 critical binaries
$CriticalBinaries = @(
    "$env:SystemRoot\System32\cmd.exe"
    "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    "$env:SystemRoot\System32\net.exe"
    "$env:SystemRoot\System32\net1.exe"
    "$env:SystemRoot\System32\sc.exe"
    "$env:SystemRoot\System32\reg.exe"
    "$env:SystemRoot\System32\regedit.exe"
    "$env:SystemRoot\System32\taskkill.exe"
    "$env:SystemRoot\System32\tasklist.exe"
    "$env:SystemRoot\System32\netstat.exe"
    "$env:SystemRoot\System32\ipconfig.exe"
    "$env:SystemRoot\System32\whoami.exe"
    "$env:SystemRoot\System32\wscript.exe"
    "$env:SystemRoot\System32\cscript.exe"
    "$env:SystemRoot\System32\mshta.exe"
    "$env:SystemRoot\System32\certutil.exe"
    "$env:SystemRoot\System32\bitsadmin.exe"
    "$env:SystemRoot\System32\schtasks.exe"
    "$env:SystemRoot\System32\at.exe"
    "$env:SystemRoot\System32\runas.exe"
    "$env:SystemRoot\System32\icacls.exe"
    "$env:SystemRoot\System32\attrib.exe"
    "$env:SystemRoot\System32\ssh.exe"
    "$env:SystemRoot\System32\OpenSSH\ssh.exe"
    "$env:SystemRoot\System32\OpenSSH\sshd.exe"
    "$env:SystemRoot\System32\ntoskrnl.exe"
    "$env:SystemRoot\System32\lsass.exe"
    "$env:SystemRoot\System32\services.exe"
    "$env:SystemRoot\System32\wininit.exe"
)

# ── Logging ───────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path (Split-Path $LogFile -Parent) -Force | Out-Null
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

# ── Backup ────────────────────────────────────────────────────────────────────
function Invoke-Backup {
    Write-Info "=== Binary Backup: $Timestamp ==="
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

    $hashManifest = @{}
    $backedUp = 0; $skipped = 0

    foreach ($bin in $CriticalBinaries) {
        if (Test-Path $bin) {
            # Preserve directory structure
            $relPath = $bin -replace [regex]::Escape($env:SystemRoot), "SystemRoot"
            $destPath = Join-Path $BackupDir $relPath
            New-Item -ItemType Directory -Path (Split-Path $destPath -Parent) -Force | Out-Null
            Copy-Item -Path $bin -Destination $destPath -Force
            # Compute hash
            $hash = (Get-FileHash -Path $bin -Algorithm SHA256).Hash
            $hashManifest[$bin] = $hash
            Write-Info "  Backed up: $bin"
            $backedUp++
        } else {
            Write-Warn "  Not found (skipped): $bin"
            $skipped++
        }
    }

    # Save hash manifest as JSON
    $hashManifest | ConvertTo-Json -Depth 3 |
        Set-Content -Path (Join-Path $BackupDir "sha256_manifest.json") -Encoding UTF8
    Set-ItemProperty -Path (Join-Path $BackupDir "sha256_manifest.json") -Name IsReadOnly -Value $true

    # Record latest backup path
    $BackupDir | Set-Content -Path $LatestFile -Encoding UTF8

    Write-Info "Backed up: $backedUp | Skipped: $skipped"
    Write-Info "Location: $BackupDir"
}

# ── Verify ────────────────────────────────────────────────────────────────────
function Invoke-Verify {
    Write-Info "=== Binary Integrity Verification ==="
    if (-not (Test-Path $LatestFile)) {
        Write-Err "No latest backup found. Run backup first."
        exit 1
    }
    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    $manifestPath = Join-Path $latestBackup "sha256_manifest.json"

    if (-not (Test-Path $manifestPath)) {
        Write-Err "Hash manifest not found: $manifestPath"
        exit 1
    }

    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
    $mismatch = 0

    $manifest.PSObject.Properties | ForEach-Object {
        $livePath     = $_.Name
        $expectedHash = $_.Value
        if (Test-Path $livePath) {
            $actualHash = (Get-FileHash -Path $livePath -Algorithm SHA256).Hash
            if ($expectedHash -ne $actualHash) {
                Write-Log "ALERT" "HASH MISMATCH: $livePath"
                Write-Log "ALERT" "  Expected: $expectedHash"
                Write-Log "ALERT" "  Actual:   $actualHash"
                $mismatch++
            } else {
                Write-Info "  OK: $livePath"
            }
        } else {
            Write-Warn "  MISSING: $livePath"
            $mismatch++
        }
    }

    if ($mismatch -eq 0) {
        Write-Info "All binaries match backup hashes. No tampering detected."
    } else {
        Write-Err "$mismatch binary/binaries differ. Investigate immediately."
        exit 2
    }
}

# ── Restore ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Info "=== Binary Restore ==="
    if (-not (Test-Path $LatestFile)) {
        Write-Err "No backup found. Run backup first."
        exit 1
    }

    # List available backups
    $snapshots = Get-ChildItem $BackupRoot -Directory | Sort-Object Name -Descending
    Write-Host "`nAvailable backups:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $snapshots.Count; $i++) {
        Write-Host "  $($i+1)) $($snapshots[$i].Name)"
    }
    $sel = Read-Host "Select backup number (or 'latest')"

    $chosenBackup = if ($sel -eq "latest") {
        Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    } elseif ($sel -match '^\d+$' -and [int]$sel -ge 1 -and [int]$sel -le $snapshots.Count) {
        $snapshots[[int]$sel - 1].FullName
    } else {
        Write-Err "Invalid selection."
        exit 1
    }

    Write-Host "`nWARNING: This will overwrite live binaries with backup from: $(Split-Path $chosenBackup -Leaf)" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'CONFIRM' to proceed"
    if ($confirm -ne "CONFIRM") { Write-Info "Restore cancelled."; exit 0 }

    $manifestPath = Join-Path $chosenBackup "sha256_manifest.json"
    $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json

    $restored = 0
    $manifest.PSObject.Properties | ForEach-Object {
        $livePath = $_.Name
        $relPath  = $livePath -replace [regex]::Escape($env:SystemRoot), "SystemRoot"
        $backupFilePath = Join-Path $chosenBackup $relPath

        if (Test-Path $backupFilePath) {
            # Save pre-restore copy
            if (Test-Path $livePath) {
                $preRestore = "${livePath}.blueteam_prerestore_${Timestamp}"
                Copy-Item -Path $livePath -Destination $preRestore -Force -ErrorAction SilentlyContinue
            }
            Copy-Item -Path $backupFilePath -Destination $livePath -Force
            Write-Info "  Restored: $livePath"
            $restored++
        } else {
            Write-Warn "  Backup file not found: $backupFilePath"
        }
    }

    Write-Info "Restore complete. $restored binaries restored."
    Write-Warn "Run with -Action verify to confirm hashes match backup."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null

switch ($Action) {
    "backup"  { Invoke-Backup }
    "restore" { Invoke-Restore }
    "verify"  { Invoke-Verify }
}
