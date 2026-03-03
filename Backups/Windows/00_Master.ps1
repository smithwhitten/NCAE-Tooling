#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — Windows Master Backup & Restore Orchestrator
# =============================================================================
# Usage (run as Administrator in PowerShell):
#   .\00_Master.ps1 -Action backup
#   .\00_Master.ps1 -Action restore
#   .\00_Master.ps1 -Action status
#
# Requirements: PowerShell 5.1+ or 7.x (Windows), Windows Server 2016/2019/2022 or Win10/11
#
# Scripts managed:
#   01_Backup-Binaries.ps1    — System32 critical binaries
#   02_Backup-SSH.ps1         — OpenSSH Server config & keys
#   03_Backup-SMB.ps1         — SMB shares & ACLs
#   04_Backup-WebServer.ps1   — IIS configuration
#   05_Backup-WebContent.ps1  — IIS web root content
#   06_Backup-MySQL.ps1       — MySQL / MariaDB databases
#   07_Backup-Postgres.ps1    — PostgreSQL databases
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","status")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Global Configuration ──────────────────────────────────────────────────────
$Global:BackupRoot = "C:\BlueteamBackups"
$Global:LogFile    = "C:\BlueteamBackups\Logs\master_$(Get-Date -f 'yyyyMMdd').log"
$Global:Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ScriptDir         = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Logging ──────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Level, [string]$Message)
    $entry = "{0} [{1}] {2}" -f (Get-Date -f "yyyy-MM-dd HH:mm:ss"), $Level.PadRight(5), $Message
    Add-Content -Path $Global:LogFile -Value $entry -ErrorAction SilentlyContinue
    switch ($Level.Trim()) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "ALERT" { Write-Host $entry -ForegroundColor Magenta }
        default { Write-Host $entry -ForegroundColor Green }
    }
}
function Write-Info    { Write-Log "INFO"  $args[0] }
function Write-Warn    { Write-Log "WARN"  $args[0] }
function Write-ErrLog  { Write-Log "ERROR" $args[0] }

# ── Preflight ─────────────────────────────────────────────────────────────────
function Initialize-Environment {
    $logDir = Split-Path $Global:LogFile -Parent
    New-Item -ItemType Directory -Path $Global:BackupRoot, $logDir -Force | Out-Null
    $acl = Get-Acl $Global:BackupRoot
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"
    )
    $acl.AddAccessRule($adminRule)
    Set-Acl $Global:BackupRoot $acl -ErrorAction SilentlyContinue

    # Report PS version — scripts support 5.1+ and 7.x on Windows
    $psVer = $PSVersionTable.PSVersion
    Write-Info "PowerShell: $($psVer.Major).$($psVer.Minor) ($($PSVersionTable.PSEdition))"
    if ($psVer.Major -lt 5 -or ($psVer.Major -eq 5 -and $psVer.Minor -lt 1)) {
        Write-Warn "PowerShell 5.1 or later is required. Current: $psVer"
    }
    Write-Info "Backup root: $($Global:BackupRoot)"
    Write-Info "Script dir:  $ScriptDir"
}

# ── Run All Backups ───────────────────────────────────────────────────────────
function Invoke-AllBackups {
    Write-Info "=== FULL BLUE TEAM BACKUP — $($Global:Timestamp) ==="

    $scripts = @(
        "01_Backup-Binaries.ps1"
        "02_Backup-SSH.ps1"
        "03_Backup-SMB.ps1"
        "04_Backup-WebServer.ps1"
        "05_Backup-WebContent.ps1"
        "06_Backup-MySQL.ps1"
        "07_Backup-Postgres.ps1"
    )

    $failed  = [System.Collections.ArrayList]@()
    $skipped = [System.Collections.ArrayList]@()

    foreach ($script in $scripts) {
        $path = Join-Path $ScriptDir $script
        if (Test-Path $path) {
            Write-Info "Running: $script"
            try {
                & $path -Action backup
                Write-Info "  Completed: $script"
            } catch {
                Write-Warn "  FAILED: $script — $_"
                $failed.Add($script) | Out-Null
            }
        } else {
            Write-Warn "  Not found (skipped): $path"
            $skipped.Add($script) | Out-Null
        }
    }

    Write-Info ""
    Write-Info "=== BACKUP SUMMARY ==="
    Write-Info "Timestamp: $($Global:Timestamp)"
    Write-Info "Location:  $($Global:BackupRoot)"
    if ($skipped.Count -gt 0) { Write-Warn "Skipped: $($skipped -join ', ')" }

    if ($failed.Count -eq 0) {
        Write-Info "All present scripts completed successfully."
    } else {
        Write-ErrLog "Failed: $($failed -join ', ')"
        Write-ErrLog "Check log: $($Global:LogFile)"
        exit 1
    }
}

# ── Restore Menu ──────────────────────────────────────────────────────────────
function Invoke-RestoreMenu {
    Write-Host "`n=== RESTORE MENU ===" -ForegroundColor Cyan
    Write-Host "  -- System ----------------------------------"
    Write-Host "  1) Binaries / Critical System Files"
    Write-Host "  2) SSH (OpenSSH Server)"
    Write-Host "  3) SMB / File Shares"
    Write-Host ""
    Write-Host "  -- Web -------------------------------------"
    Write-Host "  4) Web Server (IIS) Config"
    Write-Host "  5) Web Content"
    Write-Host ""
    Write-Host "  -- Databases --------------------------------"
    Write-Host "  6) MySQL / MariaDB"
    Write-Host "  7) PostgreSQL"
    Write-Host ""
    Write-Host "  -- All --------------------------------------"
    Write-Host "  8) ALL services (full restore)"
    Write-Host ""
    Write-Host "  0) Exit"
    $choice = Read-Host "`nChoice"

    switch ($choice) {
        "1" { & (Join-Path $ScriptDir "01_Backup-Binaries.ps1") -Action restore }
        "2" { & (Join-Path $ScriptDir "02_Backup-SSH.ps1")      -Action restore }
        "3" { & (Join-Path $ScriptDir "03_Backup-SMB.ps1")      -Action restore }
        "4" { & (Join-Path $ScriptDir "04_Backup-WebServer.ps1")-Action restore }
        "5" { & (Join-Path $ScriptDir "05_Backup-WebContent.ps1")-Action restore }
        "6" { & (Join-Path $ScriptDir "06_Backup-MySQL.ps1")    -Action restore }
        "7" { & (Join-Path $ScriptDir "07_Backup-Postgres.ps1") -Action restore }
        "8" {
            Write-Host "Full restore will interactively prompt for each service." -ForegroundColor Yellow
            $confirm = Read-Host "Type 'CONFIRM' to proceed"
            if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; return }
            $allScripts = @(
                "01_Backup-Binaries.ps1"
                "02_Backup-SSH.ps1"
                "03_Backup-SMB.ps1"
                "04_Backup-WebServer.ps1"
                "05_Backup-WebContent.ps1"
                "06_Backup-MySQL.ps1"
                "07_Backup-Postgres.ps1"
            )
            foreach ($s in $allScripts) {
                $p = Join-Path $ScriptDir $s
                if (Test-Path $p) {
                    try { & $p -Action restore } catch { Write-Warn "Error restoring $s : $_" }
                }
            }
        }
        "0" { return }
        default { Write-Warn "Invalid choice." }
    }
}

# ── Status ────────────────────────────────────────────────────────────────────
function Show-Status {
    Write-Host "`n=== BACKUP INVENTORY ===" -ForegroundColor Cyan
    if (-not (Test-Path $Global:BackupRoot)) {
        Write-Warn "No backups found at $($Global:BackupRoot)"
        return
    }

    $svcs = Get-ChildItem $Global:BackupRoot -Directory |
            Where-Object { $_.Name -ne "Logs" }

    if ($svcs.Count -eq 0) {
        Write-Warn "No service backups found. Run: .\00_Master.ps1 -Action backup"
        return
    }

    foreach ($svc in $svcs) {
        $latest = Get-ChildItem $svc.FullName -Directory |
                  Sort-Object Name -Descending | Select-Object -First 1
        $size = if ($latest) {
            $bytes = (Get-ChildItem $latest.FullName -Recurse -File -ErrorAction SilentlyContinue |
                      Measure-Object -Property Length -Sum).Sum
            "{0:N2} MB" -f ($bytes / 1MB)
        } else { "N/A" }
        $latestName = if ($latest) { $latest.Name } else { "none" }
        Write-Host ("  {0,-22} Latest: {1,-22} Size: {2}" -f
            $svc.Name,
            $latestName,
            $size) -ForegroundColor Cyan
    }
    Write-Info "$($svcs.Count) service(s) have backups."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
Initialize-Environment

switch ($Action) {
    "backup"  { Invoke-AllBackups }
    "restore" { Invoke-RestoreMenu }
    "status"  { Show-Status }
}
