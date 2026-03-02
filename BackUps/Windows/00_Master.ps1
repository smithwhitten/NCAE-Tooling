#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — Windows Master Backup & Restore Orchestrator
# =============================================================================
# Usage (run as Administrator in PowerShell):
#   .\00_Master.ps1 -Action backup
#   .\00_Master.ps1 -Action restore
#   .\00_Master.ps1 -Action status
#
# Requirements: PowerShell 5.1+, Windows Server 2016/2019/2022 or Win10/11
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","status")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Global Configuration ──────────────────────────────────────────────────────
$Global:BackupRoot  = "C:\BlueteamBackups"
$Global:LogFile     = "C:\BlueteamBackups\Logs\master_$(Get-Date -f 'yyyyMMdd').log"
$Global:Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$ScriptDir          = Split-Path -Parent $MyInvocation.MyCommand.Path

# ── Logging ───────────────────────────────────────────────────────────────────
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
function Write-Info  { Write-Log "INFO"  $args[0] }
function Write-Warn  { Write-Log "WARN"  $args[0] }
function Write-Error-Log { Write-Log "ERROR" $args[0] }

# ── Preflight ─────────────────────────────────────────────────────────────────
function Initialize-Environment {
    $logDir = Split-Path $Global:LogFile -Parent
    New-Item -ItemType Directory -Path $Global:BackupRoot, $logDir -Force | Out-Null
    # Restrict backup root to Administrators only
    $acl = Get-Acl $Global:BackupRoot
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"
    )
    $acl.AddAccessRule($adminRule)
    Set-Acl $Global:BackupRoot $acl -ErrorAction SilentlyContinue
    Write-Info "Backup root: $($Global:BackupRoot)"
}

# ── Run All Backups ───────────────────────────────────────────────────────────
function Invoke-AllBackups {
    Write-Info "===  FULL BLUE TEAM BACKUP — $($Global:Timestamp)  ==="

    $scripts = @(
        "01_Backup-Binaries.ps1"
        "02_Backup-SSH.ps1"
        "03_Backup-SMB.ps1"
        "04_Backup-WebServer.ps1"
        "05_Backup-WebContent.ps1"
    )

    $failed = @()
    foreach ($script in $scripts) {
        $path = Join-Path $ScriptDir $script
        if (Test-Path $path) {
            Write-Info "Running: $script"
            try {
                & $path -Action backup
                Write-Info "  Completed: $script"
            } catch {
                Write-Warn "FAILED: $script — $_"
                $failed += $script
            }
        } else {
            Write-Warn "Script not found: $path"
        }
    }

    Write-Info ""
    if ($failed.Count -eq 0) {
        Write-Info "All backups completed successfully."
    } else {
        Write-Error-Log "The following scripts failed: $($failed -join ', ')"
        exit 1
    }
}

# ── Restore Menu ──────────────────────────────────────────────────────────────
function Invoke-RestoreMenu {
    Write-Host "`n=== RESTORE MENU ===" -ForegroundColor Cyan
    Write-Host "  1) Binaries / Critical System Files"
    Write-Host "  2) SSH (OpenSSH Server)"
    Write-Host "  3) SMB / File Shares"
    Write-Host "  4) Web Server (IIS) Config"
    Write-Host "  5) Web Content"
    Write-Host "  6) ALL (full restore)"
    Write-Host "  0) Exit"
    $choice = Read-Host "`nChoice"

    switch ($choice) {
        "1" { & (Join-Path $ScriptDir "01_Backup-Binaries.ps1") -Action restore }
        "2" { & (Join-Path $ScriptDir "02_Backup-SSH.ps1") -Action restore }
        "3" { & (Join-Path $ScriptDir "03_Backup-SMB.ps1") -Action restore }
        "4" { & (Join-Path $ScriptDir "04_Backup-WebServer.ps1") -Action restore }
        "5" { & (Join-Path $ScriptDir "05_Backup-WebContent.ps1") -Action restore }
        "6" {
            foreach ($n in @("01","02","03","04","05")) {
                $s = Get-ChildItem $ScriptDir -Filter "${n}_Backup-*.ps1" | Select-Object -First 1
                if ($s) { & $s.FullName -Action restore }
            }
        }
        "0" { exit 0 }
        default { Write-Warn "Invalid choice." }
    }
}

# ── Status ────────────────────────────────────────────────────────────────────
function Show-Status {
    Write-Host "`n=== BACKUP INVENTORY ===" -ForegroundColor Cyan
    if (-not (Test-Path $Global:BackupRoot)) {
        Write-Warn "No backups found."
        return
    }
    Get-ChildItem $Global:BackupRoot -Directory | ForEach-Object {
        $svc = $_.Name
        $latest = Get-ChildItem $_.FullName -Directory |
                  Sort-Object Name -Descending | Select-Object -First 1
        $size = if ($latest) {
            "{0:N2} MB" -f ((Get-ChildItem $latest.FullName -Recurse -File |
                Measure-Object -Property Length -Sum).Sum / 1MB)
        } else { "N/A" }
        Write-Host ("  {0,-20} Latest: {1,-20} Size: {2}" -f $svc,
            ($latest.Name ?? "none"), $size) -ForegroundColor Cyan
    }
}

# ── Entry Point ───────────────────────────────────────────────────────────────
Initialize-Environment

switch ($Action) {
    "backup"  { Invoke-AllBackups }
    "restore" { Invoke-RestoreMenu }
    "status"  { Show-Status }
}
