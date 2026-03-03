#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — Windows IIS Web Server Configuration Backup & Restore
# =============================================================================
# Backs up IIS (Internet Information Services) configuration using the
# built-in appcmd.exe backup mechanism plus manual config file copies.
# Covers: applicationHost.config, web.config, SSL bindings, app pools.
#
# Usage:
#   .\04_Backup-WebServer.ps1 -Action backup
#   .\04_Backup-WebServer.ps1 -Action restore
#   .\04_Backup-WebServer.ps1 -Action audit
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","audit")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Configuration ─────────────────────────────────────────────────────────────
$Service    = "webserver"
$BackupRoot = "C:\BlueteamBackups\$Service"
$LogFile    = "C:\BlueteamBackups\Logs\${Service}_$(Get-Date -f 'yyyyMMdd').log"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir  = Join-Path $BackupRoot $Timestamp
$LatestFile = Join-Path $BackupRoot "latest.txt"

$AppCmd     = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
$IISConfig  = "$env:SystemRoot\System32\inetsrv\config"
$IISSchemas = "$env:SystemRoot\System32\inetsrv\config\schema"

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

function Test-IIS {
    if (-not (Test-Path $AppCmd)) {
        Write-Warn "appcmd.exe not found — IIS may not be installed."
        Write-Warn "Install IIS: Install-WindowsFeature -Name Web-Server -IncludeManagementTools"
        return $false
    }
    return $true
}

# ── Backup ────────────────────────────────────────────────────────────────────
function Invoke-Backup {
    Write-Info "=== IIS Web Server Backup: $Timestamp ==="
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

    if (-not (Test-IIS)) { Write-Warn "Proceeding with file copy only."; }

    # 1. Native appcmd backup (best method — captures complete IIS state)
    if (Test-Path $AppCmd) {
        Write-Info "Running appcmd backup..."
        $appcmdBackupName = "blueteam_$Timestamp"
        $result = & $AppCmd add backup $appcmdBackupName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Info "  appcmd backup created: $appcmdBackupName"
            # Copy appcmd backup to our backup dir too
            $appcmdBackupPath = "$env:SystemRoot\System32\inetsrv\backup\$appcmdBackupName"
            if (Test-Path $appcmdBackupPath) {
                Copy-Item -Path $appcmdBackupPath -Destination (Join-Path $BackupDir "appcmd_backup") `
                    -Recurse -Force
            }
        } else {
            Write-Warn "  appcmd backup failed: $result"
        }
    }

    # 2. Direct config file backup
    Write-Info "Backing up IIS config files..."
    if (Test-Path $IISConfig) {
        $dest = Join-Path $BackupDir "inetsrv_config"
        Copy-Item -Path $IISConfig -Destination $dest -Recurse -Force
        Write-Info "  IIS config dir backed up: $IISConfig"
    }

    # 3. Export site configurations via WebAdministration module
    try {
        Import-Module WebAdministration -ErrorAction Stop

        # Sites
        Write-Info "Exporting IIS sites..."
        $sites = Get-WebSite -ErrorAction SilentlyContinue
        $sites | Select-Object Name, PhysicalPath, State, Id,
            @{N="Bindings";E={$_.Bindings.Collection | Select-Object Protocol, BindingInformation}} |
            ConvertTo-Json -Depth 5 |
            Set-Content (Join-Path $BackupDir "iis_sites.json") -Encoding UTF8
        Write-Info "  Exported $($sites.Count) site(s)."

        # Application Pools
        Write-Info "Exporting application pools..."
        $pools = Get-WebConfiguration "system.applicationHost/applicationPools/add"
        $pools | Select-Object Name, ManagedRuntimeVersion, ManagedPipelineMode,
            StartMode, AutoStart,
            @{N="ProcessModel";E={$_.ProcessModel | Select-Object UserName, IdentityType}} |
            ConvertTo-Json -Depth 5 |
            Set-Content (Join-Path $BackupDir "iis_app_pools.json") -Encoding UTF8
        Write-Info "  Exported $($pools.Count) app pool(s)."

        # Virtual Directories
        $vdirs = Get-WebVirtualDirectory -ErrorAction SilentlyContinue
        if ($vdirs) {
            $vdirs | ConvertTo-Json -Depth 3 |
                Set-Content (Join-Path $BackupDir "iis_virtual_dirs.json") -Encoding UTF8
        }

        # SSL Bindings
        Write-Info "Exporting SSL bindings..."
        $sslBindings = Get-WebBinding -Protocol "https" -ErrorAction SilentlyContinue
        $sslBindings | Select-Object * |
            ConvertTo-Json -Depth 3 |
            Set-Content (Join-Path $BackupDir "iis_ssl_bindings.json") -Encoding UTF8

    } catch {
        Write-Warn "WebAdministration module unavailable or error: $_"
        Write-Warn "Config files were backed up — appcmd restore still functional."
    }

    # 4. Backup SSL certificates
    Write-Info "Exporting SSL certificate thumbprints (for reference)..."
    $certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
    $certs | ConvertTo-Json | Set-Content (Join-Path $BackupDir "ssl_certificates.json") -Encoding UTF8

    # 5. W3SVC service config
    $svc = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    if ($svc) {
        [PSCustomObject]@{
            Status    = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        } | ConvertTo-Json | Set-Content (Join-Path $BackupDir "w3svc_service.json") -Encoding UTF8
    }

    $BackupDir | Set-Content $LatestFile -Encoding UTF8
    Write-Info "IIS backup complete: $BackupDir"
    Invoke-Audit
}

# ── Audit ─────────────────────────────────────────────────────────────────────
function Invoke-Audit {
    Write-Info "=== IIS Security Audit ==="
    $issues = 0

    try { Import-Module WebAdministration -ErrorAction Stop } catch {
        Write-Warn "WebAdministration module unavailable — limited audit."
        return
    }

    # Check for sites with directory browsing enabled
    $dirBrowsing = Get-WebConfigurationProperty -Filter "system.webServer/directoryBrowse" `
        -Name "enabled" -PSPath "IIS:\" -ErrorAction SilentlyContinue
    if ($dirBrowsing -and $dirBrowsing.Value -eq $true) {
        Write-Alert "Directory browsing ENABLED at root — information disclosure risk"
        $issues++
    }

    # Check each site for HTTP-only (no HTTPS)
    $sites = Get-WebSite -ErrorAction SilentlyContinue
    foreach ($site in $sites) {
        $hasHttps = $site.Bindings.Collection | Where-Object { $_.Protocol -eq "https" }
        $hasHttp  = $site.Bindings.Collection | Where-Object { $_.Protocol -eq "http" }
        if ($hasHttp -and -not $hasHttps) {
            Write-Warn "  Site '$($site.Name)' has HTTP binding but no HTTPS — plaintext traffic risk"
            $issues++
        }
    }

    # Check application pool identity — avoid LOCALSYSTEM
    $pools = Get-WebConfiguration "system.applicationHost/applicationPools/add"
    foreach ($pool in $pools) {
        $identity = $pool.ProcessModel.IdentityType
        if ($identity -eq "LocalSystem") {
            Write-Alert "App pool '$($pool.Name)' runs as LocalSystem — excessive privilege"
            $issues++
        }
    }

    # Check for IIS detailed error pages (information disclosure)
    $errorMode = Get-WebConfigurationProperty -Filter "system.webServer/httpErrors" `
        -Name "errorMode" -PSPath "IIS:\" -ErrorAction SilentlyContinue
    if ($errorMode -and $errorMode.Value -eq "Detailed") {
        Write-Warn "  HTTP error mode is 'Detailed' — stack traces visible to clients"
        $issues++
    }

    # Check server header removal (X-Powered-By disclosure)
    $customHeaders = Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" `
        -Name "." -PSPath "IIS:\" -ErrorAction SilentlyContinue
    $xPowered = $customHeaders.Collection | Where-Object { $_.name -eq "X-Powered-By" }
    if ($xPowered) {
        Write-Warn "  X-Powered-By header present — technology fingerprinting risk"
        $issues++
    }

    if ($issues -eq 0) {
        Write-Info "No critical IIS misconfigurations detected."
    } else {
        Write-Warn "$issues issue(s) found. Review above."
    }
}

# ── Restore ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Info "=== IIS Restore ==="
    if (-not (Test-Path $LatestFile)) {
        Write-Err "No backup found. Run backup first."
        exit 1
    }

    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    Write-Host "Restoring IIS config from: $(Split-Path $latestBackup -Leaf)" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'CONFIRM' to proceed"
    if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; exit 0 }

    # Stop IIS
    Write-Info "Stopping IIS (W3SVC)..."
    Stop-Service -Name "W3SVC" -Force -ErrorAction SilentlyContinue
    & iisreset /stop 2>&1 | Out-Null

    # Method 1: Restore via appcmd (preferred)
    $appcmdBackupDir = Join-Path $latestBackup "appcmd_backup"
    if (Test-Path $appcmdBackupDir -and (Test-Path $AppCmd)) {
        # Copy appcmd backup back to IIS backup location
        $appcmdTarget = "$env:SystemRoot\System32\inetsrv\backup\$(Split-Path $appcmdBackupDir -Leaf)"
        Copy-Item -Path $appcmdBackupDir -Destination $appcmdTarget -Recurse -Force -ErrorAction SilentlyContinue
        $backupName = Split-Path $appcmdTarget -Leaf
        Write-Info "Restoring via appcmd..."
        $result = & $AppCmd restore backup $backupName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Info "  appcmd restore successful."
        } else {
            Write-Warn "  appcmd restore failed: $result"
            Write-Warn "  Falling back to file copy..."
            # Method 2: Direct file copy
            $srcConfig = Join-Path $latestBackup "inetsrv_config"
            if (Test-Path $srcConfig) {
                Compress-Archive -Path $IISConfig `
                    -DestinationPath "${IISConfig}_prerestore_${Timestamp}.zip" -Force -ErrorAction SilentlyContinue
                Copy-Item -Path $srcConfig\* -Destination $IISConfig -Recurse -Force
                Write-Info "  Config files restored from backup."
            }
        }
    }

    # Restart IIS
    Write-Info "Starting IIS..."
    & iisreset /start 2>&1 | Out-Null
    Start-Service -Name "W3SVC" -ErrorAction SilentlyContinue
    $status = (Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue).Status
    Write-Info "  W3SVC status: $status"

    Write-Info "IIS restore complete."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
switch ($Action) {
    "backup"  { Invoke-Backup }
    "restore" { Invoke-Restore }
    "audit"   { Invoke-Audit }
}
