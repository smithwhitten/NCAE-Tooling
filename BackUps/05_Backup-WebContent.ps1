#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — Windows Web Content Backup, Restore & Webshell Scan
# =============================================================================
# Backs up IIS web root directories, performs integrity hash verification,
# and scans for webshells, defacement, and suspicious file modifications.
#
# Usage:
#   .\05_Backup-WebContent.ps1 -Action backup
#   .\05_Backup-WebContent.ps1 -Action restore
#   .\05_Backup-WebContent.ps1 -Action scan
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","scan")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Configuration ─────────────────────────────────────────────────────────────
$Service    = "webcontent"
$BackupRoot = "C:\BlueteamBackups\$Service"
$LogFile    = "C:\BlueteamBackups\Logs\${Service}_$(Get-Date -f 'yyyyMMdd').log"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir  = Join-Path $BackupRoot $Timestamp
$LatestFile = Join-Path $BackupRoot "latest.txt"

# Default IIS web root — script will also detect sites dynamically
$DefaultWebRoots = @(
    "C:\inetpub\wwwroot"
    "C:\inetpub\ftproot"
)

# File extensions considered dangerous if found in web root
$DangerousExtensions = @(
    "*.asp", "*.aspx", "*.ashx", "*.asmx",  # ASP.NET — verify all expected
    "*.php", "*.php5", "*.phtml",            # PHP (unusual on IIS but possible)
    "*.cgi", "*.pl",                         # CGI scripts
    "*.exe", "*.bat", "*.cmd", "*.ps1",      # Executables
    "*.vbs", "*.wsf", "*.hta"               # Script files
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

# Get all IIS site physical paths
function Get-IISSitePaths {
    $paths = [System.Collections.ArrayList]@()
    try {
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-WebSite -ErrorAction SilentlyContinue
        foreach ($site in $sites) {
            if ($site.PhysicalPath -and (Test-Path $site.PhysicalPath)) {
                $paths.Add($site.PhysicalPath) | Out-Null
            }
        }
    } catch {}
    foreach ($root in $DefaultWebRoots) {
        if ((Test-Path $root) -and $root -notin $paths) {
            $paths.Add($root) | Out-Null
        }
    }
    return $paths
}

# ── Backup ────────────────────────────────────────────────────────────────────
function Invoke-Backup {
    Write-Info "=== Web Content Backup: $Timestamp ==="
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

    $webRoots = Get-IISSitePaths
    if ($webRoots.Count -eq 0) {
        Write-Warn "No web root directories found."
        exit 0
    }

    foreach ($root in $webRoots) {
        Write-Info "Backing up: $root"
        $sizeMB = [math]::Round((Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum / 1MB, 2)
        Write-Info "  Size: ${sizeMB} MB"

        $safeName = $root -replace '[:\\]','_' -replace '\s','_'
        $destPath = Join-Path $BackupDir $safeName
        New-Item -ItemType Directory -Path $destPath -Force | Out-Null

        # Use Robocopy for reliable file copy with metadata preservation
        $robocopyLog = Join-Path $BackupDir "robocopy_${safeName}.log"
        $result = robocopy $root $destPath /E /COPYALL /R:2 /W:5 /LOG:$robocopyLog /NP /NJH 2>&1
        # Robocopy exit codes 0-7 are success/partial success; 8+ are errors
        if ($LASTEXITCODE -le 7) {
            Write-Info "  Robocopy completed (exit: $LASTEXITCODE)"
        } else {
            Write-Warn "  Robocopy encountered errors (exit: $LASTEXITCODE) — check $robocopyLog"
        }
    }

    # Generate SHA-256 hash manifest
    Write-Info "Generating SHA-256 manifest..."
    $hashManifest = @{}
    Get-ChildItem -Path $BackupDir -Recurse -File |
        Where-Object { $_.Name -notin @("sha256_manifest.json") -and $_.Extension -ne ".log" } |
        ForEach-Object {
            try {
                $hashManifest[$_.FullName] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            } catch {
                Write-Warn "  Could not hash: $($_.FullName)"
            }
        }
    $hashManifest | ConvertTo-Json -Compress |
        Set-Content (Join-Path $BackupDir "sha256_manifest.json") -Encoding UTF8

    $BackupDir | Set-Content $LatestFile -Encoding UTF8
    Write-Info "Web content backup complete: $BackupDir"
    Invoke-Scan
}

# ── Webshell & Defacement Scanner ─────────────────────────────────────────────
function Invoke-Scan {
    Write-Info "=== Web Content Security Scan ==="
    $webRoots = Get-IISSitePaths
    $totalIssues = 0

    foreach ($root in $webRoots) {
        Write-Info "Scanning: $root"
        $issues = 0

        # 1. ASP/ASPX webshell signatures
        Write-Info "  Checking for webshell patterns in ASPX/ASP files..."
        $shellPatterns = @(
            'eval\s*\('
            'Execute\s*\('
            'ExecuteGlobal\s*\('
            'Response\.Write\s*\(.*Request\.'
            'ProcessStartInfo'
            'cmd\.exe'
            'powershell\.exe'
            'System\.Diagnostics\.Process'
            'WScript\.Shell'
            'Shell\.Application'
            'Convert\.FromBase64String'
            'net user\s+/add'
        )

        $aspFiles = Get-ChildItem -Path $root -Recurse -Include "*.asp","*.aspx","*.ashx" `
            -ErrorAction SilentlyContinue

        foreach ($file in $aspFiles) {
            try {
                $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                foreach ($pattern in $shellPatterns) {
                    if ($content -match $pattern) {
                        Write-Alert "  WEBSHELL PATTERN '$pattern' in: $($file.FullName)"
                        $issues++
                        break  # One alert per file max
                    }
                }
            } catch {}
        }

        # 2. Executables in web-accessible directories
        Write-Info "  Checking for executables in web root..."
        $exeFiles = Get-ChildItem -Path $root -Recurse -Include "*.exe","*.dll","*.com" `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.DirectoryName -notmatch "bin|App_Code|App_Data" }
        if ($exeFiles) {
            foreach ($f in $exeFiles) {
                Write-Alert "  Executable in web root: $($f.FullName)"
                $issues++
            }
        }

        # 3. PHP files (unusual on Windows IIS — likely malicious)
        $phpFiles = Get-ChildItem -Path $root -Recurse -Include "*.php","*.php5","*.phtml" `
            -ErrorAction SilentlyContinue
        if ($phpFiles) {
            foreach ($f in $phpFiles) {
                Write-Alert "  PHP file on IIS server (unusual — verify): $($f.FullName)"
                $issues++
            }
        }

        # 4. Recently modified files (last 24 hours)
        Write-Info "  Files modified in last 24 hours:"
        $cutoff = (Get-Date).AddHours(-24)
        $recentFiles = Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff }
        if ($recentFiles) {
            Write-Warn "  Recently modified files ($($recentFiles.Count)):"
            $recentFiles | Select-Object FullName, LastWriteTime, Length |
                ForEach-Object { Write-Warn "    $($_.LastWriteTime) | $($_.FullName)" }
        } else {
            Write-Info "  No files modified in last 24h."
        }

        # 5. Integrity check against backup
        if (Test-Path $LatestFile) {
            $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
            $manifestPath = Join-Path $latestBackup "sha256_manifest.json"
            if (Test-Path $manifestPath) {
                Write-Info "  Checking integrity against backup..."
                $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
                $mismatches = 0

                # Filter manifest entries for this web root
                $safeName = $root -replace '[:\\]','_' -replace '\s','_'
                $manifest.PSObject.Properties |
                    Where-Object { $_.Name -match [regex]::Escape($safeName) } |
                    ForEach-Object {
                        $backupPath = $_.Name
                        $expectedHash = $_.Value
                        # Reconstruct live path
                        $livePath = $backupPath -replace [regex]::Escape((Join-Path $latestBackup $safeName)), $root

                        if (Test-Path $livePath) {
                            try {
                                $actualHash = (Get-FileHash $livePath -Algorithm SHA256).Hash
                                if ($expectedHash -ne $actualHash) {
                                    Write-Warn "  CHANGED: $livePath"
                                    $mismatches++
                                }
                            } catch {}
                        } else {
                            Write-Warn "  DELETED: $livePath"
                            $mismatches++
                        }
                    }
                if ($mismatches -eq 0) {
                    Write-Info "  Integrity check: All files match backup."
                } else {
                    Write-Alert "  $mismatches file(s) changed or deleted since backup."
                    $issues += $mismatches
                }
            }
        }

        $totalIssues += $issues
        Write-Info "  Issues found in ${root}: $issues"
    }

    Write-Info ""
    if ($totalIssues -eq 0) {
        Write-Info "Web content scan complete — no critical issues detected."
    } else {
        Write-Alert "$totalIssues total issue(s) detected across all web roots. Review alerts."
    }
}

# ── Restore ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Info "=== Web Content Restore ==="
    if (-not (Test-Path $LatestFile)) {
        Write-Err "No backup found. Run backup first."
        exit 1
    }

    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    $webRoots = Get-IISSitePaths

    Write-Host "Restoring web content from: $(Split-Path $latestBackup -Leaf)" -ForegroundColor Yellow
    Write-Host "Web roots to restore: $($webRoots -join ', ')" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'CONFIRM' to proceed"
    if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; exit 0 }

    foreach ($root in $webRoots) {
        $safeName = $root -replace '[:\\]','_' -replace '\s','_'
        $srcPath  = Join-Path $latestBackup $safeName

        if (Test-Path $srcPath) {
            # Archive current content before overwrite
            $archivePath = "${root}_prerestore_${Timestamp}.zip"
            Write-Info "  Archiving current content: $archivePath"
            Compress-Archive -Path $root -DestinationPath $archivePath -Force -ErrorAction SilentlyContinue

            # Restore via Robocopy — /PURGE removes files in dest not in source
            $robocopyLog = Join-Path $BackupRoot "restore_robocopy_${Timestamp}.log"
            $result = robocopy $srcPath $root /E /COPYALL /PURGE /R:2 /W:5 /LOG:$robocopyLog /NP /NJH 2>&1
            if ($LASTEXITCODE -le 7) {
                Write-Info "  Restored: $root (robocopy exit: $LASTEXITCODE)"
            } else {
                Write-Warn "  Robocopy errors on restore for $root (exit: $LASTEXITCODE)"
            }
        } else {
            Write-Warn "  No backup found for: $root (expected: $srcPath)"
        }
    }

    # Recycle IIS app pools to pick up new content
    Write-Info "Recycling IIS application pools..."
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Get-WebConfiguration "system.applicationHost/applicationPools/add" |
            ForEach-Object {
                Restart-WebAppPool -Name $_.Name -ErrorAction SilentlyContinue
                Write-Info "  Recycled pool: $($_.Name)"
            }
    } catch {
        Write-Warn "  Could not recycle app pools — may require manual iisreset"
    }

    Write-Info "Web content restore complete."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
switch ($Action) {
    "backup"  { Invoke-Backup }
    "restore" { Invoke-Restore }
    "scan"    { Invoke-Scan }
}
