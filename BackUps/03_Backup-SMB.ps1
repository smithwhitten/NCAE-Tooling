#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — Windows SMB File Shares Backup & Restore
# =============================================================================
# Exports all SMB share definitions, permissions, and Server Message Block
# (SMB) server configuration settings. Restores in the event of
# unauthorized share creation, permission changes, or service disruption.
#
# Usage:
#   .\03_Backup-SMB.ps1 -Action backup
#   .\03_Backup-SMB.ps1 -Action restore
#   .\03_Backup-SMB.ps1 -Action audit
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","audit")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Configuration ─────────────────────────────────────────────────────────────
$Service    = "smb"
$BackupRoot = "C:\BlueteamBackups\$Service"
$LogFile    = "C:\BlueteamBackups\Logs\${Service}_$(Get-Date -f 'yyyyMMdd').log"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir  = Join-Path $BackupRoot $Timestamp
$LatestFile = Join-Path $BackupRoot "latest.txt"

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

# ── Backup ────────────────────────────────────────────────────────────────────
function Invoke-Backup {
    Write-Info "=== SMB Backup: $Timestamp ==="
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

    # 1. Export all SMB shares
    Write-Info "Exporting SMB shares..."
    $shares = Get-SmbShare -ErrorAction SilentlyContinue
    if ($shares) {
        $shares | Select-Object Name, Path, Description, ConcurrentUserLimit,
            FolderEnumerationMode, CachingMode, ShareState, ShareType |
            ConvertTo-Json -Depth 5 |
            Set-Content (Join-Path $BackupDir "smb_shares.json") -Encoding UTF8
        Write-Info "  Exported $($shares.Count) share(s)."
    } else {
        Write-Warn "  No SMB shares found (or SmbShare module unavailable)."
    }

    # 2. Export SMB share ACLs (access permissions)
    Write-Info "Exporting SMB share access permissions..."
    $shareAcls = @{}
    foreach ($share in $shares) {
        try {
            $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction Stop
            $shareAcls[$share.Name] = $acl | Select-Object Name, ScopeName,
                AccountName, AccessControlType, AccessRight
        } catch {
            Write-Warn "  Could not get ACL for share: $($share.Name)"
        }
    }
    $shareAcls | ConvertTo-Json -Depth 5 |
        Set-Content (Join-Path $BackupDir "smb_share_acls.json") -Encoding UTF8

    # 3. Export SMB server configuration
    Write-Info "Exporting SMB server configuration..."
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbConfig) {
        $smbConfig | Select-Object * |
            ConvertTo-Json -Depth 3 |
            Set-Content (Join-Path $BackupDir "smb_server_config.json") -Encoding UTF8
        Write-Info "  SMB server config exported."
    }

    # 4. Export SMB1 protocol status (security-relevant)
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($smb1) {
        [PSCustomObject]@{ SMB1_State = $smb1.State.ToString() } |
            ConvertTo-Json | Set-Content (Join-Path $BackupDir "smb1_status.json") -Encoding UTF8
        if ($smb1.State -eq "Enabled") {
            Write-Alert "SMB1 Protocol is ENABLED — this is a critical security risk (EternalBlue)"
        } else {
            Write-Info "  SMB1 Protocol: Disabled (good)"
        }
    }

    # 5. Export LanmanServer service config
    $svc = Get-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
    if ($svc) {
        [PSCustomObject]@{
            Status    = $svc.Status.ToString()
            StartType = $svc.StartType.ToString()
        } | ConvertTo-Json | Set-Content (Join-Path $BackupDir "lanmanserver_service.json") -Encoding UTF8
    }

    # 6. Snapshot current NTFS ACLs of share paths
    Write-Info "Snapshotting NTFS ACLs for share paths..."
    $ntfsAcls = @{}
    foreach ($share in $shares) {
        if ($share.Path -and (Test-Path $share.Path)) {
            try {
                $acl = Get-Acl -Path $share.Path
                $ntfsAcls[$share.Name] = @{
                    Path  = $share.Path
                    Owner = $acl.Owner
                    Access = $acl.Access | Select-Object IdentityReference, FileSystemRights,
                        AccessControlType, IsInherited | ForEach-Object { $_ | ConvertTo-Json }
                }
            } catch {
                Write-Warn "  Could not get NTFS ACL for: $($share.Path)"
            }
        }
    }
    $ntfsAcls | ConvertTo-Json -Depth 5 |
        Set-Content (Join-Path $BackupDir "ntfs_acls_snapshot.json") -Encoding UTF8

    $BackupDir | Set-Content $LatestFile -Encoding UTF8
    Write-Info "SMB backup complete: $BackupDir"
    Invoke-Audit
}

# ── Audit ─────────────────────────────────────────────────────────────────────
function Invoke-Audit {
    Write-Info "=== SMB Security Audit ==="
    $issues = 0

    # SMB1 check
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
    if ($smb1 -and $smb1.State -eq "Enabled") {
        Write-Alert "CRITICAL: SMB1 is ENABLED — vulnerable to EternalBlue (MS17-010)"
        Write-Alert "  Disable: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
        $issues++
    }

    # SMB signing check
    $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($smbConfig) {
        if (-not $smbConfig.RequireSecuritySignature) {
            Write-Warn "  SMB signing not required — susceptible to relay attacks"
            $issues++
        } else {
            Write-Info "  SMB signing required: OK"
        }
        if ($smbConfig.EnableSMB1Protocol) {
            Write-Alert "  SMB1 enabled in server config"
            $issues++
        }
    }

    # Check for everyone / anonymous access
    $shares = Get-SmbShare -ErrorAction SilentlyContinue
    foreach ($share in $shares) {
        try {
            $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction Stop
            $everyoneAccess = $acl | Where-Object {
                $_.AccountName -match "Everyone|ANONYMOUS|Guests" -and
                $_.AccessRight -ne "Deny"
            }
            if ($everyoneAccess) {
                Write-Alert "Share '$($share.Name)' grants access to: $($everyoneAccess.AccountName)"
                $issues++
            }
        } catch {}

        # Check admin shares that have been redirected (suspicious)
        if ($share.Name -match '^\w\$$') {
            if ($share.Path -notmatch "^[A-Z]:\\$") {
                Write-Warn "  Admin share $($share.Name) points to non-standard path: $($share.Path)"
            }
        }
    }

    # Check guest account
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        Write-Alert "Guest account is ENABLED — should be disabled"
        $issues++
    }

    if ($issues -eq 0) {
        Write-Info "No critical SMB issues detected."
    } else {
        Write-Warn "$issues issue(s) found. Review above."
    }
}

# ── Restore ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Info "=== SMB Restore ==="
    if (-not (Test-Path $LatestFile)) {
        Write-Err "No backup found. Run backup first."
        exit 1
    }

    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    Write-Host "Restoring SMB config from: $(Split-Path $latestBackup -Leaf)" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'CONFIRM' to proceed"
    if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; exit 0 }

    # Restore shares from JSON
    $sharesFile = Join-Path $latestBackup "smb_shares.json"
    $aclsFile   = Join-Path $latestBackup "smb_share_acls.json"

    if (Test-Path $sharesFile) {
        $backedUpShares = Get-Content $sharesFile -Raw | ConvertFrom-Json

        foreach ($share in $backedUpShares) {
            # Skip built-in admin shares
            if ($share.Name -match '^(ADMIN|IPC|[A-Z])\$$') {
                Write-Info "  Skipping built-in share: $($share.Name)"
                continue
            }

            $existing = Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue
            if (-not $existing) {
                if ($share.Path -and (Test-Path $share.Path)) {
                    New-SmbShare -Name $share.Name -Path $share.Path `
                        -Description $share.Description -ErrorAction SilentlyContinue | Out-Null
                    Write-Info "  Recreated share: $($share.Name) → $($share.Path)"
                } else {
                    Write-Warn "  Share path not found, cannot recreate: $($share.Name) → $($share.Path)"
                }
            } else {
                Write-Info "  Share already exists: $($share.Name)"
            }
        }
    }

    # Restore SMB server configuration settings
    $smbConfigFile = Join-Path $latestBackup "smb_server_config.json"
    if (Test-Path $smbConfigFile) {
        $savedConfig = Get-Content $smbConfigFile -Raw | ConvertFrom-Json
        # Restore key security settings
        Set-SmbServerConfiguration `
            -RequireSecuritySignature $savedConfig.RequireSecuritySignature `
            -EnableSMB1Protocol $savedConfig.EnableSMB1Protocol `
            -EnableSMB2Protocol $savedConfig.EnableSMB2Protocol `
            -Force -ErrorAction SilentlyContinue
        Write-Info "  SMB server configuration restored."
    }

    Write-Info "SMB restore complete."
    Write-Warn "Review share ACLs manually — ACL restore requires per-share verification."
    Write-Warn "Run: Get-SmbShareAccess -Name <ShareName> to verify access permissions."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
switch ($Action) {
    "backup"  { Invoke-Backup }
    "restore" { Invoke-Restore }
    "audit"   { Invoke-Audit }
}
