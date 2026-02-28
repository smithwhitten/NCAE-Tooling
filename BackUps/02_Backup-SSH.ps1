#Requires -RunAsAdministrator
# =============================================================================
# BLUE TEAM — Windows OpenSSH Server Backup & Restore
# =============================================================================
# Backs up OpenSSH server configuration, authorized_keys, host keys,
# and service settings. Includes security audit for common misconfigs.
#
# Usage:
#   .\02_Backup-SSH.ps1 -Action backup
#   .\02_Backup-SSH.ps1 -Action restore
#   .\02_Backup-SSH.ps1 -Action audit
# =============================================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("backup","restore","audit")]
    [string]$Action
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ── Configuration ─────────────────────────────────────────────────────────────
$Service    = "ssh"
$BackupRoot = "C:\BlueteamBackups\$Service"
$LogFile    = "C:\BlueteamBackups\Logs\${Service}_$(Get-Date -f 'yyyyMMdd').log"
$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$BackupDir  = Join-Path $BackupRoot $Timestamp
$LatestFile = Join-Path $BackupRoot "latest.txt"

# OpenSSH paths (Windows Server / Win10+)
$SSHConfigPaths = @(
    "$env:ProgramData\ssh\sshd_config"
    "$env:ProgramData\ssh\ssh_config"
    "$env:ProgramData\ssh\administrators_authorized_keys"
)
$SSHProgramDataDir = "$env:ProgramData\ssh"
$OpenSSHInstallDir = "$env:SystemRoot\System32\OpenSSH"

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

# Check if OpenSSH is installed
function Test-OpenSSH {
    $feature = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue
    $service = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if (-not $feature -and -not $service) {
        Write-Warn "OpenSSH Server may not be installed."
        Write-Warn "Install with: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
        return $false
    }
    return $true
}

# ── Backup ────────────────────────────────────────────────────────────────────
function Invoke-Backup {
    Write-Info "=== SSH Backup: $Timestamp ==="
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

    Test-OpenSSH | Out-Null

    # Backup ProgramData\ssh directory
    if (Test-Path $SSHProgramDataDir) {
        $dest = Join-Path $BackupDir "ProgramData_ssh"
        Copy-Item -Path $SSHProgramDataDir -Destination $dest -Recurse -Force
        Write-Info "  Backed up: $SSHProgramDataDir"
        # Restrict permissions on backup — contains host private keys
        $acl = Get-Acl $dest
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow"
        )
        $acl.AddAccessRule($rule)
        Set-Acl $dest $acl -ErrorAction SilentlyContinue
    } else {
        Write-Warn "  SSH config dir not found: $SSHProgramDataDir"
    }

    # Backup per-user authorized_keys
    Write-Info "Backing up per-user authorized_keys..."
    $users = Get-ChildItem "C:\Users" -Directory
    foreach ($user in $users) {
        $authKeys = Join-Path $user.FullName ".ssh\authorized_keys"
        if (Test-Path $authKeys) {
            $destDir = Join-Path $BackupDir "Users\$($user.Name)\.ssh"
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            Copy-Item -Path $authKeys -Destination $destDir -Force
            Write-Info "  $($user.Name): authorized_keys backed up"
        }
    }

    # Export OpenSSH service configuration
    $sshdService = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if ($sshdService) {
        [PSCustomObject]@{
            Status      = $sshdService.Status.ToString()
            StartType   = $sshdService.StartType.ToString()
            DisplayName = $sshdService.DisplayName
        } | ConvertTo-Json | Set-Content (Join-Path $BackupDir "sshd_service_config.json") -Encoding UTF8
        Write-Info "  Service config exported."
    }

    # Export OpenSSH firewall rule
    $fwRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if ($fwRule) {
        $fwRule | Select-Object Name, DisplayName, Enabled, Action, Direction |
            ConvertTo-Json | Set-Content (Join-Path $BackupDir "sshd_firewall_rule.json") -Encoding UTF8
        Write-Info "  Firewall rule exported."
    }

    # Hash manifest
    $hashManifest = @{}
    Get-ChildItem -Path $BackupDir -Recurse -File |
        Where-Object { $_.Name -ne "sha256_manifest.json" } |
        ForEach-Object {
            $hashManifest[$_.FullName] = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
        }
    $hashManifest | ConvertTo-Json -Depth 3 |
        Set-Content (Join-Path $BackupDir "sha256_manifest.json") -Encoding UTF8

    $BackupDir | Set-Content $LatestFile -Encoding UTF8
    Write-Info "SSH backup complete: $BackupDir"

    # Run audit
    Invoke-Audit
}

# ── Audit ─────────────────────────────────────────────────────────────────────
function Invoke-Audit {
    Write-Info "=== SSH Security Audit ==="
    $configPath = "$env:ProgramData\ssh\sshd_config"
    if (-not (Test-Path $configPath)) {
        Write-Warn "sshd_config not found at $configPath"
        return
    }

    $config = Get-Content $configPath -Raw
    $issues = 0

    # Check dangerous settings
    $checks = @{
        "PermitRootLogin\s+yes"          = "Root login enabled (uncommon on Windows but check if configured)"
        "PermitEmptyPasswords\s+yes"      = "CRITICAL: Empty passwords permitted"
        "PasswordAuthentication\s+yes"    = "Password auth enabled — prefer key-only in competitive environments"
        "X11Forwarding\s+yes"             = "X11 forwarding enabled"
        "AllowTcpForwarding\s+yes"        = "TCP forwarding enabled — tunneling risk"
        "GatewayPorts\s+yes"              = "GatewayPorts enabled — remote port forwarding risk"
    }

    foreach ($pattern in $checks.Keys) {
        if ($config -match "(?im)^\s*$pattern") {
            Write-Warn "  [FINDING] $pattern matched — $($checks[$pattern])"
            $issues++
        }
    }

    # Check for suspicious Match blocks
    $matchCount = ([regex]::Matches($config, "(?im)^\s*Match\s+")).Count
    if ($matchCount -gt 0) {
        Write-Warn "  [REVIEW] $matchCount 'Match' block(s) found in sshd_config — verify expected"
    }

    # Check administrators_authorized_keys permissions
    $adminKeys = "$env:ProgramData\ssh\administrators_authorized_keys"
    if (Test-Path $adminKeys) {
        $acl = Get-Acl $adminKeys
        $nonAdminEntries = $acl.Access | Where-Object {
            $_.IdentityReference -notmatch "SYSTEM|Administrators|BUILTIN"
        }
        if ($nonAdminEntries) {
            Write-Alert "administrators_authorized_keys has non-admin ACL entries:"
            $nonAdminEntries | ForEach-Object { Write-Alert "    $($_.IdentityReference) — $($_.FileSystemRights)" }
            $issues++
        }
        Write-Info "  Reviewing administrators_authorized_keys..."
        Get-Content $adminKeys | ForEach-Object {
            if ($_ -match "^command=") {
                Write-Warn "  [REVIEW] command= restriction found in administrators_authorized_keys: $_"
            }
        }
    }

    # Check sshd service account
    $sshdSvc = Get-WmiObject Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
    if ($sshdSvc -and $sshdSvc.StartName -ne "LocalSystem" -and $sshdSvc.StartName -notmatch "NT AUTHORITY") {
        Write-Warn "  [REVIEW] sshd running as: $($sshdSvc.StartName) — verify this is expected"
    }

    if ($issues -eq 0) {
        Write-Info "No critical SSH misconfigurations detected."
    } else {
        Write-Warn "$issues issue(s) found. Review above."
    }
}

# ── Restore ───────────────────────────────────────────────────────────────────
function Invoke-Restore {
    Write-Info "=== SSH Restore ==="
    if (-not (Test-Path $LatestFile)) {
        Write-Err "No backup found. Run backup first."
        exit 1
    }

    $latestBackup = Get-Content $LatestFile -Raw | ForEach-Object { $_.Trim() }
    Write-Host "Restoring from: $(Split-Path $latestBackup -Leaf)" -ForegroundColor Yellow
    $confirm = Read-Host "Type 'CONFIRM' to proceed"
    if ($confirm -ne "CONFIRM") { Write-Info "Cancelled."; exit 0 }

    # Stop sshd before restore
    Write-Info "Stopping sshd service..."
    Stop-Service -Name "sshd" -Force -ErrorAction SilentlyContinue

    # Restore ProgramData\ssh
    $srcSshDir = Join-Path $latestBackup "ProgramData_ssh"
    if (Test-Path $srcSshDir) {
        # Archive current config
        if (Test-Path $SSHProgramDataDir) {
            Compress-Archive -Path $SSHProgramDataDir `
                -DestinationPath "${SSHProgramDataDir}_prerestore_${Timestamp}.zip" -Force
        }
        Copy-Item -Path $srcSshDir\* -Destination $SSHProgramDataDir -Recurse -Force
        Write-Info "  Restored: $SSHProgramDataDir"
    }

    # Restore per-user authorized_keys
    $userBackupDir = Join-Path $latestBackup "Users"
    if (Test-Path $userBackupDir) {
        Get-ChildItem $userBackupDir -Directory | ForEach-Object {
            $userName = $_.Name
            $srcKeys  = Join-Path $_.FullName ".ssh\authorized_keys"
            $destKeys = "C:\Users\$userName\.ssh\authorized_keys"
            if (Test-Path $srcKeys) {
                New-Item -ItemType Directory -Path (Split-Path $destKeys -Parent) -Force | Out-Null
                Copy-Item -Path $srcKeys -Destination $destKeys -Force
                Write-Info "  Restored authorized_keys for: $userName"
            }
        }
    }

    # Restart sshd
    Write-Info "Starting sshd service..."
    Start-Service -Name "sshd" -ErrorAction SilentlyContinue
    $status = (Get-Service -Name "sshd" -ErrorAction SilentlyContinue).Status
    Write-Info "  sshd status: $status"

    Write-Info "SSH restore complete."
    Write-Warn "Open a NEW session and verify SSH connectivity before closing this one."
}

# ── Entry Point ───────────────────────────────────────────────────────────────
switch ($Action) {
    "backup"  { Invoke-Backup }
    "restore" { Invoke-Restore }
    "audit"   { Invoke-Audit }
}
