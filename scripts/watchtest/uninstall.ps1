# Sentinel v0.1.1 watch-test uninstall
# Run from an elevated (admin) PowerShell, from the same folder you ran setup.ps1.
#
# What this script does:
#   1. Verifies admin
#   2. Stops sentinel.exe processes
#   3. Restores adapter DNS from .dns-backup.json (or resets to DHCP if missing)
#   4. Flushes DNS cache

$ErrorActionPreference = 'Stop'

# 1. Admin check
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: must run from elevated (admin) PowerShell." -ForegroundColor Red
    exit 1
}

# 2a. Unregister the auto-start scheduled task BEFORE killing sentinel.exe,
#     so the task can't re-spawn the process between our kill and DNS revert.
$taskName = 'SentinelWatchtest'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "Unregistering scheduled task '$taskName'..."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
} else {
    Write-Host "No scheduled task '$taskName' registered."
}
$wrapperPath = Join-Path $PSScriptRoot 'sentinel-autostart.ps1'
if (Test-Path $wrapperPath) { Remove-Item $wrapperPath -ErrorAction SilentlyContinue }

# 2b. Stop sentinel.exe — prefer the PID file written by setup.ps1, fall
#    back to name-match so this script also works for ad-hoc kills.
$pidPath = Join-Path $PSScriptRoot '.sentinel.pid'
$stopped = $false
if (Test-Path $pidPath) {
    $sentinelPid = (Get-Content $pidPath -Raw).Trim()
    if ($sentinelPid -match '^\d+$') {
        $proc = Get-Process -Id $sentinelPid -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "Stopping sentinel.exe (pid $sentinelPid from .sentinel.pid)..."
            Stop-Process -Id $sentinelPid -Force
            $stopped = $true
        }
    }
    Remove-Item $pidPath -ErrorAction SilentlyContinue
}
if (-not $stopped) {
    $procs = Get-Process -Name sentinel -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Host "Stopping sentinel.exe ($($procs.Count) process(es) by name)..."
        $procs | Stop-Process -Force
        $stopped = $true
    }
}
if (-not $stopped) {
    Write-Host "No sentinel.exe process running."
}

# 3. Restore DNS
$backupPath = Join-Path $PSScriptRoot '.dns-backup.json'
if (Test-Path $backupPath) {
    $backup = Get-Content $backupPath -Raw | ConvertFrom-Json
    $adapterName = $backup.AdapterName
    Write-Host "Restoring DNS on '$adapterName' from $backupPath"

    if ($backup.IPv4 -and $backup.IPv4.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses $backup.IPv4
    } else {
        Set-DnsClientServerAddress -InterfaceAlias $adapterName -ResetServerAddresses
    }
    if ($backup.IPv6 -and $backup.IPv6.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceAlias $adapterName -ServerAddresses $backup.IPv6
    }
} else {
    Write-Host "No DNS backup found; resetting all 'Up' adapters to DHCP defaults." -ForegroundColor Yellow
    Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | ForEach-Object {
        Set-DnsClientServerAddress -InterfaceAlias $_.Name -ResetServerAddresses
    }
}

# 4. Flush
Clear-DnsClientCache
Write-Host ""
Write-Host "Uninstall complete." -ForegroundColor Green
Write-Host "Sentinel stopped, DNS restored, cache flushed."
