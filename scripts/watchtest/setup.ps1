# Sentinel v0.1.1 watch-test setup
# Run from an elevated (admin) PowerShell.
#
# What this script does:
#   1. Verifies admin
#   2. Detects active network adapter
#   3. Records current DNS for restore (writes ./.dns-backup.json)
#   4. Sets adapter DNS to 127.0.0.1
#   5. Starts sentinel.exe in a new window
#   6. Tells you when block-page is reachable
#
# Reverse with .\uninstall.ps1 from the same directory.

$ErrorActionPreference = 'Stop'

# 1. Admin check
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: must run from elevated (admin) PowerShell." -ForegroundColor Red
    Write-Host "Right-click PowerShell -> 'Run as administrator', then re-run this script."
    exit 1
}

# 2. Detect active up adapter
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
if (-not $adapter) {
    Write-Host "ERROR: no active network adapter found. Connect to a network and re-run." -ForegroundColor Red
    exit 1
}
Write-Host "Active adapter: $($adapter.Name) ($($adapter.InterfaceDescription))"

# 3. Backup current DNS (per IP family)
$currentV4 = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4).ServerAddresses
$currentV6 = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv6).ServerAddresses

$backup = [PSCustomObject]@{
    AdapterName = $adapter.Name
    IPv4        = @($currentV4)
    IPv6        = @($currentV6)
    BackedUpAt  = (Get-Date).ToString('o')
}
$backupPath = Join-Path $PSScriptRoot '.dns-backup.json'
$backup | ConvertTo-Json -Depth 4 | Out-File -FilePath $backupPath -Encoding utf8
Write-Host "DNS backup written to $backupPath"

# 4. Swap to 127.0.0.1
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses 127.0.0.1
Clear-DnsClientCache
Write-Host "DNS on '$($adapter.Name)' is now 127.0.0.1"

# 5. Start sentinel.exe with `service` subcommand and redirect output to a log file.
#    Without `service` the binary prints help text and exits immediately
#    (see src/main.rs). The log file is the only way Yami / the dev sees a
#    panic message; Start-Process closes the window on exit.
$exePath = Join-Path $PSScriptRoot 'sentinel.exe'
if (-not (Test-Path $exePath)) {
    Write-Host "ERROR: sentinel.exe not found at $exePath" -ForegroundColor Red
    Write-Host "Place sentinel.exe in this folder and re-run." -ForegroundColor Red
    exit 1
}
$logPath    = Join-Path $PSScriptRoot 'sentinel.log'
$errPath    = Join-Path $PSScriptRoot 'sentinel.err.log'
$pidPath    = Join-Path $PSScriptRoot '.sentinel.pid'
Write-Host "Starting sentinel.exe service (log: $logPath)..."
$proc = Start-Process -FilePath $exePath `
    -ArgumentList 'service' `
    -WorkingDirectory $PSScriptRoot `
    -RedirectStandardOutput $logPath `
    -RedirectStandardError  $errPath `
    -WindowStyle Hidden `
    -PassThru
$proc.Id | Out-File -FilePath $pidPath -Encoding ascii

# 5b. Register a Task Scheduler entry so sentinel.exe restarts after reboot.
#     Watch-test only path — v0.1 release will use a real Windows Service.
#     Registers as the current user, runs at logon with highest privileges.
#     The wrapper script preserves stdout/stderr redirection across reboots.
$wrapperPath = Join-Path $PSScriptRoot 'sentinel-autostart.ps1'
$wrapperScript = @'
# Auto-start wrapper for Sentinel watch-test. Registered by setup.ps1.
# Unregistered by uninstall.ps1.
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe  = Join-Path $root 'sentinel.exe'
$log  = Join-Path $root 'sentinel.log'
$err  = Join-Path $root 'sentinel.err.log'
$pidF = Join-Path $root '.sentinel.pid'
if (-not (Test-Path $exe)) { exit 1 }
$p = Start-Process -FilePath $exe -ArgumentList 'service' `
    -WorkingDirectory $root `
    -RedirectStandardOutput $log -RedirectStandardError $err `
    -WindowStyle Hidden -PassThru
$p.Id | Out-File -FilePath $pidF -Encoding ascii
'@
Set-Content -Path $wrapperPath -Value $wrapperScript -Encoding utf8

$taskName = 'SentinelWatchtest'
# Drop any prior registration before re-creating, so re-running setup is idempotent.
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$wrapperPath`""
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings | Out-Null
Write-Host "Auto-start registered: scheduled task '$taskName' runs at logon as $env:USERNAME"

# Brief health check: sentinel needs ~1s to bind ports. If it exited
# already, surface stderr immediately so the operator isn't left guessing.
Start-Sleep -Seconds 2
$running = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
if (-not $running) {
    Write-Host ""
    Write-Host "ERROR: sentinel.exe exited within 2 seconds of starting." -ForegroundColor Red
    if (Test-Path $errPath) {
        Write-Host "--- stderr ---" -ForegroundColor Red
        Get-Content $errPath
        Write-Host "--- end stderr ---" -ForegroundColor Red
    }
    Write-Host "DNS is currently still pointing at 127.0.0.1 with no resolver." -ForegroundColor Red
    Write-Host "Run .\uninstall.ps1 NOW to restore your DNS, then report this output." -ForegroundColor Red
    exit 1
}

# 6. Block-page reachability hint
Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "  - Resolver listening on 127.0.0.1:53"
Write-Host "  - Block-page on http://127.0.0.1/"
Write-Host ""
Write-Host "Try: open a browser and visit a URLhaus-listed domain (or any test site)."
Write-Host "If it is on the block-list you'll see the Sentinel block-page. If it isn't,"
Write-Host "the site loads normally."
Write-Host ""
Write-Host "When done testing, run .\uninstall.ps1 from this folder to revert."
