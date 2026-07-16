#Requires -Version 5.1
<#
.SYNOPSIS
    Smart System Diagnoser - one-click PC health & crash analyzer for Windows.
.DESCRIPTION
    Scans Windows event logs, crash dumps, disk SMART data and hardware-error
    channels to explain WHY a PC crashed, froze, or blue-screened - then ranks
    every finding by severity and writes an HTML report it opens automatically.

    Designed to run from Run-Diagnoser.bat (which self-elevates). Can also be run
    directly:  powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1
.PARAMETER Days
    How many days of history to scan (default 7).
.PARAMETER NoHtml
    Skip the HTML report; console output only.
#>
[CmdletBinding()]
param(
    [int]$Days = 7,
    [switch]$NoHtml
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference   = 'SilentlyContinue'
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:Start    = Get-Date

# --- Bug-check (BSOD) stop-code dictionary: code -> [name, plain-language hint] ---
$BugCheckMap = @{
    0x0A = @('IRQL_NOT_LESS_OR_EQUAL',          'A driver accessed memory it should not have. Usually a bad/old driver or faulty RAM.')
    0x1A = @('MEMORY_MANAGEMENT',               'Memory management fault. Often faulty RAM, or a driver corrupting memory.')
    0x1E = @('KMODE_EXCEPTION_NOT_HANDLED',     'A kernel-mode program caused an unhandled error. Usually a driver.')
    0x3B = @('SYSTEM_SERVICE_EXCEPTION',        'Error during a system call. Often a graphics or system driver.')
    0x50 = @('PAGE_FAULT_IN_NONPAGED_AREA',     'Referenced invalid memory. Strongly suggests faulty RAM or a bad driver.')
    0x7E = @('SYSTEM_THREAD_EXCEPTION_NOT_HANDLED','A driver threw an error it could not handle. Update/roll back drivers.')
    0x7F = @('UNEXPECTED_KERNEL_MODE_TRAP',     'CPU trap, often hardware: RAM, overclock instability, or overheating.')
    0x9F = @('DRIVER_POWER_STATE_FAILURE',      'A driver did not handle sleep/wake correctly. Update chipset/USB/GPU drivers.')
    0xC2 = @('BAD_POOL_CALLER',                 'A driver misused memory pool. Faulty driver.')
    0xC5 = @('DRIVER_CORRUPTED_EXPOOL',         'A driver corrupted system memory. Faulty driver or bad RAM.')
    0xD1 = @('DRIVER_IRQL_NOT_LESS_OR_EQUAL',   'A driver accessed bad memory at high IRQL. Network/storage drivers are common culprits.')
    0xEF = @('CRITICAL_PROCESS_DIED',           'A critical Windows process died. Often corruption (run SFC/DISM) or bad drivers.')
    0xF4 = @('CRITICAL_OBJECT_TERMINATION',     'A critical system process ended unexpectedly. Often failing disk or corruption.')
    0x101= @('CLOCK_WATCHDOG_TIMEOUT',          'A CPU core stopped responding. Often unstable overclock or CPU/power issue.')
    0x109= @('CRITICAL_STRUCTURE_CORRUPTION',   'Kernel memory was corrupted. Bad RAM, driver, or tampering.')
    0x113= @('VIDEO_DXGKRNL_FATAL_ERROR',       'Graphics subsystem fault. Update or roll back GPU drivers.')
    0x116= @('VIDEO_TDR_ERROR',                 'GPU stopped responding and could not recover. GPU driver, overheating, or failing GPU.')
    0x124= @('WHEA_UNCORRECTABLE_ERROR',        'Hardware reported a fatal error (CPU/RAM/PCIe/overheat). This is HARDWARE, not software.')
    0x133= @('DPC_WATCHDOG_VIOLATION',          'A driver ran too long. Often an old SSD firmware or storage/network driver.')
    0x139= @('KERNEL_SECURITY_CHECK_FAILURE',   'Kernel detected corruption. Bad driver or faulty RAM.')
    0x154= @('UNEXPECTED_STORE_EXCEPTION',      'The memory/store backing store failed - frequently a failing disk or its cable/port.')
    0x1000007E = @('SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M','A driver threw an unhandled error. Update/roll back drivers.')
    0xBE = @('ATTEMPTED_WRITE_TO_READONLY_MEMORY','A driver tried to write read-only memory. Faulty driver.')
}

function Add-Finding {
    param(
        [ValidateSet('CRITICAL','WARNING','INFO','OK')] [string]$Severity,
        [string]$Area,
        [string]$Title,
        [string]$Detail = '',
        [datetime]$When
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Area     = $Area
        Title    = $Title
        Detail   = $Detail
        When     = $When
    })
}

function Write-Head($text) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

function Get-Events($hash) {
    Get-WinEvent -FilterHashtable $hash -ErrorAction SilentlyContinue
}

$since = (Get-Date).AddDays(-$Days)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Clear-Host
Write-Host @"
  ____  __  __   _   ___ _____   ___ ___   _   ___ _  _  ___  ___ ___ ___
 / __||  \/  | /_\ | _ \_   _| |   \_ _| /_\ / __| \| |/ _ \/ __| __| _ \
 \__ \| |\/| |/ _ \|   / | |   | |) | | / _ \ (_ | .` | (_) \__ \ _||   /
 |___/|_|  |_/_/ \_\_|_\ |_|   |___/___/_/ \_\___|_|\_|\___/|___/___|_|_\
"@ -ForegroundColor Cyan
Write-Host "  Scanning last $Days days  |  Elevated: $isAdmin  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
if (-not $isAdmin) {
    Write-Host "  NOTE: Not running as Administrator - SMART/dump-config checks may be limited." -ForegroundColor Yellow
}

# ============================================================ 1. SYSTEM OVERVIEW
Write-Head '1. System Overview'
$os  = Get-CimInstance Win32_OperatingSystem
$cs  = Get-CimInstance Win32_ComputerSystem
$bios= Get-CimInstance Win32_BIOS
$uptime = (Get-Date) - $os.LastBootUpTime
Write-Host ("  Computer    : {0}" -f $env:COMPUTERNAME)
Write-Host ("  OS          : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
Write-Host ("  Model       : {0} {1}" -f $cs.Manufacturer, $cs.Model)
Write-Host ("  CPU/RAM     : {0} logical cores, {1} GB RAM" -f $env:NUMBER_OF_PROCESSORS, [math]::Round($cs.TotalPhysicalMemory/1GB))
Write-Host ("  Last boot   : {0}  (up {1}d {2}h {3}m)" -f $os.LastBootUpTime, $uptime.Days, $uptime.Hours, $uptime.Minutes)
Add-Finding INFO 'System' "$($os.Caption) build $($os.BuildNumber) on $($cs.Manufacturer) $($cs.Model)"

# ===================================== 2. UNEXPECTED SHUTDOWNS & BLUE SCREENS
Write-Head '2. Unexpected Shutdowns & Blue Screens'

# Kernel-Power 41 (dirty shutdown) with bugcheck decode
$kp41 = Get-Events @{LogName='System';Id=41;StartTime=$since}
if ($kp41) {
    foreach ($e in $kp41) {
        $x = [xml]$e.ToXml(); $d = @{}
        $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
        $bc = 0; [void][int64]::TryParse($d['BugcheckCode'], [ref]$bc)
        $sleep = $d['SleepInProgress']; $pwr = $d['PowerButtonTimestamp']
        if ($bc -ne 0) {
            $hex = ('0x{0:X}' -f $bc)
            $info = $BugCheckMap[[int]$bc]
            $name = if ($info) { $info[0] } else { 'UNKNOWN_BUGCHECK' }
            $hint = if ($info) { $info[1] } else { 'Unrecognized stop code - search the code online.' }
            Write-Host ("  [BSOD] {0}  stop {1} {2}" -f $e.TimeCreated, $hex, $name) -ForegroundColor Red
            Add-Finding CRITICAL 'Crash' "Blue screen: $name ($hex)" "At $($e.TimeCreated). $hint" $e.TimeCreated
        }
        elseif ($pwr -ne '0' -and $pwr) {
            Write-Host ("  [POWER] {0}  shut off via power button (held)" -f $e.TimeCreated) -ForegroundColor Yellow
            Add-Finding WARNING 'Power' "Hard power-off via power button at $($e.TimeCreated)" 'User or firmware forced power off (button held).' $e.TimeCreated
        }
        else {
            Write-Host ("  [POWER-LOSS] {0}  unclean shutdown, NO bugcheck (power cut or hard lock)" -f $e.TimeCreated) -ForegroundColor Red
            Add-Finding CRITICAL 'Power' "Abrupt power loss / hard lock at $($e.TimeCreated)" 'No bugcheck recorded = power was cut faster than Windows could react. Suspect PSU, power cable, UPS, thermal cutoff, or a hard freeze.' $e.TimeCreated
        }
    }
} else {
    Write-Host '  No unexpected-shutdown (Kernel-Power 41) events. Good.' -ForegroundColor Green
    Add-Finding OK 'Power' 'No unexpected shutdowns in the scan window.'
}

# Explicit BugCheck 1001 records (extra stop-code detail)
$bcEvents = Get-Events @{LogName='System';Id=1001;StartTime=$since} | Where-Object { $_.ProviderName -match 'BugCheck' }
foreach ($b in $bcEvents) {
    $line = ($b.Message -split "`n")[0].Trim()
    Write-Host ("  [DUMP] {0}: {1}" -f $b.TimeCreated, $line) -ForegroundColor Red
    Add-Finding CRITICAL 'Crash' 'Bugcheck record found' "$($b.TimeCreated): $line" $b.TimeCreated
}

# 6008 unexpected shutdown summary
$e6008 = Get-Events @{LogName='System';Id=6008;StartTime=$since}
if ($e6008) {
    Write-Host ("  {0} 'unexpected shutdown' (6008) record(s) in window." -f $e6008.Count) -ForegroundColor Yellow
}

# =========================================================== 3. CRASH DUMPS
Write-Head '3. Crash Dump Files'
$mini = Get-ChildItem 'C:\Windows\Minidump\*.dmp' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
if ($mini) {
    Write-Host ("  {0} minidump(s) found - newest:" -f $mini.Count) -ForegroundColor Yellow
    $mini | Select-Object -First 5 | ForEach-Object { Write-Host ("    {0}  {1} ({2} KB)" -f $_.LastWriteTime, $_.Name, [math]::Round($_.Length/1KB)) }
    Add-Finding WARNING 'Crash' "$($mini.Count) crash dump(s) present in C:\Windows\Minidump" "Newest: $($mini[0].Name) @ $($mini[0].LastWriteTime). Analyze with WinDbg/BlueScreenView for the faulting driver." $mini[0].LastWriteTime
} else {
    Write-Host '  No minidumps found.' -ForegroundColor Gray
}
if (Test-Path 'C:\Windows\MEMORY.DMP') {
    $md = Get-Item 'C:\Windows\MEMORY.DMP'
    Write-Host ("  MEMORY.DMP present ({0} MB, {1})" -f [math]::Round($md.Length/1MB), $md.LastWriteTime) -ForegroundColor Yellow
    Add-Finding INFO 'Crash' "Full memory dump present ($([math]::Round($md.Length/1MB)) MB)" "Created $($md.LastWriteTime)."
}
# volmgr 161 = dump could not be written (often = disk was unresponsive during crash)
$volmgr = Get-Events @{LogName='System';ProviderName='volmgr';Id=161;StartTime=$since}
if ($volmgr) {
    Write-Host ("  [!] Dump-creation FAILED {0} time(s) (volmgr 161) - disk may have been unresponsive during the crash." -f $volmgr.Count) -ForegroundColor Red
    Add-Finding CRITICAL 'Crash' 'Crash dump could NOT be written (volmgr 161)' "$($volmgr.Count) occurrence(s). The disk Windows writes the dump to was unresponsive - a strong sign of a failing/disconnecting drive, and the reason a BSOD can freeze instead of rebooting." $volmgr[0].TimeCreated
}

# =========================================================== 4. STORAGE HEALTH
Write-Head '4. Storage / Disk Health'
# SMART health per physical disk
$pdisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
foreach ($pd in $pdisks) {
    $color = switch ($pd.HealthStatus) { 'Healthy' {'Green'} 'Warning' {'Yellow'} default {'Red'} }
    Write-Host ("  {0} [{1}] - Health: {2}, Status: {3}" -f $pd.FriendlyName, $pd.BusType, $pd.HealthStatus, $pd.OperationalStatus) -ForegroundColor $color
    if ($pd.HealthStatus -ne 'Healthy') {
        Add-Finding CRITICAL 'Disk' "Disk not healthy: $($pd.FriendlyName)" "HealthStatus=$($pd.HealthStatus), OperationalStatus=$($pd.OperationalStatus). Back up now and plan replacement."
    }
}
# Ghost / 0-byte SATA disks (failing or disconnecting drive)
$ghost = Get-CimInstance Win32_DiskDrive | Where-Object { $_.Size -eq $null -or $_.Size -eq 0 }
foreach ($g in $ghost) {
    Write-Host ("  [!] Phantom drive on bus: '{0}' interface={1}, size=0 - a drive dropping off the bus." -f $g.Model, $g.InterfaceType) -ForegroundColor Red
    Add-Finding CRITICAL 'Disk' 'Phantom/0-byte drive detected' "Interface $($g.InterfaceType), PNP $($g.PNPDeviceID). A drive that enumerates with no size is failing or has a bad cable/port. Reseat/replace its cable or disable/remove it."
}
# storahci device resets (Event 129) - disk stopped responding
$resets = Get-Events @{LogName='System';ProviderName='storahci';Id=129;StartTime=$since}
if ($resets) {
    $byDay = $resets | Group-Object { $_.TimeCreated.Date } | Sort-Object Name
    Write-Host ("  [!] {0} storage-controller resets (storahci 129) - disk stopped responding:" -f $resets.Count) -ForegroundColor Red
    $byDay | ForEach-Object { Write-Host ("       {0}: {1} reset(s)" -f ([datetime]$_.Name).ToString('yyyy-MM-dd'), $_.Count) }
    $sev = if ($resets.Count -ge 5) { 'CRITICAL' } else { 'WARNING' }
    Add-Finding $sev 'Disk' "$($resets.Count) SATA/AHCI device resets (storahci 129)" 'The disk on the AHCI controller repeatedly stopped responding. Reseat/replace the SATA data+power cable, try another port, check SMART, or replace the drive.' $resets[0].TimeCreated
} else {
    Write-Host '  No storahci device resets. Good.' -ForegroundColor Green
}
# Generic disk I/O errors (Event 7 bad block, 51 paging error, 153 retry)
$ioerr = Get-Events @{LogName='System';Id=7,51,153;StartTime=$since} | Where-Object { $_.ProviderName -match 'disk|storahci|stornvme|nvme|Ntfs|volmgr' }
if ($ioerr) {
    Write-Host ("  [!] {0} disk I/O error event(s) (7/51/153)." -f $ioerr.Count) -ForegroundColor Red
    Add-Finding WARNING 'Disk' "$($ioerr.Count) disk I/O error event(s)" "Bad-block / paging / retry errors (Event 7/51/153) indicate a struggling drive. Run chkdsk and check SMART." $ioerr[0].TimeCreated
}
# Free space on system drive
$sys = Get-PSDrive C
if ($sys) {
    $freeGB = [math]::Round($sys.Free/1GB); $totGB = [math]::Round(($sys.Used+$sys.Free)/1GB)
    $pct = if (($sys.Used+$sys.Free) -gt 0) { [math]::Round(100*$sys.Free/($sys.Used+$sys.Free)) } else { 0 }
    $col = if ($pct -lt 10) {'Red'} elseif ($pct -lt 15) {'Yellow'} else {'Green'}
    Write-Host ("  C: free space: {0} GB of {1} GB ({2}%)" -f $freeGB, $totGB, $pct) -ForegroundColor $col
    if ($pct -lt 10) { Add-Finding CRITICAL 'Disk' "Low disk space on C: ($pct% free)" 'Below 10% free can cause instability and failed updates. Free up space.' }
    elseif ($pct -lt 15) { Add-Finding WARNING 'Disk' "Disk space getting low on C: ($pct% free)" 'Consider cleaning up.' }
}

# ===================================================== 5. MEMORY & HARDWARE ERRORS
Write-Head '5. Memory & Hardware Errors'
$whea = Get-Events @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger';StartTime=$since}
if ($whea) {
    $wErr = $whea | Where-Object { $_.LevelDisplayName -in 'Error','Critical' }
    if ($wErr) {
        Write-Host ("  [!] {0} WHEA hardware-error event(s) - CPU/RAM/PCIe/thermal faults reported by hardware:" -f $wErr.Count) -ForegroundColor Red
        $wErr | Select-Object -First 3 | ForEach-Object { Write-Host ("       {0}  Id={1}  {2}" -f $_.TimeCreated, $_.Id, (($_.Message -split "`n")[0])) }
        Add-Finding CRITICAL 'Hardware' "$($wErr.Count) WHEA hardware error(s)" 'The hardware itself reported errors (machine-check). Causes: failing CPU/RAM, overheating, unstable overclock, or a bad PCIe device. Run memory test and check temps.' $wErr[0].TimeCreated
    } else {
        Write-Host ("  {0} WHEA event(s), all informational (corrected). No fatal hardware errors." -f $whea.Count) -ForegroundColor Yellow
    }
} else {
    Write-Host '  No WHEA hardware errors. Good.' -ForegroundColor Green
    Add-Finding OK 'Hardware' 'No WHEA hardware errors reported.'
}
# Windows Memory Diagnostic results
$memDiag = Get-Events @{LogName='System';ProviderName='Microsoft-Windows-MemoryDiagnostics-Results';StartTime=$since}
if ($memDiag) {
    foreach ($m in $memDiag) {
        $bad = $m.Message -match 'error|fail'
        $c = if ($bad) {'Red'} else {'Green'}
        Write-Host ("  MemoryDiagnostic {0}: {1}" -f $m.TimeCreated, (($m.Message -split "`n")[0])) -ForegroundColor $c
        if ($bad) { Add-Finding CRITICAL 'Memory' 'Windows Memory Diagnostic found errors' "$($m.TimeCreated): $(($m.Message -split "`n")[0])" $m.TimeCreated }
    }
}

# ===================================================== 6. THERMAL & POWER
Write-Head '6. Thermal & Power'
$thermal = Get-Events @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Processor-Power';Id=86,87;StartTime=$since}
$thermZone = Get-Events @{LogName='System';Id=20,21,22;StartTime=$since} | Where-Object { $_.ProviderName -match 'Thermal' }
if ($thermZone) {
    Write-Host ("  [!] {0} thermal-zone trip event(s) - the system throttled/shut down due to heat." -f $thermZone.Count) -ForegroundColor Red
    Add-Finding CRITICAL 'Thermal' "$($thermZone.Count) thermal trip event(s)" 'A component exceeded its safe temperature. Clean dust, check fans, reseat heatsink/repaste.' $thermZone[0].TimeCreated
} else {
    Write-Host '  No thermal-trip events logged.' -ForegroundColor Green
}
# Try to read current CPU temperature via WMI (works on some systems/BIOSes)
$temp = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
if ($temp) {
    $c = [math]::Round(($temp[0].CurrentTemperature/10)-273.15,1)
    $col = if ($c -ge 90) {'Red'} elseif ($c -ge 80) {'Yellow'} else {'Green'}
    Write-Host ("  Current ACPI thermal zone: {0} C" -f $c) -ForegroundColor $col
    if ($c -ge 90) { Add-Finding WARNING 'Thermal' "High temperature reading: $c C" 'Running hot. Check cooling.' }
}

# ===================================================== 7. SERVICES & APP CRASHES
Write-Head '7. Failed Services & App Crashes'
$svc = Get-Events @{LogName='System';Id=7031,7034;StartTime=$since}
if ($svc) {
    $top = $svc | ForEach-Object { ($_.Message -split "`n")[0] } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
    Write-Host ("  {0} unexpected service termination(s). Most frequent:" -f $svc.Count) -ForegroundColor Yellow
    $top | ForEach-Object { Write-Host ("       {0}x  {1}" -f $_.Count, $_.Name) }
    Add-Finding WARNING 'Services' "$($svc.Count) unexpected service crash(es)" ($top | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join '; '
} else {
    Write-Host '  No unexpected service terminations. Good.' -ForegroundColor Green
}
$appcrash = Get-Events @{LogName='Application';ProviderName='Application Error';Id=1000;StartTime=$since}
if ($appcrash) {
    $topApp = $appcrash | ForEach-Object { ($_.Properties[0].Value) } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
    Write-Host ("  {0} application crash(es). Most frequent:" -f $appcrash.Count) -ForegroundColor Yellow
    $topApp | ForEach-Object { Write-Host ("       {0}x  {1}" -f $_.Count, $_.Name) }
    Add-Finding INFO 'Apps' "$($appcrash.Count) application crash(es)" (($topApp | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join '; ')
} else {
    Write-Host '  No application crashes logged.' -ForegroundColor Green
}

# ===================================================== 8. PENDING / UPDATE ISSUES
Write-Head '8. Updates & Pending Reboot'
$updFail = Get-Events @{LogName='System';ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=20;StartTime=$since}
if ($updFail) {
    Write-Host ("  {0} failed Windows Update installation(s)." -f $updFail.Count) -ForegroundColor Yellow
    Add-Finding WARNING 'Updates' "$($updFail.Count) failed Windows Update(s)" 'Repeated update failures can leave the system in a partially-patched state. Run the Windows Update troubleshooter.' $updFail[0].TimeCreated
}
$pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or `
           (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
if ($pending) {
    Write-Host '  A reboot is PENDING (servicing/update).' -ForegroundColor Yellow
    Add-Finding WARNING 'Updates' 'Reboot pending' 'Windows is waiting for a restart to finish servicing.'
}

# ===================================================== SUMMARY
Write-Head 'DIAGNOSIS SUMMARY'
$order = @{ 'CRITICAL'=0; 'WARNING'=1; 'INFO'=2; 'OK'=3 }
$ranked = $script:Findings | Sort-Object { $order[$_.Severity] }, { if ($_.When) { - $_.When.Ticks } else { 0 } }
$crit = ($ranked | Where-Object Severity -eq 'CRITICAL')
$warn = ($ranked | Where-Object Severity -eq 'WARNING')

if ($crit.Count -eq 0 -and $warn.Count -eq 0) {
    Write-Host "`n  No critical or warning issues found in the last $Days days. System looks healthy." -ForegroundColor Green
} else {
    Write-Host ("`n  {0} CRITICAL, {1} WARNING finding(s):`n" -f $crit.Count, $warn.Count) -ForegroundColor White
}
foreach ($f in $ranked | Where-Object Severity -in 'CRITICAL','WARNING') {
    $c = if ($f.Severity -eq 'CRITICAL') {'Red'} else {'Yellow'}
    Write-Host ("  [{0,-8}] {1,-9} {2}" -f $f.Severity, $f.Area, $f.Title) -ForegroundColor $c
    if ($f.Detail) { Write-Host ("             -> {0}" -f $f.Detail) -ForegroundColor DarkGray }
}

# Likely root-cause heuristic
Write-Host ''
$rootCause = $null
if ($script:Findings | Where-Object { $_.Title -match 'Phantom|storahci|UNEXPECTED_STORE|not healthy|dump could NOT' }) {
    $rootCause = 'STORAGE: a drive is failing or disconnecting (cable/port/disk). Back up, reseat/replace the SATA cable, test SMART, or replace the drive.'
} elseif ($script:Findings | Where-Object { $_.Title -match 'WHEA' }) {
    $rootCause = 'HARDWARE: the hardware reported machine-check errors. Test RAM (MemTest86), check CPU temps, and review any overclock.'
} elseif ($script:Findings | Where-Object { $_.Title -match 'Abrupt power loss|power button|thermal trip' }) {
    $rootCause = 'POWER/THERMAL: the system lost power with no bugcheck. Suspect PSU, power cable, UPS, or thermal cutoff.'
} elseif ($crit | Where-Object { $_.Title -match 'Blue screen' }) {
    $rootCause = 'DRIVER/SOFTWARE: a blue screen with a stop code was recorded. Analyze the minidump (BlueScreenView/WinDbg) to find the faulting driver.'
}
if ($rootCause) {
    Write-Host '  MOST LIKELY ROOT CAUSE:' -ForegroundColor Magenta
    Write-Host "    $rootCause" -ForegroundColor White
}

# ===================================================== HTML REPORT
if (-not $NoHtml) {
    $reportDir = Join-Path $PSScriptRoot 'Reports'
    if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $reportPath = Join-Path $reportDir "Diagnosis_$($env:COMPUTERNAME)_$stamp.html"
    $rowColor = @{ 'CRITICAL'='#ffd6d6'; 'WARNING'='#fff2cc'; 'INFO'='#e8f0fe'; 'OK'='#dcffe0' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<html><head><meta charset='utf-8'><title>System Diagnosis - $env:COMPUTERNAME</title><style>")
    [void]$sb.Append("body{font-family:Segoe UI,Arial;margin:24px;background:#f7f7f9;color:#222}h1{color:#0a5}")
    [void]$sb.Append("table{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 4px #0002}th,td{border:1px solid #ddd;padding:8px 10px;text-align:left;vertical-align:top}th{background:#0a5;color:#fff}")
    [void]$sb.Append(".sev{font-weight:bold}.meta{color:#666;margin-bottom:16px}</style></head><body>")
    [void]$sb.Append("<h1>Smart System Diagnoser</h1>")
    [void]$sb.Append("<div class='meta'><b>$env:COMPUTERNAME</b> &middot; $($os.Caption) build $($os.BuildNumber) &middot; $($cs.Manufacturer) $($cs.Model)<br>")
    [void]$sb.Append("Scanned last $Days days &middot; Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')<br>")
    [void]$sb.Append("<b>$($crit.Count) critical</b>, $($warn.Count) warning finding(s)</div>")
    if ($rootCause) { [void]$sb.Append("<p style='background:#fde;padding:12px;border-left:4px solid #c09'><b>Most likely root cause:</b> $([System.Web.HttpUtility]::HtmlEncode($rootCause))</p>") }
    [void]$sb.Append("<table><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Detail</th><th>When</th></tr>")
    foreach ($f in $ranked) {
        $bg = $rowColor[$f.Severity]
        $when = if ($f.When) { $f.When.ToString('yyyy-MM-dd HH:mm') } else { '' }
        $enc = { param($s) if ($s) { ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;') } else { '' } }
        [void]$sb.Append("<tr style='background:$bg'><td class='sev'>$($f.Severity)</td><td>$($f.Area)</td><td>$(& $enc $f.Title)</td><td>$(& $enc $f.Detail)</td><td>$when</td></tr>")
    }
    [void]$sb.Append("</table><p class='meta'>Generated by SystemDiagnoser.ps1</p></body></html>")
    Set-Content -Path $reportPath -Value $sb.ToString() -Encoding UTF8
    Write-Host "`n  HTML report saved: $reportPath" -ForegroundColor Cyan
    Start-Process $reportPath
}

Write-Host ("`n  Done in {0:n1}s.`n" -f ((Get-Date) - $script:Start).TotalSeconds) -ForegroundColor DarkGray
if ($host.Name -eq 'ConsoleHost' -and -not $env:CI) {
    Write-Host '  Press any key to close...' -ForegroundColor DarkGray
    $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}
