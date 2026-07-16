#Requires -Version 5.1
<#
.SYNOPSIS
    Crash-Tshoot - Smart System Diagnoser + Advanced Event Viewer.
.DESCRIPTION
    One-click PC crash/health analyzer and FullEventLogView-class event browser.
    Scans event logs, dumps, SMART, WHEA, LiveKernel/GPU signals; ranks root cause;
    writes HTML (with interactive Event Browser), JSON trends, and optional exports.

    Launchers: Run-Diagnoser.bat | Run-Diagnoser-Remote.bat | Run-EventViewer.bat
.PARAMETER Days
    Days of history to scan (default 7). Ignored if StartTime/EndTime set.
.PARAMETER NoHtml
    Skip HTML report.
.PARAMETER ComputerName
    Remote host for SSH collector.
.PARAMETER SshUser
    SSH username (default: current Windows user).
.PARAMETER FullEventScan
    Scan Critical/Error across all enabled channels (Event Viewer mode).
.PARAMETER Preset
    Custom view: CriticalErrors, BootShutdown, BSODPower, Storage, GPUDisplay,
    SecurityLogon, WHEA, AllWarningsPlus (or Diagnose for full crash scan).
.PARAMETER Level
    Event levels to include (Critical, Error, Warning, Information, Verbose).
.PARAMETER EventId
    Comma-separated Event IDs.
.PARAMETER Provider
    Provider name filter (wildcard * supported).
.PARAMETER Channel
    Channel/log name filter (wildcard * supported).
.PARAMETER MessageContains
    Substring search in rendered message.
.PARAMETER StartTime / EndTime
    Explicit time window.
.PARAMETER EvtxPath
    Single offline .evtx file.
.PARAMETER LogFolder
    Folder of offline .evtx files.
.PARAMETER Export
    Comma list: Csv,Json,Xml,Html (event exports under Reports\).
.PARAMETER ExportEvtx
    Also try wevtutil channel snapshot to .evtx.
.PARAMETER MaxEvents
    Cap for event browser / full scan (default 5000).
.PARAMETER EventViewerMode
    Shortcut: FullEventScan + CriticalErrors preset + Csv,Json export.
#>
[CmdletBinding()]
param(
    [int]$Days = 7,
    [switch]$NoHtml,
    [string]$ComputerName = '',
    [string]$SshUser = '',
    [switch]$FullEventScan,
    [string]$Preset = 'Diagnose',
    [string[]]$Level = @(),
    [string]$EventId = '',
    [string]$Provider = '',
    [string]$Channel = '',
    [string]$MessageContains = '',
    [datetime]$StartTime,
    [datetime]$EndTime,
    [string]$EvtxPath = '',
    [string]$LogFolder = '',
    [string]$Export = 'Json',
    [switch]$ExportEvtx,
    [int]$MaxEvents = 5000,
    [switch]$EventViewerMode
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference   = 'SilentlyContinue'
$script:Findings      = New-Object System.Collections.Generic.List[object]
$script:BrowserEvents = New-Object System.Collections.Generic.List[object]
$script:Timeline      = New-Object System.Collections.Generic.List[object]
$script:ChannelInventory = New-Object System.Collections.Generic.List[object]
$script:Counters      = @{
    KP41 = 0; BugCheck = 0; StorAhci129 = 0; StorNvme129 = 0
    WHEA = 0; LiveKernel193 = 0; DisplayTDR = 0; Volmgr161 = 0
    FreePct = $null; GpuName = ''
}
$script:Start         = Get-Date
$script:Snapshot      = @{}
$script:IsRemote      = $false
$script:TargetName    = $env:COMPUTERNAME

if ($EventViewerMode) {
    $FullEventScan = $true
    if ($Preset -eq 'Diagnose') { $Preset = 'CriticalErrors' }
    if ($Export -eq 'Json') { $Export = 'Csv,Json' }
}

# --- Stop codes & live dumps ---
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

$LiveDumpMap = @{
    0x193 = @('VIDEO_DXGKRNL_LIVEDUMP', 'Graphics kernel (dxgkrnl) captured a live dump - usually GPU/display driver instability, not a fatal BSOD. Update/roll back GPU drivers; check LiveKernelReports WATCHDOG dumps.')
    0x144 = @('USB3_LIVEDUMP', 'USB3 stack live dump. Check USB controllers/devices.')
    0x15C = @('PDC_WATCHDOG_TIMEOUT_LIVEDUMP', 'Power-state watchdog live dump (connected standby).')
    0x15E = @('NDIS_DRIVER_LIVE_DUMP', 'Network driver live dump.')
    0x190 = @('WIN32K_CRITICAL_FAILURE_LIVEDUMP', 'Win32k critical failure live dump.')
}

$GpuHeavyApps = @('sunshine.exe','nvcontainer.exe','nvidia share.exe','amd adrenaline','obs64.exe','obs32.exe','discord.exe','steamwebhelper.exe')

# ============================================================ HELPERS
function Add-Finding {
    param(
        [ValidateSet('CRITICAL','WARNING','INFO','OK')] [string]$Severity,
        [string]$Area,
        [string]$Title,
        [string]$Detail = '',
        [datetime]$When,
        [string]$Action = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Area     = $Area
        Title    = $Title
        Detail   = $Detail
        When     = if ($When) { $When } else { $null }
        Action   = $Action
    })
}

function Write-Head($text) {
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor DarkCyan
}

function Escape-Html([string]$s) {
    if ([string]::IsNullOrEmpty($s)) { return '' }
    ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')
}

function Get-LevelName([int]$lvl) {
    switch ($lvl) {
        1 { 'Critical' }
        2 { 'Error' }
        3 { 'Warning' }
        4 { 'Information' }
        5 { 'Verbose' }
        default { "Level$lvl" }
    }
}

function ConvertTo-EventObj {
    param($Evt)
    if (-not $Evt) { return $null }
    $data = @{}
    try {
        $x = [xml]$Evt.ToXml()
        if ($x.Event.EventData.Data) {
            foreach ($d in @($x.Event.EventData.Data)) {
                $n = if ($d.Name) { [string]$d.Name } else { "Data$($data.Count)" }
                $data[$n] = [string]$d.'#text'
            }
        }
    } catch {}
    $msg = ''
    try { $msg = $Evt.Message } catch { $msg = '' }
    if (-not $msg) { $msg = '' }
    $chan = ''
    try { $chan = $Evt.LogName } catch {}
    [pscustomobject]@{
        TimeCreated = $Evt.TimeCreated
        Id          = [int]$Evt.Id
        Level       = Get-LevelName ([int]$Evt.Level)
        LevelRaw    = [int]$Evt.Level
        Provider    = [string]$Evt.ProviderName
        Channel     = [string]$chan
        Message     = [string]$msg
        Task        = [string]$Evt.TaskDisplayName
        Opcode      = [string]$Evt.OpcodeDisplayName
        EventData   = $data
        Xml         = $null
    }
}

function Add-BrowserEvent($obj, [switch]$AlsoTimeline) {
    if (-not $obj) { return }
    if ($script:BrowserEvents.Count -ge $MaxEvents) { return }
    $script:BrowserEvents.Add($obj)
    if ($AlsoTimeline -and $obj.LevelRaw -le 2) {
        $script:Timeline.Add($obj)
    }
}

function Get-EventsLocal {
    param([hashtable]$Hash, [int]$Max = 0)
    try {
        if ($Max -gt 0) {
            $r = @(Get-WinEvent -FilterHashtable $Hash -MaxEvents $Max -ErrorAction SilentlyContinue)
        } else {
            $r = @(Get-WinEvent -FilterHashtable $Hash -ErrorAction SilentlyContinue)
        }
    } catch { $r = @() }
    return $r
}

function Test-WildcardMatch([string]$text, [string]$pattern) {
    if ([string]::IsNullOrWhiteSpace($pattern)) { return $true }
    if ([string]::IsNullOrEmpty($text)) { return $false }
    $rx = '^' + ([regex]::Escape($pattern) -replace '\\\*','.*' -replace '\\\?','.') + '$'
    return [regex]::IsMatch($text, $rx, 'IgnoreCase')
}

function Get-TimeWindow {
    $end = if ($EndTime) { $EndTime } else { Get-Date }
    $start = if ($StartTime) { $StartTime } else { $end.AddDays(-$Days) }
    return @{ Start = $start; End = $end }
}

# ============================================================ PRESETS
function Get-PresetSpec([string]$name) {
    switch ($name) {
        'CriticalErrors' {
            @{ Levels = @(1,2); EventIds = @(); Providers = @(); Channels = @(); AllChannels = $true }
        }
        'BootShutdown' {
            @{ Levels = @(); EventIds = @(6005,6006,6008,1074,41); Providers = @('EventLog','Microsoft-Windows-Kernel-Power','User32','Microsoft-Windows-Kernel-Boot'); Channels = @('System'); AllChannels = $false }
        }
        'BSODPower' {
            @{ Levels = @(); EventIds = @(41,1001); Providers = @('Microsoft-Windows-Kernel-Power','Microsoft-Windows-WER-SystemErrorReporting','BugCheck','Microsoft-Windows-WHEA-Logger'); Channels = @('System'); AllChannels = $false }
        }
        'Storage' {
            @{ Levels = @(); EventIds = @(7,51,129,153,161); Providers = @('storahci','stornvme','disk','Ntfs','volmgr','Microsoft-Windows-StorageSpaces-Driver'); Channels = @('System'); AllChannels = $false }
        }
        'GPUDisplay' {
            @{ Levels = @(); EventIds = @(4101,14,153); Providers = @('Display','Microsoft-Windows-DxgKrnl','nvlddmkm','amdkmdag','igfx'); Channels = @('System','Application'); AllChannels = $false }
        }
        'SecurityLogon' {
            @{ Levels = @(); EventIds = @(4624,4625,4634,4648,4672); Providers = @('Microsoft-Windows-Security-Auditing'); Channels = @('Security'); AllChannels = $false }
        }
        'WHEA' {
            @{ Levels = @(); EventIds = @(); Providers = @('Microsoft-Windows-WHEA-Logger'); Channels = @('System'); AllChannels = $false }
        }
        'AllWarningsPlus' {
            @{ Levels = @(1,2,3); EventIds = @(); Providers = @(); Channels = @(); AllChannels = $true }
        }
        default { $null }
    }
}

# ============================================================ EVENT ENGINE
function Get-ChannelInventory {
    Write-Head 'Event Log Channel Inventory'
    $logs = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled -or $_.RecordCount -gt 0 })
    $n = 0
    foreach ($l in ($logs | Sort-Object LogName)) {
        $n++
        $sizeMB = if ($l.FileSize) { [math]::Round($l.FileSize/1MB, 2) } else { 0 }
        $script:ChannelInventory.Add([pscustomobject]@{
            Name = $l.LogName; Enabled = $l.IsEnabled; Records = $l.RecordCount
            SizeMB = $sizeMB; LastWrite = $l.LastWriteTime
        })
        if ($sizeMB -ge 200) {
            Add-Finding WARNING 'EventLog' "Large event channel: $($l.LogName)" "Size ${sizeMB} MB, $($l.RecordCount) records. Consider archiving or increasing retention carefully." -Action 'Export then clear old events if disk is tight.'
        }
    }
    Write-Host ("  {0} channel(s) enumerated." -f $script:ChannelInventory.Count) -ForegroundColor Gray
    Add-Finding INFO 'EventLog' "$($script:ChannelInventory.Count) event channel(s) on system" 'Inventory available in HTML report.'
}

function Invoke-EventQuery {
    param(
        [datetime]$Since,
        [datetime]$Until,
        [int[]]$Levels = @(),
        [int[]]$Ids = @(),
        [string[]]$Providers = @(),
        [string[]]$Channels = @(),
        [bool]$AllChannels = $false,
        [string]$MsgFilter = '',
        [string]$ProviderWild = '',
        [string]$ChannelWild = '',
        [int]$Cap = 2000
    )
    $collected = New-Object System.Collections.Generic.List[object]
    $targetChannels = @()
    if ($AllChannels -or $FullEventScan) {
        $targetChannels = @(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.IsEnabled -and $_.RecordCount -gt 0 } |
            Select-Object -ExpandProperty LogName)
    } elseif ($Channels.Count -gt 0) {
        $targetChannels = $Channels
    } else {
        $targetChannels = @('System','Application')
    }

    if ($ChannelWild) {
        $targetChannels = @($targetChannels | Where-Object { Test-WildcardMatch $_ $ChannelWild })
    }

    foreach ($ch in $targetChannels) {
        if ($collected.Count -ge $Cap) { break }
        $hash = @{ LogName = $ch; StartTime = $Since }
        if ($Until -and $Until -lt (Get-Date).AddMinutes(-1)) {
            # EndTime not always supported in FilterHashtable on older hosts; filter later
        }
        if ($Ids.Count -gt 0) { $hash['Id'] = $Ids }
        if ($Levels.Count -eq 1) { $hash['Level'] = $Levels[0] }
        elseif ($Levels.Count -gt 1 -and $Levels.Count -le 3 -and -not ($Ids.Count -gt 0)) {
            # Get-WinEvent Level multi can be flaky; query without and filter
        }
        try {
            $evts = @(Get-WinEvent -FilterHashtable $hash -MaxEvents ($Cap - $collected.Count) -ErrorAction SilentlyContinue)
        } catch { $evts = @() }
        foreach ($e in $evts) {
            if ($e.TimeCreated -gt $Until) { continue }
            if ($Levels.Count -gt 0 -and ($Levels -notcontains [int]$e.Level)) { continue }
            if ($Providers.Count -gt 0) {
                $ok = $false
                foreach ($p in $Providers) {
                    if ($e.ProviderName -like "*$p*" -or $e.ProviderName -eq $p) { $ok = $true; break }
                }
                if (-not $ok) { continue }
            }
            if ($ProviderWild -and -not (Test-WildcardMatch $e.ProviderName $ProviderWild)) { continue }
            $obj = ConvertTo-EventObj $e
            if ($MsgFilter -and ($obj.Message -notmatch [regex]::Escape($MsgFilter))) { continue }
            $collected.Add($obj)
            if ($collected.Count -ge $Cap) { break }
        }
    }
    return $collected
}

function Apply-CliEventFilters {
    param($Window)
    $ids = @()
    if ($EventId) { $ids = @($EventId -split ',' | ForEach-Object { [int]$_.Trim() } | Where-Object { $_ -gt 0 }) }
    $lvlMap = @{ Critical=1; Error=2; Warning=3; Information=4; Verbose=5 }
    $lvls = @()
    foreach ($l in $Level) {
        if ($lvlMap.ContainsKey($l)) { $lvls += $lvlMap[$l] }
        elseif ($l -as [int]) { $lvls += [int]$l }
    }
    $spec = Get-PresetSpec $Preset
    if ($spec) {
        if ($spec.Levels.Count -gt 0 -and $lvls.Count -eq 0) { $lvls = $spec.Levels }
        if ($spec.EventIds.Count -gt 0 -and $ids.Count -eq 0) { $ids = $spec.EventIds }
        $prov = $spec.Providers
        $chans = $spec.Channels
        $all = $spec.AllChannels -or $FullEventScan
        Write-Head "Event Viewer Preset: $Preset"
        $evts = Invoke-EventQuery -Since $Window.Start -Until $Window.End -Levels $lvls -Ids $ids `
            -Providers $prov -Channels $chans -AllChannels $all -MsgFilter $MessageContains `
            -ProviderWild $Provider -ChannelWild $Channel -Cap $MaxEvents
        foreach ($o in $evts) { Add-BrowserEvent $o -AlsoTimeline }
        Write-Host ("  Matched {0} event(s)." -f $evts.Count) -ForegroundColor Yellow
        return $evts
    }
    if ($FullEventScan -or $EventId -or $Level.Count -gt 0 -or $Provider -or $Channel -or $MessageContains) {
        Write-Head 'Event Viewer Custom Filter'
        $evts = Invoke-EventQuery -Since $Window.Start -Until $Window.End -Levels $lvls -Ids $ids `
            -Providers @() -Channels @() -AllChannels $FullEventScan -MsgFilter $MessageContains `
            -ProviderWild $Provider -ChannelWild $Channel -Cap $MaxEvents
        foreach ($o in $evts) { Add-BrowserEvent $o -AlsoTimeline }
        Write-Host ("  Matched {0} event(s)." -f $evts.Count) -ForegroundColor Yellow
        return $evts
    }
    return @()
}

function Import-OfflineEvtx {
    param($Window)
    $files = @()
    if ($EvtxPath -and (Test-Path $EvtxPath)) { $files += Get-Item $EvtxPath }
    if ($LogFolder -and (Test-Path $LogFolder)) {
        $files += Get-ChildItem $LogFolder -Filter '*.evtx' -Recurse -ErrorAction SilentlyContinue
    }
    if ($files.Count -eq 0) { return @() }
    Write-Head 'Offline EVTX Import'
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        Write-Host ("  Loading {0}..." -f $f.FullName) -ForegroundColor Gray
        try {
            $evts = @(Get-WinEvent -Path $f.FullName -ErrorAction SilentlyContinue)
        } catch { $evts = @() }
        foreach ($e in $evts) {
            if ($e.TimeCreated -lt $Window.Start -or $e.TimeCreated -gt $Window.End) { continue }
            $obj = ConvertTo-EventObj $e
            $obj.Channel = if ($obj.Channel) { $obj.Channel } else { $f.BaseName }
            $list.Add($obj)
            Add-BrowserEvent $obj -AlsoTimeline
            if ($list.Count -ge $MaxEvents) { break }
        }
        if ($list.Count -ge $MaxEvents) { break }
    }
    Write-Host ("  Imported {0} event(s) from {1} file(s)." -f $list.Count, $files.Count) -ForegroundColor Yellow
    Add-Finding INFO 'EventLog' "Offline EVTX: $($list.Count) events from $($files.Count) file(s)" ($files | Select-Object -ExpandProperty Name) -join ', '
    return $list
}

# ============================================================ REMOTE SSH
function Invoke-RemoteDiagnosis {
    param([string]$HostName, [string]$User, [int]$DayCount)
    if (-not $User) { $User = $env:USERNAME }
    $sshTarget = "${User}@${HostName}"
    Write-Head "Remote SSH: $sshTarget"
    if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
        Add-Finding CRITICAL 'Remote' 'OpenSSH client (ssh) not found' 'Install OpenSSH Client optional feature.' -Action 'Settings > Apps > Optional features > OpenSSH Client'
        return $false
    }
    $remoteScript = @'
$ErrorActionPreference="SilentlyContinue"; $Days=DAYS_PLACEHOLDER; $since=(Get-Date).AddDays(-$Days)
$out=@{ ComputerName=$env:COMPUTERNAME; OS=(Get-CimInstance Win32_OperatingSystem).Caption; Build=(Get-CimInstance Win32_OperatingSystem).BuildNumber; Findings=@(); Counters=@{KP41=0;StorAhci129=0;StorNvme129=0;WHEA=0;LiveKernel193=0;DisplayTDR=0;FreePct=0}; Gpu="" }
function AF($s,$a,$t,$d=""){ $out.Findings += @{Severity=$s;Area=$a;Title=$t;Detail=$d;When=$null} }
$os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem
$out.OS=$os.Caption; $out.Build=$os.BuildNumber
$gpu=(Get-CimInstance Win32_VideoController | Select-Object -First 1).Name; $out.Gpu=$gpu
$sys=Get-PSDrive C; if($sys){ $out.Counters.FreePct=[math]::Round(100*$sys.Free/($sys.Used+$sys.Free)) }
$kp=@(Get-WinEvent -FilterHashtable @{LogName="System";Id=41;StartTime=$since} -EA SilentlyContinue)
$out.Counters.KP41=$kp.Count
foreach($e in $kp){ $x=[xml]$e.ToXml(); $d=@{}; $x.Event.EventData.Data|%{ $d[$_.Name]=$_."#text" }; $bc=0; [void][int64]::TryParse($d["BugcheckCode"],[ref]$bc); if($bc -ne 0){ AF "CRITICAL" "Crash" ("Blue screen code "+$bc) ("At "+$e.TimeCreated) } else { AF "CRITICAL" "Power" ("Abrupt power loss at "+$e.TimeCreated) "No bugcheck" } }
$sa=@(Get-WinEvent -FilterHashtable @{LogName="System";ProviderName="storahci";Id=129;StartTime=$since} -EA SilentlyContinue); $out.Counters.StorAhci129=$sa.Count; if($sa.Count -gt 0){ AF "CRITICAL" "Disk" "$($sa.Count) storahci 129 resets" "" }
$sn=@(Get-WinEvent -FilterHashtable @{LogName="System";ProviderName="stornvme";Id=129;StartTime=$since} -EA SilentlyContinue); $out.Counters.StorNvme129=$sn.Count; if($sn.Count -gt 0){ AF "CRITICAL" "Disk" "$($sn.Count) stornvme 129 resets" "" }
$wh=@(Get-WinEvent -FilterHashtable @{LogName="System";ProviderName="Microsoft-Windows-WHEA-Logger";StartTime=$since} -EA SilentlyContinue|?{$_.Level -le 2}); $out.Counters.WHEA=$wh.Count; if($wh.Count -gt 0){ AF "CRITICAL" "Hardware" "$($wh.Count) WHEA errors" "" }
$td=@(Get-WinEvent -FilterHashtable @{LogName="System";ProviderName="Display";Id=4101;StartTime=$since} -EA SilentlyContinue); $out.Counters.DisplayTDR=$td.Count; if($td.Count -gt 0){ AF "WARNING" "GPU" "$($td.Count) Display TDR (4101)" "GPU timeout" }
$ghost=@(Get-CimInstance Win32_DiskDrive|?{ $_.Size -eq $null -or $_.Size -eq 0 }); foreach($g in $ghost){ AF "CRITICAL" "Disk" "Phantom drive" $g.PNPDeviceID }
if($out.Counters.FreePct -lt 10){ AF "CRITICAL" "Disk" ("Low disk C: "+$out.Counters.FreePct+"% free") "" }
$out | ConvertTo-Json -Depth 6 -Compress
'@ -replace 'DAYS_PLACEHOLDER', $DayCount

    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($remoteScript))
    $cmd = "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $b64"
    Write-Host "  Connecting..." -ForegroundColor Gray
    $raw = & ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 $sshTarget $cmd 2>&1
    if ($LASTEXITCODE -ne 0) {
        # retry without BatchMode (may prompt)
        $raw = & ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=30 $sshTarget $cmd 2>&1
    }
    $jsonText = ($raw | Out-String).Trim()
    # find JSON object
    $start = $jsonText.IndexOf('{')
    $end = $jsonText.LastIndexOf('}')
    if ($start -lt 0 -or $end -lt 0) {
        Add-Finding CRITICAL 'Remote' "SSH collection failed for $HostName" "$raw" -Action 'Verify OpenSSH Server on target, firewall, and credentials.'
        return $false
    }
    try {
        $data = $jsonText.Substring($start, $end - $start + 1) | ConvertFrom-Json
    } catch {
        Add-Finding CRITICAL 'Remote' 'Failed to parse remote JSON' $_.Exception.Message
        return $false
    }
    $script:TargetName = $data.ComputerName
    $script:IsRemote = $true
    $script:Snapshot.OS = $data.OS
    $script:Snapshot.Build = $data.Build
    $script:Snapshot.GpuName = $data.Gpu
    $script:Counters.GpuName = $data.Gpu
    if ($data.Counters) {
        $script:Counters.KP41 = [int]$data.Counters.KP41
        $script:Counters.StorAhci129 = [int]$data.Counters.StorAhci129
        $script:Counters.StorNvme129 = [int]$data.Counters.StorNvme129
        $script:Counters.WHEA = [int]$data.Counters.WHEA
        $script:Counters.DisplayTDR = [int]$data.Counters.DisplayTDR
        $script:Counters.FreePct = $data.Counters.FreePct
    }
    foreach ($f in @($data.Findings)) {
        Add-Finding $f.Severity $f.Area $f.Title $f.Detail
    }
    Add-Finding INFO 'Remote' "Remote scan of $($data.ComputerName) via SSH" "User $User"
    Write-Host ("  Remote findings: {0}" -f @($data.Findings).Count) -ForegroundColor Green
    return $true
}

# ============================================================ WINDBG
function Find-Cdb {
    $c = Get-Command cdb.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $paths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe",
        "${env:ProgramFiles}\Windows Kits\10\Debuggers\x64\cdb.exe",
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x86\cdb.exe"
    )
    foreach ($p in $paths) { if (Test-Path $p) { return $p } }
    return $null
}

function Invoke-DumpAnalyze {
    param([string]$DumpPath)
    $cdb = Find-Cdb
    if (-not $cdb) {
        Add-Finding INFO 'Dump' 'WinDbg/cdb not installed - skipping dump analysis' 'Install Windows SDK Debugging Tools for automatic !analyze.' -Action 'Install Debugging Tools for Windows, then re-run.'
        return
    }
    if (-not (Test-Path $DumpPath)) { return }
    Write-Host ("  Analyzing dump: {0}" -f $DumpPath) -ForegroundColor Gray
    $outFile = Join-Path $env:TEMP ("cdb_analyze_{0}.txt" -f [guid]::NewGuid().ToString('N'))
    $args = @('-z', $DumpPath, '-c', '!analyze -v; q')
    try {
        $p = Start-Process -FilePath $cdb -ArgumentList $args -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outFile -RedirectStandardError "$outFile.err"
    } catch {
        Add-Finding WARNING 'Dump' 'cdb failed to start' $_.Exception.Message
        return
    }
    $text = ''
    if (Test-Path $outFile) { $text = Get-Content $outFile -Raw -ErrorAction SilentlyContinue }
    Remove-Item $outFile, "$outFile.err" -Force -ErrorAction SilentlyContinue
    if (-not $text) {
        Add-Finding WARNING 'Dump' "Empty analysis for $(Split-Path $DumpPath -Leaf)" ''
        return
    }
    $img = if ($text -match 'IMAGE_NAME:\s+(\S+)') { $Matches[1] } else { '' }
    $mod = if ($text -match 'MODULE_NAME:\s+(\S+)') { $Matches[1] } else { '' }
    $bucket = if ($text -match 'FAILURE_BUCKET_ID:\s+(\S+)') { $Matches[1] } else { '' }
    $bc = if ($text -match 'BUGCHECK_CODE:\s+(\S+)') { $Matches[1] } else { '' }
    $detail = "IMAGE_NAME=$img; MODULE_NAME=$mod; BUGCHECK_CODE=$bc; FAILURE_BUCKET_ID=$bucket"
    Add-Finding WARNING 'Dump' "Dump analysis: $(Split-Path $DumpPath -Leaf)" $detail -Action 'Update or roll back the implicated driver (IMAGE_NAME).'
    Write-Host ("  -> {0}" -f $detail) -ForegroundColor Yellow
}

# ============================================================ LOCAL DIAGNOSIS COLLECTORS
function Invoke-LocalDiagnosis {
    param($Window)
    $since = $Window.Start

    Write-Head '1. System Overview'
    $os  = Get-CimInstance Win32_OperatingSystem
    $cs  = Get-CimInstance Win32_ComputerSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    $gpus = @(Get-CimInstance Win32_VideoController)
    $gpuName = ($gpus | ForEach-Object { $_.Name }) -join '; '
    $script:Counters.GpuName = $gpuName
    $script:Snapshot = @{
        OS = $os.Caption; Build = $os.BuildNumber
        Manufacturer = $cs.Manufacturer; Model = $cs.Model
        Cores = $env:NUMBER_OF_PROCESSORS
        RamGB = [math]::Round($cs.TotalPhysicalMemory/1GB)
        LastBoot = $os.LastBootUpTime
        Uptime = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        GpuName = $gpuName
    }
    Write-Host ("  Computer    : {0}" -f $env:COMPUTERNAME)
    Write-Host ("  OS          : {0} (build {1})" -f $os.Caption, $os.BuildNumber)
    Write-Host ("  Model       : {0} {1}" -f $cs.Manufacturer, $cs.Model)
    Write-Host ("  CPU/RAM     : {0} logical cores, {1} GB RAM" -f $env:NUMBER_OF_PROCESSORS, $script:Snapshot.RamGB)
    Write-Host ("  GPU         : {0}" -f $gpuName)
    Write-Host ("  Last boot   : {0}  (up {1})" -f $os.LastBootUpTime, $script:Snapshot.Uptime)
    Add-Finding INFO 'System' "$($os.Caption) build $($os.BuildNumber) on $($cs.Manufacturer) $($cs.Model)" "GPU: $gpuName"

    # --- 2. Shutdowns / BSOD ---
    Write-Head '2. Unexpected Shutdowns & Blue Screens'
    $kp41 = Get-EventsLocal @{LogName='System';Id=41;StartTime=$since}
    $script:Counters.KP41 = @($kp41).Count
    if ($kp41) {
        foreach ($e in $kp41) {
            $obj = ConvertTo-EventObj $e
            Add-BrowserEvent $obj -AlsoTimeline
            $x = [xml]$e.ToXml(); $d = @{}
            $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
            $bc = 0; [void][int64]::TryParse($d['BugcheckCode'], [ref]$bc)
            $pwr = $d['PowerButtonTimestamp']
            if ($bc -ne 0) {
                $hex = ('0x{0:X}' -f $bc)
                $info = $BugCheckMap[[int]$bc]
                $name = if ($info) { $info[0] } else { 'UNKNOWN_BUGCHECK' }
                $hint = if ($info) { $info[1] } else { 'Unrecognized stop code - search online.' }
                Write-Host ("  [BSOD] {0}  stop {1} {2}" -f $e.TimeCreated, $hex, $name) -ForegroundColor Red
                Add-Finding CRITICAL 'Crash' "Blue screen: $name ($hex)" "At $($e.TimeCreated). $hint" $e.TimeCreated -Action 'Analyze minidump with BlueScreenView/WinDbg; update or roll back the faulting driver.'
                $script:Counters.BugCheck++
            } elseif ($pwr -ne '0' -and $pwr) {
                Write-Host ("  [POWER] {0}  power button held" -f $e.TimeCreated) -ForegroundColor Yellow
                Add-Finding WARNING 'Power' "Hard power-off via power button at $($e.TimeCreated)" 'User or firmware forced power off.' $e.TimeCreated
            } else {
                Write-Host ("  [POWER-LOSS] {0}  unclean, NO bugcheck" -f $e.TimeCreated) -ForegroundColor Red
                Add-Finding CRITICAL 'Power' "Abrupt power loss / hard lock at $($e.TimeCreated)" 'No bugcheck = power cut or hard freeze. Suspect PSU, cable, UPS, thermal cutoff.' $e.TimeCreated -Action 'Reseat PSU cables; check UPS; monitor temps under load.'
            }
        }
    } else {
        Write-Host '  No Kernel-Power 41 events. Good.' -ForegroundColor Green
        Add-Finding OK 'Power' 'No unexpected shutdowns in the scan window.'
    }

    $bcEvents = Get-EventsLocal @{LogName='System';Id=1001;StartTime=$since} | Where-Object { $_.ProviderName -match 'BugCheck|WER-SystemErrorReporting' }
    foreach ($b in $bcEvents) {
        $line = (($b.Message -split "`n")[0]).Trim()
        Add-BrowserEvent (ConvertTo-EventObj $b) -AlsoTimeline
        Add-Finding CRITICAL 'Crash' 'Bugcheck record found' "$($b.TimeCreated): $line" $b.TimeCreated
    }
    $e6008 = Get-EventsLocal @{LogName='System';Id=6008;StartTime=$since}
    if ($e6008) {
        Write-Host ("  {0} unexpected shutdown (6008) record(s)." -f $e6008.Count) -ForegroundColor Yellow
        foreach ($e in $e6008) { Add-BrowserEvent (ConvertTo-EventObj $e) -AlsoTimeline }
    }

    # --- 3. Dumps ---
    Write-Head '3. Crash & LiveKernel Dumps'
    $mini = @(Get-ChildItem 'C:\Windows\Minidump\*.dmp' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $newestDump = $null
    if ($mini) {
        Write-Host ("  {0} minidump(s); newest {1}" -f $mini.Count, $mini[0].Name) -ForegroundColor Yellow
        Add-Finding WARNING 'Crash' "$($mini.Count) crash dump(s) in Minidump" "Newest: $($mini[0].Name) @ $($mini[0].LastWriteTime)" $mini[0].LastWriteTime -Action 'Open in BlueScreenView or WinDbg (!analyze -v).'
        if ($mini[0].LastWriteTime -ge $since) { $newestDump = $mini[0].FullName }
    } else {
        Write-Host '  No minidumps.' -ForegroundColor Gray
    }
    if (Test-Path 'C:\Windows\MEMORY.DMP') {
        $md = Get-Item 'C:\Windows\MEMORY.DMP'
        Add-Finding INFO 'Crash' "Full MEMORY.DMP present ($([math]::Round($md.Length/1MB)) MB)" "Created $($md.LastWriteTime)."
    }
    $volmgr = Get-EventsLocal @{LogName='System';ProviderName='volmgr';Id=161;StartTime=$since}
    $script:Counters.Volmgr161 = @($volmgr).Count
    if ($volmgr) {
        Add-Finding CRITICAL 'Crash' 'Crash dump could NOT be written (volmgr 161)' "$($volmgr.Count) occurrence(s). Disk was unresponsive during crash." $volmgr[0].TimeCreated -Action 'Reseat/replace SATA/NVMe cable; check SMART; replace failing drive.'
        foreach ($e in $volmgr) { Add-BrowserEvent (ConvertTo-EventObj $e) -AlsoTimeline }
    }

    $lkDirs = @(
        'C:\Windows\LiveKernelReports',
        'C:\Windows\LiveKernelReports\WATCHDOG',
        "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    )
    $lkDumps = @()
    foreach ($dir in $lkDirs) {
        if (Test-Path $dir) {
            $lkDumps += Get-ChildItem $dir -Recurse -Filter '*.dmp' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $since }
        }
    }
    $lkDumps = @($lkDumps | Sort-Object LastWriteTime -Descending)
    if ($lkDumps) {
        Write-Host ("  {0} LiveKernel/WATCHDOG dump(s) in window." -f $lkDumps.Count) -ForegroundColor Yellow
        $n = $lkDumps[0]
        Add-Finding WARNING 'GPU' "$($lkDumps.Count) LiveKernel/WATCHDOG dump(s)" "Newest: $($n.FullName) @ $($n.LastWriteTime). Often VIDEO_DXGKRNL_LIVEDUMP (0x193)." $n.LastWriteTime -Action 'Clean-install GPU drivers (DDU); check GPU thermals/power.'
        if (-not $newestDump) { $newestDump = $n.FullName }
        elseif ($n.LastWriteTime -gt (Get-Item $newestDump).LastWriteTime) { $newestDump = $n.FullName }
    }

    $werApps = Get-EventsLocal @{LogName='Application';StartTime=$since} 2000 |
        Where-Object { $_.Message -match 'LiveKernelEvent' }
    $sysWer = Get-EventsLocal @{LogName='System';StartTime=$since} 500 |
        Where-Object { $_.Message -match 'LiveKernelEvent' }
    $lk193 = @($werApps) + @($sysWer) | Where-Object { $_.Message -match 'LiveKernelEvent' -and ($_.Message -match 'Code:\s*193|\b193\b|VIDEO_DXGKRNL|WATCHDOG') }
    # De-dupe by time+id
    $lk193 = @($lk193 | Sort-Object TimeCreated -Descending | Group-Object { "$($_.TimeCreated.Ticks):$($_.Id)" } | ForEach-Object { $_.Group[0] })
    $script:Counters.LiveKernel193 = @($lk193).Count
    if ($lk193) {
        $first = $lk193 | Sort-Object TimeCreated -Descending | Select-Object -First 1
        $param1 = '?'
        $obj0 = ConvertTo-EventObj $first
        if ($obj0.EventData) {
            # WER LiveKernel: Signature_00=LiveKernelEvent, _01=193 (code), _02=80e (Param1)
            if ($obj0.EventData['ProblemSignature_02'] -and ($obj0.EventData['ProblemSignature_01'] -match '193')) {
                $param1 = $obj0.EventData['ProblemSignature_02']
            } elseif ($obj0.EventData['ProblemSignature_03'] -and ($obj0.EventData['ProblemSignature_01'] -match '193')) {
                $param1 = $obj0.EventData['ProblemSignature_02']
                if (-not $param1) { $param1 = $obj0.EventData['ProblemSignature_03'] }
            } else {
                foreach ($key in @('Param1','Parameter1','param1','P1')) {
                    if ($obj0.EventData.ContainsKey($key) -and $obj0.EventData[$key]) {
                        $param1 = $obj0.EventData[$key]
                        break
                    }
                }
            }
            if ($param1 -eq '?' -and $obj0.EventData['ProblemSignature_02']) {
                $param1 = $obj0.EventData['ProblemSignature_02']
            }
        }
        if ($param1 -eq '?' -and $first.Message -match 'Parameter\s*1\s*:\s*([0-9a-fA-Fx]+)') { $param1 = $Matches[1] }
        $hint = $LiveDumpMap[0x193][1]
        $sev = if ($script:Counters.DisplayTDR -ge 3 -or $lk193.Count -ge 3) { 'CRITICAL' } else { 'WARNING' }
        Write-Host ("  [LiveKernel] {0} event(s), Param1={1}" -f $lk193.Count, $param1) -ForegroundColor Yellow
        Add-Finding $sev 'GPU' "LiveKernelEvent 193 (VIDEO_DXGKRNL_LIVEDUMP) x$($lk193.Count)" "Newest $($first.TimeCreated); Parameter1=$param1. $hint Generic WER text does NOT prove dead hardware." $first.TimeCreated -Action 'DDU + reinstall GPU driver; update Sunshine/overlays if used; free disk space on C:.'
        foreach ($e in $lk193) { Add-BrowserEvent (ConvertTo-EventObj $e) -AlsoTimeline }
    }

    # Display TDR 4101
    $tdr = Get-EventsLocal @{LogName='System';ProviderName='Display';Id=4101;StartTime=$since}
    if (-not $tdr) {
        $tdr = Get-EventsLocal @{LogName='System';Id=4101;StartTime=$since} | Where-Object { $_.ProviderName -match 'Display' }
    }
    $script:Counters.DisplayTDR = @($tdr).Count
    if ($tdr) {
        $sev = if ($tdr.Count -ge 5) { 'CRITICAL' } else { 'WARNING' }
        Add-Finding $sev 'GPU' "$($tdr.Count) Display TDR timeout(s) (Event 4101)" 'GPU stopped responding and recovered (or failed). Driver, overheating, or failing GPU.' $tdr[0].TimeCreated -Action 'Update/roll back GPU driver; check GPU temp and power connectors.'
        foreach ($e in $tdr) { Add-BrowserEvent (ConvertTo-EventObj $e) -AlsoTimeline }
    }

    if ($newestDump) { Invoke-DumpAnalyze -DumpPath $newestDump }

    # --- 4. Storage ---
    Write-Head '4. Storage / Disk Health'
    $pdisks = Get-PhysicalDisk -ErrorAction SilentlyContinue
    foreach ($pd in $pdisks) {
        $color = switch ($pd.HealthStatus) { 'Healthy' {'Green'} 'Warning' {'Yellow'} default {'Red'} }
        Write-Host ("  {0} [{1}] - Health: {2}" -f $pd.FriendlyName, $pd.BusType, $pd.HealthStatus) -ForegroundColor $color
        if ($pd.HealthStatus -ne 'Healthy') {
            Add-Finding CRITICAL 'Disk' "Disk not healthy: $($pd.FriendlyName)" "Health=$($pd.HealthStatus), Op=$($pd.OperationalStatus)" -Action 'Back up now; plan replacement.'
        }
    }
    $ghost = Get-CimInstance Win32_DiskDrive | Where-Object { $_.Size -eq $null -or $_.Size -eq 0 }
    foreach ($g in $ghost) {
        Add-Finding CRITICAL 'Disk' 'Phantom/0-byte drive detected' "Interface $($g.InterfaceType), PNP $($g.PNPDeviceID)" -Action 'Reseat cable/port or disable/remove the failing drive.'
    }
    $resetsAhci = Get-EventsLocal @{LogName='System';ProviderName='storahci';Id=129;StartTime=$since}
    $script:Counters.StorAhci129 = @($resetsAhci).Count
    if ($resetsAhci) {
        $sev = if ($resetsAhci.Count -ge 5) { 'CRITICAL' } else { 'WARNING' }
        Add-Finding $sev 'Disk' "$($resetsAhci.Count) SATA/AHCI device resets (storahci 129)" 'Disk on AHCI stopped responding.' $resetsAhci[0].TimeCreated -Action 'Reseat SATA data+power; try another port; check SMART.'
        foreach ($e in $resetsAhci) { Add-BrowserEvent (ConvertTo-EventObj $e) -AlsoTimeline }
    } else {
        Write-Host '  No storahci 129 resets.' -ForegroundColor Green
    }
    $resetsNvme = Get-EventsLocal @{LogName='System';ProviderName='stornvme';Id=129;StartTime=$since}
    if (-not $resetsNvme) {
        $resetsNvme = Get-EventsLocal @{LogName='System';Id=129;StartTime=$since} | Where-Object { $_.ProviderName -match 'stornvme|storport' }
    }
    $script:Counters.StorNvme129 = @($resetsNvme).Count
    if ($resetsNvme) {
        $sev = if ($resetsNvme.Count -ge 5) { 'CRITICAL' } else { 'WARNING' }
        Add-Finding $sev 'Disk' "$($resetsNvme.Count) NVMe/storport device resets (129)" 'NVMe/storage controller reset - drive or slot/power issue.' $resetsNvme[0].TimeCreated -Action 'Update NVMe firmware/chipset; reseat SSD; check PSU.'
        foreach ($e in $resetsNvme) { Add-BrowserEvent (ConvertTo-EventObj $e) -AlsoTimeline }
    } else {
        Write-Host '  No stornvme/storport 129 resets.' -ForegroundColor Green
    }
    $ioerr = Get-EventsLocal @{LogName='System';Id=7,51,153;StartTime=$since} | Where-Object { $_.ProviderName -match 'disk|storahci|stornvme|nvme|Ntfs|volmgr' }
    if ($ioerr) {
        Add-Finding WARNING 'Disk' "$($ioerr.Count) disk I/O error event(s) (7/51/153)" 'Bad-block / paging / retry errors.' $ioerr[0].TimeCreated -Action 'Run chkdsk; check SMART.'
    }
    $sys = Get-PSDrive C
    if ($sys) {
        $freeGB = [math]::Round($sys.Free/1GB); $totGB = [math]::Round(($sys.Used+$sys.Free)/1GB)
        $pct = if (($sys.Used+$sys.Free) -gt 0) { [math]::Round(100*$sys.Free/($sys.Used+$sys.Free)) } else { 0 }
        $script:Counters.FreePct = $pct
        $script:Snapshot.FreePct = $pct
        $script:Snapshot.FreeGB = $freeGB
        $col = if ($pct -lt 10) {'Red'} elseif ($pct -lt 15) {'Yellow'} else {'Green'}
        Write-Host ("  C: free: {0} GB of {1} GB ({2}%)" -f $freeGB, $totGB, $pct) -ForegroundColor $col
        if ($pct -lt 10) {
            Add-Finding CRITICAL 'Disk' "Low disk space on C: ($pct% free)" 'Below 10% free causes instability and failed updates.' -Action 'Free tens of GB on C: immediately.'
        } elseif ($pct -lt 15) {
            Add-Finding WARNING 'Disk' "Disk space getting low on C: ($pct% free)" 'Consider cleaning up.'
        }
    }

    # --- 5. WHEA / Memory ---
    Write-Head '5. Memory & Hardware Errors'
    $whea = Get-EventsLocal @{LogName='System';ProviderName='Microsoft-Windows-WHEA-Logger';StartTime=$since}
    if ($whea) {
        $wErr = @($whea | Where-Object { $_.Level -le 2 })
        $script:Counters.WHEA = $wErr.Count
        if ($wErr) {
            Add-Finding CRITICAL 'Hardware' "$($wErr.Count) WHEA hardware error(s)" 'Machine-check from hardware.' $wErr[0].TimeCreated -Action 'MemTest86; check temps; disable overclock.'
            foreach ($e in $wErr) { Add-BrowserEvent (ConvertTo-EventObj $e) -AlsoTimeline }
        } else {
            Write-Host ("  {0} WHEA informational event(s)." -f $whea.Count) -ForegroundColor Yellow
        }
    } else {
        Write-Host '  No WHEA errors. Good.' -ForegroundColor Green
        Add-Finding OK 'Hardware' 'No WHEA hardware errors reported.'
    }
    $memDiag = Get-EventsLocal @{LogName='System';ProviderName='Microsoft-Windows-MemoryDiagnostics-Results';StartTime=$since}
    foreach ($m in $memDiag) {
        if ($m.Message -match 'error|fail') {
            Add-Finding CRITICAL 'Memory' 'Windows Memory Diagnostic found errors' (($m.Message -split "`n")[0]) $m.TimeCreated -Action 'Replace faulty RAM.'
        }
    }

    # --- 6. Thermal ---
    Write-Head '6. Thermal & Power'
    $thermZone = Get-EventsLocal @{LogName='System';Id=20,21,22;StartTime=$since} | Where-Object { $_.ProviderName -match 'Thermal' }
    if ($thermZone) {
        Add-Finding CRITICAL 'Thermal' "$($thermZone.Count) thermal trip event(s)" 'Component exceeded safe temperature.' $thermZone[0].TimeCreated -Action 'Clean dust; check fans; reseat heatsink.'
    } else {
        Write-Host '  No thermal-trip events.' -ForegroundColor Green
    }
    $temp = Get-CimInstance -Namespace root/wmi -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction SilentlyContinue
    if ($temp) {
        $c = [math]::Round(($temp[0].CurrentTemperature/10)-273.15,1)
        Write-Host ("  ACPI thermal zone: {0} C" -f $c)
        if ($c -ge 90) { Add-Finding WARNING 'Thermal' "High temperature reading: $c C" 'Running hot.' }
    }

    # --- 7. Services & Apps ---
    Write-Head '7. Failed Services & App Crashes'
    $svc = Get-EventsLocal @{LogName='System';Id=7031,7034;StartTime=$since}
    if ($svc) {
        $top = $svc | ForEach-Object { ($_.Message -split "`n")[0] } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
        Add-Finding WARNING 'Services' "$($svc.Count) unexpected service crash(es)" (($top | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join '; ')
    }
    $appcrash = Get-EventsLocal @{LogName='Application';ProviderName='Application Error';Id=1000;StartTime=$since}
    $topApp = @()
    if ($appcrash) {
        $topApp = @($appcrash | ForEach-Object { $_.Properties[0].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 8)
        Write-Host ("  {0} application crash(es)." -f $appcrash.Count) -ForegroundColor Yellow
        $topApp | ForEach-Object { Write-Host ("       {0}x  {1}" -f $_.Count, $_.Name) }
        $gpuCorr = $false
        foreach ($a in $topApp) {
            foreach ($g in $GpuHeavyApps) {
                if ($a.Name -like "*$($g.Replace('.exe',''))*" -or $a.Name -eq $g) { $gpuCorr = $true }
            }
        }
        $sev = 'INFO'
        $detail = (($topApp | ForEach-Object { "$($_.Count)x $($_.Name)" }) -join '; ')
        if ($gpuCorr -and ($script:Counters.LiveKernel193 -gt 0 -or $script:Counters.DisplayTDR -gt 0)) {
            $sev = 'WARNING'
            $detail += ' | Correlates with GPU/LiveKernel events - streaming/overlay apps may stress the display stack.'
            Add-Finding $sev 'Apps' "$($appcrash.Count) application crash(es) (GPU-related correlation)" $detail -Action 'Update or quit Sunshine/GPU overlays; reinstall GPU driver.'
        } else {
            Add-Finding INFO 'Apps' "$($appcrash.Count) application crash(es)" $detail
        }
    }

    # --- 8. Updates ---
    Write-Head '8. Updates & Pending Reboot'
    $updFail = Get-EventsLocal @{LogName='System';ProviderName='Microsoft-Windows-WindowsUpdateClient';Id=20;StartTime=$since}
    if ($updFail) {
        Add-Finding WARNING 'Updates' "$($updFail.Count) failed Windows Update(s)" 'Partially-patched state possible.' $updFail[0].TimeCreated -Action 'Free disk space; run Windows Update troubleshooter.'
    }
    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or `
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
    if ($pending) {
        Add-Finding WARNING 'Updates' 'Reboot pending' 'Windows waiting to finish servicing.' -Action 'Reboot when convenient.'
    }

    # Seed browser with Critical/Error from System if still sparse
    if ($script:BrowserEvents.Count -lt 50) {
        $extra = Invoke-EventQuery -Since $since -Until (Get-Date) -Levels @(1,2) -Channels @('System','Application') -Cap 500
        foreach ($o in $extra) { Add-BrowserEvent $o -AlsoTimeline }
    }
}

# ============================================================ TRENDS
function Compare-Trends {
    $reportDir = Join-Path $PSScriptRoot 'Reports'
    if (-not (Test-Path $reportDir)) { return }
    $prior = Get-ChildItem $reportDir -Filter "Diagnosis_$($script:TargetName)_*.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $prior) {
        Add-Finding INFO 'Trend' 'No prior JSON report for trend comparison' 'Next run will compare against this scan.'
        return
    }
    try { $old = Get-Content $prior.FullName -Raw | ConvertFrom-Json } catch { return }
    if (-not $old.Counters) { return }
    Write-Head 'Trend vs Prior Scan'
    $pairs = @(
        @{ K='StorAhci129'; Label='storahci 129' },
        @{ K='StorNvme129'; Label='stornvme 129' },
        @{ K='LiveKernel193'; Label='LiveKernel 193' },
        @{ K='DisplayTDR'; Label='Display TDR' },
        @{ K='KP41'; Label='Kernel-Power 41' },
        @{ K='WHEA'; Label='WHEA errors' }
    )
    foreach ($p in $pairs) {
        $a = [int]$old.Counters.($p.K)
        $b = [int]$script:Counters.($p.K)
        if ($a -eq 0 -and $b -eq 0) { continue }
        if ($b -gt $a) {
            $sev = if ($b -ge ($a + 5) -or ($a -eq 0 -and $b -gt 0)) { 'WARNING' } else { 'INFO' }
            $msg = if ($a -eq 0 -and $b -gt 0) { "$($p.Label): new since last scan ($b)" } else { "$($p.Label): $a → $b (worsening)" }
            Add-Finding $sev 'Trend' $msg "Compared to $($prior.Name)" -Action 'Investigate recurring hardware/driver issue.'
            Write-Host ("  {0}" -f $msg) -ForegroundColor Yellow
        } elseif ($b -lt $a) {
            Add-Finding INFO 'Trend' "$($p.Label): $a → $b (improving)" "vs $($prior.Name)"
        }
    }
    if ($null -ne $old.Counters.FreePct -and $null -ne $script:Counters.FreePct) {
        if ([int]$script:Counters.FreePct -lt [int]$old.Counters.FreePct - 5) {
            Add-Finding WARNING 'Trend' "C: free% dropped: $($old.Counters.FreePct) → $($script:Counters.FreePct)" '' -Action 'Free disk space.'
        }
    }
}

# ============================================================ ROOT CAUSE
function Get-RootCause {
    $parts = New-Object System.Collections.Generic.List[string]
    $titles = ($script:Findings | ForEach-Object { $_.Title }) -join ' | '
    $areas = $script:Findings | Where-Object { $_.Severity -in 'CRITICAL','WARNING' }

    if ($script:Findings | Where-Object { $_.Title -match 'Phantom|storahci|stornvme|UNEXPECTED_STORE|not healthy|dump could NOT' }) {
        $parts.Add('STORAGE: a drive is failing or disconnecting (cable/port/disk). Back up; reseat/replace cable; test SMART or replace the drive.')
    }
    if ($script:Findings | Where-Object { $_.Title -match 'WHEA' -and $_.Severity -eq 'CRITICAL' }) {
        $parts.Add('HARDWARE: machine-check errors. Test RAM (MemTest86), check CPU temps, review overclock.')
    }
    if ($script:Findings | Where-Object { $_.Title -match 'Abrupt power loss|power button|thermal trip' }) {
        $parts.Add('POWER/THERMAL: power loss or thermal trip with little/no bugcheck. Check PSU, cables, UPS, cooling.')
    }
    if ($script:Findings | Where-Object { $_.Title -match 'LiveKernel|TDR|VIDEO_|GPU|WATCHDOG|dxgkrnl' -or $_.Area -eq 'GPU' }) {
        $parts.Add('GPU/DISPLAY: LiveKernel 193, TDR, or graphics dumps. Clean-install GPU drivers (DDU); check GPU power/thermals; update or quit streaming overlays (e.g. Sunshine).')
    }
    if ($script:Findings | Where-Object { $_.Title -match 'Blue screen|Bugcheck' }) {
        $parts.Add('DRIVER/SOFTWARE: BSOD stop code recorded. Analyze the minidump for the faulting driver.')
    }
    if ($script:Findings | Where-Object { $_.Title -match 'Low disk space' }) {
        $parts.Add('CONTRIBUTING: C: critically low on free space - free space before chasing subtler bugs.')
    }

    if ($parts.Count -eq 0) {
        if ($areas.Count -gt 0) {
            $top = $areas | Select-Object -First 1
            return "Primary signal: [$($top.Severity)] $($top.Area) - $($top.Title). Review WARNING/CRITICAL findings below."
        }
        return 'No dominant crash signature in the scan window. System looks healthy (or issues are informational only).'
    }
    return ($parts -join ' ')
}

function Get-ActionList {
    $acts = @($script:Findings | Where-Object { $_.Action -and $_.Severity -in 'CRITICAL','WARNING' } | Select-Object -ExpandProperty Action -Unique)
    return $acts
}

# ============================================================ AGGREGATES
function Get-EventAggregates {
    $ev = @($script:BrowserEvents)
    if ($ev.Count -eq 0) { return @{ ByLevel=@(); ByProvider=@(); ById=@(); ByChannel=@() } }
    return @{
        ByLevel    = @($ev | Group-Object Level | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { @{ Name=$_.Name; Count=$_.Count } })
        ByProvider = @($ev | Group-Object Provider | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { @{ Name=$_.Name; Count=$_.Count } })
        ById       = @($ev | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { @{ Name=$_.Name; Count=$_.Count } })
        ByChannel  = @($ev | Group-Object Channel | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { @{ Name=$_.Name; Count=$_.Count } })
    }
}

# ============================================================ EXPORTS
function Export-MatchedEvents {
    param([string]$Stamp, [string]$ReportDir)
    $formats = @($Export -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $ev = @($script:BrowserEvents)
    if ($ev.Count -eq 0) { return @() }
    $paths = @()
    $base = Join-Path $ReportDir "Events_$($script:TargetName)_$Stamp"

    $rows = $ev | ForEach-Object {
        [pscustomobject]@{
            TimeCreated = $_.TimeCreated.ToString('o')
            Level = $_.Level; Id = $_.Id; Provider = $_.Provider
            Channel = $_.Channel; Message = ($_.Message -replace '[\r\n]+',' ')
        }
    }

    if ($formats | Where-Object { $_ -match '^(?i)csv$' }) {
        $p = "$base.csv"
        $rows | Export-Csv -Path $p -NoTypeInformation -Encoding UTF8
        $paths += $p
    }
    if ($formats | Where-Object { $_ -match '^(?i)json$' }) {
        # diagnosis JSON written separately; also events json
        $p = "$base.json"
        $rows | ConvertTo-Json -Depth 4 | Set-Content -Path $p -Encoding UTF8
        $paths += $p
    }
    if ($formats | Where-Object { $_ -match '^(?i)xml$' }) {
        $p = "$base.xml"
        $x = New-Object System.Text.StringBuilder
        [void]$x.Append('<?xml version="1.0" encoding="utf-8"?><Events>')
        foreach ($r in $rows) {
            [void]$x.Append("<Event><TimeCreated>$(Escape-Html $r.TimeCreated)</TimeCreated><Level>$(Escape-Html $r.Level)</Level><Id>$($r.Id)</Id><Provider>$(Escape-Html $r.Provider)</Provider><Channel>$(Escape-Html $r.Channel)</Channel><Message>$(Escape-Html $r.Message)</Message></Event>")
        }
        [void]$x.Append('</Events>')
        Set-Content -Path $p -Value $x.ToString() -Encoding UTF8
        $paths += $p
    }
    if ($formats | Where-Object { $_ -match '^(?i)html$' }) {
        $p = "$base.events.html"
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('<html><body><table border="1"><tr><th>Time</th><th>Level</th><th>Id</th><th>Provider</th><th>Channel</th><th>Message</th></tr>')
        foreach ($r in $rows) {
            [void]$sb.Append("<tr><td>$(Escape-Html $r.TimeCreated)</td><td>$(Escape-Html $r.Level)</td><td>$($r.Id)</td><td>$(Escape-Html $r.Provider)</td><td>$(Escape-Html $r.Channel)</td><td>$(Escape-Html $r.Message)</td></tr>")
        }
        [void]$sb.Append('</table></body></html>')
        Set-Content -Path $p -Value $sb.ToString() -Encoding UTF8
        $paths += $p
    }
    if ($ExportEvtx) {
        $evtxOut = "$base.System.evtx"
        try {
            & wevtutil epl System $evtxOut /ow:true 2>$null
            if (Test-Path $evtxOut) { $paths += $evtxOut }
        } catch {}
    }
    foreach ($p in $paths) { Write-Host ("  Exported: {0}" -f $p) -ForegroundColor Cyan }
    return $paths
}

function Save-DiagnosisJson {
    param([string]$Path, [string]$RootCause)
    $obj = [pscustomobject]@{
        ComputerName = $script:TargetName
        Generated    = (Get-Date).ToString('o')
        Days         = $Days
        Counters     = $script:Counters
        Snapshot     = $script:Snapshot
        RootCause    = $RootCause
        Findings     = @($script:Findings)
    }
    $obj | ConvertTo-Json -Depth 8 | Set-Content -Path $Path -Encoding UTF8
}

# ============================================================ HTML REPORT
function Write-HtmlReport {
    param([string]$Path, [string]$RootCause, $Agg)
    $order = @{ 'CRITICAL'=0; 'WARNING'=1; 'INFO'=2; 'OK'=3 }
    $ranked = @($script:Findings | Sort-Object { $order[$_.Severity] }, { if ($_.When) { - $_.When.Ticks } else { 0 } })
    $crit = @($ranked | Where-Object Severity -eq 'CRITICAL')
    $warn = @($ranked | Where-Object Severity -eq 'WARNING')
    $actions = Get-ActionList
    $rowColor = @{ 'CRITICAL'='#ffd6d6'; 'WARNING'='#fff2cc'; 'INFO'='#e8f0fe'; 'OK'='#dcffe0' }

    # Cap browser payload
    $browser = @($script:BrowserEvents | Sort-Object TimeCreated -Descending | Select-Object -First $MaxEvents)
    $timeline = @($script:Timeline | Sort-Object TimeCreated -Descending | Select-Object -First 100)
    $evJson = ($browser | ForEach-Object {
        [pscustomobject]@{
            t = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            l = $_.Level; i = $_.Id; p = $_.Provider; c = $_.Channel
            m = if ($_.Message.Length -gt 500) { $_.Message.Substring(0,500) + '...' } else { $_.Message }
            d = $_.EventData
        }
    }) | ConvertTo-Json -Depth 5 -Compress
    if (-not $evJson) { $evJson = '[]' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Crash-Tshoot - $($script:TargetName)</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f0f2f5;color:#222}
header{background:#0a5;color:#fff;padding:20px 28px}
header h1{margin:0 0 6px;font-size:1.5rem}
.meta{opacity:.9;font-size:.9rem}
.wrap{padding:20px 28px;max-width:1200px;margin:0 auto}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px}
.card{background:#fff;border-radius:8px;padding:12px 16px;box-shadow:0 1px 3px #0002;min-width:140px}
.card b{display:block;font-size:1.2rem}
.rc{background:#fde;padding:14px 16px;border-left:4px solid #c09;margin:16px 0;border-radius:4px}
.actions{background:#eef8ff;padding:14px 16px;border-left:4px solid #08c;margin:16px 0}
.tabs{display:flex;gap:8px;margin:16px 0}
.tabs button{padding:8px 14px;border:1px solid #ccc;background:#fff;cursor:pointer;border-radius:6px}
.tabs button.active{background:#0a5;color:#fff;border-color:#0a5}
.panel{display:none;background:#fff;padding:16px;border-radius:8px;box-shadow:0 1px 4px #0002}
.panel.active{display:block}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px 10px;text-align:left;vertical-align:top;font-size:.9rem}
th{background:#0a5;color:#fff}
.sev{font-weight:bold}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.filters input,.filters select{padding:6px 8px;border:1px solid #ccc;border-radius:4px}
#evDetail{margin-top:12px;background:#f7f7f9;padding:12px;border-radius:6px;white-space:pre-wrap;font-size:.85rem;max-height:280px;overflow:auto}
.tl{border-left:3px solid #0a5;padding-left:12px;margin:8px 0}
.tl .t{color:#666;font-size:.8rem}
footer{color:#666;padding:24px 28px;font-size:.85rem}
</style></head><body>
<header>
  <h1>Crash-Tshoot - Diagnoser + Event Viewer</h1>
  <div class="meta"><b>$(Escape-Html $script:TargetName)</b>
    &middot; $(Escape-Html $script:Snapshot.OS) build $(Escape-Html ([string]$script:Snapshot.Build))
    &middot; $(Escape-Html $script:Snapshot.Manufacturer) $(Escape-Html $script:Snapshot.Model)
    <br>Scanned last $Days days &middot; Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    &middot; <b>$($crit.Count) critical</b>, $($warn.Count) warning
    $(if($script:IsRemote){' &middot; REMOTE SSH'})
  </div>
</header>
<div class="wrap">
<div class="cards">
  <div class="card"><span>Uptime</span><b>$(Escape-Html $script:Snapshot.Uptime)</b></div>
  <div class="card"><span>C: free</span><b>$($script:Counters.FreePct)%</b></div>
  <div class="card"><span>GPU</span><b style="font-size:.95rem">$(Escape-Html $script:Counters.GpuName)</b></div>
  <div class="card"><span>LiveKernel 193</span><b>$($script:Counters.LiveKernel193)</b></div>
  <div class="card"><span>TDR 4101</span><b>$($script:Counters.DisplayTDR)</b></div>
  <div class="card"><span>Events in browser</span><b>$($browser.Count)</b></div>
</div>
<div class="rc"><b>Most likely root cause:</b><br>$(Escape-Html $RootCause)</div>
"@)

    if ($actions.Count -gt 0) {
        [void]$sb.Append('<div class="actions"><b>Recommended actions</b><ul>')
        foreach ($a in $actions) { [void]$sb.Append("<li>$(Escape-Html $a)</li>") }
        [void]$sb.Append('</ul></div>')
    }

    [void]$sb.Append(@"
<div class="tabs">
  <button class="active" onclick="showTab('findings',this)">Findings</button>
  <button onclick="showTab('events',this)">Event Browser</button>
  <button onclick="showTab('timeline',this)">Timeline</button>
  <button onclick="showTab('stats',this)">Stats &amp; Channels</button>
</div>
"@)

    # Findings panel
    [void]$sb.Append('<div id="findings" class="panel active"><table><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Detail</th><th>When</th></tr>')
    foreach ($f in $ranked) {
        $bg = $rowColor[$f.Severity]
        $when = if ($f.When) { $f.When.ToString('yyyy-MM-dd HH:mm') } else { '' }
        [void]$sb.Append("<tr style='background:$bg'><td class='sev'>$($f.Severity)</td><td>$(Escape-Html $f.Area)</td><td>$(Escape-Html $f.Title)</td><td>$(Escape-Html $f.Detail)</td><td>$when</td></tr>")
    }
    [void]$sb.Append('</table></div>')

    # Event browser
    [void]$sb.Append(@"
<div id="events" class="panel">
  <div class="filters">
    <input id="fText" placeholder="Search message/provider..." oninput="filterEv()" style="flex:1;min-width:180px">
    <select id="fLevel" onchange="filterEv()"><option value="">All levels</option>
      <option>Critical</option><option>Error</option><option>Warning</option><option>Information</option></select>
    <input id="fId" placeholder="Event ID" oninput="filterEv()" style="width:90px">
    <input id="fProv" placeholder="Provider" oninput="filterEv()" style="width:140px">
  </div>
  <table id="evTable"><thead><tr>
    <th onclick="sortEv('t')">Time</th><th onclick="sortEv('l')">Level</th><th onclick="sortEv('i')">Id</th>
    <th onclick="sortEv('p')">Provider</th><th onclick="sortEv('c')">Channel</th><th>Message</th>
  </tr></thead><tbody></tbody></table>
  <div id="evDetail">Click a row for EventData details.</div>
</div>
"@)

    # Timeline
    [void]$sb.Append('<div id="timeline" class="panel">')
    foreach ($t in $timeline) {
        [void]$sb.Append("<div class='tl'><div class='t'>$(Escape-Html $t.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) · $(Escape-Html $t.Level) · Id $($t.Id) · $(Escape-Html $t.Provider)</div>$(Escape-Html (($t.Message -split "`n")[0]))</div>")
    }
    if ($timeline.Count -eq 0) { [void]$sb.Append('<p>No Critical/Error timeline events.</p>') }
    [void]$sb.Append('</div>')

    # Stats
    [void]$sb.Append('<div id="stats" class="panel"><h3>Aggregates (browser set)</h3>')
    foreach ($pair in @(@('By Level',$Agg.ByLevel),@('By Provider',$Agg.ByProvider),@('By Event ID',$Agg.ById),@('By Channel',$Agg.ByChannel))) {
        [void]$sb.Append("<h4>$($pair[0])</h4><table><tr><th>Name</th><th>Count</th></tr>")
        foreach ($r in $pair[1]) {
            [void]$sb.Append("<tr><td>$(Escape-Html $r.Name)</td><td>$($r.Count)</td></tr>")
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append('<h3>Channel inventory</h3><table><tr><th>Channel</th><th>Enabled</th><th>Records</th><th>Size MB</th></tr>')
    foreach ($c in ($script:ChannelInventory | Sort-Object SizeMB -Descending | Select-Object -First 40)) {
        [void]$sb.Append("<tr><td>$(Escape-Html $c.Name)</td><td>$($c.Enabled)</td><td>$($c.Records)</td><td>$($c.SizeMB)</td></tr>")
    }
    [void]$sb.Append('</table></div>')

    [void]$sb.Append(@"
</div>
<footer>Generated by Crash-Tshoot SystemDiagnoser.ps1 - read-only diagnostics.</footer>
<script>
const EVENTS = $evJson;
let sortKey='t', sortDir=-1;
function showTab(id,btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  btn.classList.add('active');
}
function filterEv(){
  const t=(document.getElementById('fText').value||'').toLowerCase();
  const l=document.getElementById('fLevel').value;
  const id=(document.getElementById('fId').value||'').trim();
  const pr=(document.getElementById('fProv').value||'').toLowerCase();
  let rows=EVENTS.slice();
  rows=rows.filter(e=>{
    if(l && e.l!==l) return false;
    if(id && String(e.i)!==id) return false;
    if(pr && !(e.p||'').toLowerCase().includes(pr)) return false;
    if(t && !((e.m||'')+(e.p||'')+(e.c||'')).toLowerCase().includes(t)) return false;
    return true;
  });
  rows.sort((a,b)=>{
    let x=a[sortKey], y=b[sortKey];
    if(sortKey==='i'){ x=+x; y=+y; }
    if(x<y) return -1*sortDir; if(x>y) return 1*sortDir; return 0;
  });
  const tb=document.querySelector('#evTable tbody');
  tb.innerHTML='';
  rows.slice(0,2000).forEach((e,idx)=>{
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(e.t)+'</td><td>'+esc(e.l)+'</td><td>'+e.i+'</td><td>'+esc(e.p)+'</td><td>'+esc(e.c)+'</td><td>'+esc((e.m||'').slice(0,160))+'</td>';
    tr.onclick=()=>showDetail(e);
    tb.appendChild(tr);
  });
}
function sortEv(k){ if(sortKey===k) sortDir*=-1; else { sortKey=k; sortDir=1;} filterEv(); }
function showDetail(e){
  let d=e.d||{};
  let lines=Object.keys(d).map(k=>k+': '+d[k]);
  document.getElementById('evDetail').textContent=
    e.t+' | '+e.l+' | Id '+e.i+' | '+e.p+' | '+e.c+'\n\n'+(e.m||'')+'\n\nEventData:\n'+(lines.join('\n')||'(none)');
}
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
filterEv();
</script>
</body></html>
"@)

    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
}

# ============================================================ MAIN
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Window = Get-TimeWindow

Clear-Host
Write-Host @"
  ____  __  __   _   ___ _____   ___ ___   _   ___ _  _  ___  ___ ___ ___
 / __||  \/  | /_\ | _ \_   _| |   \_ _| /_\ / __| \| |/ _ \/ __| __| _ \
 \__ \| |\/| |/ _ \|   / | |   | |) | | / _ \ (_ | .`` | (_) \__ \ _||   /
 |___/|_|  |_/_/ \_\_|_\ |_|   |___/___/_/ \_\___|_|\_|\___/|___/___|_|_\
"@ -ForegroundColor Cyan
Write-Host "  Crash-Tshoot  |  last $Days days  |  Elevated: $isAdmin  |  $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor DarkGray
Write-Host "  Preset: $Preset  |  FullEventScan: $FullEventScan  |  Export: $Export" -ForegroundColor DarkGray
if (-not $isAdmin) {
    Write-Host "  NOTE: Not Administrator - SMART/Security log/dump checks may be limited." -ForegroundColor Yellow
}

# Offline EVTX first if requested
if ($EvtxPath -or $LogFolder) {
    Import-OfflineEvtx -Window $Window | Out-Null
}

if ($ComputerName) {
    $ok = Invoke-RemoteDiagnosis -HostName $ComputerName -User $SshUser -DayCount $Days
    if (-not $ok) {
        Write-Host '  Remote diagnosis failed.' -ForegroundColor Red
    }
} else {
    Get-ChannelInventory

    # Full crash diagnosis unless user asked for a pure Event Viewer preset without EventViewerMode
    $runDiag = ($Preset -eq 'Diagnose') -or $EventViewerMode
    if ($runDiag) {
        Invoke-LocalDiagnosis -Window $Window
    }

    # Named preset / CLI filters / full channel Critical+Error scan
    if ($Preset -ne 'Diagnose') {
        Apply-CliEventFilters -Window $Window | Out-Null
        Add-Finding INFO 'EventLog' "Preset $Preset loaded $($script:BrowserEvents.Count) event(s)" "Window $($Window.Start) .. $($Window.End)"
    } elseif ($EventId -or $Level.Count -gt 0 -or $MessageContains -or $Provider -or $Channel) {
        Apply-CliEventFilters -Window $Window | Out-Null
    }

    if ($FullEventScan) {
        Write-Head 'Full Event Scan (Critical/Error, all channels)'
        $extra = Invoke-EventQuery -Since $Window.Start -Until $Window.End -Levels @(1,2) -AllChannels $true -Cap $MaxEvents
        foreach ($o in $extra) { Add-BrowserEvent $o -AlsoTimeline }
        Write-Host ("  Added {0} Critical/Error event(s) from all channels." -f $extra.Count) -ForegroundColor Yellow
    }
}

Compare-Trends

# Summary
Write-Head 'DIAGNOSIS SUMMARY'
$order = @{ 'CRITICAL'=0; 'WARNING'=1; 'INFO'=2; 'OK'=3 }
$ranked = @($script:Findings | Sort-Object { $order[$_.Severity] }, { if ($_.When) { - $_.When.Ticks } else { 0 } })
$crit = @($ranked | Where-Object Severity -eq 'CRITICAL')
$warn = @($ranked | Where-Object Severity -eq 'WARNING')
if ($crit.Count -eq 0 -and $warn.Count -eq 0) {
    Write-Host "`n  No critical or warning issues found. System looks healthy." -ForegroundColor Green
} else {
    Write-Host ("`n  {0} CRITICAL, {1} WARNING finding(s):`n" -f $crit.Count, $warn.Count) -ForegroundColor White
}
foreach ($f in $ranked | Where-Object Severity -in 'CRITICAL','WARNING') {
    $c = if ($f.Severity -eq 'CRITICAL') {'Red'} else {'Yellow'}
    Write-Host ("  [{0,-8}] {1,-9} {2}" -f $f.Severity, $f.Area, $f.Title) -ForegroundColor $c
    if ($f.Detail) { Write-Host ("             -> {0}" -f $f.Detail) -ForegroundColor DarkGray }
}

$rootCause = Get-RootCause
Write-Host ''
Write-Host '  MOST LIKELY ROOT CAUSE:' -ForegroundColor Magenta
Write-Host "    $rootCause" -ForegroundColor White

$agg = Get-EventAggregates

# Reports
$reportDir = Join-Path $PSScriptRoot 'Reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$jsonPath = Join-Path $reportDir "Diagnosis_$($script:TargetName)_$stamp.json"
Save-DiagnosisJson -Path $jsonPath -RootCause $rootCause
Write-Host "`n  JSON saved: $jsonPath" -ForegroundColor Cyan

Export-MatchedEvents -Stamp $stamp -ReportDir $reportDir | Out-Null

if (-not $NoHtml) {
    $reportPath = Join-Path $reportDir "Diagnosis_$($script:TargetName)_$stamp.html"
    Write-HtmlReport -Path $reportPath -RootCause $rootCause -Agg $agg
    Write-Host "  HTML report: $reportPath" -ForegroundColor Cyan
    Start-Process $reportPath
}

Write-Host ("`n  Done in {0:n1}s.`n" -f ((Get-Date) - $script:Start).TotalSeconds) -ForegroundColor DarkGray
if ($host.Name -eq 'ConsoleHost' -and -not $env:CI -and [Environment]::UserInteractive) {
    Write-Host '  Press any key to close...' -ForegroundColor DarkGray
    try { $null = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') } catch {}
}
