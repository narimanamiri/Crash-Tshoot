"""Windows collectors — structured crash events first, then heuristics / optional PS merge."""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from ..models import Finding, Severity, LogHit
from .base import free_space_finding, run_cmd, scan_log_file, hits_to_findings, discover_extra_logs

# Decimal bugcheck -> (name, hint)
BUGCHECK_MAP = {
    0x0A: ("IRQL_NOT_LESS_OR_EQUAL", "Bad/old driver or faulty RAM."),
    0x1A: ("MEMORY_MANAGEMENT", "Often faulty RAM or a driver corrupting memory."),
    0x1E: ("KMODE_EXCEPTION_NOT_HANDLED", "Usually a driver."),
    0x3B: ("SYSTEM_SERVICE_EXCEPTION", "Error in a system call — often graphics/storage/system driver."),
    0x50: ("PAGE_FAULT_IN_NONPAGED_AREA", "Faulty RAM or bad driver."),
    0x7E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Update/roll back drivers."),
    0x7F: ("UNEXPECTED_KERNEL_MODE_TRAP", "RAM, overclock, or overheating."),
    0x9F: ("DRIVER_POWER_STATE_FAILURE", "Sleep/wake driver issue."),
    0xC2: ("BAD_POOL_CALLER", "Faulty driver."),
    0xD1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Network/storage drivers common."),
    0xEF: ("CRITICAL_PROCESS_DIED", "Corruption or bad drivers — SFC/DISM."),
    0xF4: ("CRITICAL_OBJECT_TERMINATION", "Often failing disk."),
    0x101: ("CLOCK_WATCHDOG_TIMEOUT", "CPU core stuck — power/overclock."),
    0x113: ("VIDEO_DXGKRNL_FATAL_ERROR", "Graphics subsystem fault."),
    0x116: ("VIDEO_TDR_ERROR", "GPU timeout."),
    0x124: ("WHEA_UNCORRECTABLE_ERROR", "HARDWARE machine-check."),
    0x133: ("DPC_WATCHDOG_VIOLATION", "Driver ran too long — storage/network."),
    0x139: ("KERNEL_SECURITY_CHECK_FAILURE", "Bad driver or RAM."),
    0x154: ("UNEXPECTED_STORE_EXCEPTION", "Failing disk/cable/port highly likely."),
}

STATUS_HINTS = {
    0xC0000005: "STATUS_ACCESS_VIOLATION — bad pointer / driver.",
    0xC0000006: "STATUS_IN_PAGE_ERROR — page could not be read from disk/pagefile (failing storage, bad cable, or RAM).",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES.",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _parse_hex(val: str | None) -> int:
    if not val:
        return 0
    s = str(val).strip().lower()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s, 0) if s.startswith("0") and len(s) > 1 and s[1] in "xX" else int(s)
    except ValueError:
        try:
            return int(s, 16)
        except ValueError:
            return 0


def collect_structured_crash_events(result, days: int) -> None:
    """Query KP41, 6008, volmgr 161, stor* 129, phantom disks, LiveKernel 193 — full INCIDENTS evidence set."""
    ps = rf"""
$ErrorActionPreference='SilentlyContinue'
$since=(Get-Date).AddDays(-{int(days)})
$out=@{{
  kp41=@(); e6008=@(); volmgr161=@(); storAhci=@(); storNvme=@(); phantom=@(); liveKernel193=0; displayTdr=0; lastBoot=$null
}}
$os=Get-CimInstance Win32_OperatingSystem
$out.lastBoot=$os.LastBootUpTime.ToString('o')
Get-WinEvent -FilterHashtable @{{LogName='System';Id=41;StartTime=$since}} | ForEach-Object {{
  $x=[xml]$_.ToXml(); $d=@{{}}
  $x.Event.EventData.Data | ForEach-Object {{ $d[$_.Name]=$_.'#text' }}
  $out.kp41 += @{{
    Time=$_.TimeCreated.ToString('o')
    BugcheckCode=$d['BugcheckCode']
    P1=$d['BugcheckParameter1']
    P2=$d['BugcheckParameter2']
    P3=$d['BugcheckParameter3']
    P4=$d['BugcheckParameter4']
    PowerButton=$d['PowerButtonTimestamp']
    FromEFI=$d['BugcheckInfoFromEFI']
  }}
}}
Get-WinEvent -FilterHashtable @{{LogName='System';Id=6008;StartTime=$since}} | ForEach-Object {{
  $out.e6008 += @{{ Time=$_.TimeCreated.ToString('o'); Message=(($_.Message -split "`n")[0]) }}
}}
Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='volmgr';Id=161;StartTime=$since}} | ForEach-Object {{
  $out.volmgr161 += @{{ Time=$_.TimeCreated.ToString('o'); Message=(($_.Message -split "`n")[0]) }}
}}
$sa=@(Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='storahci';Id=129;StartTime=$since}})
$out.storAhci=@($sa | ForEach-Object {{ @{{ Time=$_.TimeCreated.ToString('o'); Message=(($_.Message -split "`n")[0]) }} }})
$sn=@(Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='stornvme';Id=129;StartTime=$since}})
if(-not $sn){{ $sn=@(Get-WinEvent -FilterHashtable @{{LogName='System';Id=129;StartTime=$since}} | Where-Object {{ $_.ProviderName -match 'stornvme|storport' }}) }}
$out.storNvme=@($sn | ForEach-Object {{ @{{ Time=$_.TimeCreated.ToString('o'); Message=(($_.Message -split "`n")[0]); Provider=$_.ProviderName }} }})
Get-CimInstance Win32_DiskDrive | Where-Object {{ $_.Size -eq $null -or $_.Size -eq 0 }} | ForEach-Object {{
  $out.phantom += @{{ Model=$_.Model; Interface=$_.InterfaceType; PNP=$_.PNPDeviceID }}
}}
$lk=@(Get-WinEvent -FilterHashtable @{{LogName='Application';StartTime=$since}} -MaxEvents 800 | Where-Object {{ $_.Message -match 'LiveKernelEvent' -and $_.Message -match '193|WATCHDOG|VIDEO_DXGKRNL' }})
$out.liveKernel193=$lk.Count
$td=@(Get-WinEvent -FilterHashtable @{{LogName='System';ProviderName='Display';Id=4101;StartTime=$since}})
$out.displayTdr=$td.Count
$out | ConvertTo-Json -Depth 6 -Compress
"""
    code, out, err = run_cmd(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        timeout=120,
    )
    if code != 0 or not out.strip():
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Crash",
                "Could not query structured crash events (Kernel-Power 41)",
                (err or out or "empty")[:500],
                action="Re-run elevated; ensure System log is readable.",
                source="collector",
            )
        )
        return

    # Extract JSON object from possible banner noise
    start, end = out.find("{"), out.rfind("}")
    if start < 0 or end < 0:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Crash",
                "Crash-event query returned non-JSON",
                out[:400],
                source="collector",
            )
        )
        return
    try:
        data = json.loads(out[start : end + 1])
    except json.JSONDecodeError as e:
        result.findings.append(
            Finding(Severity.WARNING, "Crash", "Crash-event JSON parse failed", str(e), source="collector")
        )
        return

    if data.get("lastBoot"):
        result.snapshot["last_boot"] = data["lastBoot"]

    kp41 = data.get("kp41") or []
    if isinstance(kp41, dict):
        kp41 = [kp41]
    e6008 = data.get("e6008") or []
    if isinstance(e6008, dict):
        e6008 = [e6008]
    volmgr = data.get("volmgr161") or []
    if isinstance(volmgr, dict):
        volmgr = [volmgr]

    result.counters["KP41"] = len(kp41)
    result.counters["E6008"] = len(e6008)
    result.counters["Volmgr161"] = len(volmgr)

    if not kp41 and not e6008:
        result.findings.append(
            Finding(
                Severity.OK,
                "Power",
                "No Kernel-Power 41 or unexpected-shutdown (6008) in window",
                source="collector",
            )
        )

    for e in e6008:
        result.findings.append(
            Finding(
                Severity.CRITICAL,
                "Power",
                "Unexpected shutdown recorded (Event 6008)",
                e.get("Message", ""),
                when=e.get("Time"),
                action="Pair with Kernel-Power 41: BSOD vs power-loss vs hung dump.",
                evidence=[e.get("Message", "")],
                source="collector",
            )
        )
        result.log_hits.append(
            LogHit(
                path="System:6008",
                line_no=0,
                line=e.get("Message", ""),
                pattern="6008",
                category="power",
                severity=Severity.CRITICAL,
                when=e.get("Time"),
            )
        )

    for e in kp41:
        bc = _parse_hex(e.get("BugcheckCode"))
        p1 = _parse_hex(e.get("P1"))
        pwr = str(e.get("PowerButton") or "0")
        when = e.get("Time")
        if bc != 0:
            name, hint = BUGCHECK_MAP.get(bc, ("UNKNOWN_BUGCHECK", "Search the stop code online / analyze minidump."))
            hex_bc = f"0x{bc:X}"
            status = STATUS_HINTS.get(p1, "")
            detail = (
                f"At {when}. Stop {hex_bc} {name}. "
                f"Param1=0x{p1:X} Param2={e.get('P2')} Param3={e.get('P3')} Param4={e.get('P4')}. "
                f"{hint}"
            )
            if status:
                detail += f" Param1 decode: {status}"
            action = "Analyze minidump if present; update implicated driver."
            if p1 == 0xC0000006 or bc == 0x154:
                action = (
                    "STATUS_IN_PAGE_ERROR / store failure — back up; check NVMe/SATA health & cables; "
                    "test RAM (MemTest86); free space on pagefile volume."
                )
            result.findings.append(
                Finding(
                    Severity.CRITICAL,
                    "Crash",
                    f"Blue screen: {name} ({hex_bc})",
                    detail,
                    when=when,
                    action=action,
                    evidence=[detail],
                    source="collector",
                )
            )
            result.counters["BugCheck"] = int(result.counters.get("BugCheck") or 0) + 1
            result.counters["LastBugcheck"] = hex_bc
            result.counters["LastBugcheckParam1"] = f"0x{p1:X}"
        elif pwr not in ("0", "", "None", "none"):
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Power",
                    f"Hard power-off via power button at {when}",
                    "PowerButtonTimestamp non-zero.",
                    when=when,
                    source="collector",
                )
            )
        else:
            result.findings.append(
                Finding(
                    Severity.CRITICAL,
                    "Power",
                    f"Abrupt power loss / hard lock at {when}",
                    "Kernel-Power 41 with BugcheckCode=0 — power cut or freeze before Windows could bugcheck.",
                    when=when,
                    action="Check PSU, cables, UPS, thermals; correlate with 6008 time.",
                    source="collector",
                )
            )

    for e in volmgr:
        result.findings.append(
            Finding(
                Severity.CRITICAL,
                "Crash",
                "Crash dump could NOT be written (volmgr 161)",
                e.get("Message", ""),
                when=e.get("Time"),
                action=(
                    "Dump write failed — often why a BSOD freezes until you pull the plug. "
                    "Disk/pagefile path was unresponsive; check storage health."
                ),
                evidence=[e.get("Message", "")],
                source="collector",
            )
        )

    # Incident #1 storage signals
    def _as_list(v):
        if v is None:
            return []
        return [v] if isinstance(v, dict) else list(v)

    stor_ahci = _as_list(data.get("storAhci"))
    stor_nvme = _as_list(data.get("storNvme"))
    phantom = _as_list(data.get("phantom"))
    result.counters["StorAhci129"] = len(stor_ahci)
    result.counters["StorNvme129"] = len(stor_nvme)
    result.counters["LiveKernel193"] = int(data.get("liveKernel193") or 0)
    result.counters["DisplayTDR"] = int(data.get("displayTdr") or 0)

    if stor_ahci:
        sev = Severity.CRITICAL if len(stor_ahci) >= 3 else Severity.WARNING
        sample = stor_ahci[0].get("Message", "")
        result.findings.append(
            Finding(
                sev,
                "Disk",
                f"{len(stor_ahci)} SATA/AHCI device resets (storahci 129)",
                sample or "Disk on AHCI stopped responding (RaidPort).",
                when=stor_ahci[0].get("Time"),
                action="Reseat SATA data+power; try another port; check SMART; disable phantom drive if present.",
                evidence=[x.get("Message", "")[:200] for x in stor_ahci[:5]],
                source="collector",
            )
        )
    if stor_nvme:
        sev = Severity.CRITICAL if len(stor_nvme) >= 3 else Severity.WARNING
        result.findings.append(
            Finding(
                sev,
                "Disk",
                f"{len(stor_nvme)} NVMe/storport device resets (129)",
                stor_nvme[0].get("Message", ""),
                when=stor_nvme[0].get("Time"),
                action="Update NVMe firmware; reseat SSD; check PSU.",
                evidence=[x.get("Message", "")[:200] for x in stor_nvme[:5]],
                source="collector",
            )
        )
    for g in phantom:
        result.findings.append(
            Finding(
                Severity.CRITICAL,
                "Disk",
                "Phantom/0-byte drive detected",
                f"Model={g.get('Model')}; Interface={g.get('Interface')}; PNP={g.get('PNP')}",
                action="Disable or physically unplug failing SATA device (see Incident #1).",
                evidence=[str(g.get("PNP") or "")],
                source="collector",
            )
        )

    lk_n = result.counters["LiveKernel193"]
    if lk_n:
        sev = Severity.CRITICAL if lk_n >= 3 and not result.counters.get("BugCheck") else Severity.WARNING
        result.findings.append(
            Finding(
                sev,
                "GPU",
                f"LiveKernelEvent 193 (VIDEO_DXGKRNL_LIVEDUMP) x{lk_n}",
                "Graphics kernel live dump signal (often Param 80e). Not a fatal BSOD by itself.",
                action="DDU + GPU driver; free C: space; update/quit Sunshine overlays.",
                source="collector",
            )
        )
    tdr_n = result.counters["DisplayTDR"]
    if tdr_n:
        result.findings.append(
            Finding(
                Severity.CRITICAL if tdr_n >= 5 else Severity.WARNING,
                "GPU",
                f"{tdr_n} Display TDR timeout(s) (Event 4101)",
                "GPU stopped responding and recovered (or failed).",
                action="Update/roll back GPU driver; check GPU temp and power.",
                source="collector",
            )
        )


def try_powershell_engine(days: int) -> dict | None:
    """Optional merge of SystemDiagnoser.ps1 JSON (best-effort, never blocks core diagnosis)."""
    ps1 = _project_root() / "SystemDiagnoser.ps1"
    if not ps1.is_file():
        return None
    reports = _project_root() / "Reports"
    before = {p.resolve() for p in reports.glob("Diagnosis_*.json")} if reports.is_dir() else set()
    before_t = datetime.now()
    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(ps1),
        "-Days",
        str(days),
        "-NoHtml",
        "-Export",
        "Json",
    ]
    env = os.environ.copy()
    env["CI"] = "1"
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env, errors="replace")
    except Exception:
        return None
    if not reports.is_dir():
        return None
    candidates = [
        p
        for p in reports.glob("Diagnosis_*.json")
        if p.resolve() not in before or datetime.fromtimestamp(p.stat().st_mtime) >= before_t
    ]
    if not candidates:
        return None
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    try:
        return json.loads(newest.read_text(encoding="utf-8"))
    except Exception:
        return None


def collect_windows(result, days: int = 7, extra_logs: list[str] | None = None) -> None:
    result.platform = "windows"
    since = datetime.now() - timedelta(days=days)

    f = free_space_finding("C:\\")
    if f:
        result.findings.append(f)
        m = re.search(r"\((\d+)%", f.title)
        if m:
            result.counters["FreePct"] = int(m.group(1))

    code, out, _ = run_cmd(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name",
        ]
    )
    if code == 0 and out.strip():
        gpu = "; ".join(x.strip() for x in out.splitlines() if x.strip())
        result.snapshot["gpu"] = gpu
        result.counters["GpuName"] = gpu

    # *** Primary: structured crash channel (fixes pull-the-plug miss) ***
    collect_structured_crash_events(result, days)

    # LiveKernelReports (mtime in window only)
    lk = Path(r"C:\Windows\LiveKernelReports")
    dumps = []
    if lk.is_dir():
        for p in lk.rglob("*.dmp"):
            try:
                if datetime.fromtimestamp(p.stat().st_mtime) >= since:
                    dumps.append(p)
            except OSError:
                pass
    if dumps:
        newest = max(dumps, key=lambda p: p.stat().st_mtime)
        result.findings.append(
            Finding(
                Severity.WARNING,
                "GPU",
                f"{len(dumps)} LiveKernel/WATCHDOG dump(s) in scan window",
                f"Newest: {newest} @ {datetime.fromtimestamp(newest.stat().st_mtime)}",
                when=datetime.fromtimestamp(newest.stat().st_mtime).isoformat(timespec="seconds"),
                action="Analyze with WinDbg; update GPU drivers.",
                source="collector",
            )
        )
        result.counters["LiveKernelDumps"] = len(dumps)

    mini = Path(r"C:\Windows\Minidump")
    if mini.is_dir():
        md = [p for p in mini.glob("*.dmp") if datetime.fromtimestamp(p.stat().st_mtime) >= since]
        if md:
            newest = max(md, key=lambda p: p.stat().st_mtime)
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Crash",
                    f"{len(md)} minidump(s) in scan window",
                    f"Newest: {newest.name} @ {datetime.fromtimestamp(newest.stat().st_mtime)}",
                    action="Open in BlueScreenView or WinDbg (!analyze -v).",
                    source="collector",
                )
            )
        elif result.counters.get("BugCheck"):
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Crash",
                    "BSOD recorded but no minidump in scan window",
                    "Matches volmgr 161 / hung dump — you may have had to pull the plug.",
                    action="Fix storage path used for dumps; ensure pagefile on healthy volume.",
                    source="collector",
                )
            )

    # Text heuristics (secondary)
    code, out, _ = run_cmd(
        ["wevtutil", "qe", "System", "/c:300", "/rd:true", "/f:text"],
        timeout=90,
    )
    from .base import scan_text_lines

    hits = scan_text_lines(out.splitlines(), "wevtutil:System", "windows", since) if out else []
    code2, out2, _ = run_cmd(
        ["wevtutil", "qe", "Application", "/c:300", "/rd:true", "/f:text"],
        timeout=90,
    )
    hits += scan_text_lines(out2.splitlines(), "wevtutil:Application", "windows", since) if out2 else []

    for p in discover_extra_logs(extra_logs):
        hits += scan_log_file(p, "windows")

    result.log_hits.extend(hits)
    # Avoid double-counting GPU LiveKernel noise as CRITICAL when we already have a real BSOD
    heuristic_findings = hits_to_findings(hits, platform="windows")
    if result.counters.get("BugCheck"):
        for hf in heuristic_findings:
            if hf.area.upper() in ("GPU", "THERMAL", "TIMEOUT") and hf.severity == Severity.CRITICAL:
                hf.severity = Severity.WARNING
                hf.detail = (hf.detail or "") + " (de-prioritized: real BSOD present)"
    result.findings.extend(heuristic_findings)

    # Optional PS merge — opt-in (slow; structured KP41 path is authoritative)
    if os.environ.get("CRASH_TSHOOT_PS_MERGE", "").strip() in ("1", "true", "yes"):
        data = try_powershell_engine(days)
        if data:
            result.snapshot["powershell_engine"] = True
            for f in data.get("Findings") or []:
                try:
                    sev = Severity(f.get("Severity", "INFO"))
                except ValueError:
                    sev = Severity.INFO
                title = f.get("Title", "")
                if any(x.title == title and x.area == f.get("Area", "PS") for x in result.findings):
                    continue
                result.findings.append(
                    Finding(
                        severity=sev,
                        area=f.get("Area", "PS"),
                        title=title,
                        detail=f.get("Detail", ""),
                        when=str(f.get("When") or "") or None,
                        action=f.get("Action", ""),
                        source="collector",
                    )
                )
            if data.get("RootCause"):
                result.snapshot["ps_root_cause"] = data["RootCause"]

    _dedupe_findings(result)


def _dedupe_findings(result) -> None:
    seen = set()
    uniq = []
    for f in result.findings:
        key = (f.severity.value, f.area, f.title)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    result.findings = uniq
