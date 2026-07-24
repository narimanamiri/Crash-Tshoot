"""
Advanced Event Viewer engine (FullEventLogView / journalctl / macOS log parity).

Works on:
  Windows — Get-WinEvent / EVTX
  Linux   — journalctl (JSON)
  macOS   — log show
  Any     — offline text/.evtx folder when provided
"""

from __future__ import annotations

import csv
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from .collectors.base import run_cmd, detect_platform


PRESETS: dict[str, dict[str, Any]] = {
    "CriticalErrors": {"levels": [1, 2], "all_channels": True},
    "AllWarningsPlus": {"levels": [1, 2, 3], "all_channels": True},
    "BootShutdown": {
        "event_ids": [6005, 6006, 6008, 1074, 41],
        "channels": ["System"],
        "providers": ["EventLog", "Microsoft-Windows-Kernel-Power", "User32"],
    },
    "BSODPower": {
        "event_ids": [41, 1001],
        "channels": ["System"],
        "providers": [
            "Microsoft-Windows-Kernel-Power",
            "Microsoft-Windows-WER-SystemErrorReporting",
            "Microsoft-Windows-WHEA-Logger",
        ],
    },
    "Storage": {
        "event_ids": [7, 51, 129, 153, 161],
        "channels": ["System"],
        "providers": ["storahci", "stornvme", "disk", "Ntfs", "volmgr"],
    },
    "GPUDisplay": {
        "event_ids": [4101, 14],
        "channels": ["System", "Application"],
        "providers": ["Display", "Microsoft-Windows-DxgKrnl"],
    },
    "SecurityLogon": {
        "event_ids": [4624, 4625, 4634, 4648, 4672],
        "channels": ["Security"],
    },
    "WHEA": {"providers": ["Microsoft-Windows-WHEA-Logger"], "channels": ["System"]},
    "WindowsUpdate": {
        "channels": ["System", "Setup"],
        "providers": ["Microsoft-Windows-WindowsUpdateClient", "Microsoft-Windows-Setup"],
        "levels": [1, 2, 3],
    },
    "Defender": {
        "channels": ["Microsoft-Windows-Windows Defender/Operational"],
        "levels": [1, 2, 3],
    },
    "Network": {
        "channels": ["System", "Microsoft-Windows-NetworkProfile/Operational"],
        "providers": ["Tcpip", "e1dexpress", "Netwtw", "Microsoft-Windows-NDIS"],
        "levels": [1, 2, 3],
    },
    "DiskIO": {
        "event_ids": [7, 51, 129, 153, 55, 98],
        "channels": ["System"],
        "providers": ["disk", "ntfs", "storahci", "stornvme", "volmgr"],
    },
    "HyperV": {
        "channels": ["System"],
        "providers": ["Microsoft-Windows-Hyper-V"],
        "levels": [1, 2, 3],
    },
    "Setup": {"channels": ["Setup"], "levels": [1, 2, 3]},
    # Cross-platform friendly aliases (mapped per OS in query_*)
    "Kernel": {"levels": [1, 2], "message_hint": "kernel|panic|fault|watchdog"},
    "Errors": {"levels": [1, 2]},
}


# Preset → journalctl / macOS predicate hints
_LINUX_PRESET_HINTS = {
    "CriticalErrors": {"priority": "err"},
    "AllWarningsPlus": {"priority": "warning"},
    "Errors": {"priority": "err"},
    "BootShutdown": {"priority": "err", "grep": "Started|Stopped|reboot|shutdown|watchdog"},
    "BSODPower": {"priority": "err", "grep": "panic|BUG|Oops|Power|thermal|MCE"},
    "Storage": {"priority": "err", "grep": "I/O error|nvme|ata|ext4|XFS|disk|scsi|blk"},
    "GPUDisplay": {"priority": "err", "grep": "amdgpu|i915|nouveau|drm|GPU|Xid"},
    "SecurityLogon": {"priority": "info", "grep": "sshd|sudo|auth|Failed password|session"},
    "WHEA": {"priority": "err", "grep": "mce|Hardware Error|EDAC"},
    "Network": {"priority": "err", "grep": "link down|NIC|eth|wlan|dns|dhcp"},
    "DiskIO": {"priority": "err", "grep": "I/O|blk_|nvme|scsi|Buffer I/O"},
    "Kernel": {"priority": "err", "grep": "kernel|panic|BUG|Oops|lockup"},
    "WindowsUpdate": {"priority": "err", "grep": "apt|dnf|yum|pacman|zypper|update"},
    "Defender": {"priority": "warning", "grep": "clamav|fail2ban|audit"},
    "HyperV": {"priority": "err", "grep": "kvm|qemu|libvirt|xen"},
    "Setup": {"priority": "notice", "grep": "install|upgrade|kernel"},
}

_MACOS_PRESET_HINTS = {
    "CriticalErrors": {"predicate": "messageType == error OR messageType == fault OR eventType == fault"},
    "AllWarningsPlus": {"predicate": "messageType == error OR messageType == fault OR messageType == default"},
    "Errors": {"predicate": "messageType == error OR messageType == fault"},
    "BootShutdown": {"predicate": 'eventMessage CONTAINS[c] "shutdown" OR eventMessage CONTAINS[c] "boot" OR eventMessage CONTAINS[c] "restart"'},
    "BSODPower": {"predicate": 'eventMessage CONTAINS[c] "panic" OR eventMessage CONTAINS[c] "watchdog" OR eventMessage CONTAINS[c] "SMC"'},
    "Storage": {"predicate": 'eventMessage CONTAINS[c] "disk" OR eventMessage CONTAINS[c] "I/O" OR eventMessage CONTAINS[c] "NVMe" OR eventMessage CONTAINS[c] "SMART"'},
    "GPUDisplay": {"predicate": 'eventMessage CONTAINS[c] "GPU" OR eventMessage CONTAINS[c] "graphics" OR eventMessage CONTAINS[c] "Metal" OR eventMessage CONTAINS[c] "IOAccelerator"'},
    "SecurityLogon": {"predicate": 'eventMessage CONTAINS[c] "login" OR eventMessage CONTAINS[c] "auth" OR eventMessage CONTAINS[c] "ssh"'},
    "Kernel": {"predicate": 'process == "kernel" OR eventMessage CONTAINS[c] "panic" OR eventMessage CONTAINS[c] "watchdog"'},
    "Network": {"predicate": 'eventMessage CONTAINS[c] "network" OR eventMessage CONTAINS[c] "Wi-Fi" OR eventMessage CONTAINS[c] "en0"'},
    "DiskIO": {"predicate": 'eventMessage CONTAINS[c] "disk" OR eventMessage CONTAINS[c] "I/O" OR subsystem CONTAINS "disk"'},
    "Thermal": {"predicate": 'eventMessage CONTAINS[c] "thermal" OR eventMessage CONTAINS[c] "temperature"'},
}


@dataclass
class EvFilter:
    days: int = 7
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    levels: list[int] = field(default_factory=list)  # 1=Critical .. 5=Verbose
    event_ids: list[int] = field(default_factory=list)
    exclude_event_ids: list[int] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)  # substring / wildcard *
    exclude_providers: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    exclude_channels: list[str] = field(default_factory=list)
    message_contains: str = ""
    user_contains: str = ""
    all_channels: bool = False
    max_events: int = 5000
    preset: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.start:
            d["start"] = self.start.isoformat()
        if self.end:
            d["end"] = self.end.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvFilter":
        f = cls()
        for k, v in d.items():
            if k in ("start", "end") and v:
                setattr(f, k, datetime.fromisoformat(str(v).replace("Z", "+00:00")))
            elif hasattr(f, k):
                setattr(f, k, v)
        return f

    def apply_preset(self, name: str) -> None:
        spec = PRESETS.get(name)
        if not spec:
            raise ValueError(f"Unknown preset '{name}'. Choose: {', '.join(sorted(PRESETS))}")
        self.preset = name
        if spec.get("levels") and not self.levels:
            self.levels = list(spec["levels"])
        if spec.get("event_ids") and not self.event_ids:
            self.event_ids = list(spec["event_ids"])
        if spec.get("providers") and not self.providers:
            self.providers = list(spec["providers"])
        if spec.get("channels") and not self.channels:
            self.channels = list(spec["channels"])
        if spec.get("all_channels"):
            self.all_channels = True


def _wild(text: str, pattern: str) -> bool:
    if not pattern:
        return True
    rx = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return bool(re.match(rx, text or "", re.I))


def _level_name(n: int) -> str:
    return {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose"}.get(n, f"Level{n}")


def list_channels() -> list[dict[str, Any]]:
    plat = detect_platform()
    if plat == "windows":
        return _list_channels_windows()
    if plat == "linux":
        return _list_channels_linux()
    if plat == "macos":
        return _list_channels_macos()
    if plat == "bsd":
        return [
            {"Name": "dmesg", "Enabled": True, "Records": -1, "SizeMB": 0},
            {"Name": "/var/log/messages", "Enabled": Path("/var/log/messages").is_file(), "Records": -1, "SizeMB": 0},
            {"Name": "/var/log/system.log", "Enabled": Path("/var/log/system.log").is_file(), "Records": -1, "SizeMB": 0},
        ]
    return [{"Name": "offline-logs", "Enabled": True, "Records": 0, "SizeMB": 0, "Note": "Use --log-folder"}]


def _list_channels_windows() -> list[dict[str, Any]]:
    # wevtutil el is faster/more reliable than Get-WinEvent -ListLog *
    code, out, _ = run_cmd(["wevtutil", "el"], timeout=60)
    names: list[str] = []
    if code == 0 and out.strip():
        names = [ln.strip() for ln in out.splitlines() if ln.strip()]
    else:
        ps = r"""
$ErrorActionPreference='SilentlyContinue'
@(Get-WinEvent -ListLog Application,System,Security,Setup -EA SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ Name=$_.LogName; Enabled=$_.IsEnabled; Records=$_.RecordCount; SizeMB=[math]::Round(($_.FileSize/1MB),2) }
}) | ConvertTo-Json -Compress
"""
        code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=60)
        if code == 0 and out.strip():
            try:
                data = json.loads(out[out.find("[") : out.rfind("]") + 1] if "[" in out else out)
                return data if isinstance(data, list) else [data]
            except Exception:
                pass
        return []

    # Enrich classic channels with record counts; others listed as enabled inventory
    enrich = {"Application", "System", "Security", "Setup"}
    enriched: dict[str, dict[str, Any]] = {}
    if any(n in enrich for n in names):
        ps = r"""
$ErrorActionPreference='SilentlyContinue'
@(Get-WinEvent -ListLog Application,System,Security,Setup -EA SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ Name=$_.LogName; Enabled=$_.IsEnabled; Records=$_.RecordCount; SizeMB=[math]::Round(($_.FileSize/1MB),2) }
}) | ConvertTo-Json -Compress
"""
        code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=45)
        if code == 0 and out.strip():
            try:
                data = json.loads(out[out.find("[") : out.rfind("]") + 1] if "[" in out else out)
                if isinstance(data, dict):
                    data = [data]
                for row in data:
                    enriched[str(row.get("Name"))] = row
            except Exception:
                pass

    rows: list[dict[str, Any]] = []
    for name in names:
        if name in enriched:
            rows.append(enriched[name])
        else:
            rows.append({"Name": name, "Enabled": True, "Records": -1, "SizeMB": 0})
    return rows


def _list_channels_linux() -> list[dict[str, Any]]:
    out_list = []
    code, out, _ = run_cmd(["journalctl", "--header"], timeout=30)
    if code == 0 and out.strip():
        out_list.append({"Name": "journald", "Enabled": True, "Records": -1, "SizeMB": 0, "Note": out.splitlines()[0][:120]})
    for unit_src in ("system", "user"):
        out_list.append({"Name": f"journal:{unit_src}", "Enabled": True, "Records": -1, "SizeMB": 0})
    for p in ("/var/log/syslog", "/var/log/messages", "/var/log/kern.log", "/var/log/auth.log"):
        path = Path(p)
        if path.is_file():
            out_list.append(
                {
                    "Name": p,
                    "Enabled": True,
                    "Records": -1,
                    "SizeMB": round(path.stat().st_size / 1e6, 2),
                }
            )
    return out_list


def _list_channels_macos() -> list[dict[str, Any]]:
    items = [
        {"Name": "unified:log show", "Enabled": True, "Records": -1, "SizeMB": 0},
        {"Name": "pmset:log", "Enabled": True, "Records": -1, "SizeMB": 0},
    ]
    for p in (
        Path.home() / "Library/Logs/DiagnosticReports",
        Path("/Library/Logs/DiagnosticReports"),
        Path("/var/log/system.log"),
    ):
        if p.exists():
            size = p.stat().st_size / 1e6 if p.is_file() else 0
            items.append({"Name": str(p), "Enabled": True, "Records": -1, "SizeMB": round(size, 2)})
    return items


def query_events(filt: EvFilter) -> list[dict[str, Any]]:
    """Query live OS logs; platform-dispatch."""
    plat = detect_platform()
    if plat == "windows":
        return _query_windows(filt)
    if plat == "linux":
        return _query_linux(filt)
    if plat == "macos":
        return _query_macos(filt)
    if plat == "bsd":
        return _query_bsd(filt)
    return []


def _normalize_line_event(
    *,
    when: str,
    message: str,
    provider: str,
    channel: str,
    level: str = "Information",
    level_raw: int = 4,
    event_id: int = 0,
) -> dict[str, Any]:
    return {
        "TimeCreated": when,
        "Id": event_id,
        "Level": level,
        "LevelRaw": level_raw,
        "Provider": provider,
        "Channel": channel,
        "RecordId": 0,
        "Task": "",
        "Opcode": "",
        "Message": message,
        "EventData": {},
        "Strings": [message[:200]],
        "UserName": None,
        "Xml": None,
    }


def _filter_message(ev: dict[str, Any], filt: EvFilter) -> bool:
    msg = ev.get("Message") or ""
    prov = ev.get("Provider") or ""
    if filt.message_contains and filt.message_contains.lower() not in msg.lower():
        return False
    if filt.user_contains and filt.user_contains.lower() not in msg.lower():
        return False
    if filt.providers:
        if not any(p.lower() in prov.lower() for p in filt.providers):
            return False
    if filt.exclude_providers:
        if any(p.lower() in prov.lower() for p in filt.exclude_providers):
            return False
    if filt.levels and int(ev.get("LevelRaw") or 0) not in filt.levels:
        # On unix we approximate levels; allow through if preset used message grep
        if not filt.preset:
            return False
    return True


def _query_linux(filt: EvFilter) -> list[dict[str, Any]]:
    hint = _LINUX_PRESET_HINTS.get(filt.preset or "", {})
    priority = hint.get("priority", "err")
    if filt.levels:
        # map 1,2 -> err, 3 -> warning
        if max(filt.levels) <= 2:
            priority = "err"
        elif max(filt.levels) <= 3:
            priority = "warning"
        else:
            priority = "info"
    args = [
        "journalctl",
        "-p",
        priority,
        f"--since={filt.days} days ago",
        "--no-pager",
        "-o",
        "json",
        "-n",
        str(min(filt.max_events, 5000)),
    ]
    if hint.get("grep"):
        args.extend(["--grep", hint["grep"]])
    if filt.message_contains:
        args.extend(["--grep", filt.message_contains])
    code, out, _ = run_cmd(args, timeout=120)
    if code != 0 or not out.strip():
        # fallback text
        code, out, _ = run_cmd(
            ["journalctl", "-p", priority, f"--since={filt.days} days ago", "--no-pager", "-n", str(filt.max_events)],
            timeout=90,
        )
        events = []
        for ln in out.splitlines()[-filt.max_events :]:
            ev = _normalize_line_event(
                when=datetime.now().isoformat(timespec="seconds"),
                message=ln,
                provider="journald",
                channel="journal",
                level="Error" if priority == "err" else "Warning",
                level_raw=2 if priority == "err" else 3,
            )
            if _filter_message(ev, filt):
                events.append(ev)
        return events[: filt.max_events]

    events = []
    for ln in out.splitlines():
        if not ln.strip():
            continue
        try:
            j = json.loads(ln)
        except json.JSONDecodeError:
            continue
        # realtime timestamp usec
        ts = j.get("__REALTIME_TIMESTAMP") or j.get("_SOURCE_REALTIME_TIMESTAMP")
        when = datetime.now().isoformat(timespec="seconds")
        if ts:
            try:
                when = datetime.fromtimestamp(int(ts) / 1_000_000).isoformat(timespec="seconds")
            except Exception:
                pass
        pri = int(j.get("PRIORITY", 5))
        # syslog: 0-3 ~ critical/error, 4 warning
        if pri <= 2:
            level, level_raw = "Critical", 1
        elif pri == 3:
            level, level_raw = "Error", 2
        elif pri == 4:
            level, level_raw = "Warning", 3
        else:
            level, level_raw = "Information", 4
        msg = j.get("MESSAGE") or ""
        prov = j.get("SYSLOG_IDENTIFIER") or j.get("_SYSTEMD_UNIT") or j.get("_COMM") or "journald"
        ev = _normalize_line_event(
            when=when,
            message=str(msg),
            provider=str(prov),
            channel=str(j.get("_SYSTEMD_UNIT") or "journal"),
            level=level,
            level_raw=level_raw,
        )
        ev["EventData"] = {k: str(v) for k, v in j.items() if k.startswith("_") or k in ("PRIORITY", "MESSAGE")}
        if filt.exclude_event_ids:
            continue
        if _filter_message(ev, filt):
            events.append(ev)
        if len(events) >= filt.max_events:
            break
    return events


def _query_macos(filt: EvFilter) -> list[dict[str, Any]]:
    hint = _MACOS_PRESET_HINTS.get(filt.preset or "", {})
    predicate = hint.get("predicate", "messageType == error OR messageType == fault")
    if filt.message_contains:
        safe = filt.message_contains.replace('"', "")
        predicate = f'({predicate}) AND eventMessage CONTAINS[c] "{safe}"'
    args = [
        "log",
        "show",
        "--last",
        f"{filt.days}d",
        "--style",
        "ndjson",
        "--predicate",
        predicate,
    ]
    code, out, _ = run_cmd(args, timeout=120)
    events = []
    if code == 0 and out.strip():
        for ln in out.splitlines():
            if not ln.strip():
                continue
            try:
                j = json.loads(ln)
            except json.JSONDecodeError:
                continue
            msg = j.get("eventMessage") or j.get("message") or ""
            when = j.get("timestamp") or datetime.now().isoformat(timespec="seconds")
            mtype = (j.get("messageType") or "").lower()
            if mtype in ("fault", "error"):
                level, level_raw = ("Error", 2) if mtype == "error" else ("Critical", 1)
            elif mtype in ("default", "info"):
                level, level_raw = "Information", 4
            else:
                level, level_raw = "Warning", 3
            prov = j.get("processImagePath") or j.get("senderImagePath") or j.get("subsystem") or "log"
            if isinstance(prov, str) and "/" in prov:
                prov = Path(prov).name
            ev = _normalize_line_event(
                when=str(when),
                message=str(msg),
                provider=str(prov),
                channel=str(j.get("subsystem") or "unified"),
                level=level,
                level_raw=level_raw,
            )
            if _filter_message(ev, filt):
                events.append(ev)
            if len(events) >= filt.max_events:
                break
        return events

    # fallback compact
    code, out, _ = run_cmd(
        ["log", "show", "--last", f"{min(filt.days, 2)}d", "--style", "compact", "--predicate", predicate],
        timeout=90,
    )
    for ln in (out or "").splitlines()[-filt.max_events :]:
        ev = _normalize_line_event(
            when=datetime.now().isoformat(timespec="seconds"),
            message=ln,
            provider="log",
            channel="unified",
            level="Error",
            level_raw=2,
        )
        if _filter_message(ev, filt):
            events.append(ev)
    return events[: filt.max_events]


def _query_bsd(filt: EvFilter) -> list[dict[str, Any]]:
    events = []
    code, out, _ = run_cmd(["dmesg"], timeout=60)
    for ln in (out or "").splitlines()[-filt.max_events :]:
        ev = _normalize_line_event(
            when=datetime.now().isoformat(timespec="seconds"),
            message=ln,
            provider="dmesg",
            channel="kernel",
            level="Warning",
            level_raw=3,
        )
        if _filter_message(ev, filt):
            events.append(ev)
    return events[: filt.max_events]


def _query_windows(filt: EvFilter) -> list[dict[str, Any]]:
    """Query live Windows logs via PowerShell; return normalized event dicts."""

    end = filt.end or datetime.now()
    start = filt.start or (end - timedelta(days=filt.days))
    # Build compact filter for PS
    payload = {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "levels": filt.levels,
        "ids": filt.event_ids,
        "exIds": filt.exclude_event_ids,
        "providers": filt.providers,
        "exProviders": filt.exclude_providers,
        "channels": filt.channels,
        "exChannels": filt.exclude_channels,
        "msg": filt.message_contains,
        "user": filt.user_contains,
        "all": filt.all_channels,
        "cap": filt.max_events,
    }
    b64 = __import__("base64").b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    ps = rf"""
$ErrorActionPreference='SilentlyContinue'
$j = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}')) | ConvertFrom-Json
$since = [datetime]$j.start
$until = [datetime]$j.end
$cap = [int]$j.cap
$channels = @()
if ($j.all) {{
  $channels = @(Get-WinEvent -ListLog * | Where-Object {{ $_.IsEnabled -and $_.RecordCount -gt 0 }} | Select-Object -ExpandProperty LogName)
}} elseif ($j.channels -and $j.channels.Count -gt 0) {{
  $channels = @($j.channels)
}} else {{
  $channels = @('System','Application')
}}
if ($j.exChannels) {{
  $channels = @($channels | Where-Object {{ $n=$_; -not ($j.exChannels | Where-Object {{ $n -like $_ -or $n -eq $_ }}) }})
}}
$out = New-Object System.Collections.Generic.List[object]
foreach ($ch in $channels) {{
  if ($out.Count -ge $cap) {{ break }}
  $hash = @{{ LogName=$ch; StartTime=$since }}
  if ($j.ids -and $j.ids.Count -gt 0) {{ $hash['Id'] = @($j.ids) }}
  try {{ $evts = @(Get-WinEvent -FilterHashtable $hash -MaxEvents ($cap - $out.Count) -EA SilentlyContinue) }} catch {{ $evts=@() }}
  foreach ($e in $evts) {{
    if ($e.TimeCreated -gt $until) {{ continue }}
    if ($j.levels -and $j.levels.Count -gt 0 -and ($j.levels -notcontains [int]$e.Level)) {{ continue }}
    if ($j.exIds -and ($j.exIds -contains [int]$e.Id)) {{ continue }}
    $prov = [string]$e.ProviderName
    if ($j.providers -and $j.providers.Count -gt 0) {{
      $ok=$false; foreach ($p in $j.providers) {{ if ($prov -like ("*"+$p+"*") -or $prov -eq $p) {{ $ok=$true; break }} }}; if (-not $ok) {{ continue }}
    }}
    if ($j.exProviders) {{
      $skip=$false; foreach ($p in $j.exProviders) {{ if ($prov -like ("*"+$p+"*") -or $prov -eq $p) {{ $skip=$true; break }} }}; if ($skip) {{ continue }}
    }}
    $msg = ''; try {{ $msg = [string]$e.Message }} catch {{}}
    if ($j.msg -and ($msg -notmatch [regex]::Escape([string]$j.msg))) {{ continue }}
    $data=@{{}}; try {{
      $x=[xml]$e.ToXml()
      if ($x.Event.EventData.Data) {{
        $i=0; foreach ($d in @($x.Event.EventData.Data)) {{
          $n = if ($d.Name) {{ [string]$d.Name }} else {{ "String$i" }}; $data[$n]=[string]$d.'#text'; $i++
        }}
      }}
    }} catch {{}}
    if ($j.user) {{
      $blob = ($data.Values -join ' ') + ' ' + $msg
      if ($blob -notmatch [regex]::Escape([string]$j.user)) {{ continue }}
    }}
    $lvl = switch ([int]$e.Level) {{ 1 {{'Critical'}} 2 {{'Error'}} 3 {{'Warning'}} 4 {{'Information'}} 5 {{'Verbose'}} default {{"Level$($e.Level)"}} }}
    $strings = @($data.GetEnumerator() | Select-Object -First 12 | ForEach-Object {{ $_.Value }})
    $out.Add([pscustomobject]@{{
      TimeCreated=$e.TimeCreated.ToString('o'); Id=[int]$e.Id; Level=$lvl; LevelRaw=[int]$e.Level
      Provider=$prov; Channel=[string]$e.LogName; RecordId=[int64]$e.RecordId
      Task=[string]$e.TaskDisplayName; Opcode=[string]$e.OpcodeDisplayName
      Message=$msg; EventData=$data; Strings=$strings
      UserName=$($data['SubjectUserName']); Xml=$null
    }})
    if ($out.Count -ge $cap) {{ break }}
  }}
}}
$out | ConvertTo-Json -Depth 6 -Compress
"""
    code, out, err = run_cmd(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        timeout=180,
    )
    if code != 0 or not out.strip():
        return []
    try:
        start = out.find("[")
        if start < 0:
            start = out.find("{")
            end = out.rfind("}")
            data = json.loads(out[start : end + 1])
            return [data] if isinstance(data, dict) else []
        end = out.rfind("]")
        data = json.loads(out[start : end + 1])
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def load_evtx_folder(path: str | Path, filt: EvFilter) -> list[dict[str, Any]]:
    """Load .evtx (Windows) or text logs (any OS) from a file/folder."""
    root = Path(path)
    plat = detect_platform()

    # Text / syslog offline on any platform
    text_files: list[Path] = []
    if root.is_file() and root.suffix.lower() not in (".evtx",):
        text_files = [root]
    elif root.is_dir():
        for pat in ("*.log", "*.txt", "syslog*", "messages*", "kern.log*", "*.out"):
            text_files.extend(root.glob(pat))
            text_files.extend(root.glob("**/" + pat))
        text_files = list({p.resolve(): p for p in text_files if p.is_file()}.values())[:100]

    events: list[dict[str, Any]] = []
    if text_files:
        for f in text_files:
            try:
                raw = f.read_text(errors="replace")
            except OSError:
                continue
            for i, ln in enumerate(raw.splitlines()[-filt.max_events :], 1):
                if filt.message_contains and filt.message_contains.lower() not in ln.lower():
                    continue
                events.append(
                    _normalize_line_event(
                        when=datetime.now().isoformat(timespec="seconds"),
                        message=ln,
                        provider=f.name,
                        channel=str(f),
                        level="Information",
                        level_raw=4,
                        event_id=i,
                    )
                )
                if len(events) >= filt.max_events:
                    return events

    if plat != "windows":
        return events[: filt.max_events]

    files: list[Path] = []
    if root.is_file() and root.suffix.lower() == ".evtx":
        files = [root]
    elif root.is_dir():
        files = list(root.rglob("*.evtx"))[:80]
    if not files:
        return events[: filt.max_events]

    end = filt.end or datetime.now()
    start = filt.start or (end - timedelta(days=filt.days))
    collected: list[dict[str, Any]] = []
    for f in files:
        if len(collected) >= filt.max_events:
            break
        ps = rf"""
$ErrorActionPreference='SilentlyContinue'
$cap={filt.max_events - len(collected)}
$evts=@(Get-WinEvent -Path '{str(f).replace("'", "''")}' -MaxEvents $cap -EA SilentlyContinue)
$out=@()
foreach($e in $evts){{
  $msg=''; try{{$msg=[string]$e.Message}}catch{{}}
  $data=@{{}}; try{{ $x=[xml]$e.ToXml(); if($x.Event.EventData.Data){{ $i=0; foreach($d in @($x.Event.EventData.Data)){{ $n=if($d.Name){{[string]$d.Name}}else{{"String$i"}}; $data[$n]=[string]$d.'#text'; $i++ }} }} }}catch{{}}
  $lvl=switch([int]$e.Level){{1{{'Critical'}}2{{'Error'}}3{{'Warning'}}4{{'Information'}}5{{'Verbose'}}default{{"Level$($e.Level)"}}}}
  $out += [pscustomobject]@{{ TimeCreated=$e.TimeCreated.ToString('o'); Id=[int]$e.Id; Level=$lvl; LevelRaw=[int]$e.Level; Provider=[string]$e.ProviderName; Channel='{f.stem}'; RecordId=[int64]$e.RecordId; Message=$msg; EventData=$data; Strings=@($data.Values); LogFile='{str(f).replace(chr(39), chr(39)+chr(39))}' }}
}}
$out | ConvertTo-Json -Depth 5 -Compress
"""
        code, out, _ = run_cmd(["powershell", "-NoProfile", "-Command", ps], timeout=120)
        if code != 0 or not out.strip():
            continue
        try:
            s, e = out.find("["), out.rfind("]")
            if s < 0:
                continue
            batch = json.loads(out[s : e + 1])
            if isinstance(batch, dict):
                batch = [batch]
            for ev in batch:
                tc = datetime.fromisoformat(ev["TimeCreated"].replace("Z", "+00:00"))
                # naive compare if tz-aware
                if tc.replace(tzinfo=None) < start.replace(tzinfo=None):
                    continue
                if filt.event_ids and int(ev.get("Id", 0)) not in filt.event_ids:
                    continue
                if filt.exclude_event_ids and int(ev.get("Id", 0)) in filt.exclude_event_ids:
                    continue
                if filt.levels and int(ev.get("LevelRaw", 0)) not in filt.levels:
                    continue
                if filt.message_contains and filt.message_contains.lower() not in (ev.get("Message") or "").lower():
                    continue
                collected.append(ev)
                if len(collected) >= filt.max_events:
                    break
        except Exception:
            continue
    return (events + collected)[: filt.max_events]


def aggregates(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    from collections import Counter

    def top(key: str, n: int = 10):
        c = Counter((e.get(key) or "?") for e in events)
        return [{"Name": k, "Count": v} for k, v in c.most_common(n)]

    return {
        "ByLevel": top("Level"),
        "ByProvider": top("Provider"),
        "ById": top("Id"),
        "ByChannel": top("Channel"),
    }


def export_events(events: list[dict[str, Any]], out_dir: Path, stamp: str, formats: list[str]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = out_dir / f"Events_{stamp}"
    paths: list[Path] = []
    rows = []
    for e in events:
        strings = e.get("Strings") or []
        if isinstance(strings, dict):
            strings = list(strings.values())
        row = {
            "TimeCreated": e.get("TimeCreated", ""),
            "Level": e.get("Level", ""),
            "Id": e.get("Id", ""),
            "RecordId": e.get("RecordId", ""),
            "Provider": e.get("Provider", ""),
            "Channel": e.get("Channel", ""),
            "Message": (e.get("Message") or "").replace("\r", " ").replace("\n", " "),
            "LogFile": e.get("LogFile", ""),
        }
        for i, s in enumerate(list(strings)[:10], 1):
            row[f"String{i}"] = s
        rows.append(row)

    fmts = {f.lower() for f in formats}
    if "csv" in fmts:
        p = Path(str(base) + ".csv")
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["TimeCreated"])
            w.writeheader()
            w.writerows(rows)
        paths.append(p)
    if "tsv" in fmts or "tab" in fmts:
        p = Path(str(base) + ".tsv")
        with p.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else ["TimeCreated"], delimiter="\t")
            w.writeheader()
            w.writerows(rows)
        paths.append(p)
    if "json" in fmts:
        p = Path(str(base) + ".json")
        p.write_text(json.dumps(events, indent=2), encoding="utf-8")
        paths.append(p)
    if "txt" in fmts or "text" in fmts:
        p = Path(str(base) + ".txt")
        lines = []
        for e in events:
            lines.append(
                f"{e.get('TimeCreated')}\t{e.get('Level')}\t{e.get('Id')}\t{e.get('Provider')}\t{e.get('Channel')}\t{(e.get('Message') or '')[:300]}"
            )
        p.write_text("\n".join(lines), encoding="utf-8")
        paths.append(p)
    if "xml" in fmts:
        p = Path(str(base) + ".xml")
        root = ET.Element("Events")
        for e in events:
            el = ET.SubElement(root, "Event")
            for k in ("TimeCreated", "Level", "Id", "Provider", "Channel", "RecordId", "Message"):
                child = ET.SubElement(el, k)
                child.text = str(e.get(k, ""))
        ET.ElementTree(root).write(p, encoding="utf-8", xml_declaration=True)
        paths.append(p)
    if "rawxml" in fmts or "srawxml" in fmts:
        p = Path(str(base) + ".raw.xml")
        chunks = ["<?xml version='1.0' encoding='utf-8'?><Events>"]
        for e in events:
            # reconstruct minimal raw-ish xml from fields
            ed = e.get("EventData") or {}
            data_xml = "".join(f'<Data Name="{k}">{_escape_xml(str(v))}</Data>' for k, v in ed.items())
            chunks.append(
                f"<Event><System><Provider Name=\"{_escape_xml(str(e.get('Provider','')))}\"/>"
                f"<EventID>{e.get('Id')}</EventID><Level>{e.get('LevelRaw','')}</Level>"
                f"<Channel>{_escape_xml(str(e.get('Channel','')))}</Channel>"
                f"<TimeCreated SystemTime=\"{e.get('TimeCreated')}\"/></System>"
                f"<EventData>{data_xml}</EventData>"
                f"<RenderingInfo><Message>{_escape_xml(str(e.get('Message','')))}</Message></RenderingInfo></Event>"
            )
        chunks.append("</Events>")
        p.write_text("".join(chunks), encoding="utf-8")
        paths.append(p)
    if "html" in fmts:
        p = Path(str(base) + ".html")
        p.write_text(_events_html(events, aggregates(events)), encoding="utf-8")
        paths.append(p)
    return paths


def _escape_xml(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _events_html(events: list[dict[str, Any]], agg: dict) -> str:
    """Interactive browser: filters, EventData string columns, bookmarks (FullEventLogView-like)."""
    payload = []
    for e in events[:5000]:
        strings = e.get("Strings") or []
        if isinstance(strings, dict):
            strings = list(strings.values())
        payload.append(
            {
                "t": e.get("TimeCreated", ""),
                "l": e.get("Level", ""),
                "i": e.get("Id", ""),
                "r": e.get("RecordId", ""),
                "p": e.get("Provider", ""),
                "c": e.get("Channel", ""),
                "m": (e.get("Message") or "")[:800],
                "s": list(strings)[:10],
                "d": e.get("EventData") or {},
            }
        )
    ev_json = json.dumps(payload)
    agg_rows = ""
    for title, key in (("Level", "ByLevel"), ("Provider", "ByProvider"), ("Id", "ById"), ("Channel", "ByChannel")):
        agg_rows += f"<h4>By {title}</h4><table>"
        for r in agg.get(key, []):
            agg_rows += f"<tr><td>{r['Name']}</td><td>{r['Count']}</td></tr>"
        agg_rows += "</table>"

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Crash-Tshoot Event Viewer</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:0;background:#f4f5f7}}
header{{background:#0a5;color:#fff;padding:16px 20px}}
.wrap{{padding:16px 20px}}
.filters input,.filters select{{padding:6px;margin:4px}}
table{{border-collapse:collapse;width:100%;background:#fff;font-size:.88rem}}
th,td{{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}}
th{{background:#0a5;color:#fff;cursor:pointer}}
tr.bm{{background:#d6eaff}}
#detail{{margin-top:12px;background:#111;color:#ddd;padding:12px;border-radius:6px;white-space:pre-wrap;max-height:260px;overflow:auto;font-size:.82rem}}
.bar button{{margin:4px;padding:6px 10px}}
</style></head><body>
<header><h1>Event Viewer</h1><div>{len(events)} event(s) loaded · bookmarks + string columns · FullEventLogView-class filters</div></header>
<div class="wrap">
<div class="filters">
  <input id="q" placeholder="Quick filter (message/provider/channel)..." style="width:40%" oninput="filt()">
  <select id="lv" onchange="filt()"><option value="">All levels</option>
    <option>Critical</option><option>Error</option><option>Warning</option><option>Information</option></select>
  <input id="fid" placeholder="Event ID" style="width:90px" oninput="filt()">
  <input id="fprov" placeholder="Provider" style="width:140px" oninput="filt()">
  <label><input type="checkbox" id="bmOnly" onchange="filt()"> Bookmarks only</label>
</div>
<div class="bar">
  <button onclick="toggleBm()">Toggle bookmark (selected)</button>
  <button onclick="nextBm(1)">Next bookmark</button>
  <button onclick="nextBm(-1)">Prev bookmark</button>
  <button onclick="clearBm()">Clear bookmarks</button>
</div>
<table id="ev"><thead><tr>
  <th onclick="sortK('t')">Time</th><th onclick="sortK('l')">Level</th><th onclick="sortK('i')">Id</th>
  <th onclick="sortK('r')">Record</th><th onclick="sortK('p')">Provider</th><th onclick="sortK('c')">Channel</th>
  <th>String1</th><th>String2</th><th>Message</th>
</tr></thead><tbody></tbody></table>
<div id="detail">Select a row for EventData / description (lower pane).</div>
<div>{agg_rows}</div>
</div>
<script>
const EV={ev_json};
let sortKey='t', sortDir=-1, selected=-1;
const BM=new Set(JSON.parse(localStorage.getItem('ct_ev_bm')||'[]'));
function saveBm(){{ localStorage.setItem('ct_ev_bm', JSON.stringify([...BM])); }}
function keyOf(e){{ return e.t+'|'+e.i+'|'+e.r+'|'+e.p; }}
function filt(){{
  const q=(document.getElementById('q').value||'').toLowerCase();
  const lv=document.getElementById('lv').value;
  const id=(document.getElementById('fid').value||'').trim();
  const pr=(document.getElementById('fprov').value||'').toLowerCase();
  const bmOnly=document.getElementById('bmOnly').checked;
  let rows=EV.slice();
  rows=rows.filter(e=>{{
    if(bmOnly && !BM.has(keyOf(e))) return false;
    if(lv && e.l!==lv) return false;
    if(id && String(e.i)!==id) return false;
    if(pr && !(e.p||'').toLowerCase().includes(pr)) return false;
    if(q && !((e.m||'')+(e.p||'')+(e.c||'')+(e.s||[]).join(' ')).toLowerCase().includes(q)) return false;
    return true;
  }});
  rows.sort((a,b)=>{{
    let x=a[sortKey], y=b[sortKey];
    if(sortKey==='i'||sortKey==='r'){{ x=+x||0; y=+y||0; }}
    if(x<y) return -1*sortDir; if(x>y) return 1*sortDir; return 0;
  }});
  const tb=document.querySelector('#ev tbody'); tb.innerHTML='';
  rows.slice(0,2500).forEach((e,idx)=>{{
    const tr=document.createElement('tr');
    if(BM.has(keyOf(e))) tr.classList.add('bm');
    const s1=(e.s&&e.s[0])||''; const s2=(e.s&&e.s[1])||'';
    tr.innerHTML=`<td>${{esc(e.t)}}</td><td>${{esc(e.l)}}</td><td>${{e.i}}</td><td>${{e.r||''}}</td><td>${{esc(e.p)}}</td><td>${{esc(e.c)}}</td><td>${{esc(String(s1).slice(0,40))}}</td><td>${{esc(String(s2).slice(0,40))}}</td><td>${{esc((e.m||'').slice(0,120))}}</td>`;
    tr.onclick=()=>{{ selected=EV.indexOf(e); show(e); document.querySelectorAll('#ev tbody tr').forEach(x=>x.style.outline=''); tr.style.outline='2px solid #08c'; }};
    tb.appendChild(tr);
  }});
}}
function sortK(k){{ if(sortKey===k) sortDir*=-1; else {{sortKey=k; sortDir=1;}} filt(); }}
function show(e){{
  const d=e.d||{{}};
  const lines=Object.keys(d).map(k=>k+': '+d[k]);
  document.getElementById('detail').textContent=
    e.t+' | '+e.l+' | Id '+e.i+' | Record '+e.r+' | '+e.p+' | '+e.c+'\\n\\n'+(e.m||'')+'\\n\\nEventData / Strings:\\n'+(lines.join('\\n')||'(none)');
}}
function toggleBm(){{
  if(selected<0) return;
  const e=EV[selected]; const k=keyOf(e);
  if(BM.has(k)) BM.delete(k); else BM.add(k);
  saveBm(); filt();
}}
function nextBm(dir){{
  const keys=[...BM];
  if(!keys.length) return;
  let idx=selected;
  for(let n=0;n<EV.length;n++){{
    idx=(idx+dir+EV.length)%EV.length;
    if(BM.has(keyOf(EV[idx]))){{ selected=idx; show(EV[idx]); filt(); return; }}
  }}
}}
function clearBm(){{ BM.clear(); saveBm(); filt(); }}
function esc(s){{ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;'); }}
filt();
</script></body></html>"""


def watch_loop(filt: EvFilter, interval: int = 5, rounds: int = 12) -> None:
    """Auto-refresh (smooth): print new matching events (FullEventLogView Auto Refresh)."""
    import time

    seen: set[str] = set()
    print(f"Watching events every {interval}s ({rounds} rounds). Ctrl+C to stop.")
    for _ in range(rounds):
        evs = query_events(filt)
        new = []
        for e in evs:
            k = f"{e.get('TimeCreated')}|{e.get('RecordId')}|{e.get('Id')}|{e.get('Provider')}"
            if k not in seen:
                seen.add(k)
                new.append(e)
        for e in sorted(new, key=lambda x: x.get("TimeCreated") or ""):
            msg = (e.get("Message") or "").replace("\n", " ")[:160]
            print(f"  + {e.get('TimeCreated')} [{e.get('Level')}] Id={e.get('Id')} {e.get('Provider')}: {msg}")
        if not new:
            print("  (no new events)")
        time.sleep(max(1, interval))
