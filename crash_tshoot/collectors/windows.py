"""Windows collectors — prefer PowerShell deep scan when available; always do file/log heuristics."""

from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from ..models import Finding, Severity
from .base import free_space_finding, run_cmd, scan_log_file, hits_to_findings, discover_extra_logs


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def try_powershell_engine(days: int) -> dict | None:
    """Run existing SystemDiagnoser.ps1 -NoHtml and load newest JSON if produced."""
    ps1 = _project_root() / "SystemDiagnoser.ps1"
    if not ps1.is_file():
        return None
    reports = _project_root() / "Reports"
    before = set(reports.glob("Diagnosis_*.json")) if reports.is_dir() else set()
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
        subprocess.run(cmd, capture_output=True, text=True, timeout=180, env=env, errors="replace")
    except Exception:
        return None
    after = list(reports.glob("Diagnosis_*.json")) if reports.is_dir() else []
    new = [p for p in after if p not in before]
    candidates = new or after
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

    # Disk free on C:
    f = free_space_finding("C:\\")
    if f:
        result.findings.append(f)
        result.counters["FreePct"] = int(f.title.split("(")[1].split("%")[0]) if "%" in f.title else None

    # GPU via WMIC / PowerShell CIM
    code, out, _ = run_cmd(
        ["powershell", "-NoProfile", "-Command",
         "Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"]
    )
    if code == 0 and out.strip():
        gpu = "; ".join(x.strip() for x in out.splitlines() if x.strip())
        result.snapshot["gpu"] = gpu
        result.counters["GpuName"] = gpu

    # LiveKernelReports
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
                f"{len(dumps)} LiveKernel/WATCHDOG dump(s)",
                f"Newest: {newest} @ {datetime.fromtimestamp(newest.stat().st_mtime)}",
                when=datetime.fromtimestamp(newest.stat().st_mtime).isoformat(timespec="seconds"),
                action="Analyze with WinDbg; update GPU drivers.",
                source="collector",
            )
        )
        result.counters["LiveKernelDumps"] = len(dumps)

    # Minidumps
    mini = Path(r"C:\Windows\Minidump")
    if mini.is_dir():
        md = [p for p in mini.glob("*.dmp")]
        if md:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Crash",
                    f"{len(md)} minidump(s) in C:\\Windows\\Minidump",
                    f"Newest: {max(md, key=lambda p: p.stat().st_mtime).name}",
                    action="Open in BlueScreenView or WinDbg (!analyze -v).",
                    source="collector",
                )
            )

    # wevtutil recent System critical/error (text)
    code, out, _ = run_cmd(
        ["wevtutil", "qe", "System", "/q:*[System[(Level=1 or Level=2)]]",
         f"/q:*[System[TimeCreated[timediff(@SystemTime) <= {days * 24 * 3600 * 1000}]]]",
         "/f:text", "/c:200"],
        timeout=90,
    )
    # wevtutil query syntax is awkward combined; fallback simpler:
    if code != 0 or not out.strip():
        code, out, _ = run_cmd(
            ["wevtutil", "qe", "System", "/c:300", "/rd:true", "/f:text"],
            timeout=90,
        )
    from .base import scan_text_lines

    hits = scan_text_lines(out.splitlines(), "wevtutil:System", "windows", since)
    # Application log snippet
    code2, out2, _ = run_cmd(
        ["wevtutil", "qe", "Application", "/c:300", "/rd:true", "/f:text"],
        timeout=90,
    )
    hits += scan_text_lines(out2.splitlines(), "wevtutil:Application", "windows", since)

    # Extra user logs
    for p in discover_extra_logs(extra_logs):
        hits += scan_log_file(p, "windows")

    result.log_hits.extend(hits)
    result.findings.extend(hits_to_findings(hits, platform="windows"))

    # Merge deep PowerShell JSON if available
    data = try_powershell_engine(days)
    if data:
        result.snapshot["powershell_engine"] = True
        result.counters.update({k: v for k, v in (data.get("Counters") or {}).items() if v is not None})
        for f in data.get("Findings") or []:
            try:
                sev = Severity(f.get("Severity", "INFO"))
            except ValueError:
                sev = Severity.INFO
            result.findings.append(
                Finding(
                    severity=sev,
                    area=f.get("Area", "PS"),
                    title=f.get("Title", ""),
                    detail=f.get("Detail", ""),
                    when=str(f.get("When") or "") or None,
                    action=f.get("Action", ""),
                    source="collector",
                )
            )
        if data.get("RootCause"):
            result.snapshot["ps_root_cause"] = data["RootCause"]
        result.findings.append(
            Finding(
                Severity.INFO,
                "System",
                "Merged Windows PowerShell deep scan",
                "SystemDiagnoser.ps1 results included.",
                source="collector",
            )
        )
    else:
        result.findings.append(
            Finding(
                Severity.INFO,
                "System",
                "PowerShell deep scan skipped or unavailable",
                "Using wevtutil + file heuristics. Run Run-Diagnoser.bat as admin for deeper Windows coverage.",
                source="collector",
            )
        )

    # Deduplicate titles roughly
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
