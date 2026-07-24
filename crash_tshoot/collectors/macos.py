"""macOS collectors — unified logging, DiagnosticReports, disk, thermal."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from ..models import Finding, Severity
from .base import (
    discover_extra_logs,
    free_space_finding,
    hits_to_findings,
    run_cmd,
    scan_log_file,
    scan_text_lines,
)


def collect_macos(result, days: int = 7, extra_logs: list[str] | None = None) -> None:
    result.platform = "macos"
    since = datetime.now() - timedelta(days=days)

    for mount in ("/", "/System/Volumes/Data", "/Users"):
        if Path(mount).exists():
            f = free_space_finding(mount)
            if f:
                result.findings.append(f)
                if mount == "/":
                    try:
                        import re

                        m = re.search(r"\((\d+)%", f.title)
                        if m:
                            result.counters["FreePct"] = int(m.group(1))
                    except Exception:
                        pass

    code, out, _ = run_cmd(["uname", "-a"])
    if code == 0:
        result.snapshot["uname"] = out.strip()
    code, out, _ = run_cmd(["sw_vers"])
    if code == 0:
        result.snapshot["sw_vers"] = " | ".join(
            ln.strip() for ln in out.splitlines() if ln.strip()
        )
    code, out, _ = run_cmd(["sysctl", "-n", "hw.model"])
    if code == 0 and out.strip():
        result.snapshot["model"] = out.strip()
    code, out, _ = run_cmd(["sysctl", "-n", "machdep.cpu.brand_string"])
    if code == 0 and out.strip():
        result.snapshot["cpu"] = out.strip()
    code, out, _ = run_cmd(["uptime"])
    if code == 0:
        result.snapshot["uptime"] = out.strip()

    hits = []

    # Unified logging (last N days) — compact text for pattern scan
    code, out, _ = run_cmd(
        [
            "log",
            "show",
            "--last",
            f"{days}d",
            "--style",
            "compact",
            "--predicate",
            'eventMessage CONTAINS[c] "panic" OR eventMessage CONTAINS[c] "fault" OR '
            'eventMessage CONTAINS[c] "error" OR eventMessage CONTAINS[c] "GPU" OR '
            'eventMessage CONTAINS[c] "I/O" OR eventMessage CONTAINS[c] "disk" OR '
            'eventMessage CONTAINS[c] "watchdog" OR eventType == fault OR '
            'messageType == error OR messageType == fault',
        ],
        timeout=120,
    )
    if code != 0 or not out.strip():
        code, out, _ = run_cmd(
            ["log", "show", "--last", f"{min(days, 2)}d", "--style", "compact"],
            timeout=90,
        )
    if out.strip():
        lines = out.splitlines()
        hits += scan_text_lines(lines[-4000:], "log:show", "macos", since)

    # Panic / shutdown reports
    for crash_dir in (
        Path.home() / "Library/Logs/DiagnosticReports",
        Path("/Library/Logs/DiagnosticReports"),
        Path("/Library/Logs/CrashReporter"),
    ):
        if not crash_dir.is_dir():
            continue
        recent = []
        for p in crash_dir.glob("*"):
            if not p.is_file():
                continue
            try:
                if datetime.fromtimestamp(p.stat().st_mtime) >= since:
                    recent.append(p)
            except OSError:
                continue
        if recent:
            names = ", ".join(x.name for x in sorted(recent, key=lambda p: p.stat().st_mtime, reverse=True)[:8])
            panicish = any("panic" in p.name.lower() for p in recent)
            result.findings.append(
                Finding(
                    Severity.CRITICAL if panicish else Severity.WARNING,
                    "Crash",
                    f"{len(recent)} DiagnosticReports file(s) in window",
                    f"{crash_dir}: {names}",
                    action="Open .panic / .crash in Console.app; note faulting process.",
                    source="collector",
                )
            )
            for p in recent[:5]:
                if p.suffix.lower() in (".panic", ".crash", ".ips", ".log", ".diag"):
                    hits += scan_log_file(p, "macos", max_bytes=2_000_000)

    # Previous shutdown reason (asadmin often needed)
    code, out, _ = run_cmd(["pmset", "-g", "log"], timeout=30)
    if code == 0 and out.strip():
        interesting = [
            ln
            for ln in out.splitlines()
            if any(k in ln.lower() for k in ("shutdown", "sleep", "wake", "thermal", "darkwake", "restart"))
        ]
        hits += scan_text_lines(interesting[-500:], "pmset:log", "macos", since)

    # Disk SMART via diskutil (limited)
    code, out, _ = run_cmd(["diskutil", "list"])
    if code == 0 and out.strip():
        result.snapshot["diskutil"] = out[:1500]
    code, out, _ = run_cmd(["diskutil", "info", "disk0"])
    if code == 0 and ("SMART Status" in out or "SmartStatus" in out or "SMART" in out):
        bad = "failing" in out.lower() or "not supported" not in out.lower() and "verified" not in out.lower() and "Verified" not in out
        # Prefer explicit Verified
        if "Verified" in out or "verified" in out.lower():
            result.findings.append(
                Finding(Severity.OK, "Disk", "disk0 SMART Verified (diskutil)", source="collector")
            )
        elif "Failing" in out or "failing" in out.lower():
            result.findings.append(
                Finding(
                    Severity.CRITICAL,
                    "Disk",
                    "disk0 SMART failing (diskutil)",
                    out[:800],
                    action="Back up immediately; replace drive.",
                    source="collector",
                )
            )

    # GPU hint
    code, out, _ = run_cmd(["system_profiler", "SPDisplaysDataType", "-detailLevel", "mini"])
    if code == 0 and out.strip():
        gpus = [ln.strip() for ln in out.splitlines() if "Chipset" in ln or "Vendor" in ln or "Metal" in ln]
        if gpus:
            result.snapshot["gpu"] = "; ".join(gpus[:4])
            result.counters["GpuName"] = result.snapshot["gpu"]

    for p in discover_extra_logs(extra_logs):
        hits += scan_log_file(p, "macos")

    # Classic text logs if present
    for rel in (
        "/var/log/system.log",
        "/var/log/install.log",
        str(Path.home() / "Library/Logs/DiagnosticReports"),
    ):
        path = Path(rel)
        if path.is_file():
            hits += scan_log_file(path, "macos")

    result.log_hits.extend(hits)
    result.findings.extend(hits_to_findings(hits, platform="macos"))

    # Unexpected restart hint from last
    code, out, _ = run_cmd(["last", "reboot"])
    if code == 0 and out.strip():
        result.snapshot["last_reboot"] = out.splitlines()[0][:200]
