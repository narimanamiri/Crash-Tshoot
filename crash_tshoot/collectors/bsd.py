"""BSD collectors — dmesg + syslog (FreeBSD/OpenBSD/NetBSD)."""

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


def collect_bsd(result, days: int = 7, extra_logs: list[str] | None = None) -> None:
    result.platform = "bsd"
    since = datetime.now() - timedelta(days=days)

    f = free_space_finding("/")
    if f:
        result.findings.append(f)

    code, out, _ = run_cmd(["uname", "-a"])
    if code == 0:
        result.snapshot["uname"] = out.strip()

    hits = []
    code, out, _ = run_cmd(["dmesg"], timeout=60)
    if out.strip():
        hits += scan_text_lines(out.splitlines()[-3000:], "dmesg", "bsd", since)

    for rel in ("/var/log/messages", "/var/log/system.log", "/var/log/auth.log"):
        hits += scan_log_file(Path(rel), "bsd")

    for p in discover_extra_logs(extra_logs):
        hits += scan_log_file(p, "bsd")

    result.log_hits.extend(hits)
    result.findings.extend(hits_to_findings(hits, platform="bsd"))
    if not hits and not extra_logs:
        result.findings.append(
            Finding(
                Severity.INFO,
                "System",
                "BSD scan complete (limited native sources)",
                "Pass --log-folder for richer offline analysis.",
                source="collector",
            )
        )
