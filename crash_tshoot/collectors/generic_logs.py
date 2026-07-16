"""Generic / offline log folder analysis for any OS or forensic copies."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding, Severity
from .base import discover_extra_logs, hits_to_findings, scan_log_file


def collect_generic(result, days: int = 7, extra_logs: list[str] | None = None) -> None:
    hits = []
    paths = discover_extra_logs(extra_logs)
    if not paths:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "System",
                "Unknown platform and no logs provided",
                "Pass --log-folder or --log with syslog/journal exports.",
                action="Provide log files for analysis.",
                source="collector",
            )
        )
        return

    plat = result.platform if result.platform in ("windows", "linux") else "unknown"
    for p in paths:
        hits += scan_log_file(p, plat)

    result.log_hits.extend(hits)
    result.findings.extend(hits_to_findings(hits, platform=plat))
    result.findings.append(
        Finding(
            Severity.INFO,
            "EventLog",
            f"Scanned {len(paths)} offline/extra log file(s)",
            ", ".join(str(p) for p in paths[:12]),
            source="collector",
        )
    )
