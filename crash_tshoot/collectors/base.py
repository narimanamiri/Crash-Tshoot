from __future__ import annotations

import platform
import shutil
import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional

from ..models import DiagnosisResult, Finding, LogHit, Severity, now_iso
from ..patterns import all_rules


def detect_platform() -> str:
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    if s == "linux":
        return "linux"
    if s == "darwin":
        return "macos"
    if s in ("freebsd", "openbsd", "netbsd"):
        return "bsd"
    return "unknown"


def default_mounts(plat: str | None = None) -> list[str]:
    plat = plat or detect_platform()
    if plat == "windows":
        return ["C:\\"]
    if plat == "macos":
        return ["/", "/System/Volumes/Data"]
    if plat in ("linux", "bsd"):
        return ["/", "/var", "/home", "/tmp"]
    return ["/"]


def run_cmd(args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)


def scan_text_lines(
    lines: Iterable[str],
    source: str,
    plat: str,
    since: datetime,
    max_hits: int = 2000,
) -> list[LogHit]:
    rules = all_rules(plat)
    hits: list[LogHit] = []
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        for rx, category, sev, _title, _action in rules:
            if rx.search(line):
                hits.append(
                    LogHit(
                        path=source,
                        line_no=i,
                        line=line[:2000],
                        pattern=rx.pattern[:120],
                        category=category,
                        severity=sev,
                    )
                )
                break
        if len(hits) >= max_hits:
            break
    return hits


def scan_log_file(path: Path, plat: str, max_bytes: int = 8_000_000) -> list[LogHit]:
    if not path.is_file():
        return []
    try:
        size = path.stat().st_size
        with path.open("r", errors="replace") as f:
            if size > max_bytes:
                f.seek(max(0, size - max_bytes))
                f.readline()  # discard partial
            return scan_text_lines(f, str(path), plat, datetime.now())
    except OSError:
        return []


def free_space_finding(path: str = "/") -> Optional[Finding]:
    try:
        usage = shutil.disk_usage(path)
        pct = round(100 * usage.free / usage.total) if usage.total else 0
        free_gb = round(usage.free / (1024**3), 1)
        total_gb = round(usage.total / (1024**3), 1)
        if pct < 10:
            return Finding(
                Severity.CRITICAL,
                "Disk",
                f"Low disk space on {path} ({pct}% free)",
                f"{free_gb} GB of {total_gb} GB free. Below 10% causes instability.",
                action="Free substantial space on this volume.",
                source="collector",
            )
        if pct < 15:
            return Finding(
                Severity.WARNING,
                "Disk",
                f"Disk space getting low on {path} ({pct}% free)",
                f"{free_gb} GB of {total_gb} GB free.",
                source="collector",
            )
    except OSError:
        pass
    return None


def base_snapshot(days: int) -> DiagnosisResult:
    plat = detect_platform()
    return DiagnosisResult(
        hostname=socket.gethostname(),
        platform=plat,
        generated=now_iso(),
        days=days,
        snapshot={
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        counters={},
    )


def hits_to_findings(hits: list[LogHit], min_cluster: int = 1, platform: str = "unknown") -> list[Finding]:
    """Collapse log hits into ranked findings by category."""
    from collections import defaultdict

    by_cat: dict[str, list[LogHit]] = defaultdict(list)
    for h in hits:
        by_cat[h.category].append(h)

    from ..patterns import all_rules

    rule_meta = {}
    for rx, cat, sev, title, action in all_rules(platform):
        rule_meta.setdefault(cat, (sev, title, action))

    findings: list[Finding] = []
    for cat, group in sorted(by_cat.items(), key=lambda x: -len(x[1])):
        if len(group) < min_cluster:
            continue
        sev_rank = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2, Severity.OK: 3}
        worst = min(group, key=lambda h: sev_rank[h.severity])
        meta = rule_meta.get(cat, (worst.severity, f"Log pattern cluster: {cat}", "Inspect matching log lines."))
        sev, title, action = meta
        # escalate if many hits
        if len(group) >= 5 and sev == Severity.WARNING:
            sev = Severity.CRITICAL
        samples = [g.line[:240] for g in group[:5]]
        findings.append(
            Finding(
                severity=sev,
                area=cat.upper(),
                title=f"{title} ({len(group)} hit(s))",
                detail=f"Sources include: {', '.join(sorted({g.path for g in group})[:5])}",
                action=action,
                evidence=samples,
                source="anomaly" if cat in ("hang", "integrity", "crash") and "panic" not in title.lower() else "rules",
            )
        )
    return findings


def discover_extra_logs(extra: list[str] | None) -> list[Path]:
    paths: list[Path] = []
    for e in extra or []:
        p = Path(e)
        if p.is_file():
            paths.append(p)
        elif p.is_dir():
            for pat in ("*.log", "*.txt", "*.out", "syslog*", "messages*", "kern.log*"):
                paths.extend(p.glob(pat))
                paths.extend(p.glob("**/" + pat))
    # de-dupe
    seen = set()
    out = []
    for p in paths:
        rp = p.resolve()
        if rp not in seen and p.is_file():
            seen.add(rp)
            out.append(p)
    return out[:200]
