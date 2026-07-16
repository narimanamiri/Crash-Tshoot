"""Linux collectors — journalctl, dmesg, syslog, SMART, coredumps."""

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


def collect_linux(result, days: int = 7, extra_logs: list[str] | None = None) -> None:
    result.platform = "linux"
    since = datetime.now() - timedelta(days=days)

    # Free space on /
    f = free_space_finding("/")
    if f:
        result.findings.append(f)

    # Also check /var and /home if distinct
    for mount in ("/var", "/home", "/tmp"):
        if Path(mount).is_dir():
            ff = free_space_finding(mount)
            if ff and ff.severity in (Severity.CRITICAL, Severity.WARNING):
                result.findings.append(ff)

    # Uname / uptime
    code, out, _ = run_cmd(["uname", "-a"])
    if code == 0:
        result.snapshot["uname"] = out.strip()
    code, out, _ = run_cmd(["uptime", "-p"])
    if code == 0:
        result.snapshot["uptime"] = out.strip()

    hits = []

    # journalctl
    code, out, _ = run_cmd(
        ["journalctl", "-p", "err", f"--since={days} days ago", "--no-pager", "-n", "2000"],
        timeout=120,
    )
    if code == 0 and out.strip():
        hits += scan_text_lines(out.splitlines(), "journalctl:err", "linux", since)
    else:
        code, out, _ = run_cmd(
            ["journalctl", "-b", "-p", "warning", "--no-pager", "-n", "1000"],
            timeout=90,
        )
        if out.strip():
            hits += scan_text_lines(out.splitlines(), "journalctl:boot", "linux", since)

    # dmesg
    code, out, _ = run_cmd(["dmesg", "-T"], timeout=60)
    if code != 0:
        code, out, _ = run_cmd(["dmesg"], timeout=60)
    if out.strip():
        # only last portion for noise
        lines = out.splitlines()
        hits += scan_text_lines(lines[-3000:], "dmesg", "linux", since)

    # Classic log files
    for rel in (
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/dmesg",
        "/var/log/Xorg.0.log",
        "/var/log/gpu-manager.log",
    ):
        hits += scan_log_file(Path(rel), "linux")

    # Crash dumps
    crash_dir = Path("/var/crash")
    if crash_dir.is_dir():
        crashes = list(crash_dir.glob("*"))
        recent = [p for p in crashes if p.is_file()]
        if recent:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Crash",
                    f"{len(recent)} file(s) under /var/crash",
                    ", ".join(p.name for p in recent[:8]),
                    action="Inspect with apport-unpack / coredumpctl.",
                    source="collector",
                )
            )

    # coredumpctl list
    code, out, _ = run_cmd(["coredumpctl", "list", "--no-pager"], timeout=30)
    if code == 0 and out.strip() and "No coredumps" not in out:
        lines = [ln for ln in out.splitlines() if ln.strip()][1:11]
        result.findings.append(
            Finding(
                Severity.WARNING,
                "Crash",
                "systemd-coredump entries present",
                "\n".join(lines)[:1500],
                action="coredumpctl info / gdb on the crashing unit.",
                source="collector",
            )
        )

    # SMART if smartctl present
    code, out, _ = run_cmd(["lsblk", "-ndo", "NAME,TYPE"])
    if code == 0:
        disks = [ln.split()[0] for ln in out.splitlines() if "disk" in ln]
        for d in disks[:6]:
            c2, o2, _ = run_cmd(["smartctl", "-H", f"/dev/{d}"], timeout=30)
            text = (o2 or "").lower()
            if "passed" in text:
                result.findings.append(
                    Finding(Severity.OK, "Disk", f"SMART passed: /dev/{d}", source="collector")
                )
            elif c2 == 0 or "result" in text or "fail" in text:
                sev = Severity.CRITICAL if "fail" in text else Severity.WARNING
                result.findings.append(
                    Finding(
                        sev,
                        "Disk",
                        f"SMART check: /dev/{d}",
                        o2[:800],
                        action="Back up; replace drive if SMART failing.",
                        source="collector",
                    )
                )

    # Failed systemd units
    code, out, _ = run_cmd(["systemctl", "--failed", "--no-pager"])
    if code == 0 and out.strip() and "0 loaded units" not in out.lower():
        if "UNIT" in out:
            result.findings.append(
                Finding(
                    Severity.WARNING,
                    "Services",
                    "Failed systemd units",
                    out[:1200],
                    action="systemctl status <unit>; journalctl -u <unit>.",
                    source="collector",
                )
            )

    for p in discover_extra_logs(extra_logs):
        hits += scan_log_file(p, "linux")

    result.log_hits.extend(hits)
    result.findings.extend(hits_to_findings(hits, platform="linux"))

    # GPU name hint
    code, out, _ = run_cmd(["lspci"])
    if code == 0:
        gpus = [ln for ln in out.splitlines() if "VGA" in ln or "3D" in ln or "Display" in ln]
        if gpus:
            result.snapshot["gpu"] = "; ".join(gpus[:3])
            result.counters["GpuName"] = result.snapshot["gpu"]
