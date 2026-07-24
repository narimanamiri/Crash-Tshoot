"""Shared pattern library for known + generic failure signatures across OSes."""

from __future__ import annotations

import re
from typing import Pattern

from .models import Severity

# Each rule: (compiled regex, category, severity, title_hint, action)
PatternRule = tuple[Pattern[str], str, Severity, str, str]

WINDOWS_PATTERNS: list[PatternRule] = [
    (re.compile(r"LiveKernelEvent|VIDEO_DXGKRNL_LIVEDUMP|Code:\s*193", re.I), "gpu", Severity.CRITICAL,
     "LiveKernel / GPU live dump signal", "Clean-install GPU drivers (DDU); check WATCHDOG dumps."),
    (re.compile(r"Display driver .+ stopped responding|Event ID[:\s]*4101|TDR", re.I), "gpu", Severity.WARNING,
     "Display TDR / GPU timeout", "Update or roll back GPU driver; check thermals."),
    (re.compile(r"storahci|stornvme|Reset to device|RaidPort", re.I), "storage", Severity.CRITICAL,
     "Storage controller reset", "Reseat cable/SSD; check SMART; replace failing drive."),
    (re.compile(r"UNEXPECTED_STORE_EXCEPTION|BugCheck.*154|0x154", re.I), "storage", Severity.CRITICAL,
     "BSOD UNEXPECTED_STORE_EXCEPTION", "Failing disk/cable highly likely — back up now."),
    (re.compile(r"Kernel-Power.*41|BugcheckCode|WHEA-Logger|Machine Check", re.I), "hardware", Severity.CRITICAL,
     "Kernel power / WHEA hardware signal", "Distinguish BSOD vs power-loss; run MemTest; check PSU."),
    (re.compile(r"volmgr.*161|Dump file creation failed", re.I), "storage", Severity.CRITICAL,
     "Crash dump write failed", "Disk unresponsive during crash."),
]

LINUX_PATTERNS: list[PatternRule] = [
    (re.compile(r"Out of memory|oom-kill|Killed process", re.I), "memory", Severity.CRITICAL,
     "OOM killer activity", "Add RAM / fix memory leak; check cgroup limits."),
    (re.compile(r"I/O error|Buffer I/O error|ext4_error|XFS .*error|nvme .*reset|ata\d+: .*failed", re.I),
     "storage", Severity.CRITICAL, "Disk I/O / filesystem error", "Check SMART (smartctl); replace drive; fsck."),
    (re.compile(r"Blocked for more than|hung_task|soft lockup|hard LOCKUP|NMI watchdog", re.I),
     "hang", Severity.CRITICAL, "Kernel hang / lockup", "Check GPU/storage drivers; disable bad modules; check thermals."),
    (re.compile(r"GPU hang|amdgpu|i915 .*reset|nouveau .*fault|NVRM|Xid", re.I),
     "gpu", Severity.WARNING, "GPU hang / driver fault", "Update GPU driver/firmware; check power/thermals."),
    (re.compile(r"segfault|general protection fault|Unable to handle kernel", re.I),
     "crash", Severity.CRITICAL, "Segfault / kernel fault", "Bisect recent packages; check RAM; review dmesg."),
    (re.compile(r"thermal|Critical temperature|CPU\d+: Package temperature above threshold", re.I),
     "thermal", Severity.CRITICAL, "Thermal warning", "Clean cooling; check fans; reduce load."),
    (re.compile(r"EXT4-fs error|Remounting filesystem read-only|I/O error.*superblock", re.I),
     "storage", Severity.CRITICAL, "Filesystem remounted read-only", "Unclean disk — back up; fsck; replace drive."),
    (re.compile(r"systemd-shutdown|Failed to start|Core dump", re.I),
     "service", Severity.WARNING, "Service / core dump signal", "journalctl -xe for unit; inspect coredumpctl."),
]

MACOS_PATTERNS: list[PatternRule] = [
    (re.compile(r"panic\(|Kernel trap|Debugger CPU|Machine Check|SMC panic", re.I),
     "crash", Severity.CRITICAL, "macOS kernel panic signal", "Check DiagnosticReports .panic; note GPU/IOKit culprit."),
    (re.compile(r"watchdog|userspace watchdog|Previous shutdown cause", re.I),
     "hang", Severity.CRITICAL, "Watchdog / unexpected shutdown cause", "Check Console.app + pmset -g log; thermals/PSU."),
    (re.compile(r"disk\d+s\d+|I/O error|medium error|SMART|NVMe.*error|Failed to eject", re.I),
     "storage", Severity.CRITICAL, "Disk / NVMe I/O signal", "Run Disk Utility First Aid; back up; replace drive."),
    (re.compile(r"GPU Reset|IOAccelerator|Metal.*error|AMDRadeon|NVDA", re.I),
     "gpu", Severity.WARNING, "GPU / graphics fault signal", "Update macOS; check thermals; external GPU."),
    (re.compile(r"thermal( level| pressure| warning)|CPU_Scheduler|overtemp", re.I),
     "thermal", Severity.WARNING, "Thermal pressure signal", "Clean vents; check fans; reduce load."),
    (re.compile(r"jetsam|memorystatus|low memory|EXC_RESOURCE", re.I),
     "memory", Severity.WARNING, "Memory pressure / jetsam", "Close heavy apps; check memory leaks."),
    (re.compile(r"Code Signature|AMFI|EXC_BAD_ACCESS|Segmentation fault", re.I),
     "crash", Severity.WARNING, "Process crash / bad access", "Update the app; check crash report in Console."),
]

# Generic “unseen scenario” catch-alls — broad but scored lower unless clustered
GENERIC_PATTERNS: list[PatternRule] = [
    (re.compile(r"\b(panic|BUG:|Oops:|fatal error|FATAL|assertion failed|stack smashing)\b", re.I),
     "crash", Severity.CRITICAL, "Fatal / panic language in logs", "Capture surrounding log context; identify crashing binary."),
    (re.compile(r"\b(hung_task|deadlock|soft lockup|hard lockup|NMI watchdog)\b", re.I),
     "hang", Severity.WARNING, "Hang / lockup language", "Correlate with CPU/disk/GPU load around the timestamp."),
    (re.compile(r"\b(timeout|timed out)\b", re.I),
     "timeout", Severity.WARNING, "Timeout language in logs", "Correlate with the failing service or device around the timestamp."),
    (re.compile(r"\b(corrupt|corruption|checksum|CRC error|ECC)\b", re.I),
     "integrity", Severity.WARNING, "Corruption / checksum language", "Test RAM and storage integrity."),
    (re.compile(r"\b(overheat|over-temp|thermal (trip|shutdown|critical)|package temperature above)\b", re.I),
     "thermal", Severity.WARNING, "Thermal stress language", "Improve cooling; check dust and paste."),
    (re.compile(r"\b(power (fail|loss|cut)|undervolt|brownout|PSU)\b", re.I),
     "power", Severity.WARNING, "Power delivery language", "Check PSU, cables, UPS, wall circuit."),
    (re.compile(r"\b(out of (disk|space)|No space left|ENOSPC)\b", re.I),
     "diskspace", Severity.CRITICAL, "Disk full language", "Free space on the affected volume immediately."),
]


def all_rules(platform: str) -> list[PatternRule]:
    rules = list(GENERIC_PATTERNS)
    if platform == "windows":
        rules = WINDOWS_PATTERNS + rules
    elif platform == "linux":
        rules = LINUX_PATTERNS + rules
    elif platform == "macos":
        rules = MACOS_PATTERNS + rules
    elif platform == "bsd":
        rules = LINUX_PATTERNS + rules
    else:
        rules = WINDOWS_PATTERNS + LINUX_PATTERNS + MACOS_PATTERNS + rules
    return rules
