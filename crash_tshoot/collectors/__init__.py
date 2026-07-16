from __future__ import annotations

from .base import base_snapshot, detect_platform, discover_extra_logs, hits_to_findings
from .linux import collect_linux
from .windows import collect_windows
from ..models import DiagnosisResult


def collect_all(days: int = 7, extra_logs: list[str] | None = None, log_folder: str | None = None) -> DiagnosisResult:
    plat = detect_platform()
    result = base_snapshot(days)
    extras = list(extra_logs or [])
    if log_folder:
        extras.append(log_folder)

    if plat == "windows":
        collect_windows(result, days=days, extra_logs=extras)
    elif plat == "linux":
        collect_linux(result, days=days, extra_logs=extras)
    else:
        # Unknown OS: still scan any provided logs + generic
        from .generic_logs import collect_generic

        collect_generic(result, days=days, extra_logs=extras)

    return result
