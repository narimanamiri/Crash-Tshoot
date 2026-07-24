from __future__ import annotations

from .base import base_snapshot, detect_platform
from .linux import collect_linux
from .windows import collect_windows
from .macos import collect_macos
from .bsd import collect_bsd
from .generic_logs import collect_generic
from ..models import DiagnosisResult, Finding, Severity


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
    elif plat == "macos":
        collect_macos(result, days=days, extra_logs=extras)
    elif plat == "bsd":
        collect_bsd(result, days=days, extra_logs=extras)
    else:
        collect_generic(result, days=days, extra_logs=extras)
        result.findings.append(
            Finding(
                Severity.INFO,
                "System",
                f"Platform '{plat}' using generic log scanner",
                "Provide --log / --log-folder for best results.",
                source="collector",
            )
        )

    return result
