from __future__ import annotations

from .models import DiagnosisResult, Finding, Severity


PRIORITY = [
    ("storage", ["Phantom", "storahci", "stornvme", "UNEXPECTED_STORE", "I/O error", "SMART", "read-only", "Disk I/O", "filesystem"]),
    ("hardware", ["WHEA", "Machine Check", "MemTest", "ECC"]),
    ("power", ["Abrupt power", "power loss", "brownout", "PSU"]),
    ("thermal", ["thermal", "Thermal", "overheat", "temperature"]),
    ("gpu", ["LiveKernel", "TDR", "GPU", "WATCHDOG", "dxgkrnl", "amdgpu", "i915", "Xid"]),
    ("memory", ["OOM", "Out of memory", "oom-kill"]),
    ("hang", ["lockup", "hung_task", "soft lockup", "hang"]),
    ("crash", ["Blue screen", "Bugcheck", "panic", "segfault", "Oops"]),
    ("diskspace", ["Low disk space", "Disk full", "ENOSPC"]),
]


def score_root_cause(result: DiagnosisResult) -> str:
    titles = " | ".join(f.title + " " + f.detail for f in result.findings)
    parts: list[str] = []

    def has(*needles: str) -> bool:
        t = titles.lower()
        return any(n.lower() in t for n in needles)

    # Highest priority: dump failed + in-page / store exception = storage freeze (pull-the-plug pattern)
    if has("dump could not", "volmgr 161") and has(
        "in_page", "in-page", "0xc0000006", "unexpected_store", "0x154", "system_service_exception"
    ):
        parts.append(
            "STORAGE/PAGEFILE PATH: BSOD occurred and Windows could not write the crash dump (volmgr 161) — "
            "this is why the machine froze until you pulled the power. "
            "STATUS_IN_PAGE_ERROR / store exceptions mean a page could not be read from disk. "
            "Back up; check NVMe health/firmware; ensure pagefile sits on a healthy volume with free space; test RAM."
        )
    elif has("phantom", "storahci", "stornvme", "unexpected_store", "i/o error", "smart fail", "read-only", "filesystem"):
        parts.append(
            "STORAGE: drive or filesystem failing. Back up; check SMART/cables; fsck or replace the disk."
        )
    if has("whea", "machine check"):
        parts.append("HARDWARE: machine-check / WHEA. Test RAM; check temps; review overclock.")
    if has("abrupt power loss", "power loss / hard lock", "brownout") and not has("blue screen"):
        parts.append("POWER: abrupt loss or hard lock with no bugcheck. Check PSU, cables, UPS.")
    if has("thermal trip", "overheat", "temperature above") and not has("blue screen"):
        parts.append("THERMAL: overheating signals. Clean cooling path; verify fans.")
    if has("blue screen", "bugcheck") and not any("STORAGE/PAGEFILE" in p for p in parts):
        parts.append(
            "CRASH: BSOD stop code recorded. Analyze minidump if present; match Param1 (e.g. 0xC0000006 = in-page/disk)."
        )
    if has("livekernel", "tdr", "dxgkrnl", "amdgpu", "gpu hang", "xid") and not has("blue screen"):
        parts.append(
            "GPU/DISPLAY: graphics stack instability. Update/reinstall GPU drivers; check power/thermals."
        )
    elif has("livekernel", "tdr") and has("blue screen"):
        parts.append("CONTRIBUTING: prior GPU LiveKernel/TDR noise — secondary to the BSOD unless dumps implicate the GPU driver.")
    if has("oom", "out of memory", "oom-kill"):
        parts.append("MEMORY PRESSURE: OOM killer ran. Find the leak or add RAM / raise limits.")
    if has("lockup", "hung_task", "soft lockup", "hard lockup"):
        parts.append("HANG: kernel lockup. Check drivers (GPU/storage/NFS); review dmesg around the stamp.")
    if has("low disk space", "disk full", "enospc"):
        parts.append("CONTRIBUTING: critically low free space — free space before chasing subtler bugs.")

    ps = result.snapshot.get("ps_root_cause")
    if ps and ps not in parts:
        parts.append(f"(Windows deep scan) {ps}")

    if not parts:
        crit = [f for f in result.findings if f.severity == Severity.CRITICAL]
        warn = [f for f in result.findings if f.severity == Severity.WARNING]
        if crit:
            top = crit[0]
            return f"Primary signal: [{top.severity.value}] {top.area} - {top.title}. Review CRITICAL findings and log evidence."
        if warn:
            top = warn[0]
            return f"No dominant crash signature; top warning: {top.area} - {top.title}."
        return "No dominant crash signature in the scan window. System looks healthy (or only informational findings)."

    return " ".join(parts)


def action_list(result: DiagnosisResult) -> list[str]:
    acts = []
    seen = set()
    for f in result.findings:
        if f.severity not in (Severity.CRITICAL, Severity.WARNING):
            continue
        if f.action and f.action not in seen:
            seen.add(f.action)
            acts.append(f.action)
    return acts


def finalize(result: DiagnosisResult) -> DiagnosisResult:
    result.root_cause = score_root_cause(result)
    result.actions = action_list(result)
    # Match historical INCIDENTS.md profiles (#1–#4)
    from .incidents import apply_incident_matches

    result = apply_incident_matches(result)
    # Re-sort after incident findings appended
    order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2, Severity.OK: 3}
    result.findings.sort(key=lambda f: (order.get(f.severity, 9), f.area, f.title))
    result.browser_events = [
        {
            "t": h.when or "",
            "l": h.severity.value,
            "i": h.line_no,
            "p": h.category,
            "c": h.path,
            "m": h.line[:500],
            "d": {"pattern": h.pattern},
        }
        for h in result.log_hits[:3000]
    ]
    return result
