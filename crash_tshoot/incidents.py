"""
Known incident profiles from INCIDENTS.md — matched against live findings/counters.

These are the real cases this toolkit was built from. Matching is deterministic
(application rules); the report cites which historical pattern(s) fit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .models import DiagnosisResult, Finding, Severity


@dataclass
class IncidentProfile:
    id: str
    name: str
    summary: str
    evidence: list[str]
    resolution: list[str]
    match: Callable[[DiagnosisResult], tuple[bool, int, str]]  # matched, score 0-100, why


def _text(result: DiagnosisResult) -> str:
    parts = [f.title + " " + f.detail for f in result.findings]
    parts += [str(k) + "=" + str(v) for k, v in (result.counters or {}).items()]
    return " ".join(parts).lower()


def _has(text: str, *needles: str) -> bool:
    t = (text or "").lower()
    return any(n.lower() in t for n in needles)


def _count(result: DiagnosisResult, key: str) -> int:
    try:
        return int(result.counters.get(key) or 0)
    except (TypeError, ValueError):
        return 0


def _match_incident1(result: DiagnosisResult) -> tuple[bool, int, str]:
    """Failing SATA/AHCI disk: phantom drive, storahci 129, 0x154, volmgr 161 hang."""
    t = _text(result)
    score = 0
    reasons = []
    if _has(t, "phantom", "0-byte drive", "0-byte"):
        score += 40
        reasons.append("phantom/0-byte drive")
    if _count(result, "StorAhci129") >= 1 or _has(t, "storahci 129", "raidport"):
        score += 30
        reasons.append("storahci 129 resets")
    if _has(t, "0x154", "unexpected_store"):
        score += 25
        reasons.append("BSOD 0x154 UNEXPECTED_STORE_EXCEPTION")
    if _has(t, "volmgr 161", "dump could not"):
        score += 20
        reasons.append("volmgr 161 dump failed (BSOD hang)")
    if _count(result, "StorNvme129") >= 3 and score >= 20:
        score += 10
        reasons.append("stornvme 129 cluster")
    ok = score >= 50
    return ok, min(score, 100), "; ".join(reasons) if ok else ""


def _match_incident2(result: DiagnosisResult) -> tuple[bool, int, str]:
    """Abrupt power loss / hard lock: KP41 BugcheckCode=0, no BSOD."""
    t = _text(result)
    score = 0
    reasons = []
    if _has(t, "abrupt power loss", "hard lock", "bugcheckcode=0", "no bugcheck"):
        score += 50
        reasons.append("Kernel-Power 41 with BugcheckCode=0")
    # Explicit: we have KP41 power-loss finding and NO blue screen finding
    power_loss = any(
        f.severity == Severity.CRITICAL
        and f.area.lower() == "power"
        and _has(f.title + f.detail, "abrupt", "power loss", "hard lock")
        for f in result.findings
    )
    has_bsod = any(_has(f.title, "blue screen") for f in result.findings)
    if power_loss and not has_bsod:
        score = max(score, 70)
        if "Kernel-Power 41 with BugcheckCode=0" not in reasons:
            reasons.append("unclean shutdown without stop code")
    if _count(result, "KP41") >= 2 and power_loss:
        score += 15
        reasons.append("multiple KP41 events (burst)")
    if has_bsod:
        return False, 0, ""
    ok = score >= 50
    return ok, min(score, 100), "; ".join(reasons) if ok else ""


def _match_incident3(result: DiagnosisResult) -> tuple[bool, int, str]:
    """LiveKernelEvent 193 / GPU live dump (non-fatal)."""
    t = _text(result)
    score = 0
    reasons = []
    lk = _count(result, "LiveKernel193") or _count(result, "LiveKernelDumps")
    if lk >= 1 or _has(t, "livekernel", "video_dxgkrnl_livedump", "0x193"):
        score += 45
        reasons.append("LiveKernelEvent 193 / WATCHDOG")
    if _has(t, "tdr", "4101", "display timeout"):
        score += 20
        reasons.append("Display TDR")
    if _has(t, "sunshine"):
        score += 15
        reasons.append("Sunshine/GPU-heavy app correlation")
    if _has(t, "low disk space") and score >= 40:
        score += 10
        reasons.append("low disk space contributing")
    # If a real BSOD dominates, this is contributing not primary — still match at lower confidence
    has_bsod = any(_has(f.title, "blue screen") for f in result.findings)
    if has_bsod and score >= 45:
        score = min(score, 55)
        reasons.append("secondary to BSOD")
    ok = score >= 45
    return ok, min(score, 100), "; ".join(reasons) if ok else ""


def _match_incident4(result: DiagnosisResult) -> tuple[bool, int, str]:
    """BSOD 0x3B + STATUS_IN_PAGE_ERROR + hung dump (pull-the-plug)."""
    t = _text(result)
    score = 0
    reasons = []
    if _has(t, "0x3b", "system_service_exception"):
        score += 35
        reasons.append("BSOD 0x3B SYSTEM_SERVICE_EXCEPTION")
    if _has(t, "0xc0000006", "in_page", "in-page", "status_in_page"):
        score += 35
        reasons.append("Param1 STATUS_IN_PAGE_ERROR (0xC0000006)")
    if _has(t, "volmgr 161", "dump could not"):
        score += 25
        reasons.append("volmgr 161 dump failed / freeze until power pull")
    if _has(t, "no minidump", "bsod recorded but no minidump"):
        score += 10
        reasons.append("no minidump written")
    if _has(t, "6008", "unexpected shutdown"):
        score += 5
        reasons.append("6008 unexpected shutdown")
    ok = score >= 60
    return ok, min(score, 100), "; ".join(reasons) if ok else ""


INCIDENT_PROFILES: list[IncidentProfile] = [
    IncidentProfile(
        id="1",
        name="Failing SATA/AHCI disk (hung BSOD)",
        summary=(
            "Storage on AHCI stopped responding (storahci 129 / phantom 0-byte drive). "
            "Often ends in 0x154 UNEXPECTED_STORE_EXCEPTION and volmgr 161 so the BSOD freezes overnight."
        ),
        evidence=[
            "storahci Event 129 (Reset to device / RaidPort)",
            "Phantom Win32_DiskDrive Size=0",
            "Bugcheck 0x154",
            "volmgr 161 dump creation failed",
            "Event 6008 unexpected shutdown",
        ],
        resolution=[
            "Back up immediately",
            "Disable or physically unplug the phantom/failing SATA device",
            "Reseat SATA data+power; try another port; replace cable/drive",
            "Verify SMART on remaining disks",
        ],
        match=_match_incident1,
    ),
    IncidentProfile(
        id="2",
        name="Abrupt power loss / hard lock (no BSOD)",
        summary=(
            "Kernel-Power 41 with BugcheckCode=0 — Windows never recorded a stop code. "
            "Power was cut or the board reset faster than a software bugcheck (PSU/UPS/thermal)."
        ),
        evidence=[
            "Kernel-Power 41 BugcheckCode=0",
            "No BugCheck 1001 / no minidump",
            "Event 6005 soon after (reboot)",
            "Often two failures minutes apart under load",
        ],
        resolution=[
            "Reseat 24-pin and CPU EPS power cables",
            "Check UPS / wall circuit; swap known-good PSU",
            "Monitor CPU/VRM temps under load (HWiNFO64)",
        ],
        match=_match_incident2,
    ),
    IncidentProfile(
        id="3",
        name="LiveKernelEvent 193 (GPU live dump)",
        summary=(
            "VIDEO_DXGKRNL_LIVEDUMP — graphics kernel live dump (often Param 80e). "
            "Not a fatal BSOD; WER hardware wording is boilerplate. Correlate Sunshine/overlays and free space."
        ),
        evidence=[
            "WER LiveKernelEvent Code 193 / Param 80e",
            "WATCHDOG-*.dmp under LiveKernelReports",
            "Optional Display 4101 TDR",
            "Optional sunshine.exe crashes; low C: free space",
        ],
        resolution=[
            "Free space on C: (well above 10%)",
            "DDU + clean GPU driver install",
            "Update or quit Sunshine / GPU overlays",
            "Optional WinDbg !analyze on WATCHDOG dump",
        ],
        match=_match_incident3,
    ),
    IncidentProfile(
        id="4",
        name="BSOD 0x3B IN_PAGE_ERROR + hung dump (pull plug)",
        summary=(
            "SYSTEM_SERVICE_EXCEPTION with STATUS_IN_PAGE_ERROR (0xC0000006). "
            "Dump write fails (volmgr 161) so the machine freezes until power is pulled — same hang mechanic as #1."
        ),
        evidence=[
            "Kernel-Power 41 Bugcheck 0x3B",
            "BugcheckParameter1 = 0xC0000006",
            "volmgr 161 / BugCheckProgress 0x00040049",
            "No minidump for this crash",
            "Event 6008 at crash wall-clock time",
        ],
        resolution=[
            "Free substantial space on C: / pagefile volume",
            "NVMe health + firmware; reseat SSD if needed",
            "MemTest86 (in-page can also be RAM)",
            "Ensure dumps can write to a healthy volume",
        ],
        match=_match_incident4,
    ),
]


@dataclass
class MatchedIncident:
    id: str
    name: str
    score: int
    why: str
    summary: str
    resolution: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "score": self.score,
            "why": self.why,
            "summary": self.summary,
            "resolution": self.resolution,
            "evidence": self.evidence,
        }


def match_incidents(result: DiagnosisResult) -> list[MatchedIncident]:
    matched: list[MatchedIncident] = []
    for profile in INCIDENT_PROFILES:
        ok, score, why = profile.match(result)
        if ok:
            matched.append(
                MatchedIncident(
                    id=profile.id,
                    name=profile.name,
                    score=score,
                    why=why,
                    summary=profile.summary,
                    resolution=list(profile.resolution),
                    evidence=list(profile.evidence),
                )
            )
    matched.sort(key=lambda m: -m.score)
    return matched


def apply_incident_matches(result: DiagnosisResult) -> DiagnosisResult:
    """Attach matched incident findings + enrich root cause with profile citations."""
    matched = match_incidents(result)
    result.snapshot["matched_incidents"] = [m.to_dict() for m in matched]

    if not matched:
        result.findings.append(
            Finding(
                Severity.INFO,
                "Incident",
                "No historical incident profile matched",
                "Scan did not fit Incidents #1–#4 signatures. Review CRITICAL findings; extend profiles if this is a new class.",
                source="rules",
            )
        )
        return result

    primary = matched[0]
    for m in matched:
        sev = Severity.CRITICAL if m.score >= 70 else Severity.WARNING
        result.findings.append(
            Finding(
                severity=sev,
                area="Incident",
                title=f"Matches Incident #{m.id}: {m.name} (score {m.score})",
                detail=f"{m.why}. {m.summary}",
                action="; ".join(m.resolution[:3]),
                evidence=m.evidence[:6],
                source="rules",
            )
        )

    cite = f"Matches known Incident #{primary.id} ({primary.name}). "
    if result.root_cause and cite.strip() not in result.root_cause:
        result.root_cause = cite + result.root_cause
    elif not result.root_cause:
        result.root_cause = cite + primary.summary

    # Prefer incident resolutions at front of actions
    for step in reversed(primary.resolution):
        if step not in result.actions:
            result.actions.insert(0, step)

    return result
