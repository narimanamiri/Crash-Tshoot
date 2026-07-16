from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"
    OK = "OK"


@dataclass
class Finding:
    severity: Severity
    area: str
    title: str
    detail: str = ""
    when: Optional[str] = None  # ISO timestamp
    action: str = ""
    evidence: list[str] = field(default_factory=list)
    source: str = "rules"  # rules | anomaly | llm | collector

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class LogHit:
    path: str
    line_no: int
    line: str
    pattern: str
    category: str
    severity: Severity
    when: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class DiagnosisResult:
    hostname: str
    platform: str  # windows | linux | unknown
    generated: str
    days: int
    snapshot: dict[str, Any] = field(default_factory=dict)
    counters: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    log_hits: list[LogHit] = field(default_factory=list)
    root_cause: str = ""
    actions: list[str] = field(default_factory=list)
    llm_summary: str = ""
    llm_used: bool = False
    browser_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "platform": self.platform,
            "generated": self.generated,
            "days": self.days,
            "snapshot": self.snapshot,
            "counters": self.counters,
            "findings": [f.to_dict() for f in self.findings],
            "log_hits": [h.to_dict() for h in self.log_hits],
            "root_cause": self.root_cause,
            "actions": self.actions,
            "llm_summary": self.llm_summary,
            "llm_used": self.llm_used,
            "browser_events": self.browser_events[:5000],
        }


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")
