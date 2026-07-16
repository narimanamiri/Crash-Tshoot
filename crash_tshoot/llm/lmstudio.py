"""Optional LM Studio (OpenAI-compatible) enrichment. Application rules run first; LLM is advisory only."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional

from ..models import DiagnosisResult, Finding, Severity


DEFAULT_BASE = "http://localhost:1234/v1"


def list_models(base_url: str = DEFAULT_BASE, timeout: float = 5.0) -> list[str]:
    url = base_url.rstrip("/") + "/models"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
        return [m.get("id", "") for m in data.get("data", []) if m.get("id")]
    except Exception:
        return []


def chat_completion(
    messages: list[dict[str, str]],
    *,
    base_url: str = DEFAULT_BASE,
    model: str = "",
    temperature: float = 0.2,
    max_tokens: int = 1200,
    timeout: float = 120.0,
) -> str:
    if not model:
        models = list_models(base_url, timeout=min(timeout, 10))
        if not models:
            raise RuntimeError("LM Studio has no loaded models (or server unreachable).")
        model = models[0]

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": "Bearer lm-studio"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode("utf-8", errors="replace"))
    return body["choices"][0]["message"]["content"]


def build_prompt(result: DiagnosisResult) -> list[dict[str, str]]:
    # Compact evidence — keep under context limits
    findings = result.findings[:40]
    hits = result.log_hits[:40]
    payload = {
        "hostname": result.hostname,
        "platform": result.platform,
        "app_root_cause": result.root_cause,
        "findings": [
            {"severity": f.severity.value, "area": f.area, "title": f.title, "detail": f.detail[:300]}
            for f in findings
        ],
        "sample_log_hits": [
            {"path": h.path, "category": h.category, "line": h.line[:240]}
            for h in hits
        ],
        "snapshot": result.snapshot,
        "counters": result.counters,
    }
    system = (
        "You are a senior systems reliability engineer assisting Crash-Tshoot. "
        "The application ALREADY computed a root cause with deterministic rules. "
        "Your job: (1) confirm or refine that root cause, (2) explain odd/unmatched log lines, "
        "(3) propose ordered remediation steps, (4) list what evidence is still missing. "
        "Be concise. Do NOT invent hardware failures without evidence. "
        "If unsure, say so. Prefer actionable steps over theory."
    )
    user = (
        "Analyze this diagnosis JSON. Reply in markdown with sections: "
        "Verdict, Why, Remediations (numbered), Unmatched/Uncertain, Missing evidence.\n\n"
        + json.dumps(payload, indent=2)[:14000]
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


def enrich_with_lmstudio(
    result: DiagnosisResult,
    *,
    base_url: str = DEFAULT_BASE,
    model: str = "",
    enabled: bool = True,
) -> DiagnosisResult:
    if not enabled:
        return result
    try:
        text = chat_completion(build_prompt(result), base_url=base_url, model=model)
        result.llm_summary = text.strip()
        result.llm_used = True
        result.findings.append(
            Finding(
                Severity.INFO,
                "LLM",
                "LM Studio advisory analysis attached",
                "Local model opinion only — application rules remain authoritative for automated decisions.",
                source="llm",
            )
        )
    except urllib.error.URLError as e:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "LLM",
                "LM Studio unreachable",
                f"{base_url}: {e}. Start the LM Studio server (Developer tab) and load a model.",
                action="Enable Local Server in LM Studio; default http://localhost:1234/v1",
                source="llm",
            )
        )
    except Exception as e:
        result.findings.append(
            Finding(
                Severity.WARNING,
                "LLM",
                "LM Studio analysis failed",
                str(e),
                source="llm",
            )
        )
    return result
