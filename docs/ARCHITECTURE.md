# Architecture

Crash-Tshoot v2 is a **cross-platform application** (Python 3.10+) that diagnoses
crashes, hangs, and instability on **Windows** and **Linux**. Optional deep Windows
coverage still uses [`SystemDiagnoser.ps1`](../SystemDiagnoser.ps1). Optional narrative
analysis uses a **local LM Studio** OpenAI-compatible API.

## Design principles

1. **Application does the work** — collectors + pattern rules + clustering + root-cause
   scoring produce the verdict without any LLM.
2. **LLM is optional and advisory** — LM Studio may refine explanations; it never
   replaces rule findings as the source of truth for automation.
3. **Unseen scenarios** — generic log patterns (panic, timeout, corruption, ENOSPC, …)
   plus offline `--log-folder` scanning catch failures not in the hard-coded OS maps.
4. **Stdlib-first** — no required pip packages for core diagnosis or LM Studio (`urllib`).

## Pipeline

```text
┌─────────────┐   ┌──────────────────┐   ┌─────────────┐   ┌──────────────┐
│ Collectors  │ → │ Pattern / anomaly│ → │ Root-cause  │ → │ HTML + JSON  │
│ Win/Linux/  │   │ engine (rules)   │   │ scorer      │   │ reports      │
│ offline logs│   └──────────────────┘   └─────────────┘   └──────────────┘
└─────────────┘                                    │
                                                   ▼ optional
                                            ┌─────────────┐
                                            │ LM Studio   │
                                            │ /v1/chat…   │
                                            └─────────────┘
```

## Package layout

| Path | Role |
|------|------|
| `crash_tshoot/cli.py` | CLI entry |
| `crash_tshoot/collectors/` | OS + offline collectors |
| `crash_tshoot/patterns.py` | Known + generic regex rules |
| `crash_tshoot/root_cause.py` | Deterministic scoring |
| `crash_tshoot/llm/lmstudio.py` | Optional local LLM |
| `crash_tshoot/report.py` | HTML / JSON writers |
| `SystemDiagnoser.ps1` | Windows Event Viewer deep engine (merged when present) |

## Platforms

| OS | Live sources | Notes |
|----|--------------|-------|
| Windows | wevtutil, LiveKernelReports, Minidump, free space, GPU CIM; optional PS1 | Prefer admin |
| Linux | journalctl, dmesg, /var/log/*, SMART, coredumpctl, systemd --failed | Prefer root for SMART/dmesg |
| Any | `--log` / `--log-folder` / `--offline-only` | Forensic copies |

See [WINDOWS.md](WINDOWS.md), [LINUX.md](LINUX.md), [LOG_ANALYSIS.md](LOG_ANALYSIS.md),
[LLM_LM_STUDIO.md](LLM_LM_STUDIO.md), [CLI_REFERENCE.md](CLI_REFERENCE.md).
