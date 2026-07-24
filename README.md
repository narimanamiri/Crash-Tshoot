# Crash-Tshoot

Cross-platform **crash & log diagnoser** for **Windows, Linux, macOS, and BSD**.

- **Application-first:** collectors + pattern rules + clustering + root-cause scoring
  explain failures **without** an LLM.
- **Unseen scenarios:** generic log language (panic, hang, corruption, ENOSPC, …) and
  offline log folders catch cases not in the hard-coded maps.
- **Optional LM Studio:** local OpenAI-compatible API for advisory narrative only.
- **Windows deep mode:** PowerShell Event Viewer engine still available and
  optionally merged when present.

Platform matrix: [docs/PLATFORMS.md](docs/PLATFORMS.md).

---

## Quick start

### Windows

| Launcher | Use when |
|----------|----------|
| [`Run-Python-Diagnoser.bat`](Run-Python-Diagnoser.bat) | Cross-platform Python app (recommended default) |
| [`Run-Diagnoser.bat`](Run-Diagnoser.bat) | PowerShell deep Event Viewer / crash engine |
| [`Run-EventViewer.bat`](Run-EventViewer.bat) | Full-channel event browse + export |
| [`Run-Diagnoser-Remote.bat`](Run-Diagnoser-Remote.bat) | SSH remote Windows scan |

```bat
Run-Python-Diagnoser.bat
Run-Python-Diagnoser.bat --llm
Run-Python-Diagnoser.bat --days 14 --log-folder D:\evidence
```

### Linux / macOS / BSD

```bash
chmod +x run-diagnoser.sh
./run-diagnoser.sh --days 7
sudo ./run-diagnoser.sh --days 7 --llm          # Linux: fuller journal/dmesg/SMART
./run-diagnoser.sh --event-viewer --preset Errors
./run-diagnoser.sh --offline-only --log-folder /path/to/logs
```

On macOS you can also double-click [`run-diagnoser.command`](run-diagnoser.command).

Requires **Python 3.10+**. Core diagnosis uses the **stdlib only** (see `requirements.txt`).
Optional install: `pip install -e .` → `crash-tshoot` on PATH.

---

## What it does

| Layer | Windows | Linux | macOS | BSD | Offline |
|-------|---------|-------|-------|-----|---------|
| Live collectors | wevtutil, dumps, disk, GPU; optional PS merge | journalctl, dmesg, SMART, coredumps | `log show`, DiagnosticReports, pmset, diskutil | dmesg + syslog | `--log` / `--log-folder` |
| Known rules | LiveKernel 193, TDR, stor* 129, WHEA, BSOD… | OOM, I/O, lockup, GPU hang… | panic, watchdog, disk I/O… | Linux-shared rules | Same engine |
| Event Viewer | Get-WinEvent / EVTX | journalctl | `log show` | dmesg | text (+ EVTX on Windows) |
| Root cause / reports | HTML + JSON | Same | Same | Same | Same |
| Optional LLM | LM Studio | Same | Same | Same | Same |

---

## Documentation

| Doc | Topic |
|-----|--------|
| [docs/PLATFORMS.md](docs/PLATFORMS.md) | OS matrix, launchers, limitations |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Pipeline & package layout |
| [docs/WINDOWS.md](docs/WINDOWS.md) | Windows collectors & PS merge |
| [docs/LINUX.md](docs/LINUX.md) | Linux collectors & permissions |
| [docs/LOG_ANALYSIS.md](docs/LOG_ANALYSIS.md) | Rules, unseen scenarios, extending patterns |
| [docs/LLM_LM_STUDIO.md](docs/LLM_LM_STUDIO.md) | Optional local LLM setup |
| [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | Full CLI flags |
| [docs/EVENT_VIEWER.md](docs/EVENT_VIEWER.md) | Event Viewer feature matrix |
| [docs/INCIDENT_PROFILES.md](docs/INCIDENT_PROFILES.md) | Incidents #1–#4 encoded as profiles |
| [STOPCODES.md](STOPCODES.md) | BSOD / LiveKernel codes |
| [INCIDENTS.md](INCIDENTS.md) | Real diagnosed cases |
| [CONTEXT.md](CONTEXT.md) | Session / machine notes |

---

## LM Studio (optional)

1. Start LM Studio → Developer → local server (`http://localhost:1234`).
2. Load a model.
3. `python run_diagnoser.py --llm`

The HTML report keeps **application root cause** on top; LLM text is an advisory block.
Details: [docs/LLM_LM_STUDIO.md](docs/LLM_LM_STUDIO.md).

---

## PowerShell engine (Windows)

Still the richest **Windows Event Viewer** experience (presets, exports, interactive browser,
remote SSH). The Python app can merge it when `CRASH_TSHOOT_PS_MERGE=1`.

---

## Exit codes

- `0` — no CRITICAL findings  
- `2` — CRITICAL findings present  
- `1` — tool/usage error  

---

## License / use

Personal diagnostic utility. Read-only collectors; writes under `Reports/`.
LLM traffic stays on the URL you configure (default localhost).
