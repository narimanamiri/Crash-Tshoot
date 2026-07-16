# Crash-Tshoot

Cross-platform **crash & log diagnoser** for **Windows** and **Linux**.

- **Application-first:** collectors + pattern rules + clustering + root-cause scoring
  explain failures **without** an LLM.
- **Unseen scenarios:** generic log language (panic, hang, corruption, ENOSPC, …) and
  offline log folders catch cases not in the hard-coded maps.
- **Optional LM Studio:** local OpenAI-compatible API for advisory narrative only.
- **Windows deep mode:** existing PowerShell Event Viewer engine still available and
  auto-merged when present.

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

### Linux

```bash
chmod +x run-diagnoser.sh
./run-diagnoser.sh --days 7
sudo ./run-diagnoser.sh --days 7 --llm
./run-diagnoser.sh --offline-only --log-folder /path/to/logs
```

Requires **Python 3.10+**. Core diagnosis uses the **stdlib only** (see `requirements.txt`).

---

## What it does

| Layer | Windows | Linux | Offline logs |
|-------|---------|-------|--------------|
| Live collectors | wevtutil, dumps, disk, GPU; merges `SystemDiagnoser.ps1` | journalctl, dmesg, syslog, SMART, coredumps | `--log` / `--log-folder` |
| Known rules | LiveKernel 193, TDR, stor* 129, WHEA, BSOD… | OOM, I/O, lockup, GPU hang, thermal… | Same pattern engine |
| Unseen | Generic panic/timeout/corrupt/power/ENOSPC clusters | Same | Same |
| Root cause | Scored summary + actions | Same | Same |
| Optional LLM | LM Studio `/v1/chat/completions` | Same | Same |
| Reports | `Reports/*.html` + `*.json` with log browser | Same | Same |

---

## Documentation

| Doc | Topic |
|-----|--------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Pipeline & package layout |
| [docs/WINDOWS.md](docs/WINDOWS.md) | Windows collectors & PS merge |
| [docs/LINUX.md](docs/LINUX.md) | Linux collectors & permissions |
| [docs/LOG_ANALYSIS.md](docs/LOG_ANALYSIS.md) | Rules, unseen scenarios, extending patterns |
| [docs/LLM_LM_STUDIO.md](docs/LLM_LM_STUDIO.md) | Optional local LLM setup |
| [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | Full CLI flags |
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

Still the richest **Event Viewer** experience (presets, exports, interactive browser,
remote SSH). The Python app calls it when available and merges findings.

See prior README sections historically covered by `SystemDiagnoser.ps1` parameters
(`-Preset`, `-FullEventScan`, `-Export`, `-ComputerName`, …).

---

## Exit codes

- `0` — no CRITICAL findings  
- `2` — CRITICAL findings present  
- `1` — tool/usage error  

---

## License / use

Personal diagnostic utility. Read-only collectors; writes under `Reports\`.
LLM traffic stays on the URL you configure (default localhost).
