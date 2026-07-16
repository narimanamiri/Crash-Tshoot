# Crash-Tshoot session context

## Product shape (2026-07-16+)

- **v1:** PowerShell `SystemDiagnoser.ps1` — Windows Event Viewer + crash diagnoser
- **v2:** Python `crash_tshoot` — Windows + Linux + offline logs + optional LM Studio

## Machine (authoring host)

DESKTOP-72P233G — ASUS, RTX 4060, Win11 26200, Samsung 990 PRO NVMe

## Driving incident

LiveKernelEvent **193** / Param **80e** / WATCHDOG dump — GPU live dump, not fatal BSOD;
correlated with C: ~1% free and sunshine.exe crashes. See INCIDENTS #3.

## How to run

- Windows app: `Run-Python-Diagnoser.bat` or `python run_diagnoser.py`
- With LLM: add `--llm` (LM Studio server on :1234)
- Linux: `./run-diagnoser.sh`
- Docs: `docs/`
