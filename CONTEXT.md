# Crash-Tshoot session context

## Product
- v1 PowerShell Event Viewer engine
- v2 Python cross-platform app (rules-first; optional LM Studio)

## Machine
DESKTOP-72P233G — ASUS, RTX 4060, Win11 26200, 3x Samsung 990 PRO

## Incidents (see INCIDENTS.md)
1. Storage 0x154 + phantom SATA + volmgr 161 hang
2. Remote power-loss BugcheckCode=0
3. LiveKernel 193 / 80e (GPU live dump)
4. **2026-07-20 23:25** — BSOD 0x3B + Param1 0xC0000006 + volmgr 161; pull-plug

## Encoded in scripts (2026-07-21)
- `crash_tshoot/incidents.py` — match Incidents #1–#4, cite in root cause + HTML
- `SystemDiagnoser.ps1` — `Get-MatchedIncidents` mirror
- Docs: `docs/INCIDENT_PROFILES.md`

## Event Viewer upgrade (studied FullEventLogView + Event Log Explorer)
- Python `crash_tshoot/event_viewer.py` + `--event-viewer` CLI
- Extra presets: Defender, Network, DiskIO, HyperV, Setup, WindowsUpdate
- Exclude filters, save/load filter JSON, watch/auto-refresh
- Exports: Csv, Tsv, Txt, Json, Xml, RawXml, Html (bookmarks + String columns)
- Docs: `docs/EVENT_VIEWER.md`
