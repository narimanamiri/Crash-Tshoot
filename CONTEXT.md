# Crash-Tshoot session context (2026-07-16)

## Machine
DESKTOP-72P233G — ASUS, RTX 4060, 28 cores, 128 GB, Win11 Ent N 26200, Samsung 990 PRO NVMe x3

## User issue that drove the upgrade
WER LiveKernelEvent **193**, Parameter1 **80e**, dump `WATCHDOG-20260715-1432.dmp`
= VIDEO_DXGKRNL_LIVEDUMP (not a fatal BSOD). Correlated: C: ~1% free, sunshine.exe crashes.

## Product after Full Product Pass
- SystemDiagnoser.ps1: diagnoser + Event Viewer engine, trends JSON, remote SSH, optional cdb, HTML Event Browser
- Launchers: Run-Diagnoser.bat, Run-EventViewer.bat, Run-Diagnoser-Remote.bat
- Docs: README feature matrix, STOPCODES live-dump section, INCIDENTS #3

## Prior incidents (see INCIDENTS.md)
1. Storage 0x154 + phantom SATA + storahci 129 + volmgr 161
2. Remote power-loss KP41 BugcheckCode=0
3. GPU LiveKernel 193
