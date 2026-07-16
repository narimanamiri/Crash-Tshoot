# Crash-Tshoot — Smart System Diagnoser + Advanced Event Viewer

One-click Windows crash analyzer **and** FullEventLogView-class event browser.
Double-click a launcher, approve UAC, get a ranked root-cause report with an
interactive Event Browser — no install, no external modules, no internet.

Built from real BSOD / LiveKernel investigations (see [INCIDENTS.md](INCIDENTS.md)).

---

## Quick start

| Launcher | What it does |
|----------|----------------|
| [`Run-Diagnoser.bat`](Run-Diagnoser.bat) | Full local crash diagnosis (7 days) + HTML report |
| [`Run-EventViewer.bat`](Run-EventViewer.bat) | Event Viewer mode: all-channel Critical/Error scan, CSV+JSON export, Event Browser |
| [`Run-Diagnoser-Remote.bat`](Run-Diagnoser-Remote.bat) | Same diagnosis over **OpenSSH** to another PC |

Reports land in [`Reports\`](Reports) as HTML + JSON (trends) + optional CSV/XML.

---

## Feature matrix

### Diagnoser

| Area | Detects |
|------|---------|
| Blue screens / power | Kernel-Power `41`, BugCheck `1001`, `6008`; stop-code dictionary; power-loss vs BSOD |
| LiveKernel / GPU | **LiveKernelEvent 193** (`VIDEO_DXGKRNL_LIVEDUMP`), WATCHDOG dumps, Display TDR `4101`, GPU adapters, Sunshine correlation |
| Storage | SMART, phantom 0-byte drives, **storahci + stornvme** `129`, I/O `7/51/153`, `volmgr 161`, free space |
| Hardware | WHEA, Memory Diagnostic, thermal trips |
| Apps / updates | Service crashes, app crashes, failed updates, pending reboot |
| Dumps | Minidumps, `MEMORY.DMP`, LiveKernelReports; optional **cdb/WinDbg `!analyze`** |
| Trends | Compares counters to prior `Reports\*.json` for the same machine |
| Root cause | Scored summary (storage → WHEA → power → GPU → BSOD → disk space) + action list |

### Event Viewer (FullEventLogView-class)

| Capability | How |
|------------|-----|
| All channels | Inventory + optional `-FullEventScan` Critical/Error across enabled logs |
| Filters | `-Level`, `-EventId`, `-Provider`, `-Channel`, `-MessageContains`, `-StartTime`/`-EndTime`, `-Days` |
| Custom Views | `-Preset CriticalErrors\|BootShutdown\|BSODPower\|Storage\|GPUDisplay\|SecurityLogon\|WHEA\|AllWarningsPlus` |
| Offline | `-EvtxPath` / `-LogFolder` for copied `.evtx` files |
| Remote | `-ComputerName` / `-SshUser` (SSH JSON collector) |
| Export | `-Export Csv,Json,Xml,Html` + optional `-ExportEvtx` |
| Aggregates | Top providers / IDs / channels / levels |
| UI | HTML **Event Browser** tab: search, filter, sort, EventData detail (no WinForms) |

---

## Usage examples

```powershell
# Default diagnosis (also via Run-Diagnoser.bat)
powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1 -Days 7

# Event Viewer mode
powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1 -EventViewerMode -Days 14

# GPU-focused custom view + exports
powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1 -Preset GPUDisplay -Export Csv,Json -Days 14

# Offline forensic logs
powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1 -LogFolder D:\copied\winevt\Logs -Days 30 -Export Json

# Remote over SSH
powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1 -ComputerName 192.168.20.50 -SshUser ai -Days 7
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Days` | `7` | History window |
| `-NoHtml` | off | Console only |
| `-Preset` | `Diagnose` | Custom view name (see above) |
| `-FullEventScan` | off | Critical/Error on all enabled channels |
| `-EventViewerMode` | off | FullEventScan + CriticalErrors + Csv,Json |
| `-Export` | `Json` | `Csv,Json,Xml,Html` |
| `-ExportEvtx` | off | `wevtutil` System channel snapshot |
| `-MaxEvents` | `5000` | Cap for browser / full scan |
| `-ComputerName` / `-SshUser` | | Remote SSH |
| `-EvtxPath` / `-LogFolder` | | Offline EVTX |

---

## Files

| File | Purpose |
|------|---------|
| `Run-Diagnoser.bat` | Local one-click diagnoser |
| `Run-EventViewer.bat` | Event Viewer mode |
| `Run-Diagnoser-Remote.bat` | Remote SSH wizard |
| `SystemDiagnoser.ps1` | Engine |
| `Reports\` | HTML, JSON, CSV/XML exports |
| `INCIDENTS.md` | Worked crash cases |
| `STOPCODES.md` | BSOD + LiveKernel code reference |

---

## Requirements

- Windows 10 / 11 (tested on builds 26100 / 26200)
- Windows PowerShell 5.1
- Administrator for full coverage (launchers elevate)
- Remote: OpenSSH Client locally + OpenSSH Server on target
- Optional dump analysis: Windows SDK **Debugging Tools** (`cdb.exe`)

---

## Limitations

- Does not clear event logs (by design).
- Does not auto-repair drivers or hardware.
- Full channel scans are capped (`-MaxEvents`) to avoid multi-GB RAM use.
- Live CPU temps need BIOS ACPI exposure; prefer HWiNFO64 for thermals.

---

## License / use

Personal diagnostic utility. Read-only against the system; writes only under `Reports\`.
