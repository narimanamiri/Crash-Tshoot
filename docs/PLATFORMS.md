# Cross-platform support

Crash-Tshoot v2 targets **Windows, Linux, macOS, and BSD** with one Python entrypoint.
Windows also keeps the PowerShell deep engine for Event Viewer / EVTX.

## Matrix

| Capability | Windows | Linux | macOS | BSD | Offline any OS |
|------------|---------|-------|-------|-----|----------------|
| Crash diagnosis | wevtutil + KP41/6008/volmgr + PS merge | journalctl, dmesg, SMART, coredump | `log show`, DiagnosticReports, pmset, diskutil | dmesg + syslog | `--log` / `--log-folder` |
| Pattern rules | WINDOWS_* | LINUX_* | MACOS_* | LINUX_* (shared) | GENERIC + all |
| Incident profiles #1–#4 | Yes (Windows-shaped) | Partial (storage/GPU/OOM language) | Partial (panic/watchdog/disk) | Partial | Via log text |
| Event Viewer | Get-WinEvent / EVTX | journalctl JSON | `log show` ndjson | dmesg text | text logs + EVTX on Windows |
| Presets | Full Windows set | Mapped journal grep/priority | Mapped predicates | Basic | Filters still apply |
| LM Studio | localhost API | same | same | same | same |
| HTML/JSON reports | Yes | Yes | Yes | Yes | Yes |

## Requirements

| Platform | Runtime | Notes |
|----------|---------|-------|
| All | **Python 3.10+** | Stdlib only for core |
| Windows | PowerShell 5.1 | For structured events / EVTX / optional `SystemDiagnoser.ps1` |
| Linux | `journalctl`, optional `smartctl` | Prefer `sudo` for full dmesg/SMART |
| macOS | `log`, `pmset`, `diskutil` | Full Disk Access may be needed for unified logs |
| BSD | `dmesg` | Prefer `--log-folder /var/log` |

## Launchers

| OS | Command |
|----|---------|
| Windows | `Run-Python-Diagnoser.bat` / `Run-EventViewer.bat` / `Run-Diagnoser.bat` |
| Linux / BSD | `./run-diagnoser.sh` |
| macOS | `./run-diagnoser.sh` or double-click `run-diagnoser.command` |

```bash
# Linux
./run-diagnoser.sh --days 7
sudo ./run-diagnoser.sh --days 7
./run-diagnoser.sh --event-viewer --preset Storage --export Html,Json

# macOS
./run-diagnoser.sh --days 7
./run-diagnoser.sh --event-viewer --preset Kernel --days 2

# Offline forensic (any OS)
python3 run_diagnoser.py --offline-only --log-folder ./host-logs --days 30
```

## Platform detection

`crash_tshoot.collectors.base.detect_platform()` returns:
`windows` | `linux` | `macos` | `bsd` | `unknown`

Unknown platforms still run the **generic log scanner** when you pass files.

## Limitations

- Windows EVTX offline analysis requires a Windows host (or tools that understand EVTX).
- macOS unified logging may need **Full Disk Access** for Terminal/Python.
- Incident #1–#4 matchers are tuned to Windows evidence; on Unix they still fire when log language matches (panic, I/O error, GPU hang, etc.).
- PowerShell-only features (remote SSH Windows collector, wevtutil channel clear-not-implemented, WinDbg) stay Windows-only.
