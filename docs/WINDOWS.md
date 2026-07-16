# Windows coverage

## Python app (`run_diagnoser.py` / `Run-Python-Diagnoser.bat`)

Collects:

- Free space on `C:\`
- GPU names (`Win32_VideoController`)
- `C:\Windows\LiveKernelReports\**\*.dmp` and `Minidump\*.dmp`
- Recent **System** and **Application** events via `wevtutil` (pattern-scanned)
- Extra files from `--log` / `--log-folder`
- If [`SystemDiagnoser.ps1`](../SystemDiagnoser.ps1) is present: runs it with `-NoHtml`
  and **merges** its JSON findings (LiveKernel 193, storahci/stornvme, WHEA, trends, …)

## PowerShell deep engine (still recommended on Windows)

Use for FullEventLogView-class browsing, presets, exports, remote SSH:

- `Run-Diagnoser.bat`
- `Run-EventViewer.bat`
- `Run-Diagnoser-Remote.bat`

## Typical Windows failure maps

| Signal | Meaning |
|--------|---------|
| LiveKernelEvent 193 / WATCHDOG | GPU live dump (`VIDEO_DXGKRNL_LIVEDUMP`) |
| Display 4101 | TDR |
| storahci/stornvme 129 | Disk reset |
| Kernel-Power 41 + Bugcheck≠0 | BSOD |
| Kernel-Power 41 + Bugcheck=0 | Power loss / hard lock |
| WHEA | Hardware machine-check |
| volmgr 161 | Dump write failed (dead disk during crash) |

See [STOPCODES.md](../STOPCODES.md) and [INCIDENTS.md](../INCIDENTS.md).
