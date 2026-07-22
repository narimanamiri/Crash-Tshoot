# Advanced Event Viewer

Crash-Tshoot includes a **FullEventLogView / Event Log Explorer–class** event engine
(without clearing logs or shipping a WinForms GUI). The interactive UI is the HTML
Event Browser (filters, EventData string columns, bookmarks).

## Feature matrix vs advanced tools

| Capability | FullEventLogView | Event Log Explorer | Crash-Tshoot |
|------------|------------------|--------------------|--------------|
| Local live logs | Yes | Yes | Yes |
| Remote | Yes | Yes | Yes (SSH / PS remote) |
| Offline EVTX / folder | Yes | Yes | Yes (`--evtx`, `--log-folder`, `-EvtxPath`, `-LogFolder`) |
| Level / ID / Provider / Channel filters | Yes | Yes | Yes |
| Exclude filters | Partial | Yes | Yes (`--exclude-*`, `-Exclude*`) |
| Message / description search | Yes | Yes | Yes |
| User string filter | — | Yes | Yes (`--user-contains`) |
| Custom Views / presets | — | Saved filters | Built-in presets + save/load filter JSON |
| Channel inventory | — | Yes | Yes (`--list-channels`) |
| Aggregates (top ID/provider) | — | Yes | Yes |
| Export CSV | `/scomma` | Yes | Yes |
| Export TSV / TXT | `/stab` `/stext` | Text | Yes |
| Export JSON / XML / Raw XML | `/sjson` `/sxml` `/srawxml` | — | Yes |
| Export HTML | `/shtml` | Yes | Interactive HTML browser |
| Auto Refresh / watch | Yes | Monitor | `--watch N` / `-WatchSeconds` |
| Bookmarks | — | Yes | HTML localStorage bookmarks |
| EventData as String1..N columns | Yes | Custom columns | Yes (Python HTML + export) |
| Clear channel | Yes | Yes | **Not implemented** (by design) |

## Presets

`CriticalErrors`, `AllWarningsPlus`, `BootShutdown`, `BSODPower`, `Storage`,
`GPUDisplay`, `SecurityLogon`, `WHEA`, `WindowsUpdate`, `Defender`, `Network`,
`DiskIO`, `HyperV`, `Setup`

```bash
python run_diagnoser.py --list-presets
python run_diagnoser.py --event-viewer --preset GPUDisplay --days 14
python run_diagnoser.py --event-viewer --full-scan --level Critical,Error --export Csv,Tsv,Json,Html,RawXml
python run_diagnoser.py --event-viewer --evtx D:\logs\System.evtx --export Html
python run_diagnoser.py --event-viewer --preset BootShutdown --save-filter filters\boot.json
python run_diagnoser.py --event-viewer --load-filter filters\boot.json
python run_diagnoser.py --event-viewer --watch 5 --preset CriticalErrors
python run_diagnoser.py --list-channels
```

Windows one-click: [`Run-EventViewer.bat`](../Run-EventViewer.bat)

PowerShell equivalents:

```powershell
.\SystemDiagnoser.ps1 -EventViewerMode -Preset Storage -Export Csv,Json,Tsv,Html
.\SystemDiagnoser.ps1 -Preset Defender -Days 7 -Export Json
.\SystemDiagnoser.ps1 -WatchSeconds 5 -Preset CriticalErrors -WatchRounds 20
.\SystemDiagnoser.ps1 -SaveFilter .\myfilter.json -Preset BootShutdown
.\SystemDiagnoser.ps1 -LoadFilter .\myfilter.json -EventViewerMode
```

## HTML Event Browser

- Quick filter (message / provider / channel)
- Level + Event ID filters
- Sortable columns including Record ID and String1/String2
- Lower pane: full message + EventData (FELV “Show Event Data + Description”)
- Bookmarks with next/prev (persisted in browser localStorage)

## Intentionally omitted

- Clearing / wiping event channels
- Tray balloons / always-on GUI service
- Excel COM export (use CSV/TSV in Excel instead)
