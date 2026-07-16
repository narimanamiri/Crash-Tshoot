# Crash-Tshoot — Smart System Diagnoser

A one-click Windows crash & health analyzer. Double-click one file and get a
ranked, color-coded report explaining **why your PC crashed, froze, or
blue-screened** — built from real-world BSOD investigations (see
[INCIDENTS.md](INCIDENTS.md)).

No installation, no external modules, no internet required. Pure PowerShell.

---

## Quick start

1. Download/copy this folder anywhere (e.g. `Desktop\Crash-Tshoot`).
2. **Double-click [`Run-Diagnoser.bat`](Run-Diagnoser.bat).**
3. Approve the UAC prompt (it needs admin to read SMART data and dump settings).
4. Read the on-screen summary. An HTML report opens automatically and is saved
   in the [`Reports\`](Reports) folder.

That's it.

---

## What it checks

| # | Section | What it looks for |
|---|---------|-------------------|
| 1 | **System Overview** | OS build, model, CPU/RAM, last boot, uptime |
| 2 | **Unexpected Shutdowns & Blue Screens** | Kernel-Power `41`, BugCheck `1001`, `6008`. Decodes the **stop code into plain English** (built-in dictionary of ~25 codes). Distinguishes a real BSOD from an abrupt power loss / hard lock. |
| 3 | **Crash Dumps** | Minidumps, `MEMORY.DMP`, and `volmgr 161` dump-write failures (= disk was unresponsive during the crash). |
| 4 | **Storage / Disk Health** | SMART health per drive, **phantom/0-byte drives**, **`storahci 129` device resets**, disk I/O errors (`7/51/153`), low free space. |
| 5 | **Memory & Hardware Errors** | **WHEA** machine-check errors (CPU/RAM/PCIe/thermal), Windows Memory Diagnostic results. |
| 6 | **Thermal & Power** | Thermal-trip events, live ACPI temperature (if the BIOS exposes it). |
| 7 | **Failed Services & App Crashes** | Service crashes (`7031/7034`), application crashes (`Application Error 1000`), grouped by most frequent. |
| 8 | **Updates & Pending Reboot** | Failed Windows Updates, pending-reboot flags. |

Every finding is tagged **CRITICAL / WARNING / INFO / OK**, sorted by severity,
and the tool prints a **"Most likely root cause"** line using a simple
heuristic (storage → hardware → power/thermal → driver).

---

## Files

| File | Purpose |
|------|---------|
| [`Run-Diagnoser.bat`](Run-Diagnoser.bat) | **One-click launcher.** Self-elevates (UAC) and runs the engine. |
| [`SystemDiagnoser.ps1`](SystemDiagnoser.ps1) | The diagnostic engine — all logic lives here. |
| [`Reports\`](Reports) | Auto-generated, timestamped HTML reports (one per run). |
| [`INCIDENTS.md`](INCIDENTS.md) | Real diagnosed cases this tool was built from. |
| [`STOPCODES.md`](STOPCODES.md) | Reference: BSOD stop codes and what they mean. |

---

## Usage options

The `.bat` runs a 7-day scan by default. To customize, run the engine directly
from an **elevated** PowerShell:

```powershell
# Scan the last 30 days
powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1 -Days 30

# Console only, no HTML report
powershell -ExecutionPolicy Bypass -File .\SystemDiagnoser.ps1 -NoHtml
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Days <n>` | `7` | How many days of event-log history to scan. |
| `-NoHtml` | off | Skip the HTML report (console output only). |

To change the default window for the one-click launcher, edit the last line of
[`Run-Diagnoser.bat`](Run-Diagnoser.bat) and change `-Days 7`.

---

## Reading the output

- **CRITICAL** (red) — likely cause of a crash or imminent failure. Act on these
  first.
- **WARNING** (yellow) — degraded or risky, worth fixing.
- **INFO** (blue) — context, not necessarily a problem.
- **OK** (green) — a check that passed.

The **"Most likely root cause"** line is a best-guess summary; always read the
individual CRITICAL findings, because a machine can have more than one problem.

---

## How it works (under the hood)

The engine is plain Windows PowerShell 5.1 and relies only on built-in
facilities:

- `Get-WinEvent` against the **System** and **Application** event logs, filtered
  by provider + event ID + time window.
- `Get-CimInstance` for `Win32_OperatingSystem`, `Win32_ComputerSystem`,
  `Win32_DiskDrive`, and ACPI thermal data.
- `Get-PhysicalDisk` for SMART HealthStatus.
- Registry probes for pending-reboot state.

Findings are accumulated into a list, ranked, printed, and rendered to a
self-contained HTML file (HTML-escaped, no external assets).

### The stop-code dictionary

The core of the BSOD analysis is a hashtable mapping bug-check codes to a
`[name, plain-language hint]` pair — for example:

```
0x154 -> UNEXPECTED_STORE_EXCEPTION : "The memory/store backing store failed -
         frequently a failing disk or its cable/port."
```

See [STOPCODES.md](STOPCODES.md) for the full list and what to do about each.

---

## Requirements & compatibility

- **Windows 10 / 11** (and Server 2016+). Built and tested on Windows 11 build
  26100 / 26200.
- **Windows PowerShell 5.1** (ships with Windows) — no PowerShell 7 needed.
- **Administrator rights** for full coverage. It still runs without elevation but
  SMART and some dump-config checks are limited (the launcher elevates for you).

---

## Limitations

- It **reads logs and SMART data** — it does not analyze the binary contents of
  minidumps. For the exact faulting driver, open a flagged dump in
  **BlueScreenView** or **WinDbg** (`!analyze -v`).
- Live CPU temperature is only available if the motherboard/BIOS exposes
  `MSAcpi_ThermalZoneTemperature` (many don't). For reliable temps use
  **HWiNFO64**.
- It diagnoses; it does **not** auto-repair. All remediation is left to you (by
  design — see each finding's "Detail").

---

## Roadmap / ideas

- **Remote mode** — point it at an IP over SSH and run the same report against
  another machine (the technique used in [INCIDENTS.md](INCIDENTS.md) for
  `192.168.20.50`).
- **Trend tracking** — persist findings per run to spot, e.g., `storahci` resets
  increasing over time.
- **Optional minidump auto-analysis** via the Debugging Tools for Windows.

---

## License / use

Personal diagnostic utility. Use at your own risk; it only **reads** system
state and writes report files into its own `Reports\` folder.
