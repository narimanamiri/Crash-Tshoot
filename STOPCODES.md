# BSOD Stop-Code Reference

Plain-language reference for the Windows bug-check (blue screen) stop codes the
diagnoser recognizes. The same `code → name → meaning` data lives in the
`$BugCheckMap` table inside [`SystemDiagnoser.ps1`](SystemDiagnoser.ps1).

When a blue screen happens, Windows records the code in **Kernel-Power 41**
(`BugcheckCode`) and/or **BugCheck 1001**. The diagnoser reads it, converts the
decimal value to hex, and looks it up here.

> **Tip:** A stop code points at a *category* of cause, not the exact culprit.
> For the precise faulting driver, analyze the minidump
> (`C:\Windows\Minidump`) with **BlueScreenView** or **WinDbg** (`!analyze -v`).

---

## Recognized codes

| Hex | Name | Plain meaning & first thing to check |
|-----|------|--------------------------------------|
| `0x0A` | IRQL_NOT_LESS_OR_EQUAL | A driver touched memory it shouldn't. Bad/old driver or faulty RAM. |
| `0x1A` | MEMORY_MANAGEMENT | Memory-management fault. Often faulty RAM, or a driver corrupting memory. Run MemTest86. |
| `0x1E` | KMODE_EXCEPTION_NOT_HANDLED | A kernel-mode program hit an unhandled error. Usually a driver. |
| `0x3B` | SYSTEM_SERVICE_EXCEPTION | Error during a system call. Often a graphics or system driver. |
| `0x50` | PAGE_FAULT_IN_NONPAGED_AREA | Referenced invalid memory. Strongly suggests **faulty RAM** or a bad driver. |
| `0x7E` | SYSTEM_THREAD_EXCEPTION_NOT_HANDLED | A driver threw an error it couldn't handle. Update / roll back drivers. |
| `0x7F` | UNEXPECTED_KERNEL_MODE_TRAP | CPU trap — often hardware: RAM, overclock instability, or overheating. |
| `0x9F` | DRIVER_POWER_STATE_FAILURE | A driver mishandled sleep/wake. Update chipset / USB / GPU drivers. |
| `0xBE` | ATTEMPTED_WRITE_TO_READONLY_MEMORY | A driver tried to write read-only memory. Faulty driver. |
| `0xC2` | BAD_POOL_CALLER | A driver misused the memory pool. Faulty driver. |
| `0xC5` | DRIVER_CORRUPTED_EXPOOL | A driver corrupted system memory. Faulty driver or bad RAM. |
| `0xD1` | DRIVER_IRQL_NOT_LESS_OR_EQUAL | A driver accessed bad memory at high IRQL. Network / storage drivers are common culprits. |
| `0xEF` | CRITICAL_PROCESS_DIED | A critical Windows process died. Often corruption (run `sfc /scannow`, `DISM`) or bad drivers. |
| `0xF4` | CRITICAL_OBJECT_TERMINATION | A critical system process ended unexpectedly. Often a **failing disk** or corruption. |
| `0x101` | CLOCK_WATCHDOG_TIMEOUT | A CPU core stopped responding. Often unstable overclock or a CPU/power issue. |
| `0x109` | CRITICAL_STRUCTURE_CORRUPTION | Kernel memory was corrupted. Bad RAM, driver, or tampering. |
| `0x113` | VIDEO_DXGKRNL_FATAL_ERROR | Graphics subsystem fault. Update or roll back GPU drivers. |
| `0x116` | VIDEO_TDR_ERROR | GPU stopped responding and couldn't recover. GPU driver, overheating, or failing GPU. |
| `0x124` | WHEA_UNCORRECTABLE_ERROR | Hardware reported a fatal error (CPU/RAM/PCIe/overheat). **This is hardware, not software.** |
| `0x133` | DPC_WATCHDOG_VIOLATION | A driver ran too long. Often old SSD firmware or a storage/network driver. |
| `0x139` | KERNEL_SECURITY_CHECK_FAILURE | Kernel detected corruption. Bad driver or faulty RAM. |
| `0x154` | UNEXPECTED_STORE_EXCEPTION | The memory/store backing store failed — frequently a **failing disk or its cable/port**. |

---

## LiveKernel / live-dump codes (not fatal BSODs)

These are **live dumps**: Windows keeps running and writes a triage dump (often under
`C:\Windows\LiveKernelReports\`). WER may show *“A problem with your hardware…”* —
that text is generic and does **not** by itself prove a dead component.

| Hex | Name | Plain meaning & first thing to check |
|-----|------|--------------------------------------|
| `0x193` | VIDEO_DXGKRNL_LIVEDUMP | Graphics kernel (`dxgkrnl`) live dump. Often Parameter1=`80e`. Update/roll back **GPU drivers**; check WATCHDOG dumps; streaming apps (e.g. Sunshine) can correlate. |
| `0x144` | USB3 live dump | USB3 stack issue — controllers/devices. |
| `0x15C` | PDC_WATCHDOG_TIMEOUT_LIVEDUMP | Connected-standby / power-state watchdog. |
| `0x15E` | NDIS_DRIVER_LIVE_DUMP | Network driver live dump. |
| `0x190` | WIN32K_CRITICAL_FAILURE_LIVEDUMP | Win32k critical failure live dump. |

Related Event Viewer signals: Display **4101** (TDR), WER **LiveKernelEvent** with Code **193**,
files named `WATCHDOG-*.dmp`.

---

## Special case: stop code `0` (no bug-check)

If Kernel-Power `41` shows **`BugcheckCode = 0`** and there's **no dump**, it was
**not** a software blue screen. Windows had no chance to record anything because
power was cut faster than it could react. Causes:

- **Power loss** — failing PSU, loose power cable, tripped circuit, UPS dropout.
- **Thermal cutoff** — CPU/PSU over-temp protection instantly kills power.
- **Hard lock** — a freeze severe enough that the hardware watchdog reset the board.

The diagnoser reports this as **"Abrupt power loss / hard lock"** rather than a
blue screen. See the `192.168.20.50` case in [INCIDENTS.md](INCIDENTS.md).

Also check the `PowerButtonTimestamp` field: if non-zero, someone **held the
power button** to force the shutdown.

---

## General triage order

1. **Storage codes** (`0x154`, `0xF4`) + `storahci 129` resets or `volmgr 161` →
   back up, check SMART, reseat/replace SATA cable, test/replace drive.
2. **Hardware codes** (`0x124`) or WHEA errors → MemTest86, check temps, review
   overclock.
3. **Memory codes** (`0x1A`, `0x50`, `0x109`, `0x139`) → MemTest86.
4. **Driver codes** (`0xD1`, `0x7E`, `0x3B`, `0x9F`, `0x116`) → update or roll
   back the implicated driver; analyze the minidump for its name.
5. **Corruption codes** (`0xEF`) → `sfc /scannow` then
   `DISM /Online /Cleanup-Image /RestoreHealth`.
