# Incident Log

Real crashes diagnosed with this toolkit. These are the cases the diagnoser was
built from — kept as worked examples of the method.

---

## Incident #1 — Local PC `DESKTOP-72P233G`: stuck on blue screen overnight

- **Date:** night of 2026-06-21 → recovered 2026-06-22
- **Machine:** ASUS desktop, 28 logical cores, 128 GB RAM, Windows 11 Enterprise N
  (build 26200). Four drives: 3× Samsung 990 PRO NVMe + 1× HIKSEMI USB SSD.
- **Symptom:** Blue screen, then **frozen on the BSOD all night** until forced off
  in the morning.

### Root cause
A **SATA drive on the AHCI controller (RaidPort0) stopped responding.** The
storage driver issued repeated device resets, the disk never came back, the
kernel bug-checked with **`0x154 UNEXPECTED_STORE_EXCEPTION`**, and then **could
not write the crash dump to that same dead disk** — which is exactly why the BSOD
hung instead of rebooting.

### Evidence
| Time (6/22) | Event | Meaning |
|------|-------|---------|
| 22:56:03 (prev. night) | EventLog `6008` | "Previous shutdown was unexpected" — the real crash time. |
| 09:56:24–09:56:54 | `storahci 129` ×4 | "Reset to device, `\Device\RaidPort0`" every 10 s — disk hung. |
| 09:56:55 | `volmgr 161` | "Dump file creation failed… BugCheckProgress 0x00040049". |
| 09:56:55 | Kernel-Power `41` | `BugcheckCode = 340` (`0x154`), `BugcheckInfoFromEFI = true`. |

- **No** `C:\Windows\Minidump` folder and **no** `MEMORY.DMP` — dump never written.
- `storahci 129` resets recurred across days (6/12 ×10, 6/13 ×5, 6/15 ×3, 6/22 ×5).
- `Win32_DiskDrive` listed a **phantom drive**: blank model, `IDE` interface,
  **0 bytes, 0 partitions**, PNP `SCSI\DISK&VEN_&PROD_\4&11742CA2&0&050000` — a
  SATA drive dropping off the bus. The four real drives all reported **Healthy**.

### Resolution
The failing SATA drive (blank model, 0 bytes, no partitions) was **disabled** at
the OS level to stop it crashing the system:

```powershell
# Run elevated. To re-enable later, swap Disable for Enable.
Disable-PnpDevice -InstanceId 'SCSI\DISK&VEN_&PROD_\4&11742CA2&0&050000' -Confirm:$false
```

It then reported `Status = Error / CM_PROB_DISABLED` (correct for a manually
disabled device). **Permanent fix:** physically unplug or replace that drive /
its SATA cable.

### Follow-ups surfaced later by the diagnoser
- 🔴 **C: at 5% free** (106 GB of 1999 GB) — below 10% causes instability.
- 🔴 **`dorsandesk.exe` crashed 64×** in 7 days.
- 🟡 **4 failed Windows Updates** (likely tied to low disk space).

---

## Incident #2 — Remote PC `DESKTOP-V25CIH2` (`192.168.20.50`): died twice in 3 minutes

- **Date:** evening of 2026-06-22
- **Machine:** AMD workstation, 32 logical cores, Windows 11 Enterprise
  (build 26100). Reached over **SSH** (OpenSSH server, default shell behaved like
  Windows — `whoami` returned `desktop-v25cih2\ai`).
- **Symptom:** "Died last night." Came back up on its own.

### Root cause
**Abrupt power loss / hard reset — NOT a blue screen.** The machine lost power
twice within three minutes, then stabilized. Most likely a **power-delivery
problem (PSU / cable / UPS)** or a **thermal cutoff** on a high-core-count
workstation under load.

### Evidence
| Time (6/22) | Event | Meaning |
|------|-------|---------|
| 19:23:26 | Kernel-Power `41` | `BugcheckCode = 0`, `FromEFI = false` — no bug-check. |
| 19:23:28 | EventLog `6005` | Log restarted (booted back up). |
| 19:26:13 | Kernel-Power `41` | `BugcheckCode = 0` again — died a second time. |
| 19:26:15 | EventLog `6005` | Booted again, then stayed up. |

Everything that would indicate a software BSOD was **empty**:

- Stop code **`0`** on both `41` events (a real BSOD records non-zero — cf. `0x154`).
- **No** BugCheck `1001`, **no** minidumps, **no** `MEMORY.DMP`.
- **No** WHEA-Logger events (CPU/RAM/PCIe hardware-error channel was silent).

The **two failures three minutes apart** are the tell: crash → reboot →
immediate crash under load → stabilize = classic marginal power/thermal behavior.
A prior unexpected shutdown on 6/16 made this the second event in a week.

### Recommended fixes (hardware)
1. Reseat the 24-pin and CPU/EPS power cables; check the UPS / wall circuit.
   Swap in a known-good PSU to confirm.
2. Check CPU/VRM temps under load (HWiNFO64) for a thermal cutoff.
3. Treat as a developing hardware fault, not a fluke.

### Unrelated issues noticed
- Windows Update failing on an AMD driver (`0x80240016` / `0x8024200B`).
- Secure Boot/TPM update failing (`1796`).

---

## Incident #3 — Local PC `DESKTOP-72P233G`: LiveKernelEvent 193 (GPU live dump)

- **Date:** 2026-07-15 (WER dump `WATCHDOG-20260715-1432.dmp`); re-confirmed by diagnoser 2026-07-16
- **Machine:** ASUS desktop, RTX 4060, Windows 11 Enterprise N build 26200
- **Symptom:** Windows Error Reporting: *“A problem with your hardware caused Windows
  to stop working correctly”* with **LiveKernelEvent Code 193**, Parameter1 **80e**.

### Root cause
**Not a fatal BSOD.** Code **193** is `VIDEO_DXGKRNL_LIVEDUMP` — the DirectX graphics
kernel (`dxgkrnl`) captured a **live watchdog dump** because of a graphics-stack
hiccup. The scary WER wording is boilerplate.

Contributing / correlated signals on the same machine:
- **C: at ~1% free** — amplifies instability and failed updates.
- **`sunshine.exe` crashed 2×** — GPU encode/streaming stress aligns with LiveKernel/GPU events.
- **No** Kernel-Power 41, **no** WHEA — unlike Incidents #1 and #2.

### Evidence
| Signal | Meaning |
|--------|---------|
| LiveKernelEvent 193 / Param `80e` | dxgkrnl live dump reason code |
| `WATCHDOG-*.dmp` | Graphics watchdog triage dump |
| sunshine.exe Application Error 1000 | GPU-heavy app instability |
| C: 1% free | Critical free-space pressure |

### Resolution path
1. Free substantial space on **C:** (well above 10%).
2. Clean-install GPU drivers (DDU → vendor driver).
3. Update or temporarily quit Sunshine / overlays; re-test.
4. Optional: open the WATCHDOG dump in WinDbg (`!analyze -v`) for `IMAGE_NAME`.

### How the upgraded diagnoser reports this
Area **GPU**, title **LiveKernelEvent 193 (VIDEO_DXGKRNL_LIVEDUMP)**, Apps finding
promoted to WARNING when Sunshine correlates, root cause line prioritizes
**GPU/DISPLAY** with **CONTRIBUTING** low disk space.

---

## Method notes (how these were diagnosed)

The repeatable process, now automated by [`SystemDiagnoser.ps1`](SystemDiagnoser.ps1):

1. **Kernel-Power `41`** + **BugCheck `1001`** → was there a bug-check, and what
   stop code? Decode it.
2. **`BugcheckCode = 0`?** → not a BSOD; suspect power/thermal/hard-lock.
3. **`6008` / `6005`** → pin down the real crash time and reboot pattern.
4. **Minidump / `MEMORY.DMP` / `volmgr 161`** → did a dump get written? A *failed*
   dump points at an unresponsive disk.
5. **`storahci 129`, SMART, phantom drives** → storage failing or disconnecting?
6. **WHEA-Logger** → did the hardware itself report a fatal error?
7. **Correlate timeline** around the crash minute for the triggering events.

### Two contrasting signatures, side by side
| | Incident #1 (storage) | Incident #2 (power) | Incident #3 (GPU live dump) |
|--|----------------------|---------------------|------------------------------|
| Stop / code | `0x154` (non-zero) | `0` | LiveKernel **193** (not a BSOD) |
| Dump written | No (`volmgr 161` failure) | No (none attempted) | WATCHDOG live dump |
| `storahci` resets | Yes, recurring | No | No |
| WHEA errors | No | No | No |
| Verdict | Failing SATA disk | Abrupt power loss / thermal | dxgkrnl / GPU driver (+ low disk / Sunshine) |
