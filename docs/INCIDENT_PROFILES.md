# Incident profiles (encoded in the scripts)

All four real cases from [`INCIDENTS.md`](../INCIDENTS.md) are first-class
**matchable profiles** in both engines:

| Engine | Module / function |
|--------|-------------------|
| Python | [`crash_tshoot/incidents.py`](../crash_tshoot/incidents.py) → `apply_incident_matches()` |
| PowerShell | `Get-MatchedIncidents` / `Get-RootCause` in [`SystemDiagnoser.ps1`](../SystemDiagnoser.ps1) |

## Profiles

| # | Name | Key signals | Score threshold |
|---|------|-------------|-----------------|
| 1 | Failing SATA/AHCI disk (hung BSOD) | phantom 0-byte drive, storahci 129, 0x154, volmgr 161 | ≥ 50 |
| 2 | Abrupt power loss / hard lock | KP41 BugcheckCode=0, no BSOD finding | ≥ 50 |
| 3 | LiveKernelEvent 193 (GPU live dump) | LiveKernel 193 / WATCHDOG, optional TDR / Sunshine | ≥ 45 |
| 4 | BSOD 0x3B IN_PAGE + hung dump | 0x3B, Param1 0xC0000006, volmgr 161, no minidump | ≥ 60 |

Multiple profiles can match (e.g. #3 secondary + #4 primary). Highest score is
cited first in the root-cause line: `Matches known Incident #N (…)`.

## Collectors that feed the matcher

Windows structured query gathers in one pass:

- Kernel-Power 41 (with Param1 decode)
- Event 6008
- volmgr 161
- storahci / stornvme 129
- Phantom Win32_DiskDrive Size=0
- LiveKernel 193 count, Display 4101

## Adding a new incident

1. Document it in `INCIDENTS.md` as Incident #N.
2. Add `_match_incidentN` + `IncidentProfile` in `crash_tshoot/incidents.py`.
3. Mirror scoring in `Get-MatchedIncidents` in `SystemDiagnoser.ps1`.
4. Ensure collectors emit the evidence strings the matcher searches for.
