# Log analysis & unseen scenarios

The application does **not** only match a fixed list of known incidents. It uses
layered detection:

## 1. Platform-specific rules

High-confidence signatures (Windows LiveKernel/TDR/storage; Linux OOM/I/O/lockup/GPU).
Defined in [`crash_tshoot/patterns.py`](../crash_tshoot/patterns.py).

## 2. Generic failure language (unseen scenarios)

Cross-OS regexes for:

- panic / BUG / Oops / fatal / assertion
- timeout / hung / deadlock / not responding
- corrupt / checksum / CRC / ECC
- overheat / throttle
- power fail / brownout
- ENOSPC / out of disk space

Hits are **clustered by category**. Many WARNING hits escalate to CRITICAL.

## 3. Offline / forensic logs

Any text log:

```bash
python run_diagnoser.py --offline-only --log-folder ./evidence --days 90
python run_diagnoser.py --log crash.log --log kern.log
```

Supports mixed Windows Event exports, journal dumps, app logs, installer logs.

## 4. Evidence in the report

Each finding can carry **sample matching lines**. The HTML **Log Browser** tab
searches the hit list (path, category, message).

## 5. When rules are not enough

Enable `--llm` so LM Studio reads the compact finding+hit JSON and proposes
interpretations for unmatched lines. The app root cause remains authoritative;
LLM text is labeled **advisory**.

## Extending rules

Add a tuple to `WINDOWS_PATTERNS`, `LINUX_PATTERNS`, or `GENERIC_PATTERNS`:

```python
(re.compile(r"my-rare-error", re.I), "custom", Severity.WARNING,
 "My rare error", "Do X then Y.")
```

No LLM required for the new rule to fire on the next scan.
