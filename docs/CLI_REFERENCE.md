# CLI reference

```text
python run_diagnoser.py [options]
python -m crash_tshoot [options]
./run-diagnoser.sh [options]
Run-Python-Diagnoser.bat [options]
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--days N` | `7` | History window (collectors that support time filters) |
| `--log PATH` | | Extra log file (repeatable) |
| `--log-folder DIR` | | Scan folder for `*.log`, syslog, messages, … |
| `--offline-only` | off | Skip live OS collectors; only scan provided logs |
| `--no-html` | off | JSON only; do not open browser |
| `--report-dir DIR` | `./Reports` | Output directory |
| `--llm` | off | Enable LM Studio enrichment |
| `--lm-url URL` | `http://localhost:1234/v1` | OpenAI-compat base URL |
| `--lm-model ID` | first loaded | Model identifier |
| `--list-lm-models` | | Print models from LM Studio and exit |
| `--version` | | Print version |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No CRITICAL findings |
| `2` | One or more CRITICAL findings |
| `1` | Usage / LM list failure |

## Examples

```bash
# Default local diagnosis
python run_diagnoser.py

# Two weeks + local LLM
python run_diagnoser.py --days 14 --llm

# Forensic bundle from another machine
python run_diagnoser.py --offline-only --log-folder ./host-logs --llm

# Windows deep PS merge happens automatically when SystemDiagnoser.ps1 exists
python run_diagnoser.py --days 7
```
