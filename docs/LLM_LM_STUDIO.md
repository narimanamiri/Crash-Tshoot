# Optional LM Studio analysis

Crash-Tshoot talks to LM Studio’s **OpenAI-compatible** API (stdlib `urllib` only).

## Setup

1. Install [LM Studio](https://lmstudio.ai/).
2. Download/load a model (7B+ instruct recommended for log triage).
3. **Developer** tab → start server (default `http://localhost:1234`).
4. Run:

```bash
python run_diagnoser.py --llm
python run_diagnoser.py --llm --lm-url http://192.168.1.10:1234/v1
python run_diagnoser.py --llm --lm-model "my-model-id"
python run_diagnoser.py --list-lm-models
```

Windows: `Run-Python-Diagnoser.bat --llm`

## What is sent

A **compact JSON** of:

- Application root cause (already computed)
- Top findings
- Sample log hits
- Snapshot / counters

System prompt instructs the model to confirm/refine, list remediations, and
**not invent** hardware faults without evidence.

## What is not sent

- Full multi-GB logs
- Passwords / secrets (not collected by design)
- Nothing leaves your machine unless you point `--lm-url` at a remote host you control

## Failure modes

| Symptom | Fix |
|---------|-----|
| “LM Studio unreachable” | Start server; check firewall; URL/port |
| “no loaded models” | Load a model in LM Studio |
| Slow / truncated | Use smaller `max_tokens` (code default 1200) or a faster model |

## Policy

| Layer | Role |
|-------|------|
| Collectors + patterns + root_cause | **Authoritative** |
| LM Studio | **Advisory** narrative in HTML “LM Studio advisory” block |

Exit codes and CRITICAL/WARNING lists come from the application, not the model.
