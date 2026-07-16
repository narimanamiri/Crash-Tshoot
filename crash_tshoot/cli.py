from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .collectors import collect_all
from .collectors.generic_logs import collect_generic
from .llm import DEFAULT_BASE, enrich_with_lmstudio, list_models
from .report import write_reports
from .root_cause import finalize


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="crash-tshoot",
        description="Cross-platform crash & log diagnoser (Windows + Linux). "
        "Deterministic rules first; optional LM Studio enrichment.",
    )
    p.add_argument("--days", type=int, default=7, help="History window in days (default 7)")
    p.add_argument("--log", action="append", default=[], help="Extra log file (repeatable)")
    p.add_argument("--log-folder", default="", help="Folder of logs / offline .log copies")
    p.add_argument("--no-html", action="store_true", help="Do not write/open HTML report")
    p.add_argument("--report-dir", default="", help="Report output directory (default ./Reports)")
    p.add_argument("--llm", action="store_true", help="Enable optional LM Studio analysis")
    p.add_argument("--lm-url", default=DEFAULT_BASE, help=f"LM Studio OpenAI base URL (default {DEFAULT_BASE})")
    p.add_argument("--lm-model", default="", help="Model id (default: first loaded model)")
    p.add_argument("--list-lm-models", action="store_true", help="List LM Studio models and exit")
    p.add_argument("--offline-only", action="store_true", help="Only scan --log / --log-folder (no live OS collectors)")
    p.add_argument("--version", action="version", version=f"crash-tshoot {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_lm_models:
        models = list_models(args.lm_url)
        if not models:
            print("No models (is LM Studio server running at", args.lm_url, "?)", file=sys.stderr)
            return 1
        for m in models:
            print(m)
        return 0

    print(f"Crash-Tshoot v{__version__} - scanning last {args.days} day(s)...")

    if args.offline_only:
        from .collectors.base import base_snapshot

        result = base_snapshot(args.days)
        extras = list(args.log or [])
        if args.log_folder:
            extras.append(args.log_folder)
        collect_generic(result, days=args.days, extra_logs=extras)
    else:
        result = collect_all(
            days=args.days,
            extra_logs=args.log,
            log_folder=args.log_folder or None,
        )

    result = finalize(result)

    if args.llm:
        print("LM Studio enrichment…")
        result = enrich_with_lmstudio(result, base_url=args.lm_url, model=args.lm_model, enabled=True)

    # Console summary
    crit = [f for f in result.findings if f.severity.value == "CRITICAL"]
    warn = [f for f in result.findings if f.severity.value == "WARNING"]
    print(f"\n{len(crit)} CRITICAL, {len(warn)} WARNING finding(s)")
    for f in crit + warn:
        print(f"  [{f.severity.value:8}] {f.area:10} {f.title}")
        if f.detail:
            print(f"             -> {f.detail[:200]}")
    print("\nMOST LIKELY ROOT CAUSE:")
    print(f"  {result.root_cause}")
    if result.llm_used:
        print("\n--- LM Studio (advisory) ---")
        print(result.llm_summary[:2000])

    root = Path(__file__).resolve().parents[1]
    report_dir = Path(args.report_dir) if args.report_dir else root / "Reports"
    if not args.no_html:
        html_path, json_path = write_reports(result, report_dir, open_html=True)
        print(f"\nHTML: {html_path}")
        print(f"JSON: {json_path}")
    else:
        report_dir.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        import json

        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        json_path = report_dir / f"Diagnosis_{result.hostname}_{stamp}.json"
        json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"\nJSON: {json_path}")

    return 0 if not crit else 2


if __name__ == "__main__":
    raise SystemExit(main())
