from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
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
        description="Crash diagnoser + advanced Event Viewer (FullEventLogView-class).",
    )
    p.add_argument("--days", type=int, default=7, help="History window in days (default 7)")
    p.add_argument("--log", action="append", default=[], help="Extra log file (repeatable)")
    p.add_argument("--log-folder", default="", help="Folder of logs / offline .log or .evtx copies")
    p.add_argument("--no-html", action="store_true", help="Do not write/open HTML report")
    p.add_argument("--report-dir", default="", help="Report output directory (default ./Reports)")
    p.add_argument("--llm", action="store_true", help="Enable optional LM Studio analysis")
    p.add_argument("--lm-url", default=DEFAULT_BASE, help=f"LM Studio OpenAI base URL (default {DEFAULT_BASE})")
    p.add_argument("--lm-model", default="", help="Model id (default: first loaded model)")
    p.add_argument("--list-lm-models", action="store_true", help="List LM Studio models and exit")
    p.add_argument("--offline-only", action="store_true", help="Only scan --log / --log-folder (no live OS collectors)")
    p.add_argument("--version", action="version", version=f"crash-tshoot {__version__}")

    # --- Event Viewer mode (FullEventLogView parity) ---
    p.add_argument("--event-viewer", action="store_true", help="Advanced Event Viewer mode")
    p.add_argument("--preset", default="", help="EV preset: CriticalErrors, BootShutdown, Storage, GPUDisplay, ...")
    p.add_argument("--list-presets", action="store_true", help="List Event Viewer presets and exit")
    p.add_argument("--list-channels", action="store_true", help="List Windows event channels and exit")
    p.add_argument("--event-id", default="", help="Comma-separated Event IDs")
    p.add_argument("--exclude-event-id", default="", help="Comma-separated Event IDs to exclude")
    p.add_argument("--level", default="", help="Comma levels: Critical,Error,Warning,Information,Verbose or 1-5")
    p.add_argument("--provider", default="", help="Provider filter (substring / wildcard *)")
    p.add_argument("--exclude-provider", default="", help="Exclude provider (substring)")
    p.add_argument("--channel", default="", help="Channel filter (wildcard *)")
    p.add_argument("--exclude-channel", default="", help="Exclude channel")
    p.add_argument("--message-contains", default="", help="Full-text message filter")
    p.add_argument("--user-contains", default="", help="Filter by user string in EventData/message")
    p.add_argument("--full-scan", action="store_true", help="Scan all enabled channels (Critical/Error unless levels set)")
    p.add_argument("--evtx", default="", help="Single offline .evtx file")
    p.add_argument("--max-events", type=int, default=5000, help="Cap events (default 5000)")
    p.add_argument(
        "--export",
        default="Csv,Json,Html",
        help="EV export formats: Csv,Json,Xml,Html,Tsv,Txt,RawXml",
    )
    p.add_argument("--save-filter", default="", help="Save current EV filter to JSON file")
    p.add_argument("--load-filter", default="", help="Load EV filter from JSON file")
    p.add_argument("--watch", type=int, default=0, metavar="SECONDS", help="Auto-refresh watch interval (Event Viewer)")
    p.add_argument("--watch-rounds", type=int, default=12, help="Watch iterations (default 12)")
    return p


def _parse_ids(s: str) -> list[int]:
    if not s:
        return []
    out = []
    for part in s.split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return out


def _parse_levels(s: str) -> list[int]:
    if not s:
        return []
    m = {"critical": 1, "error": 2, "warning": 3, "information": 4, "info": 4, "verbose": 5}
    out = []
    for part in s.split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
        elif part.lower() in m:
            out.append(m[part.lower()])
    return out


def run_event_viewer(args: argparse.Namespace) -> int:
    from .event_viewer import (
        PRESETS,
        EvFilter,
        aggregates,
        export_events,
        list_channels,
        load_evtx_folder,
        query_events,
        watch_loop,
    )
    import webbrowser

    if args.list_presets:
        for name in sorted(PRESETS):
            print(name)
        return 0
    if args.list_channels:
        for ch in list_channels():
            print(f"{ch.get('Name')}\t enabled={ch.get('Enabled')} records={ch.get('Records')} sizeMB={ch.get('SizeMB')}")
        return 0

    filt = EvFilter(days=args.days, max_events=args.max_events)
    if args.load_filter:
        filt = EvFilter.from_dict(json.loads(Path(args.load_filter).read_text(encoding="utf-8")))
    if args.preset:
        filt.apply_preset(args.preset)
    if args.full_scan:
        filt.all_channels = True
        if not filt.levels:
            filt.levels = [1, 2]
    if args.event_id:
        filt.event_ids = _parse_ids(args.event_id)
    if args.exclude_event_id:
        filt.exclude_event_ids = _parse_ids(args.exclude_event_id)
    if args.level:
        filt.levels = _parse_levels(args.level)
    if args.provider:
        filt.providers = [args.provider]
    if args.exclude_provider:
        filt.exclude_providers = [args.exclude_provider]
    if args.channel:
        filt.channels = [args.channel]
    if args.exclude_channel:
        filt.exclude_channels = [args.exclude_channel]
    if args.message_contains:
        filt.message_contains = args.message_contains
    if args.user_contains:
        filt.user_contains = args.user_contains

    if args.save_filter:
        Path(args.save_filter).write_text(json.dumps(filt.to_dict(), indent=2), encoding="utf-8")
        print(f"Saved filter: {args.save_filter}")

    if args.watch:
        watch_loop(filt, interval=args.watch, rounds=args.watch_rounds)
        return 0

    print(f"Event Viewer — preset={filt.preset or '(custom)'} days={filt.days} max={filt.max_events}")
    events: list = []
    if args.evtx or args.log_folder:
        path = args.evtx or args.log_folder
        print(f"Loading EVTX from {path}...")
        events = load_evtx_folder(path, filt)
    else:
        print("Querying live Windows event logs...")
        events = query_events(filt)

    print(f"Matched {len(events)} event(s).")
    agg = aggregates(events)
    for title, key in (("Level", "ByLevel"), ("Provider", "ByProvider"), ("Id", "ById")):
        top = agg.get(key, [])[:5]
        if top:
            print(f"  Top {title}: " + ", ".join(f"{r['Name']}={r['Count']}" for r in top))

    root = Path(__file__).resolve().parents[1]
    report_dir = Path(args.report_dir) if args.report_dir else root / "Reports"
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    formats = [x.strip() for x in args.export.split(",") if x.strip()]
    paths = export_events(events, report_dir, stamp, formats)
    for p in paths:
        print(f"  Exported: {p}")
        if p.suffix.lower() == ".html" and not args.no_html:
            try:
                webbrowser.open(p.as_uri())
            except Exception:
                pass
    # also save filter used
    (report_dir / f"Filter_{stamp}.json").write_text(json.dumps(filt.to_dict(), indent=2), encoding="utf-8")
    return 0 if events else 1


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

    if args.list_presets or args.list_channels or args.event_viewer or args.preset or args.watch or args.evtx:
        # EV mode if any EV-specific flag (except bare --log-folder used by diagnosis too)
        if args.list_presets or args.list_channels or args.event_viewer or args.watch or args.evtx or (
            args.preset and args.event_viewer
        ):
            return run_event_viewer(args)
        if args.preset:
            return run_event_viewer(args)

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
        print("LM Studio enrichment...")
        result = enrich_with_lmstudio(result, base_url=args.lm_url, model=args.lm_model, enabled=True)

    crit = [f for f in result.findings if f.severity.value == "CRITICAL"]
    warn = [f for f in result.findings if f.severity.value == "WARNING"]
    print(f"\n{len(crit)} CRITICAL, {len(warn)} WARNING finding(s)")
    for f in crit + warn:
        print(f"  [{f.severity.value:8}] {f.area:10} {f.title}")
        if f.detail:
            print(f"             -> {f.detail[:200]}")
    print("\nMOST LIKELY ROOT CAUSE:")
    print(f"  {result.root_cause}")
    matched = result.snapshot.get("matched_incidents") or []
    if matched:
        print("\nMATCHED INCIDENTS:")
        for m in matched:
            print(f"  #{m.get('id')} {m.get('name')} (score {m.get('score')}): {m.get('why')}")
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
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        json_path = report_dir / f"Diagnosis_{result.hostname}_{stamp}.json"
        json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        print(f"\nJSON: {json_path}")

    return 0 if not crit else 2


if __name__ == "__main__":
    raise SystemExit(main())
