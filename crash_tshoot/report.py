from __future__ import annotations

import html
import json
from pathlib import Path

from .models import DiagnosisResult, Severity


ROW = {
    Severity.CRITICAL: "#ffd6d6",
    Severity.WARNING: "#fff2cc",
    Severity.INFO: "#e8f0fe",
    Severity.OK: "#dcffe0",
}


def write_reports(result: DiagnosisResult, report_dir: Path, open_html: bool = True) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    from datetime import datetime

    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    base = report_dir / f"Diagnosis_{result.hostname}_{stamp}"
    json_path = Path(str(base) + ".json")
    html_path = Path(str(base) + ".html")

    json_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    html_path.write_text(_render_html(result), encoding="utf-8")

    if open_html:
        try:
            import webbrowser

            webbrowser.open(html_path.as_uri())
        except Exception:
            pass
    return html_path, json_path


def _esc(s: str) -> str:
    return html.escape(s or "")


def _render_html(result: DiagnosisResult) -> str:
    crit = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    warn = sum(1 for f in result.findings if f.severity == Severity.WARNING)
    ev_json = json.dumps(result.browser_events[:2000])

    rows = []
    for f in result.findings:
        bg = ROW.get(f.severity, "#fff")
        ev = "<br>".join(_esc(x) for x in (f.evidence or [])[:3])
        rows.append(
            f"<tr style='background:{bg}'><td><b>{f.severity.value}</b></td>"
            f"<td>{_esc(f.area)}</td><td>{_esc(f.title)}</td>"
            f"<td>{_esc(f.detail)}{'<hr>'+ev if ev else ''}</td>"
            f"<td>{_esc(f.when or '')}</td><td>{_esc(f.source)}</td></tr>"
        )

    actions = "".join(f"<li>{_esc(a)}</li>" for a in result.actions)
    llm_block = ""
    if result.llm_used and result.llm_summary:
        llm_block = f"<div class='llm'><h2>LM Studio advisory</h2><pre>{_esc(result.llm_summary)}</pre></div>"

    snap = " · ".join(f"{_esc(k)}={_esc(str(v))[:80]}" for k, v in list(result.snapshot.items())[:8])

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Crash-Tshoot { _esc(result.hostname) }</title>
<style>
body{{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#f0f2f5;color:#222}}
header{{background:#0a5;color:#fff;padding:20px 28px}}
.wrap{{padding:20px 28px;max-width:1200px;margin:0 auto}}
.rc{{background:#fde;padding:14px;border-left:4px solid #c09;margin:16px 0}}
.actions{{background:#eef8ff;padding:14px;border-left:4px solid #08c}}
.llm{{background:#1e1e2e;color:#cdd6f4;padding:16px;border-radius:8px;margin:16px 0}}
.llm pre{{white-space:pre-wrap;font-size:.9rem}}
table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;font-size:.9rem}}
th{{background:#0a5;color:#fff}}
.tabs button{{margin:4px;padding:8px 12px;cursor:pointer}}
.panel{{display:none;background:#fff;padding:12px;border-radius:8px}}
.panel.active{{display:block}}
.filters input,.filters select{{padding:6px;margin:4px}}
</style></head><body>
<header>
  <h1>Crash-Tshoot v2</h1>
  <div>{_esc(result.hostname)} · {_esc(result.platform)} · last {result.days} days ·
  generated {_esc(result.generated)} · <b>{crit} critical</b>, {warn} warning
  {" · LLM on" if result.llm_used else ""}</div>
  <div style="opacity:.85;margin-top:6px">{snap}</div>
</header>
<div class="wrap">
  <div class="rc"><b>Most likely root cause (application rules):</b><br>{_esc(result.root_cause)}</div>
  <div class="actions"><b>Actions</b><ul>{actions or "<li>None</li>"}</ul></div>
  {llm_block}
  <div class="tabs">
    <button onclick="show('f',this)" class="on">Findings</button>
    <button onclick="show('e',this)">Log Browser</button>
  </div>
  <div id="f" class="panel active">
    <table><tr><th>Severity</th><th>Area</th><th>Finding</th><th>Detail</th><th>When</th><th>Source</th></tr>
    {''.join(rows)}
    </table>
  </div>
  <div id="e" class="panel">
    <div class="filters">
      <input id="q" placeholder="Search..." oninput="filt()" style="width:40%">
      <select id="lv" onchange="filt()"><option value="">All</option>
        <option>CRITICAL</option><option>WARNING</option><option>INFO</option></select>
    </div>
    <table id="et"><thead><tr><th>Time</th><th>Sev</th><th>Line</th><th>Cat</th><th>Path</th><th>Message</th></tr></thead><tbody></tbody></table>
  </div>
</div>
<script>
const EV={ev_json};
function show(id,btn){{
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}}
function filt(){{
  const q=(document.getElementById('q').value||'').toLowerCase();
  const lv=document.getElementById('lv').value;
  const tb=document.querySelector('#et tbody'); tb.innerHTML='';
  EV.filter(e=>{{
    if(lv && e.l!==lv) return false;
    if(q && !((e.m||'')+(e.c||'')+(e.p||'')).toLowerCase().includes(q)) return false;
    return true;
  }}).slice(0,1500).forEach(e=>{{
    const tr=document.createElement('tr');
    tr.innerHTML=`<td>${{esc(e.t)}}</td><td>${{esc(e.l)}}</td><td>${{e.i}}</td><td>${{esc(e.p)}}</td><td>${{esc(e.c)}}</td><td>${{esc((e.m||'').slice(0,200))}}</td>`;
    tb.appendChild(tr);
  }});
}}
function esc(s){{return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;');}}
filt();
</script>
</body></html>"""
