"""
report.py - STEP 4: Report Generation.

Takes the combined list of Finding objects from every module and
produces a structured report in JSON, plain text, and HTML, sorted by
severity (CRITICAL first).
"""

import json
import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "#7a0b0b",
    "HIGH": "#c0392b",
    "MEDIUM": "#d68910",
    "LOW": "#2874a6",
    "INFO": "#566573",
}


def _sorted_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 5))


def summarize(findings):
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def to_json(findings, context, path):
    data = {
        "generated_at": datetime.datetime.now().isoformat(),
        "host_context": {
            "user": context.get("user"),
            "id": context.get("id"),
            "kernel": context.get("kernel"),
            "is_root": context.get("is_root"),
            "os_release": context.get("os_release"),
        },
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in _sorted_findings(findings)],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def to_text(findings, context, path):
    lines = []
    lines.append("=" * 70)
    lines.append("LINUX PRIVILEGE ESCALATION AUTOMATION TOOLKIT - REPORT")
    lines.append(f"Generated: {datetime.datetime.now().isoformat()}")
    lines.append(f"User: {context.get('user')}  |  Root session: {context.get('is_root')}")
    lines.append("=" * 70)

    counts = summarize(findings)
    lines.append("\nSUMMARY:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"  {sev:<9}: {counts.get(sev, 0)}")

    lines.append("\nFINDINGS (sorted by severity):\n")
    for f in _sorted_findings(findings):
        lines.append("-" * 70)
        lines.append(f"[{f.severity}] {f.title}  ({f.module})")
        lines.append(f"Detail: {f.detail}")
        if getattr(f, "confidence", None) and f.confidence != "N/A":
            lines.append(f"Confidence: {f.confidence}")
        if f.exploitability and f.exploitability != "N/A":
            lines.append(f"Exploitability: {f.exploitability}")
        if f.mitigation and f.mitigation != "N/A":
            lines.append(f"Mitigation: {f.mitigation}")
    lines.append("-" * 70)

    text = "\n".join(lines)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def to_html(findings, context, path):
    counts = summarize(findings)
    rows = []
    for f in _sorted_findings(findings):
        color = SEVERITY_COLOR.get(f.severity, "#566573")
        conf_html = (
            f"<br><strong>Confidence:</strong> {_esc(f.confidence)}"
            if getattr(f, "confidence", None) and f.confidence != "N/A"
            else ""
        )
        expl_html = (
            f"<br><em>Exploitability: {_esc(f.exploitability)}</em>"
            if f.exploitability and f.exploitability != "N/A"
            else ""
        )
        mit_html = (
            f"<br><strong>Mitigation:</strong> {_esc(f.mitigation)}"
            if f.mitigation and f.mitigation != "N/A"
            else ""
        )
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.severity}</span></td>
          <td>{f.module}</td>
          <td><strong>{_esc(f.title)}</strong><br>
              <span class="detail">{_esc(f.detail)}</span>
              {conf_html}
              {expl_html}
              {mit_html}
          </td>
        </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Linux Privilege Escalation Audit Report</title>
<style>
  :root {{
    --bg: #0f1216; --panel: #171b21; --text: #e6e8eb; --muted: #9aa4af;
    --border: #262c34;
    color-scheme: dark;
  }}
  @media (prefers-color-scheme: light) {{
    :root:not([data-theme="dark"]) {{
      --bg: #f5f6f8; --panel: #ffffff; --text: #1b1f24; --muted: #5b6672;
      --border: #e1e4e8;
    }}
  }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, Segoe UI, Roboto, sans-serif;
          margin: 0; padding: 32px 16px; }}
  .wrap {{ max-width: 980px; margin: 0 auto; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 4px; }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 24px; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 28px; }}
  .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
           padding: 12px 18px; min-width: 90px; text-align: center; }}
  .stat .num {{ font-size: 1.4rem; font-weight: 700; }}
  .stat .lbl {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: .04em; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border);
           border-radius: 10px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 0.88rem; }}
  th {{ color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: .04em; }}
  .badge {{ color: white; padding: 2px 8px; border-radius: 6px; font-size: 0.72rem; font-weight: 700; white-space: nowrap; }}
  .detail {{ color: var(--muted); white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem; }}
  .tablewrap {{ overflow-x: auto; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Linux Privilege Escalation Audit Report</h1>
  <div class="meta">
    Generated {datetime.datetime.now().isoformat()} &middot;
    User: {_esc(context.get('user', ''))} &middot;
    Root session: {context.get('is_root')}
  </div>
  <div class="summary">
    {''.join(f'<div class="stat"><div class="num" style="color:{SEVERITY_COLOR[s]}">{counts.get(s,0)}</div><div class="lbl">{s}</div></div>' for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"))}
  </div>
  <div class="tablewrap">
  <table>
    <thead><tr><th>Severity</th><th>Module</th><th>Finding</th></tr></thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
  </div>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


def _esc(s):
    if s is None:
        return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
