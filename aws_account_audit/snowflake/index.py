from __future__ import annotations

import html as html_module
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aws_account_audit.account_index import (
    _findings_page_html,
    _render_findings_groups_html,
    _severity_anchor,
    _severity_badges,
)


def _rel(path: Path | None, base: Path) -> str | None:
    if path is None:
        return None
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return str(path)


def load_audit_data(audit_json: Path | None) -> dict[str, Any]:
    if audit_json is None or not audit_json.exists():
        return {"findings": [], "findings_by_severity": {}}
    payload = json.loads(audit_json.read_text(encoding="utf-8"))
    findings = list(payload.get("findings") or [])
    summary = payload.get("summary") or {}
    return {
        "findings": findings,
        "findings_by_severity": summary.get("findings_by_severity") or {},
    }


def render_snowflake_findings_html(
    *,
    summary: dict[str, Any],
    run_dir: Path,
    generated_at: datetime | None = None,
) -> str:
    account = str(summary.get("account") or summary.get("account_id") or "unknown-account")
    generated_at = generated_at or datetime.now(timezone.utc)
    audit_json = summary.get("audit_json")
    audit_path = Path(str(audit_json)) if audit_json else None
    if audit_path and not audit_path.is_absolute():
        audit_path = (run_dir / audit_path).resolve()
    audit_data = load_audit_data(audit_path)
    findings = list(audit_data.get("findings") or [])
    findings_by_severity = dict(audit_data.get("findings_by_severity") or {})
    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    back_link = _rel(run_dir / "snowflake-view.html", run_dir) or "snowflake-view.html"

    return _findings_page_html(
        title=f"Security findings: {account}",
        subtitle=f"Snowflake audit findings · generated {generated_label}",
        back_link=back_link,
        back_label="Back to Snowflake view",
        severity_badges_html=_severity_badges(
            findings_by_severity,
            link_for_severity=lambda severity: f"#{_severity_anchor(severity)}",
        ),
        body_html=_render_findings_groups_html(findings),
    )


def write_snowflake_findings_html(*, summary: dict[str, Any], run_dir: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run_dir / "findings.html"
    findings_path.write_text(
        render_snowflake_findings_html(summary=summary, run_dir=run_dir),
        encoding="utf-8",
    )
    return findings_path


def render_snowflake_index_html(
    *,
    summary: dict[str, Any],
    run_dir: Path,
    generated_at: datetime | None = None,
) -> str:
    account = str(summary.get("account") or summary.get("account_id") or "unknown-account")
    generated_at = generated_at or datetime.now(timezone.utc)
    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    audit_json = summary.get("audit_json")
    audit_path = Path(str(audit_json)) if audit_json else None
    if audit_path and not audit_path.is_absolute():
        audit_path = (run_dir / audit_path).resolve()
    audit_data = load_audit_data(audit_path)
    findings_by_severity = dict(audit_data.get("findings_by_severity") or {})

    def _findings_link(severity: str) -> str:
        return f"findings.html#{_severity_anchor(severity)}"

    severity_html = _severity_badges(findings_by_severity, link_for_severity=_findings_link)

    def _artifact_row(label: str, key: str, primary: bool = False) -> str:
        value = summary.get(key)
        if not value:
            return (
                f'<li class="missing">{html_module.escape(label)} '
                f'<span class="tag">not generated</span></li>'
            )
        rel = _rel(Path(str(value)), run_dir) or str(value)
        badge = '<span class="tag primary">full view</span>' if primary else ""
        return (
            f'<li><a href="{html_module.escape(rel)}">{html_module.escape(label)}</a>{badge}</li>'
        )

    security_rows = "".join(
        [
            _artifact_row(
                "Security findings (interactive)",
                "findings_html" if summary.get("findings_html") else "audit_json",
                True,
            ),
            _artifact_row("Security findings (JSON source)", "audit_json", False),
        ]
    )
    inventory_rows = "".join(
        [
            _artifact_row("Resource inventory tables (interactive)", "inventory_html", True),
            _artifact_row("Snowflake audit (JSON)", "audit_json", False),
            _artifact_row("Snowflake audit (text)", "audit_text", False),
            _artifact_row("Resource inventory (JSON)", "inventory_json", False),
            _artifact_row("Resource inventory (text)", "inventory_text", False),
        ]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Snowflake account view: {html_module.escape(account)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --accent: #0d9488;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, "Segoe UI", sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.5;
    }}
    header {{
      padding: 1.5rem;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
    }}
    h1 {{ margin: 0 0 0.35rem; font-size: 1.5rem; }}
    .subtitle {{ margin: 0; color: var(--muted); font-size: 0.9rem; }}
    main {{ padding: 1.25rem; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1rem 1.25rem;
      margin-bottom: 1rem;
    }}
    ul {{ margin: 0; padding-left: 1.1rem; }}
    li {{ margin: 0.35rem 0; }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .tag {{
      display: inline-block;
      margin-left: 0.35rem;
      padding: 0.05rem 0.35rem;
      border-radius: 0.35rem;
      font-size: 0.72rem;
      border: 1px solid var(--border);
      color: var(--muted);
    }}
    .tag.primary {{
      color: #0f766e;
      border-color: #99f6e4;
      background: #f0fdfa;
    }}
    .missing {{ color: var(--muted); font-style: italic; list-style: none; margin-left: -1.1rem; }}
    .finding-summary {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.35rem;
      margin-top: 0.85rem;
    }}
    .finding-summary-label {{
      font-size: 0.75rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      margin-right: 0.25rem;
    }}
    .severity {{
      display: inline-block;
      margin: 0.1rem 0.25rem 0.1rem 0;
      padding: 0.05rem 0.4rem;
      border-radius: 0.35rem;
      font-size: 0.72rem;
      border: 1px solid var(--border);
      background: var(--bg);
      color: inherit;
    }}
    a.severity-link {{ text-decoration: none; color: inherit; }}
    a.severity-link:hover .severity {{
      filter: brightness(0.95);
      box-shadow: 0 0 0 1px var(--accent);
    }}
    .severity.critical {{ color: #991b1b; background: #fef2f2; border-color: #fecaca; }}
    .severity.high {{ color: #9a3412; background: #fff7ed; border-color: #fed7aa; }}
    .severity.medium {{ color: #a16207; background: #fefce8; border-color: #fde68a; }}
    .severity.low {{ color: #1d4ed8; background: #eff6ff; border-color: #bfdbfe; }}
  </style>
</head>
<body>
  <header>
    <h1>Snowflake account view: {html_module.escape(account)}</h1>
    <p class="subtitle">Snowflake audit artifacts · generated {generated_label}</p>
    <div class="finding-summary">
      <span class="finding-summary-label">Findings</span>
      {severity_html if severity_html else '<span class="muted">none</span>'}
    </div>
  </header>
  <main>
    <section class="card">
      <h2>Security findings</h2>
      <ul>{security_rows}</ul>
    </section>
    <section class="card">
      <h2>Inventory audit</h2>
      <ul>{inventory_rows}</ul>
    </section>
  </main>
</body>
</html>
"""


def write_snowflake_index_html(*, summary: dict[str, Any], run_dir: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    index_path = run_dir / "snowflake-view.html"
    index_path.write_text(
        render_snowflake_index_html(summary=summary, run_dir=run_dir),
        encoding="utf-8",
    )
    return index_path


def build_summary(
    *,
    report_metadata: dict[str, Any],
    written: dict[str, Path],
    run_dir: Path,
    findings_path: Path,
    index_path: Path,
) -> dict[str, Any]:
    return {
        "provider": "snowflake",
        "account": report_metadata.get("account"),
        "account_id": report_metadata.get("account_id"),
        "user": report_metadata.get("user"),
        "role": report_metadata.get("role"),
        "generated_at": report_metadata.get("generated_at"),
        "audit_json": str(_rel(written.get("json"), run_dir) or ""),
        "audit_text": str(_rel(written.get("text"), run_dir) or ""),
        "inventory_json": str(_rel(written.get("inventory_json"), run_dir) or ""),
        "inventory_text": str(_rel(written.get("inventory_text"), run_dir) or ""),
        "inventory_html": str(_rel(written.get("inventory_html"), run_dir) or ""),
        "findings_html": str(_rel(findings_path, run_dir) or "findings.html"),
        "snowflake_view_html": str(_rel(index_path, run_dir) or "snowflake-view.html"),
    }
