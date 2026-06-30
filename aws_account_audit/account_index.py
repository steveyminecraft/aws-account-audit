"""Render a single 'full account view' HTML index for an account-check run.

The account check writes many separate artifacts (audit report, IAM relationship
graph, account-wide network graph, and per-resource network maps). Large IAM/account
graphs do not fit well in a static PNG, so this index links the interactive HTML
views as the primary 'full view' and lists every other artifact for quick access.
"""

from __future__ import annotations

import html as html_module
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# Artifact rows are (label, path, is_primary). ``is_primary`` marks the
# interactive HTML views that render the full diagram with pan/zoom.
ArtifactRow = tuple[str, "Path | None", bool]


def _rel(path: Path | None, base: Path) -> str | None:
    if path is None:
        return None
    try:
        return os.path.relpath(path, base)
    except ValueError:
        return str(path)


def collect_network_map_links(network_dir: Path) -> list[tuple[str, Path]]:
    """Return (label, path) for every per-resource network map HTML file."""
    links: list[tuple[str, Path]] = []
    for subdir in ("from-audit", "all-security-groups"):
        directory = network_dir / subdir
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.html")):
            links.append((f"{subdir}/{path.name}", path))
    return links


def _section_html(title: str, rows: Iterable[ArtifactRow], base: Path) -> str:
    items: list[str] = []
    for label, path, is_primary in rows:
        rel = _rel(path, base)
        if rel is None:
            items.append(
                f'<li class="missing">{html_module.escape(label)} '
                f'<span class="tag">not generated</span></li>'
            )
            continue
        href = html_module.escape(rel)
        text = html_module.escape(label)
        badge = '<span class="tag primary">full view</span>' if is_primary else ""
        items.append(f'<li><a href="{href}">{text}</a>{badge}</li>')
    if not items:
        items.append('<li class="missing">none</li>')
    return (
        f'<section class="card"><h2>{html_module.escape(title)}</h2>'
        f"<ul>{''.join(items)}</ul></section>"
    )


def render_account_index_html(
    *,
    summary: dict,
    run_dir: Path,
    network_links: Iterable[tuple[str, Path]] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Build a self-contained HTML index linking every account-check artifact."""
    account_id = str(summary.get("account_id") or "unknown-account")
    generated_at = generated_at or datetime.now(timezone.utc)
    iam_summary = summary.get("iam_graph_summary") or {}

    def _path(key: str) -> Path | None:
        value = summary.get(key)
        return Path(value) if value else None

    identity_rows: list[ArtifactRow] = [
        ("IAM relationship graph (interactive)", _path("iam_graph_html"), True),
        ("IAM relationship graph (PNG)", _path("iam_graph_png"), False),
        ("IAM relationship graph (JSON)", _path("iam_graph_json"), False),
        ("IAM audit data (JSON)", _path("iam_audit_json"), False),
    ]
    section_rows: list[ArtifactRow] = [
        (f"IAM section {index}", Path(value), False)
        for index, value in enumerate(summary.get("iam_graph_sections") or [], start=1)
    ]
    account_rows: list[ArtifactRow] = [
        ("Account network graph (interactive)", _path("account_graph_html"), True),
        ("Account network graph (PNG)", _path("account_graph_png"), False),
        ("Account network graph (JSON)", _path("account_graph_json"), False),
    ]
    audit_rows: list[ArtifactRow] = [
        ("Resource inventory tables (interactive)", _path("inventory_html"), True),
        ("Account inventory audit (JSON)", _path("audit_json"), False),
        ("Account inventory audit (text)", _path("audit_text"), False),
        ("Resource inventory (JSON)", _path("inventory_json"), False),
        ("Resource inventory (text)", _path("inventory_text"), False),
    ]

    network_rows: list[ArtifactRow] = [
        (label, path, False) for label, path in (network_links or [])
    ]

    stat_pairs = [
        ("Account", account_id),
        ("IAM users", iam_summary.get("user_count", "-")),
        ("IAM groups", iam_summary.get("group_count", "-")),
        ("IAM roles", iam_summary.get("role_count", "-")),
        ("IAM policies", iam_summary.get("policy_count", "-")),
        ("IAM edges", iam_summary.get("edge_count", "-")),
        ("Network maps", len(network_rows)),
    ]
    stats_html = "".join(
        f'<div class="stat"><span class="stat-value">{html_module.escape(str(value))}</span>'
        f'<span class="stat-label">{html_module.escape(str(label))}</span></div>'
        for label, value in stat_pairs
    )

    section_cards = [
        _section_html("Identity & access (IAM)", identity_rows, run_dir),
        _section_html("Account network", account_rows, run_dir),
        _section_html("Inventory audit", audit_rows, run_dir),
        _section_html("Per-resource network maps", network_rows, run_dir),
    ]
    if section_rows:
        section_cards.insert(
            1, _section_html("IAM graph sections (zoom-friendly tiles)", section_rows, run_dir)
        )
    sections = "".join(section_cards)

    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account view: {html_module.escape(account_id)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --accent: #2563eb;
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
    .stats {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-top: 1rem;
    }}
    .stat {{
      display: flex;
      flex-direction: column;
      padding: 0.5rem 0.85rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 0.6rem;
      min-width: 5rem;
    }}
    .stat-value {{ font-size: 1.2rem; font-weight: 600; }}
    .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }}
    main {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1rem;
      padding: 1.25rem;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1rem 1.25rem;
    }}
    .card h2 {{ margin: 0 0 0.6rem; font-size: 1.05rem; }}
    ul {{ list-style: none; margin: 0; padding: 0; }}
    li {{ padding: 0.3rem 0; border-bottom: 1px solid var(--border); }}
    li:last-child {{ border-bottom: none; }}
    a {{ color: var(--accent); text-decoration: none; word-break: break-all; }}
    a:hover {{ text-decoration: underline; }}
    .tag {{
      display: inline-block;
      margin-left: 0.5rem;
      padding: 0.05rem 0.45rem;
      font-size: 0.7rem;
      border-radius: 0.4rem;
      background: var(--bg);
      color: var(--muted);
      border: 1px solid var(--border);
    }}
    .tag.primary {{ background: #dbeafe; color: #1d4ed8; border-color: #bfdbfe; }}
    .missing {{ color: var(--muted); font-style: italic; }}
  </style>
</head>
<body>
  <header>
    <h1>AWS account view: {html_module.escape(account_id)}</h1>
    <p class="subtitle">Full account-check overview &middot; generated {generated_label}</p>
    <div class="stats">{stats_html}</div>
  </header>
  <main>
    {sections}
  </main>
</body>
</html>
"""


def _resolve_artifact_path(value: str | None, *, output_dir: Path) -> Path | None:
    if not value:
        return None
    path = Path(value)
    candidates = [
        path,
        output_dir.parent / path,
        Path.cwd() / path,
        output_dir / path,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    if path.suffix:
        return path
    return None


def extract_audit_metrics(audit_json_path: Path | None) -> dict[str, object]:
    if audit_json_path is None or not audit_json_path.is_file():
        return {}
    try:
        payload = json.loads(audit_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    summary = payload.get("summary") or {}
    return {
        "finding_count": int(summary.get("finding_count") or 0),
        "resource_count": int(summary.get("resource_count") or 0),
        "findings_by_severity": dict(summary.get("findings_by_severity") or {}),
    }


def _severity_badges(findings_by_severity: dict[str, object]) -> str:
    order = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    badges: list[str] = []
    for severity in order:
        count = findings_by_severity.get(severity)
        if not count:
            continue
        css = severity.lower()
        badges.append(
            f'<span class="severity {css}">{html_module.escape(severity)}: '
            f"{html_module.escape(str(count))}</span>"
        )
    return " ".join(badges) if badges else '<span class="muted">none</span>'


def _scan_status_badge(scan_status: str | None) -> str:
    status = scan_status or "unknown"
    css = {
        "ok": "ok",
        "failed": "failed",
        "assume_role_failed": "blocked",
    }.get(status, "unknown")
    return (
        f'<span class="scan-status {css}">{html_module.escape(status.replace("_", " "))}</span>'
    )


def render_organization_index_html(
    *,
    org_summary: dict,
    org_dir: Path,
    output_dir: Path,
    generated_at: datetime | None = None,
) -> str:
    """Build an HTML index linking every account in an organization scan."""
    organization_id = str(org_summary.get("organization_id") or "unknown-organization")
    generated_at = generated_at or datetime.now(timezone.utc)
    accounts = org_summary.get("accounts") or []

    account_rows: list[str] = []
    total_findings = 0
    total_resources = 0
    scanned_accounts = 0

    for account in accounts:
        account_id = str(account.get("account_id") or "")
        account_name = str(account.get("account_name") or account_id)
        scan_status = str(account.get("scan_status") or "unknown")
        summary = account.get("summary") or {}
        account_view = _resolve_artifact_path(
            str(summary.get("account_view_html") or ""),
            output_dir=output_dir,
        )
        if account_view is None and account_id:
            candidate = output_dir / f"account-{account_id}" / "account-view.html"
            account_view = candidate if candidate.is_file() else candidate

        audit_metrics: dict[str, object] = {}
        if scan_status != "assume_role_failed":
            audit_json = _resolve_artifact_path(
                str(summary.get("audit_json") or ""),
                output_dir=output_dir,
            )
            audit_metrics = extract_audit_metrics(audit_json)
            scanned_accounts += 1
            total_findings += int(audit_metrics.get("finding_count") or 0)
            total_resources += int(audit_metrics.get("resource_count") or 0)

        iam_summary = summary.get("iam_graph_summary") or {}
        findings_by_severity = audit_metrics.get("findings_by_severity") or {}

        if scan_status == "assume_role_failed":
            details = html_module.escape(str(account.get("error") or "assume role failed"))
            account_cell = (
                f"<strong>{html_module.escape(account_id)}</strong><br>"
                f'<span class="muted">{html_module.escape(account_name)}</span>'
            )
            link_cell = f'<span class="muted">{details}</span>'
            findings_cell = '<span class="muted">—</span>'
            resources_cell = '<span class="muted">—</span>'
            roles_cell = '<span class="muted">—</span>'
        else:
            account_cell = (
                f"<strong>{html_module.escape(account_id)}</strong><br>"
                f'<span class="muted">{html_module.escape(account_name)}</span>'
            )
            rel_view = _rel(account_view, org_dir)
            if rel_view and account_view is not None:
                link_cell = (
                    f'<a href="{html_module.escape(rel_view)}">Open account view</a>'
                )
            else:
                link_cell = '<span class="muted">account view not generated</span>'
            findings_cell = _severity_badges(findings_by_severity)
            resources_cell = html_module.escape(str(audit_metrics.get("resource_count", "—")))
            roles_cell = html_module.escape(str(iam_summary.get("role_count", "—")))

        account_rows.append(
            "<tr>"
            f"<td>{account_cell}</td>"
            f"<td>{_scan_status_badge(scan_status)}</td>"
            f"<td>{findings_cell}</td>"
            f"<td>{resources_cell}</td>"
            f"<td>{roles_cell}</td>"
            f"<td>{link_cell}</td>"
            "</tr>"
        )

    if not account_rows:
        account_rows.append(
            '<tr><td colspan="6" class="muted">No accounts were scanned.</td></tr>'
        )

    summary_json = _rel(org_dir / "organization-check-summary.json", org_dir) or (
        "organization-check-summary.json"
    )

    stat_pairs = [
        ("Organization", organization_id),
        ("Accounts listed", len(accounts)),
        ("Accounts scanned", scanned_accounts),
        ("Accounts failed", org_summary.get("accounts_failed", "-")),
        ("Total findings", total_findings),
        ("Total resources", total_resources),
        ("Assume role", org_summary.get("role_name", "-")),
    ]
    stats_html = "".join(
        f'<div class="stat"><span class="stat-value">{html_module.escape(str(value))}</span>'
        f'<span class="stat-label">{html_module.escape(str(label))}</span></div>'
        for label, value in stat_pairs
    )

    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    master_account_id = html_module.escape(str(org_summary.get("master_account_id") or "—"))
    organization_arn = html_module.escape(str(org_summary.get("organization_arn") or "—"))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Organization view: {html_module.escape(organization_id)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --accent: #2563eb;
      --ok: #166534;
      --failed: #b45309;
      --blocked: #b91c1c;
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
    .meta {{
      margin: 0.75rem 0 0;
      color: var(--muted);
      font-size: 0.85rem;
    }}
    .stats {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      margin-top: 1rem;
    }}
    .stat {{
      display: flex;
      flex-direction: column;
      padding: 0.5rem 0.85rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 0.6rem;
      min-width: 5rem;
    }}
    .stat-value {{ font-size: 1.2rem; font-weight: 600; }}
    .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; }}
    main {{ padding: 1.25rem; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1rem 1.25rem;
      overflow-x: auto;
    }}
    .card h2 {{ margin: 0 0 0.85rem; font-size: 1.05rem; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }}
    th, td {{
      padding: 0.65rem 0.5rem;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--muted);
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .muted {{ color: var(--muted); font-style: italic; }}
    .scan-status {{
      display: inline-block;
      padding: 0.1rem 0.45rem;
      border-radius: 0.4rem;
      font-size: 0.75rem;
      text-transform: capitalize;
      border: 1px solid var(--border);
      background: var(--bg);
    }}
    .scan-status.ok {{ color: var(--ok); border-color: #bbf7d0; background: #f0fdf4; }}
    .scan-status.failed {{ color: var(--failed); border-color: #fde68a; background: #fffbeb; }}
    .scan-status.blocked {{ color: var(--blocked); border-color: #fecaca; background: #fef2f2; }}
    .severity {{
      display: inline-block;
      margin: 0.1rem 0.25rem 0.1rem 0;
      padding: 0.05rem 0.4rem;
      border-radius: 0.35rem;
      font-size: 0.72rem;
      border: 1px solid var(--border);
      background: var(--bg);
    }}
    .severity.critical {{ color: #991b1b; background: #fef2f2; border-color: #fecaca; }}
    .severity.high {{ color: #9a3412; background: #fff7ed; border-color: #fed7aa; }}
    .severity.medium {{ color: #a16207; background: #fefce8; border-color: #fde68a; }}
    .severity.low {{ color: #1d4ed8; background: #eff6ff; border-color: #bfdbfe; }}
    .footer {{
      margin-top: 1rem;
      color: var(--muted);
      font-size: 0.85rem;
    }}
  </style>
</head>
<body>
  <header>
    <h1>AWS organization view: {html_module.escape(organization_id)}</h1>
    <p class="subtitle">Organization-wide account-check overview &middot; generated {generated_label}</p>
    <p class="meta">Management account: {master_account_id}<br>ARN: {organization_arn}</p>
    <div class="stats">{stats_html}</div>
  </header>
  <main>
    <section class="card">
      <h2>Member accounts</h2>
      <table>
        <thead>
          <tr>
            <th>Account</th>
            <th>Scan</th>
            <th>Findings</th>
            <th>Resources</th>
            <th>IAM roles</th>
            <th>View</th>
          </tr>
        </thead>
        <tbody>
          {''.join(account_rows)}
        </tbody>
      </table>
      <p class="footer">Machine-readable index: <a href="{html_module.escape(summary_json)}">organization-check-summary.json</a></p>
    </section>
  </main>
</body>
</html>
"""


def write_organization_index_html(
    *,
    org_summary: dict,
    org_dir: Path,
    output_dir: Path,
) -> Path:
    """Write the organization index page into ``org_dir`` and return its path."""
    org_dir.mkdir(parents=True, exist_ok=True)
    index_path = org_dir / "organization-view.html"
    index_path.write_text(
        render_organization_index_html(
            org_summary=org_summary,
            org_dir=org_dir,
            output_dir=output_dir,
        ),
        encoding="utf-8",
    )
    return index_path


def write_account_index_html(
    *,
    summary: dict,
    run_dir: Path,
    network_links: Iterable[tuple[str, Path]] | None = None,
) -> Path:
    """Write the account index page into ``run_dir`` and return its path."""
    run_dir.mkdir(parents=True, exist_ok=True)
    index_path = run_dir / "account-view.html"
    index_path.write_text(
        render_account_index_html(
            summary=summary,
            run_dir=run_dir,
            network_links=network_links,
        ),
        encoding="utf-8",
    )
    return index_path
