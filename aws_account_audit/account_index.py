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
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Artifact rows are (label, path, is_primary). ``is_primary`` marks the
# interactive HTML views that render the full diagram with pan/zoom.
ArtifactRow = tuple[str, "Path | None", bool]

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

_SEVERITY_STYLES = """
    .severity {
      display: inline-block;
      margin: 0.1rem 0.25rem 0.1rem 0;
      padding: 0.05rem 0.4rem;
      border-radius: 0.35rem;
      font-size: 0.72rem;
      border: 1px solid var(--border);
      background: var(--bg);
      color: inherit;
    }
    a.severity-link {
      text-decoration: none;
      color: inherit;
    }
    a.severity-link:hover .severity {
      filter: brightness(0.95);
      box-shadow: 0 0 0 1px var(--accent);
    }
    .severity.critical { color: #991b1b; background: #fef2f2; border-color: #fecaca; }
    .severity.high { color: #9a3412; background: #fff7ed; border-color: #fed7aa; }
    .severity.medium { color: #a16207; background: #fefce8; border-color: #fde68a; }
    .severity.low { color: #1d4ed8; background: #eff6ff; border-color: #bfdbfe; }
    .finding-summary {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.35rem;
      margin-top: 0.85rem;
    }
    .finding-summary-label {
      font-size: 0.75rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.03em;
      margin-right: 0.25rem;
    }
    .findings-card { margin-bottom: 1rem; }
    .finding-group {
      margin-top: 1rem;
      padding-top: 0.5rem;
      scroll-margin-top: 1rem;
    }
    .finding-group:target {
      background: #f8fafc;
      border-radius: 0.5rem;
      padding: 0.75rem;
      margin-left: -0.75rem;
      margin-right: -0.75rem;
      box-shadow: inset 0 0 0 2px #bfdbfe;
    }
    .finding-group h3 {
      margin: 0 0 0.5rem;
      font-size: 0.95rem;
    }
    .finding-list { list-style: none; margin: 0; padding: 0; }
    .finding-item {
      padding: 0.65rem 0;
      border-bottom: 1px solid var(--border);
    }
    .finding-item:last-child { border-bottom: none; }
    .finding-title { font-weight: 600; }
    .finding-detail { color: var(--text); margin-top: 0.15rem; }
    .finding-meta {
      color: var(--muted);
      font-size: 0.82rem;
      margin-top: 0.2rem;
      word-break: break-all;
    }
    .finding-account {
      font-size: 0.82rem;
      color: var(--muted);
      margin-bottom: 0.15rem;
    }
    .back-link {
      display: inline-block;
      margin-top: 0.5rem;
      font-size: 0.9rem;
    }
    .page-main {
      padding: 1.25rem;
    }
    .page-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1rem 1.25rem;
    }
"""

_PAGE_BASE_STYLES = """
    :root {
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --accent: #2563eb;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, "Segoe UI", sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.5;
    }
    header {
      padding: 1.5rem;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
    }
    h1 { margin: 0 0 0.35rem; font-size: 1.5rem; }
    .subtitle { margin: 0; color: var(--muted); font-size: 0.9rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    .muted { color: var(--muted); font-style: italic; }
""" + _SEVERITY_STYLES


def _findings_page_html(
    *,
    title: str,
    subtitle: str,
    body_html: str,
    back_link: str | None = None,
    back_label: str = "Back to account view",
    severity_badges_html: str = "",
) -> str:
    back_html = ""
    if back_link:
        back_html = (
            f'<a class="back-link" href="{html_module.escape(back_link)}">'
            f"{html_module.escape(back_label)}</a>"
        )
    badges_block = ""
    if severity_badges_html:
        badges_block = (
            '<div class="finding-summary">'
            '<span class="finding-summary-label">By severity</span> '
            f"{severity_badges_html}"
            "</div>"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html_module.escape(title)}</title>
  <style>{_PAGE_BASE_STYLES}</style>
</head>
<body>
  <header>
    <h1>{html_module.escape(title)}</h1>
    <p class="subtitle">{subtitle}</p>
    {back_html}
    {badges_block}
  </header>
  <main class="page-main">
    <section class="page-card">
      {body_html}
    </section>
  </main>
</body>
</html>
"""


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


def _section_html(
    title: str,
    rows: Iterable[ArtifactRow],
    base: Path,
    *,
    section_id: str | None = None,
) -> str:
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
    id_attr = ""
    if section_id:
        id_attr = f' id="{html_module.escape(section_id)}"'
    return (
        f'<section class="card"{id_attr}>'
        f"<h2>{html_module.escape(title)}</h2>"
        f"<ul>{''.join(items)}</ul></section>"
    )


def _account_artifact_sections(
    *,
    summary: dict,
    run_dir: Path,
    network_links: Iterable[tuple[str, Path]] | None = None,
) -> list[tuple[str, list[ArtifactRow]]]:
    """Return ``(title, rows)`` for every artifact group on the account view."""

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
    findings_path = run_dir / "findings.html"
    security_rows: list[ArtifactRow] = [
        ("Security findings (interactive)", findings_path, True),
        ("Security findings (JSON source)", _path("audit_json"), False),
    ]

    sections: list[tuple[str, list[ArtifactRow]]] = [
        ("Security findings", security_rows),
        ("Identity & access (IAM)", identity_rows),
    ]
    if section_rows:
        sections.append(("IAM graph sections (zoom-friendly tiles)", section_rows))
    sections.extend(
        [
            ("Account network", account_rows),
            ("Inventory audit", audit_rows),
            ("Per-resource network maps", network_rows),
        ]
    )
    return sections


def _severity_anchor(severity: str) -> str:
    return f"findings-{severity.lower()}"


def _severity_badges(
    findings_by_severity: dict[str, object],
    *,
    link_for_severity: Callable[[str], str | None] | None = None,
) -> str:
    badges: list[str] = []
    for severity in SEVERITY_ORDER:
        count = findings_by_severity.get(severity)
        if not count:
            continue
        css = severity.lower()
        badge = (
            f'<span class="severity {css}">{html_module.escape(severity)}: '
            f"{html_module.escape(str(count))}</span>"
        )
        href = link_for_severity(severity) if link_for_severity else None
        if href:
            badge = (
                f'<a class="severity-link" href="{html_module.escape(href)}">{badge}</a>'
            )
        badges.append(badge)
    return " ".join(badges) if badges else '<span class="muted">none</span>'


def _render_finding_item(
    finding: dict[str, Any],
    *,
    account_id: str | None = None,
    account_name: str | None = None,
    account_href: str | None = None,
) -> str:
    title = html_module.escape(str(finding.get("title") or "Untitled finding"))
    detail = html_module.escape(str(finding.get("detail") or ""))
    category = html_module.escape(str(finding.get("category") or "general"))
    resource_arn = finding.get("resource_arn")
    meta_parts = [f"Category: {category}"]
    if resource_arn:
        meta_parts.append(html_module.escape(str(resource_arn)))
    meta = " · ".join(meta_parts)

    account_html = ""
    if account_id:
        label = html_module.escape(f"{account_id} ({account_name or account_id})")
        if account_href:
            account_html = (
                f'<div class="finding-account"><a href="{html_module.escape(account_href)}">'
                f"{label}</a></div>"
            )
        else:
            account_html = f'<div class="finding-account">{label}</div>'

    return (
        '<li class="finding-item">'
        f"{account_html}"
        f'<div class="finding-title">{title}</div>'
        f'<div class="finding-detail">{detail}</div>'
        f'<div class="finding-meta">{meta}</div>'
        "</li>"
    )


def _render_findings_groups_html(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<p class="muted">No security findings recorded.</p>'

    grouped: dict[str, list[dict[str, Any]]] = {severity: [] for severity in SEVERITY_ORDER}
    other: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        if severity in grouped:
            grouped[severity].append(finding)
        else:
            other.append(finding)

    groups: list[str] = []
    for severity in SEVERITY_ORDER:
        items = grouped[severity]
        if not items:
            continue
        anchor = _severity_anchor(severity)
        items_html = "".join(_render_finding_item(item) for item in items)
        groups.append(
            f'<div class="finding-group" id="{anchor}">'
            f"<h3>{html_module.escape(severity)} ({len(items)})</h3>"
            f'<ul class="finding-list">{items_html}</ul>'
            "</div>"
        )

    if other:
        items_html = "".join(_render_finding_item(item) for item in other)
        groups.append(
            '<div class="finding-group" id="findings-other">'
            f"<h3>OTHER ({len(other)})</h3>"
            f'<ul class="finding-list">{items_html}</ul>'
            "</div>"
        )

    return "".join(groups)


def _findings_href_for_summary(summary: dict, run_dir: Path) -> str:
    findings_html = summary.get("findings_html")
    if findings_html:
        rel = _rel(Path(str(findings_html)), run_dir)
        if rel:
            return rel
    return "findings.html"


def render_account_findings_html(
    *,
    summary: dict,
    run_dir: Path,
    generated_at: datetime | None = None,
) -> str:
    account_id = str(summary.get("account_id") or "unknown-account")
    generated_at = generated_at or datetime.now(timezone.utc)
    audit_json = _resolve_artifact_path(
        str(summary.get("audit_json") or ""),
        output_dir=run_dir.parent,
    )
    audit_data = load_audit_data(audit_json)
    findings = list(audit_data.get("findings") or [])
    findings_by_severity = dict(audit_data.get("findings_by_severity") or {})
    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    back_link = _rel(run_dir / "account-view.html", run_dir) or "account-view.html"

    return _findings_page_html(
        title=f"Security findings: {account_id}",
        subtitle=f"Account audit findings · generated {generated_label}",
        back_link=back_link,
        back_label="Back to account view",
        severity_badges_html=_severity_badges(
            findings_by_severity,
            link_for_severity=lambda severity: f"#{_severity_anchor(severity)}",
        ),
        body_html=_render_findings_groups_html(findings),
    )


def write_account_findings_html(
    *,
    summary: dict,
    run_dir: Path,
) -> Path:
    """Write the account findings page into ``run_dir`` and return its path."""
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = run_dir / "findings.html"
    findings_path.write_text(
        render_account_findings_html(summary=summary, run_dir=run_dir),
        encoding="utf-8",
    )
    return findings_path


def _collect_organization_findings(
    org_summary: dict,
    output_dir: Path,
    org_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Return flattened findings with account metadata and severity counts."""
    flattened: list[dict[str, Any]] = []
    severity_counts: dict[str, int] = {}

    for account in org_summary.get("accounts") or []:
        if account.get("scan_status") == "assume_role_failed":
            continue
        account_id = str(account.get("account_id") or "")
        account_name = str(account.get("account_name") or account_id)
        account_summary = account.get("summary") or {}
        audit_json = _resolve_artifact_path(
            str(account_summary.get("audit_json") or ""),
            output_dir=output_dir,
        )
        audit_data = load_audit_data(audit_json)
        account_findings_path = output_dir / f"account-{account_id}" / "findings.html"
        account_findings_href = _rel(account_findings_path, org_dir)

        for finding in audit_data.get("findings") or []:
            severity = str(finding.get("severity") or "INFO").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            flattened.append(
                {
                    **finding,
                    "_account_id": account_id,
                    "_account_name": account_name,
                    "_account_findings_href": account_findings_href,
                }
            )

    return flattened, severity_counts


def render_organization_findings_html(
    *,
    org_summary: dict,
    org_dir: Path,
    output_dir: Path,
    generated_at: datetime | None = None,
) -> str:
    organization_id = str(org_summary.get("organization_id") or "unknown-organization")
    generated_at = generated_at or datetime.now(timezone.utc)
    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    findings, severity_counts = _collect_organization_findings(org_summary, output_dir, org_dir)
    back_link = _rel(org_dir / "organization-view.html", org_dir) or "organization-view.html"

    grouped: dict[str, list[dict[str, Any]]] = {severity: [] for severity in SEVERITY_ORDER}
    other: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(finding.get("severity") or "INFO").upper()
        if severity in grouped:
            grouped[severity].append(finding)
        else:
            other.append(finding)

    groups: list[str] = []
    for severity in SEVERITY_ORDER:
        items = grouped[severity]
        if not items:
            continue
        anchor = _severity_anchor(severity)
        items_html = "".join(
            _render_finding_item(
                finding,
                account_id=str(finding.get("_account_id") or ""),
                account_name=str(finding.get("_account_name") or ""),
                account_href=str(finding.get("_account_findings_href") or "") or None,
            )
            for finding in items
        )
        groups.append(
            f'<div class="finding-group" id="{anchor}">'
            f"<h3>{html_module.escape(severity)} ({len(items)})</h3>"
            f'<ul class="finding-list">{items_html}</ul>'
            "</div>"
        )

    if other:
        items_html = "".join(
            _render_finding_item(
                finding,
                account_id=str(finding.get("_account_id") or ""),
                account_name=str(finding.get("_account_name") or ""),
                account_href=str(finding.get("_account_findings_href") or "") or None,
            )
            for finding in other
        )
        groups.append(
            '<div class="finding-group" id="findings-other">'
            f"<h3>OTHER ({len(other)})</h3>"
            f'<ul class="finding-list">{items_html}</ul>'
            "</div>"
        )

    body_html = "".join(groups) if groups else '<p class="muted">No security findings recorded.</p>'

    return _findings_page_html(
        title=f"Organization findings: {organization_id}",
        subtitle=f"All member-account audit findings · generated {generated_label}",
        back_link=back_link,
        back_label="Back to organization view",
        severity_badges_html=_severity_badges(
            severity_counts,
            link_for_severity=lambda severity: f"#{_severity_anchor(severity)}",
        ),
        body_html=body_html,
    )


def write_organization_findings_html(
    *,
    org_summary: dict,
    org_dir: Path,
    output_dir: Path,
) -> Path:
    """Write the organization findings page into ``org_dir`` and return its path."""
    org_dir.mkdir(parents=True, exist_ok=True)
    findings_path = org_dir / "organization-findings.html"
    findings_path.write_text(
        render_organization_findings_html(
            org_summary=org_summary,
            org_dir=org_dir,
            output_dir=output_dir,
        ),
        encoding="utf-8",
    )
    return findings_path


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

    audit_json = _resolve_artifact_path(
        str(summary.get("audit_json") or ""),
        output_dir=run_dir.parent,
    )
    audit_data = load_audit_data(audit_json)
    findings_by_severity = dict(audit_data.get("findings_by_severity") or {})
    findings_href = _findings_href_for_summary(summary, run_dir)
    findings_summary_html = _severity_badges(
        findings_by_severity,
        link_for_severity=lambda severity: (
            f"{findings_href}#{_severity_anchor(severity)}"
        ),
    )

    artifact_sections = _account_artifact_sections(
        summary=summary,
        run_dir=run_dir,
        network_links=network_links,
    )
    network_rows = [
        row
        for title, rows in artifact_sections
        if title == "Per-resource network maps"
        for row in rows
    ]

    stat_pairs = [
        ("Account", account_id),
        ("Total findings", audit_data.get("finding_count", "-")),
        ("Resources", audit_data.get("resource_count", "-")),
        ("IAM users", iam_summary.get("user_count", "-")),
        ("IAM groups", iam_summary.get("group_count", "-")),
        ("IAM roles", iam_summary.get("role_count", "-")),
        ("IAM policies", iam_summary.get("policy_count", "-")),
        ("Network maps", len(network_rows)),
    ]
    stats_html = "".join(
        f'<div class="stat"><span class="stat-value">{html_module.escape(str(value))}</span>'
        f'<span class="stat-label">{html_module.escape(str(label))}</span></div>'
        for label, value in stat_pairs
    )

    section_cards = [
        _section_html(title, rows, run_dir) for title, rows in artifact_sections
    ]
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
      padding: 1.25rem;
    }}
    .card-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 1rem;
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
    {_SEVERITY_STYLES}
  </style>
</head>
<body>
  <header>
    <h1>AWS account view: {html_module.escape(account_id)}</h1>
    <p class="subtitle">Full account-check overview &middot; generated {generated_label}</p>
    <div class="stats">{stats_html}</div>
    <div class="finding-summary">
      <span class="finding-summary-label">By severity</span>
      {findings_summary_html}
    </div>
  </header>
  <main>
    <div class="card-grid">
      {sections}
    </div>
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


def load_audit_data(audit_json_path: Path | None) -> dict[str, object]:
    if audit_json_path is None or not audit_json_path.is_file():
        return {
            "finding_count": 0,
            "resource_count": 0,
            "findings_by_severity": {},
            "findings": [],
        }
    try:
        payload = json.loads(audit_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "finding_count": 0,
            "resource_count": 0,
            "findings_by_severity": {},
            "findings": [],
        }
    summary = payload.get("summary") or {}
    findings = list(payload.get("findings") or [])
    return {
        "finding_count": int(summary.get("finding_count") or len(findings)),
        "resource_count": int(summary.get("resource_count") or 0),
        "findings_by_severity": dict(summary.get("findings_by_severity") or {}),
        "findings": findings,
    }


def extract_audit_metrics(audit_json_path: Path | None) -> dict[str, object]:
    data = load_audit_data(audit_json_path)
    return {
        "finding_count": data["finding_count"],
        "resource_count": data["resource_count"],
        "findings_by_severity": data["findings_by_severity"],
    }


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
    org_findings_by_severity: dict[str, int] = {}
    org_findings_rel = "organization-findings.html"

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
        rel_view: str | None = None
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
        for severity, count in findings_by_severity.items():
            org_findings_by_severity[str(severity)] = org_findings_by_severity.get(
                str(severity), 0
            ) + int(count or 0)

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
            account_findings_path = output_dir / f"account-{account_id}" / "findings.html"
            rel_findings = _rel(account_findings_path, org_dir) or (
                f"../account-{account_id}/findings.html"
            )
            if rel_view and account_view is not None:
                link_cell = (
                    f'<a href="{html_module.escape(rel_view)}">Open account view</a>'
                )
            else:
                link_cell = '<span class="muted">account view not generated</span>'

            def _account_severity_link(
                severity: str,
                findings_href: str | None = rel_findings,
            ) -> str | None:
                if not findings_href:
                    return None
                return f"{findings_href}#{_severity_anchor(severity)}"

            findings_cell = _severity_badges(
                findings_by_severity,
                link_for_severity=_account_severity_link,
            )
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
    org_findings_summary_html = _severity_badges(
        org_findings_by_severity,
        link_for_severity=lambda severity: (
            f"{org_findings_rel}#{_severity_anchor(severity)}"
        ),
    )

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
    {_SEVERITY_STYLES}
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
    <div class="finding-summary">
      <span class="finding-summary-label">All findings by severity</span>
      {org_findings_summary_html}
      · <a href="{html_module.escape(org_findings_rel)}">Open organization findings</a>
    </div>
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
      <p class="footer">
        Machine-readable index:
        <a href="{html_module.escape(summary_json)}">organization-check-summary.json</a>
        · Detailed findings:
        <a href="{html_module.escape(org_findings_rel)}">organization-findings.html</a>
      </p>
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
) -> tuple[Path, Path]:
    """Write organization index and findings pages; return both paths."""
    org_dir.mkdir(parents=True, exist_ok=True)
    findings_path = write_organization_findings_html(
        org_summary=org_summary,
        org_dir=org_dir,
        output_dir=output_dir,
    )
    index_path = org_dir / "organization-view.html"
    index_path.write_text(
        render_organization_index_html(
            org_summary=org_summary,
            org_dir=org_dir,
            output_dir=output_dir,
        ),
        encoding="utf-8",
    )
    return index_path, findings_path


def write_account_index_html(
    *,
    summary: dict,
    run_dir: Path,
    network_links: Iterable[tuple[str, Path]] | None = None,
) -> tuple[Path, Path]:
    """Write account index and findings pages into ``run_dir``."""
    run_dir.mkdir(parents=True, exist_ok=True)
    findings_path = write_account_findings_html(summary=summary, run_dir=run_dir)
    enriched_summary = {**summary, "findings_html": str(findings_path)}
    index_path = run_dir / "account-view.html"
    index_path.write_text(
        render_account_index_html(
            summary=enriched_summary,
            run_dir=run_dir,
            network_links=network_links,
        ),
        encoding="utf-8",
    )
    return index_path, findings_path
