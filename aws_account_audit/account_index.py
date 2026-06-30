"""Render a single 'full account view' HTML index for an account-check run.

The account check writes many separate artifacts (audit report, IAM relationship
graph, account-wide network graph, and per-resource network maps). Large IAM/account
graphs do not fit well in a static PNG, so this index links the interactive HTML
views as the primary 'full view' and lists every other artifact for quick access.
"""

from __future__ import annotations

import html as html_module
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
