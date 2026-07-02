from __future__ import annotations

import html as html_module
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from aws_account_audit.snowflake.query import execute_query, execute_with_fallback, normalize_rows

CATEGORIES = (
    "users",
    "roles",
    "warehouses",
    "integrations",
    "network_policies",
    "databases",
)

PRIVILEGED_ROLES = frozenset({"ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN", "USERADMIN", "ORGADMIN"})


@dataclass(frozen=True)
class TableSpec:
    category: str
    title: str
    columns: tuple[str, ...]


_TABLE_SPECS: tuple[TableSpec, ...] = (
    TableSpec(
        "users",
        "Users",
        ("name", "login_name", "default_role", "disabled", "has_mfa", "last_success_login"),
    ),
    TableSpec("roles", "Roles", ("name", "owner", "comment", "is_default")),
    TableSpec(
        "warehouses",
        "Warehouses",
        ("name", "size", "auto_suspend", "auto_resume", "owner", "state"),
    ),
    TableSpec(
        "integrations",
        "Security integrations",
        ("name", "type", "category", "enabled", "comment"),
    ),
    TableSpec(
        "network_policies",
        "Network policies",
        ("name", "allowed_ip_list", "blocked_ip_list", "comment"),
    ),
    TableSpec("databases", "Databases", ("name", "owner", "comment", "retention_time")),
)


def collect_snowflake_inventory(
    connection: Any,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    inventory: dict[str, list[dict[str, Any]]] = {category: [] for category in CATEGORIES}
    errors: list[str] = []

    users, user_errors = _collect_users(connection)
    inventory["users"] = users
    errors.extend(user_errors)

    roles, role_errors = _collect_roles(connection)
    inventory["roles"] = roles
    errors.extend(role_errors)

    warehouses, warehouse_errors = _collect_warehouses(connection)
    inventory["warehouses"] = warehouses
    errors.extend(warehouse_errors)

    integrations, integration_errors = _collect_integrations(connection)
    inventory["integrations"] = integrations
    errors.extend(integration_errors)

    policies, policy_errors = _collect_network_policies(connection)
    inventory["network_policies"] = policies
    errors.extend(policy_errors)

    databases, database_errors = _collect_databases(connection)
    inventory["databases"] = databases
    errors.extend(database_errors)

    return inventory, errors


def _collect_users(connection: Any) -> tuple[list[dict[str, Any]], list[str]]:
    primary_sql = """
        SELECT
            name,
            login_name,
            display_name,
            email,
            disabled,
            default_role,
            default_warehouse,
            has_password,
            has_rsa_public_key,
            has_mfa,
            ext_authn_duo,
            last_success_login,
            created_on
        FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
        WHERE deleted_on IS NULL
        ORDER BY name
    """

    def _show_users(conn: Any) -> tuple[list[dict[str, Any]], str | None]:
        rows, error = execute_query(conn, "SHOW USERS")
        if error:
            return [], error
        normalized = normalize_rows(rows)
        return [_summarize_user_from_show(row) for row in normalized], None

    rows, errors = execute_with_fallback(connection, primary_sql, _show_users)
    if rows and "login_name" not in rows[0]:
        return [_summarize_user_from_show(row) for row in normalize_rows(rows)], errors
    return [_summarize_user_from_account_usage(row) for row in normalize_rows(rows)], errors


def _collect_roles(connection: Any) -> tuple[list[dict[str, Any]], list[str]]:
    primary_sql = """
        SELECT name, comment, owner, created_on, deleted_on
        FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES
        WHERE deleted_on IS NULL
        ORDER BY name
    """

    def _show_roles(conn: Any) -> tuple[list[dict[str, Any]], str | None]:
        rows, error = execute_query(conn, "SHOW ROLES")
        if error:
            return [], error
        return [_summarize_role_from_show(row) for row in normalize_rows(rows)], None

    rows, errors = execute_with_fallback(connection, primary_sql, _show_roles)
    if rows and "owner" not in rows[0]:
        return [_summarize_role_from_show(row) for row in normalize_rows(rows)], errors
    return [_summarize_role_from_account_usage(row) for row in normalize_rows(rows)], errors


def _collect_warehouses(connection: Any) -> tuple[list[dict[str, Any]], list[str]]:
    primary_sql = """
        SELECT
            warehouse_name AS name,
            warehouse_size AS size,
            auto_suspend,
            auto_resume,
            owner,
            state,
            created_on
        FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSES
        WHERE deleted_on IS NULL
        ORDER BY warehouse_name
    """

    def _show_warehouses(conn: Any) -> tuple[list[dict[str, Any]], str | None]:
        rows, error = execute_query(conn, "SHOW WAREHOUSES")
        if error:
            return [], error
        return [_summarize_warehouse_from_show(row) for row in normalize_rows(rows)], None

    rows, errors = execute_with_fallback(connection, primary_sql, _show_warehouses)
    if rows and "size" not in rows[0] and "warehouse_size" not in rows[0]:
        return [_summarize_warehouse_from_show(row) for row in normalize_rows(rows)], errors
    return [_summarize_warehouse_from_account_usage(row) for row in normalize_rows(rows)], errors


def _collect_integrations(connection: Any) -> tuple[list[dict[str, Any]], list[str]]:
    rows, error = execute_query(connection, "SHOW INTEGRATIONS")
    if error:
        return [], [error]
    return [_summarize_integration(row) for row in normalize_rows(rows)], []


def _collect_network_policies(connection: Any) -> tuple[list[dict[str, Any]], list[str]]:
    rows, error = execute_query(connection, "SHOW NETWORK POLICIES")
    if error:
        return [], [error]
    return [_summarize_network_policy(row) for row in normalize_rows(rows)], []


def _collect_databases(connection: Any) -> tuple[list[dict[str, Any]], list[str]]:
    primary_sql = """
        SELECT database_name AS name, owner, comment, retention_time, created_on
        FROM SNOWFLAKE.ACCOUNT_USAGE.DATABASES
        WHERE deleted_on IS NULL
        ORDER BY database_name
    """

    def _show_databases(conn: Any) -> tuple[list[dict[str, Any]], str | None]:
        rows, error = execute_query(conn, "SHOW DATABASES")
        if error:
            return [], error
        return [_summarize_database_from_show(row) for row in normalize_rows(rows)], None

    rows, errors = execute_with_fallback(connection, primary_sql, _show_databases)
    if rows and "retention_time" not in rows[0]:
        return [_summarize_database_from_show(row) for row in normalize_rows(rows)], errors
    return [_summarize_database_from_account_usage(row) for row in normalize_rows(rows)], errors


def _summarize_user_from_account_usage(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name"),
        "login_name": row.get("login_name"),
        "display_name": row.get("display_name"),
        "email": row.get("email"),
        "disabled": row.get("disabled"),
        "default_role": row.get("default_role"),
        "default_warehouse": row.get("default_warehouse"),
        "has_password": row.get("has_password"),
        "has_rsa_public_key": row.get("has_rsa_public_key"),
        "has_mfa": row.get("has_mfa"),
        "ext_authn_duo": row.get("ext_authn_duo"),
        "last_success_login": row.get("last_success_login"),
        "created_on": row.get("created_on"),
    }


def _summarize_user_from_show(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name"),
        "login_name": row.get("login_name"),
        "display_name": row.get("display_name"),
        "email": row.get("email"),
        "disabled": row.get("disabled"),
        "default_role": row.get("default_role"),
        "default_warehouse": row.get("default_warehouse"),
        "has_password": row.get("has_password"),
        "has_rsa_public_key": row.get("has_rsa_public_key"),
        "has_mfa": row.get("has_mfa"),
        "ext_authn_duo": row.get("ext_authn_duo"),
        "last_success_login": row.get("last_success_login"),
        "created_on": row.get("created_on"),
    }


def _summarize_role_from_account_usage(row: dict[str, Any]) -> dict[str, Any]:
    name = row.get("name")
    return {
        "name": name,
        "owner": row.get("owner"),
        "comment": row.get("comment"),
        "is_default": name in PRIVILEGED_ROLES,
        "created_on": row.get("created_on"),
    }


def _summarize_role_from_show(row: dict[str, Any]) -> dict[str, Any]:
    name = row.get("name")
    return {
        "name": name,
        "owner": row.get("owner"),
        "comment": row.get("comment"),
        "is_default": name in PRIVILEGED_ROLES,
        "created_on": row.get("created_on"),
    }


def _summarize_warehouse_from_account_usage(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name") or row.get("warehouse_name"),
        "size": row.get("size") or row.get("warehouse_size"),
        "auto_suspend": row.get("auto_suspend"),
        "auto_resume": row.get("auto_resume"),
        "owner": row.get("owner"),
        "state": row.get("state"),
        "created_on": row.get("created_on"),
    }


def _summarize_warehouse_from_show(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name"),
        "size": row.get("size"),
        "auto_suspend": row.get("auto_suspend"),
        "auto_resume": row.get("auto_resume"),
        "owner": row.get("owner"),
        "state": row.get("state"),
        "created_on": row.get("created_on"),
    }


def _summarize_integration(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name"),
        "type": row.get("type"),
        "category": row.get("category"),
        "enabled": row.get("enabled"),
        "comment": row.get("comment"),
    }


def _summarize_network_policy(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name"),
        "allowed_ip_list": row.get("allowed_ip_list"),
        "blocked_ip_list": row.get("blocked_ip_list"),
        "comment": row.get("comment"),
    }


def _summarize_database_from_account_usage(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name") or row.get("database_name"),
        "owner": row.get("owner"),
        "comment": row.get("comment"),
        "retention_time": row.get("retention_time"),
        "created_on": row.get("created_on"),
    }


def _summarize_database_from_show(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name"),
        "owner": row.get("owner"),
        "comment": row.get("comment"),
        "retention_time": row.get("retention_time"),
        "created_on": row.get("created_on"),
    }


def inventory_to_dict(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    *,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "metadata": metadata,
        "inventory": inventory,
        "errors": errors or [],
        "counts": {category: len(inventory.get(category, [])) for category in CATEGORIES},
    }


def write_inventory_files(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    output_dir: Any,
    base_name: str,
    *,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    from pathlib import Path

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = inventory_to_dict(metadata, inventory, errors=errors)
    json_path = output_dir / f"{base_name}-inventory.json"
    text_path = output_dir / f"{base_name}-inventory.log"
    html_path = output_dir / f"{base_name}-inventory.html"
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    text_path.write_text(
        render_inventory_report(metadata, inventory, errors=errors), encoding="utf-8"
    )
    html_path.write_text(
        render_inventory_html(metadata, inventory, errors=errors), encoding="utf-8"
    )
    return {
        "inventory_json": json_path,
        "inventory_text": text_path,
        "inventory_html": html_path,
    }


def render_inventory_report(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    *,
    errors: list[str] | None = None,
) -> str:
    account = metadata.get("account") or metadata.get("account_id") or "unknown-account"
    lines = [
        "Snowflake resource inventory",
        "=" * 72,
        f"Account: {account}",
        f"User:    {metadata.get('user')}",
        "",
    ]
    for spec in _TABLE_SPECS:
        rows = inventory.get(spec.category, []) or []
        lines.append(f"{spec.title}: {len(rows)}")
        for row in rows:
            values = [
                f"{column}={row.get(column)}"
                for column in spec.columns
                if row.get(column) is not None
            ]
            lines.append(f"  - {row.get('name') or row.get('id')}: {', '.join(values)}")
        lines.append("")
    if errors:
        lines.append("Errors:")
        lines.extend(f"  - {error}" for error in errors)
    return "\n".join(lines) + "\n"


def render_inventory_html(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    *,
    errors: list[str] | None = None,
    generated_at: datetime | None = None,
) -> str:
    account = str(metadata.get("account") or metadata.get("account_id") or "unknown-account")
    generated_at = generated_at or datetime.now(timezone.utc)
    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    user = str(metadata.get("user") or "-")
    role = str(metadata.get("role") or "-")

    cards: list[str] = []
    for spec in _TABLE_SPECS:
        rows = inventory.get(spec.category, []) or []
        if not rows:
            continue
        cards.append(_inventory_table_html(spec, rows))

    if not cards:
        cards.append(
            '<section class="card"><p class="empty">No resources discovered '
            "(check credentials or permissions).</p></section>"
        )

    if errors:
        error_items = "".join(f"<li>{html_module.escape(str(error))}</li>" for error in errors)
        cards.append(
            '<section class="card errors"><h2>Collection errors '
            f'<span class="count">{len(errors)}</span></h2>'
            f"<ul>{error_items}</ul></section>"
        )

    stats = [
        ("Account", account),
        ("User", user),
        ("Role", role),
        ("Total resources", sum(len(inventory.get(category, [])) for category in CATEGORIES)),
    ]
    for spec in _TABLE_SPECS:
        stats.append((spec.title, len(inventory.get(spec.category, []))))

    stats_html = "".join(
        f'<div class="stat"><span class="stat-value">{html_module.escape(str(value))}</span>'
        f'<span class="stat-label">{html_module.escape(str(label))}</span></div>'
        for label, value in stats
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Snowflake inventory: {html_module.escape(account)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --accent: #0d9488;
      --row-alt: #f1f5f9;
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
      position: sticky;
      top: 0;
      z-index: 5;
    }}
    h1 {{ margin: 0 0 0.35rem; font-size: 1.5rem; }}
    .subtitle {{ margin: 0; color: var(--muted); font-size: 0.9rem; }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 0.75rem;
      margin-top: 1rem;
    }}
    .stat {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 0.65rem 0.75rem;
    }}
    .stat-value {{ display: block; font-weight: 700; font-size: 1.1rem; }}
    .stat-label {{ display: block; color: var(--muted); font-size: 0.75rem; }}
    main {{ padding: 1.25rem; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1rem 1.25rem;
      margin-bottom: 1rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }}
    th, td {{
      border-bottom: 1px solid var(--border);
      padding: 0.45rem 0.5rem;
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    tr:nth-child(even) td {{ background: var(--row-alt); }}
    .empty {{ color: var(--muted); font-style: italic; }}
    .count {{
      display: inline-block;
      margin-left: 0.35rem;
      padding: 0.05rem 0.4rem;
      border-radius: 999px;
      background: var(--bg);
      border: 1px solid var(--border);
      font-size: 0.75rem;
      color: var(--muted);
    }}
  </style>
</head>
<body>
  <header>
    <h1>Snowflake inventory: {html_module.escape(account)}</h1>
    <p class="subtitle">Generated {generated_label}</p>
    <div class="stats">{stats_html}</div>
  </header>
  <main>{"".join(cards)}</main>
</body>
</html>
"""


def _inventory_table_html(spec: TableSpec, rows: list[dict[str, Any]]) -> str:
    headers = "".join(f"<th>{html_module.escape(column)}</th>" for column in spec.columns)
    body_rows: list[str] = []
    for row in rows:
        cells = "".join(
            f"<td>{html_module.escape(str(row.get(column) if row.get(column) is not None else '-'))}</td>"
            for column in spec.columns
        )
        body_rows.append(f"<tr>{cells}</tr>")
    return (
        f'<section class="card"><h2>{html_module.escape(spec.title)} '
        f'<span class="count">{len(rows)}</span></h2>'
        f"<table><thead><tr>{headers}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody></table></section>"
    )
