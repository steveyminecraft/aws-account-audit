from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_account_audit import __version__
from aws_account_audit.models import AuditReport, utc_now_iso
from aws_account_audit.snowflake.collectors import collect_identity, collect_security, collect_user_grants
from aws_account_audit.snowflake.inventory import collect_snowflake_inventory, write_inventory_files
from aws_account_audit.snowflake.session import SnowflakeConfig, connect


def run_snowflake_audit(
    config: SnowflakeConfig,
    *,
    include_inventory: bool = True,
) -> tuple[AuditReport, Any]:
    connection = connect(config)
    try:
        identity_section = collect_identity(connection)
        identity = identity_section.data

        inventory: dict[str, list[dict[str, Any]]] | None = None
        inventory_errors: list[str] = []
        if include_inventory:
            inventory, inventory_errors = collect_snowflake_inventory(connection)

        grants_section = collect_user_grants(connection)
        security_section = collect_security(connection, inventory or {})

        report = AuditReport(
            metadata={
                "generated_at": utc_now_iso(),
                "tool_version": __version__,
                "provider": "snowflake",
                "account": identity.get("account"),
                "account_id": identity.get("account"),
                "region": identity.get("region"),
                "user": identity.get("user"),
                "role": identity.get("role"),
                "warehouse": identity.get("warehouse"),
                "database": identity.get("database"),
                "schema": identity.get("schema"),
            },
            sections=[identity_section, grants_section, security_section],
            resource_inventory=inventory,
            resource_inventory_errors=inventory_errors,
        )
        return report, connection
    except Exception:
        connection.close()
        raise


def write_snowflake_report(
    report: AuditReport,
    output_dir: Path,
    formats: set[str],
) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = report.metadata["generated_at"].replace(":", "").replace("+00:00", "Z")
    account = report.metadata.get("account") or report.metadata.get("account_id") or "unknown-account"
    base_name = f"snowflake-{account}-{timestamp}"

    written: dict[str, Path] = {}
    payload = report.to_dict()

    if "json" in formats:
        json_path = output_dir / f"{base_name}.json"
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        written["json"] = json_path

    if "text" in formats:
        text_path = output_dir / f"{base_name}.log"
        text_path.write_text(render_text_report(payload), encoding="utf-8")
        written["text"] = text_path

    if report.resource_inventory is not None:
        written.update(
            write_inventory_files(
                report.metadata,
                report.resource_inventory,
                output_dir,
                base_name,
                errors=report.resource_inventory_errors,
            )
        )

    return written


def render_text_report(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    metadata = payload["metadata"]
    summary = payload["summary"]

    lines.append("Snowflake Account Audit Report")
    lines.append("=" * 72)
    lines.append(f"Generated: {metadata['generated_at']}")
    lines.append(f"Account:   {metadata.get('account')}")
    lines.append(f"User:      {metadata.get('user')}")
    lines.append(f"Role:      {metadata.get('role')}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 72)
    lines.append(f"Sections:  {summary['section_count']}")
    lines.append(f"Findings:  {summary['finding_count']}")
    for severity, count in sorted(summary["findings_by_severity"].items()):
        lines.append(f"  {severity}: {count}")

    if payload["findings"]:
        lines.append("")
        lines.append("Findings")
        lines.append("-" * 72)
        for finding in payload["findings"]:
            lines.append(f"[{finding['severity']}] {finding['title']}")
            lines.append(f"  {finding['detail']}")

    for section in payload["sections"]:
        lines.append("")
        lines.append(f"===== {section['name']} =====")
        if section["errors"]:
            lines.append("Errors:")
            for error in section["errors"]:
                lines.append(f"  - {error}")
        lines.append(f"Status: {section['status']}")
        if "count" in section["data"]:
            lines.append(f"Count: {section['data']['count']}")

    lines.append("")
    lines.append(f"Audit complete at {utc_now_iso()}")
    return "\n".join(lines) + "\n"
