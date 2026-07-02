from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from aws_account_audit import __version__
from aws_account_audit.collectors import (
    collect_global_dns,
    collect_global_messaging,
    collect_global_storage,
    collect_iam,
    collect_identity,
    collect_regional_compute,
    collect_regional_network,
    collect_regional_serverless,
    collect_regional_storage,
    collect_regional_kms,
    collect_security_services,
    collect_tagged_resources,
)
from aws_account_audit.inventory import collect_account_inventory, write_inventory_files
from aws_account_audit.models import AuditReport, SectionResult, utc_now_iso
from aws_account_audit.session import caller_identity, create_session, enabled_regions


GLOBAL_COLLECTORS: list[tuple[str, Callable[..., SectionResult]]] = [
    ("identity", collect_identity),
    ("iam", collect_iam),
    ("security_services", collect_security_services),
    ("global_storage", collect_global_storage),
    ("global_dns", collect_global_dns),
    ("global_messaging", collect_global_messaging),
]

REGIONAL_COLLECTORS: list[tuple[str, Callable[..., SectionResult]]] = [
    ("tagging", collect_tagged_resources),
    ("compute", collect_regional_compute),
    ("network", collect_regional_network),
    ("serverless", collect_regional_serverless),
    ("storage", collect_regional_storage),
    ("kms", collect_regional_kms),
]


def run_audit(
    *,
    profile: str | None = None,
    region: str = "eu-west-1",
    regions: list[str] | None = None,
    all_regions: bool = True,
    max_workers: int = 8,
    sections: set[str] | None = None,
    include_inventory: bool = True,
) -> AuditReport:
    session = create_session(profile)
    identity = caller_identity(session, region)
    if regions:
        scan_regions = sorted(set(regions))
    elif all_regions:
        scan_regions = enabled_regions(session, region)
    else:
        scan_regions = [region]

    selected = sections or {"all"}
    include_all = "all" in selected

    report = AuditReport(
        metadata={
            "generated_at": utc_now_iso(),
            "tool_version": __version__,
            "profile": profile,
            "home_region": region,
            "regions_scanned": scan_regions,
            "account_id": identity.get("Account"),
            "caller_arn": identity.get("Arn"),
        }
    )

    jobs: list[tuple[str, Callable[..., SectionResult], tuple[Any, ...]]] = []

    for name, collector in GLOBAL_COLLECTORS:
        if include_all or name in selected:
            jobs.append((name, collector, (session, region)))

    for scan_region in scan_regions:
        for name, collector in REGIONAL_COLLECTORS:
            key = f"{name}:{scan_region}"
            if include_all or name in selected or key in selected:
                jobs.append((key, collector, (session, scan_region)))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(collector, *args): label for label, collector, args in jobs}
        for future in as_completed(futures):
            report.sections.append(future.result())

    report.sections.sort(key=lambda section: section.name)

    if include_inventory:
        inventory, inventory_errors = collect_account_inventory(
            session, scan_regions, home_region=region
        )
        report.resource_inventory = inventory
        report.resource_inventory_errors = inventory_errors

    return report


def write_report(report: AuditReport, output_dir: Path, formats: set[str]) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = report.metadata["generated_at"].replace(":", "").replace("+00:00", "Z")
    account_id = report.metadata.get("account_id") or "unknown-account"
    base_name = f"audit-{account_id}-{timestamp}"

    written: dict[str, Path] = {}
    payload = report.to_dict()

    if "json" in formats:
        json_path = output_dir / f"{base_name}.json"
        json_path.write_text(json.dumps(payload, indent=2, default=str))
        written["json"] = json_path

    if "text" in formats:
        text_path = output_dir / f"{base_name}.log"
        text_path.write_text(render_text_report(payload))
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

    lines.append("AWS Account Audit Report")
    lines.append("=" * 72)
    lines.append(f"Generated: {metadata['generated_at']}")
    lines.append(f"Account:   {metadata.get('account_id')}")
    lines.append(f"Caller:    {metadata.get('caller_arn')}")
    lines.append(f"Regions:   {', '.join(metadata.get('regions_scanned', []))}")
    lines.append("")
    lines.append("Summary")
    lines.append("-" * 72)
    lines.append(f"Sections:  {summary['section_count']}")
    lines.append(f"Resources: {summary['resource_count']}")
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
        if "by_type" in section["data"]:
            lines.append("By type:")
            for resource_type, count in section["data"]["by_type"].items():
                lines.append(f"  {resource_type}: {count}")

    lines.append("")
    lines.append(f"Audit complete at {utc_now_iso()}")
    return "\n".join(lines) + "\n"
