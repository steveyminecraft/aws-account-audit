from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


SG_ID_PATTERN = re.compile(r"(sg-[0-9a-f]+)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate aws_network_map exports in a loop from an audit JSON report.",
    )
    parser.add_argument(
        "--audit-json",
        type=Path,
        required=True,
        help="Path to an audit-*.json file created by aws_account_audit.",
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("network-maps/from-audit"),
        help="Directory where map bundles are written (default: ./network-maps/from-audit)",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        help="Optional region allow-list for generated maps (example: us-east-1 us-east-2)",
    )
    parser.add_argument(
        "--default-region",
        default="eu-west-1",
        help="Fallback region when one cannot be inferred from the report (default: eu-west-1)",
    )
    parser.add_argument(
        "--format",
        choices=["mermaid", "text", "json", "html", "md", "export"],
        default="export",
        help="Output format for each mapped resource (default: export)",
    )
    parser.add_argument(
        "--direction",
        choices=["LR", "TB"],
        default="LR",
        help="Mermaid direction for generated diagrams (default: LR)",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="Per-map command timeout in seconds (default: 300)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned mapping commands without executing aws_network_map.",
    )
    return parser


def _extract_targets(report: dict, default_region: str) -> dict[str, set[str]]:
    targets: dict[str, set[str]] = {}

    for section in report.get("sections", []):
        section_name = section.get("name", "")
        if not section_name.startswith("resources:compute:"):
            continue
        region = section_name.rsplit(":", 1)[-1]
        if not region:
            continue
        section_data = section.get("data") or {}
        for rule in section_data.get("open_security_group_rules", []) or []:
            group_id = rule.get("group_id")
            if not group_id:
                continue
            targets.setdefault(group_id, set()).add(region)

    # Fallback: pull SG IDs from finding text if no section-derived targets were available.
    if targets:
        return targets

    for finding in report.get("findings", []):
        if finding.get("category") != "compute":
            continue
        detail = finding.get("detail", "")
        for group_id in SG_ID_PATTERN.findall(detail):
            targets.setdefault(group_id, set()).add(default_region)

    return targets


def _run_map_command(
    *,
    group_id: str,
    region: str,
    output_base: Path,
    profile: str | None,
    output_format: str,
    direction: str,
    timeout_seconds: int,
    dry_run: bool,
) -> int:
    command = [
        sys.executable,
        "-m",
        "aws_network_map",
        "--resource",
        group_id,
        "--region",
        region,
        "--output",
        str(output_base),
        "--format",
        output_format,
        "--direction",
        direction,
    ]
    if profile:
        command.extend(["--profile", profile])

    print("RUN", " ".join(command), file=sys.stderr)
    if dry_run:
        return 0

    try:
        completed = subprocess.run(command, check=False, timeout=timeout_seconds)
        return int(completed.returncode)
    except subprocess.TimeoutExpired:
        print(
            f"TIMEOUT: {group_id} in {region} exceeded {timeout_seconds}s",
            file=sys.stderr,
        )
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.audit_json.exists():
        print(f"Audit file not found: {args.audit_json}", file=sys.stderr)
        return 1

    try:
        report = json.loads(args.audit_json.read_text())
    except json.JSONDecodeError as exc:
        print(f"Audit file is not valid JSON ({args.audit_json}): {exc}", file=sys.stderr)
        return 1
    targets = _extract_targets(report, default_region=args.default_region)

    if not targets:
        print("No security group targets found in report.", file=sys.stderr)
        return 1

    regions_filter = set(args.regions or [])
    output_dir = args.output_dir
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    runs = 0
    for group_id in sorted(targets):
        for region in sorted(targets[group_id]):
            if regions_filter and region not in regions_filter:
                continue
            output_base = output_dir / f"{region}-{group_id}"
            runs += 1
            code = _run_map_command(
                group_id=group_id,
                region=region,
                output_base=output_base,
                profile=args.profile,
                output_format=args.format,
                direction=args.direction,
                timeout_seconds=args.timeout_seconds,
                dry_run=args.dry_run,
            )
            if code != 0:
                failures += 1

    if runs == 0:
        print("No targets matched the selected filters.", file=sys.stderr)
        return 1

    print(f"Completed {runs} map runs with {failures} failure(s).", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
