from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from aws_account_audit.audit import run_audit, write_report
from aws_account_audit.iam_graph import main as iam_graph_main
from aws_account_audit.session import client, create_session, enabled_regions
from aws_network_map.account_graph import main as account_graph_main
from aws_network_map.cli import main as network_map_main
from aws_network_map.from_audit import main as from_audit_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a full account check with audit, resource maps, and IAM graph outputs.",
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", default="eu-west-1", help="Home region (default: eu-west-1)")
    parser.add_argument("--regions", nargs="*", help="Explicit regions to scan/map")
    parser.add_argument(
        "--all-regions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Scan all enabled regions when --regions is omitted (default: true)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("account-check-runs"),
        help="Base output directory for all generated artifacts",
    )
    parser.add_argument(
        "--skip-from-audit-maps",
        action="store_true",
        help="Skip `aws_network_map.from_audit` mapping stage",
    )
    parser.add_argument(
        "--skip-all-sg-maps",
        action="store_true",
        help="Skip mapping all security groups in target regions",
    )
    parser.add_argument(
        "--max-security-groups",
        type=int,
        help="Optional max number of security groups to map (after dedupe)",
    )
    parser.add_argument(
        "--direction",
        choices=["LR", "TB"],
        default="LR",
        help="Mermaid direction for generated graphs",
    )
    return parser


def _selected_regions(
    profile: str | None, region: str, regions: list[str] | None, all_regions: bool
) -> list[str]:
    if regions:
        return sorted(set(regions))
    if not all_regions:
        return [region]
    session = create_session(profile)
    return enabled_regions(session, region)


def _collect_security_group_targets(
    profile: str | None, regions: list[str]
) -> list[tuple[str, str]]:
    session = create_session(profile)
    targets: list[tuple[str, str]] = []
    for region in regions:
        ec2 = client(session, "ec2", region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId")
                if sg_id:
                    targets.append((region, sg_id))
    # deterministic and deduped ordering
    return sorted(set(targets))


def _run_all_sg_maps(
    profile: str | None,
    targets: list[tuple[str, str]],
    output_dir: Path,
    direction: str,
    max_security_groups: int | None,
) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    mapped = 0
    failures = 0
    for region, sg_id in targets:
        if max_security_groups is not None and mapped >= max_security_groups:
            break
        output_base = output_dir / f"{region}-{sg_id}"
        argv = [
            "--resource",
            sg_id,
            "--region",
            region,
            "--output",
            str(output_base),
            "--direction",
            direction,
        ]
        if profile:
            argv.extend(["--profile", profile])
        rc = network_map_main(argv)
        mapped += 1
        if rc != 0:
            failures += 1
    return failures


def _copy_map_jsons(source_dirs: list[Path], destination: Path) -> int:
    destination.mkdir(parents=True, exist_ok=True)
    copied = 0
    for source in source_dirs:
        if not source.exists():
            continue
        for path in sorted(source.glob("*.json")):
            target_name = f"{source.name}-{path.name}"
            shutil.copy2(path, destination / target_name)
            copied += 1
    return copied


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    selected_regions = _selected_regions(args.profile, args.region, args.regions, args.all_regions)
    report = run_audit(
        profile=args.profile,
        region=args.region,
        regions=selected_regions,
        all_regions=False,
    )
    account_id = str(report.metadata.get("account_id") or "unknown-account")
    run_dir = args.output_dir / f"account-{account_id}"
    audit_dir = run_dir / "audit-runs"
    network_dir = run_dir / "network-maps"
    from_audit_dir = network_dir / "from-audit"
    all_sg_dir = network_dir / "all-security-groups"
    combined_dir = network_dir / "combined-json"

    written = write_report(report, audit_dir, {"json", "text"})
    audit_json = written["json"]

    from_audit_rc = 0
    if not args.skip_from_audit_maps:
        from_audit_argv = [
            "--audit-json",
            str(audit_json),
            "--output-dir",
            str(from_audit_dir),
            "--direction",
            args.direction,
            "--format",
            "export",
        ]
        if args.profile:
            from_audit_argv.extend(["--profile", args.profile])
        from_audit_rc = from_audit_main(from_audit_argv)

    all_sg_failures = 0
    if not args.skip_all_sg_maps:
        sg_targets = _collect_security_group_targets(args.profile, selected_regions)
        all_sg_failures = _run_all_sg_maps(
            args.profile,
            sg_targets,
            all_sg_dir,
            args.direction,
            args.max_security_groups,
        )

    copied_json_files = _copy_map_jsons([from_audit_dir, all_sg_dir], combined_dir)
    if copied_json_files == 0:
        print("No map JSON files were generated; cannot build account graph.", file=sys.stderr)
        return 1

    account_graph_base = network_dir / f"account-graph-{account_id}"
    account_graph_rc = account_graph_main(
        [
            "--audit-json",
            str(audit_json),
            "--map-dir",
            str(combined_dir),
            "--output-base",
            str(account_graph_base),
            "--skip-mapping",
            "--direction",
            args.direction,
        ]
    )

    iam_graph_base = network_dir / f"iam-graph-{account_id}"
    iam_argv = [
        "--region",
        args.region,
        "--output-base",
        str(iam_graph_base),
        "--direction",
        args.direction,
    ]
    if args.profile:
        iam_argv.extend(["--profile", args.profile])
    iam_graph_rc = iam_graph_main(iam_argv)

    summary = {
        "account_id": account_id,
        "audit_json": str(audit_json),
        "audit_text": str(written["text"]),
        "from_audit_rc": from_audit_rc,
        "all_sg_failures": all_sg_failures,
        "copied_map_json_files": copied_json_files,
        "account_graph_json": str(account_graph_base.with_suffix(".json")),
        "account_graph_html": str(account_graph_base.with_suffix(".html")),
        "account_graph_png": str(account_graph_base.with_suffix(".png")),
        "account_graph_rc": account_graph_rc,
        "iam_graph_json": str(iam_graph_base.with_suffix(".json")),
        "iam_graph_html": str(iam_graph_base.with_suffix(".html")),
        "iam_graph_png": str(iam_graph_base.with_suffix(".png")),
        "iam_graph_rc": iam_graph_rc,
    }
    summary_path = run_dir / "account-check-summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote account check summary: {summary_path}")

    if account_graph_rc != 0 or iam_graph_rc != 0 or from_audit_rc != 0 or all_sg_failures > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
