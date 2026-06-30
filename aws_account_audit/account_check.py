from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from aws_account_audit import __version__
from aws_account_audit import inventory as inventory_module
from aws_account_audit.account_index import (
    collect_network_map_links,
    write_account_index_html,
    write_organization_index_html,
)
from aws_account_audit.audit import run_audit, write_report
from aws_account_audit.iam_graph import (
    collect_iam_relationship_data,
    generate_iam_outputs,
    write_iam_data_json,
)
from aws_account_audit.inventory import build_inventory_graph
from aws_account_audit.organizations import (
    DEFAULT_ORG_ROLE_NAME,
    assume_role_credentials,
    describe_organization,
    filter_organization_accounts,
    list_organization_accounts,
)
from aws_account_audit.session import (
    client,
    create_session,
    region_was_explicit,
    resolve_scan_regions,
    temporary_credentials_env,
)
from aws_network_map.account_graph import main as account_graph_main
from aws_network_map.cli import main as network_map_main
from aws_network_map.from_audit import main as from_audit_main


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a full account check with audit, resource maps, and IAM graph outputs.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", default="eu-west-1", help="Home region (default: eu-west-1)")
    parser.add_argument("--regions", nargs="*", help="Explicit regions to scan/map")
    parser.add_argument(
        "--all-regions",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Scan all enabled regions. Default: all regions when --region is omitted; "
            "only the home region when --region is set."
        ),
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
        "--skip-iam-shell-audit",
        action="store_true",
        help="Skip scripts/audit-iam.sh shell audit stage",
    )
    parser.add_argument(
        "--direction",
        choices=["LR", "TB"],
        default="TB",
        help="Mermaid direction for generated network graphs (default: TB)",
    )
    parser.add_argument(
        "--iam-direction",
        choices=["LR", "TB"],
        default="LR",
        help=(
            "Mermaid direction for the IAM relationship graph (default: LR). "
            "LR keeps the PNG readable; TB produces a very wide image when an "
            "account has many policies."
        ),
    )
    parser.add_argument(
        "--iam-png-scale",
        type=float,
        default=None,
        help=(
            "Override the IAM PNG render scale to produce one large, zoomable image "
            "(e.g. 4 or 6). Larger values are sharper but much bigger on disk."
        ),
    )
    parser.add_argument(
        "--iam-sections",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Slice the IAM PNG into overlapping, readable section tiles "
            "(default: enabled). Use --no-iam-sections to skip."
        ),
    )
    parser.add_argument(
        "--inventory",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Collect resource inventory and write separate *-inventory.json / "
            "*-inventory.log files (default: enabled). Use --no-inventory to skip."
        ),
    )
    parser.add_argument(
        "--inventory-graph",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Merge the resource inventory (EC2/EBS/RDS/ELB/Lambda/S3/DynamoDB) into the "
            "account graph PNG/HTML (default: enabled). Use --no-inventory-graph to skip."
        ),
    )
    parser.add_argument(
        "--scan-organization",
        action="store_true",
        help=(
            "Scan every active AWS Organizations member account by assuming a cross-account "
            "role (off by default; scans only the caller account)."
        ),
    )
    parser.add_argument(
        "--org-role-name",
        default=DEFAULT_ORG_ROLE_NAME,
        help=(
            "IAM role name to assume in each member account "
            f"(default: {DEFAULT_ORG_ROLE_NAME})."
        ),
    )
    parser.add_argument(
        "--org-accounts",
        nargs="*",
        metavar="ACCOUNT_ID",
        help="When --scan-organization is set, limit scans to these account IDs.",
    )
    parser.add_argument(
        "--org-exclude-accounts",
        nargs="*",
        metavar="ACCOUNT_ID",
        help="When --scan-organization is set, skip these account IDs.",
    )
    return parser


def _selected_regions(
    profile: str | None,
    region: str,
    regions: list[str] | None,
    all_regions: bool | None,
    region_explicit: bool,
) -> list[str]:
    return resolve_scan_regions(
        profile=profile,
        region=region,
        regions=regions,
        all_regions=all_regions,
        region_explicit=region_explicit,
    )


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


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    aws_path = shutil.which("aws")
    if aws_path:
        aws_bin = str(Path(aws_path).parent)
        env["PATH"] = f"{aws_bin}:{env.get('PATH', '')}"
        env["AWS_CLI"] = aws_path
    return env


def _run_audit_iam_shell(profile: str | None, region: str, output_dir: Path) -> int:
    script = Path(__file__).resolve().parents[1] / "scripts" / "audit-iam.sh"
    if not script.exists():
        print(f"IAM shell audit script not found: {script}", file=sys.stderr)
        return 1

    if shutil.which("aws") is None:
        print(
            "IAM shell audit skipped: aws CLI not found on PATH. "
            "Install AWS CLI v2 or ensure it is available to account_check.",
            file=sys.stderr,
        )
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    command = ["bash", str(script), "--region", region, "--output-dir", str(output_dir)]
    if profile:
        command.extend(["--profile", profile])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
            env=_subprocess_env(),
        )
    except subprocess.TimeoutExpired:
        print("IAM shell audit timed out after 900 seconds.", file=sys.stderr)
        return 1

    if result.returncode != 0:
        details = (result.stderr or result.stdout or "").strip()
        print(f"IAM shell audit failed with exit code {result.returncode}.", file=sys.stderr)
        if details:
            print(details, file=sys.stderr)
    return result.returncode


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


def _run_single_account_check(
    args: argparse.Namespace,
    *,
    profile: str | None,
    selected_regions: list[str],
) -> tuple[int, dict[str, object]]:
    report = run_audit(
        profile=profile,
        region=args.region,
        regions=selected_regions,
        all_regions=False,
        include_inventory=args.inventory,
    )
    account_id = str(report.metadata.get("account_id") or "unknown-account")
    run_dir = args.output_dir / f"account-{account_id}"
    audit_dir = run_dir / "audit-runs"
    iam_dir = run_dir / "iam-runs"
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
        if profile:
            from_audit_argv.extend(["--profile", profile])
        from_audit_rc = from_audit_main(from_audit_argv)

    all_sg_failures = 0
    if not args.skip_all_sg_maps:
        sg_targets = _collect_security_group_targets(profile, selected_regions)
        all_sg_failures = _run_all_sg_maps(
            profile,
            sg_targets,
            all_sg_dir,
            args.direction,
            args.max_security_groups,
        )

    copied_json_files = _copy_map_jsons([from_audit_dir, all_sg_dir], combined_dir)

    inventory_overlay_path: Path | None = None
    resource_inventory = getattr(report, "resource_inventory", None)
    if args.inventory_graph and resource_inventory:
        overlay = build_inventory_graph(resource_inventory, account_id)
        if overlay["nodes"]:
            combined_dir.mkdir(parents=True, exist_ok=True)
            inventory_overlay_path = combined_dir / "resource-inventory-overlay.json"
            inventory_overlay_path.write_text(
                json.dumps(overlay, indent=2, default=str), encoding="utf-8"
            )
            copied_json_files += 1

    if copied_json_files == 0:
        print("No map JSON files were generated; cannot build account graph.", file=sys.stderr)
        return 1, {"account_id": account_id, "error": "no_map_json_files"}

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

    iam_audit_json = iam_dir / f"iam-audit-{account_id}.json"
    iam_data = collect_iam_relationship_data(profile=profile, region=args.region)
    write_iam_data_json(iam_data, iam_audit_json)

    iam_shell_rc = 0
    if not args.skip_iam_shell_audit:
        iam_shell_rc = _run_audit_iam_shell(profile, args.region, iam_dir)

    iam_graph_base = iam_dir / f"iam-graph-{account_id}"
    iam_graph = generate_iam_outputs(
        data=iam_data,
        output_base=iam_graph_base,
        direction=args.iam_direction,
        png_scale=args.iam_png_scale,
        sections=args.iam_sections,
    )
    iam_graph_rc = 0
    iam_sections_dir = Path(f"{iam_graph_base}-sections")
    iam_section_files = (
        sorted(iam_sections_dir.glob("section-*.png")) if iam_sections_dir.exists() else []
    )

    summary: dict[str, object] = {
        "account_id": account_id,
        "audit_json": str(audit_json),
        "audit_text": str(written["text"]),
        "inventory_json": str(written.get("inventory_json", "")),
        "inventory_text": str(written.get("inventory_text", "")),
        "inventory_html": str(written.get("inventory_html", "")),
        "iam_audit_json": str(iam_audit_json),
        "iam_shell_audit_rc": iam_shell_rc,
        "iam_graph_json": str(iam_graph_base.with_suffix(".json")),
        "iam_graph_html": str(iam_graph_base.with_suffix(".html")),
        "iam_graph_png": str(iam_graph_base.with_suffix(".png")),
        "iam_graph_sections": [str(path) for path in iam_section_files],
        "iam_graph_summary": iam_graph.summary(),
        "iam_graph_rc": iam_graph_rc,
        "from_audit_rc": from_audit_rc,
        "all_sg_failures": all_sg_failures,
        "copied_map_json_files": copied_json_files,
        "inventory_overlay_json": str(inventory_overlay_path or ""),
        "account_graph_json": str(account_graph_base.with_suffix(".json")),
        "account_graph_html": str(account_graph_base.with_suffix(".html")),
        "account_graph_png": str(account_graph_base.with_suffix(".png")),
        "account_graph_rc": account_graph_rc,
    }
    network_links = collect_network_map_links(network_dir)
    index_path, findings_path = write_account_index_html(
        summary=summary,
        run_dir=run_dir,
        network_links=network_links,
    )
    summary["account_view_html"] = str(index_path)
    summary["findings_html"] = str(findings_path)

    summary_path = run_dir / "account-check-summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote account check summary: {summary_path}")
    print(f"Wrote full account view: {index_path}")
    print(f"Wrote security findings: {findings_path}")

    exit_code = 0
    if (
        account_graph_rc != 0
        or iam_graph_rc != 0
        or iam_shell_rc != 0
        or from_audit_rc != 0
        or all_sg_failures > 0
    ):
        exit_code = 1
    return exit_code, summary


def _run_organization_scan(
    args: argparse.Namespace,
    *,
    selected_regions_for: Callable[[str | None], list[str]],
) -> int:
    base_session = create_session(args.profile)
    org_info, org_error = describe_organization(base_session, args.region)
    if org_error or org_info is None:
        print(f"Organization scan failed: {org_error or 'unknown error'}", file=sys.stderr)
        return 1

    accounts, accounts_error = list_organization_accounts(base_session, args.region)
    if accounts_error:
        print(f"Organization scan failed: {accounts_error}", file=sys.stderr)
        return 1
    if not accounts:
        print("Organization scan failed: no active accounts returned.", file=sys.stderr)
        return 1

    accounts = filter_organization_accounts(
        accounts,
        include_accounts=args.org_accounts,
        exclude_accounts=args.org_exclude_accounts,
    )
    if not accounts:
        print("Organization scan failed: account filter excluded every account.", file=sys.stderr)
        return 1

    org_dir = args.output_dir / f"organization-{org_info.organization_id}"
    org_dir.mkdir(parents=True, exist_ok=True)
    print(
        f"Organization scan: {len(accounts)} account(s) via role "
        f"{args.org_role_name!r} (management account {org_info.master_account_id} uses "
        "caller credentials).",
        file=sys.stderr,
    )

    account_results: list[dict[str, object]] = []
    failures = 0
    for account in accounts:
        account_result: dict[str, object] = {
            "account_id": account.account_id,
            "account_name": account.name,
            "status": account.status,
        }
        print(
            f"Scanning organization account {account.account_id} ({account.name})...",
            file=sys.stderr,
        )

        if account.account_id == org_info.master_account_id:
            scan_profile = args.profile
            credential_env = None
        else:
            credentials, assume_error = assume_role_credentials(
                base_session,
                account_id=account.account_id,
                role_name=args.org_role_name,
                region=args.region,
            )
            if assume_error or credentials is None:
                account_result["scan_status"] = "assume_role_failed"
                account_result["error"] = assume_error or "missing credentials"
                print(
                    f"Skipping {account.account_id}: {account_result['error']}",
                    file=sys.stderr,
                )
                account_results.append(account_result)
                failures += 1
                continue
            scan_profile = None
            credential_env = credentials

        selected_regions = selected_regions_for(scan_profile)
        print(f"Scanning regions: {', '.join(selected_regions)}", file=sys.stderr)
        with temporary_credentials_env(credential_env):
            exit_code, summary = _run_single_account_check(
                args,
                profile=scan_profile,
                selected_regions=selected_regions,
            )
        account_result["scan_status"] = "ok" if exit_code == 0 else "failed"
        account_result["exit_code"] = exit_code
        account_result["summary"] = summary
        account_results.append(account_result)
        if exit_code != 0:
            failures += 1

    org_summary = {
        "organization_id": org_info.organization_id,
        "organization_arn": org_info.arn,
        "master_account_id": org_info.master_account_id,
        "role_name": args.org_role_name,
        "accounts_requested": len(accounts),
        "accounts_failed": failures,
        "accounts": account_results,
    }
    org_summary_path = org_dir / "organization-check-summary.json"
    org_view_path, org_findings_path = write_organization_index_html(
        org_summary=org_summary,
        org_dir=org_dir,
        output_dir=args.output_dir,
    )
    org_summary["organization_view_html"] = str(org_view_path)
    org_summary["organization_findings_html"] = str(org_findings_path)
    org_summary_path.write_text(json.dumps(org_summary, indent=2), encoding="utf-8")
    print(f"Wrote organization check summary: {org_summary_path}", file=sys.stderr)
    print(f"Wrote organization view: {org_view_path}", file=sys.stderr)
    print(f"Wrote organization findings: {org_findings_path}", file=sys.stderr)
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    cli_argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(cli_argv)

    print(
        f"aws-account-audit {__version__} (inventory: {inventory_module.__file__})",
        file=sys.stderr,
    )

    region_explicit = region_was_explicit(cli_argv)

    def selected_regions_for(profile: str | None) -> list[str]:
        return _selected_regions(
            profile,
            args.region,
            args.regions,
            args.all_regions,
            region_explicit,
        )

    if args.scan_organization:
        return _run_organization_scan(
            args,
            selected_regions_for=selected_regions_for,
        )

    selected_regions = selected_regions_for(args.profile)
    print(f"Scanning regions: {', '.join(selected_regions)}", file=sys.stderr)
    exit_code, _summary = _run_single_account_check(
        args,
        profile=args.profile,
        selected_regions=selected_regions,
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
