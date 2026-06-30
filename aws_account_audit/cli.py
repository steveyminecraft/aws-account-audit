from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aws_account_audit.audit import run_audit, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only AWS account inventory and security audit.",
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--region",
        default="eu-west-1",
        help="Home region for global services (default: eu-west-1)",
    )
    parser.add_argument(
        "--regions",
        nargs="*",
        help="Explicit region list; overrides --all-regions when provided",
    )
    parser.add_argument(
        "--all-regions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Scan all enabled regions (default: true)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("audit-runs"),
        help="Directory for report files (default: ./audit-runs)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--sections",
        nargs="*",
        help=(
            "Limit sections. Examples: identity iam security_services compute network "
            "serverless storage tagging global_storage global_dns global_messaging"
        ),
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=8,
        help="Parallel worker count (default: 8)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the text report to stdout in addition to writing files",
    )
    parser.add_argument(
        "--inventory",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Also write separate resource inventory files (*-inventory.json / "
            "*-inventory.log) in addition to the standard audit outputs (default: true)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    sections = set(args.sections) if args.sections else None
    all_regions = args.all_regions
    region = args.region

    report = run_audit(
        profile=args.profile,
        region=region,
        regions=args.regions,
        all_regions=all_regions,
        max_workers=args.max_workers,
        sections=sections,
        include_inventory=args.inventory,
    )

    formats = {"json", "text"} if args.format == "both" else {args.format}
    written = write_report(report, args.output_dir, formats)

    if args.stdout or args.format == "text":
        from aws_account_audit.audit import render_text_report

        text = render_text_report(report.to_dict())
        print(text, end="")

    for label, path in written.items():
        print(f"Wrote {label} report: {path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
