from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aws_account_audit import __version__
from aws_account_audit.snowflake.audit import render_text_report, run_snowflake_audit, write_snowflake_report
from aws_account_audit.snowflake.index import (
    build_summary,
    write_snowflake_findings_html,
    write_snowflake_index_html,
)
from aws_account_audit.snowflake.session import SnowflakeConfig, load_config_from_env, merge_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a read-only Snowflake account audit with inventory and security findings.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--account", help="Snowflake account identifier (overrides SNOWFLAKE_ACCOUNT)")
    parser.add_argument("--user", help="Snowflake user (overrides SNOWFLAKE_USER)")
    parser.add_argument("--password", help="Snowflake password (overrides SNOWFLAKE_PASSWORD)")
    parser.add_argument("--role", help="Snowflake role (overrides SNOWFLAKE_ROLE)")
    parser.add_argument("--warehouse", help="Snowflake warehouse (overrides SNOWFLAKE_WAREHOUSE)")
    parser.add_argument("--database", help="Snowflake database (overrides SNOWFLAKE_DATABASE)")
    parser.add_argument("--schema", help="Snowflake schema (overrides SNOWFLAKE_SCHEMA)")
    parser.add_argument(
        "--authenticator",
        help="Snowflake authenticator (overrides SNOWFLAKE_AUTHENTICATOR, e.g. externalbrowser)",
    )
    parser.add_argument(
        "--private-key-path",
        help="Path to PEM private key (overrides SNOWFLAKE_PRIVATE_KEY_PATH)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("snowflake-check-runs"),
        help="Base output directory for generated artifacts",
    )
    parser.add_argument(
        "--no-inventory",
        action="store_true",
        help="Skip separate resource inventory files",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the text audit report to stdout",
    )
    return parser


def resolve_config(args: argparse.Namespace) -> SnowflakeConfig:
    try:
        base = load_config_from_env()
    except ValueError:
        if not args.account or not args.user:
            raise SystemExit(
                "Snowflake credentials are required. Set SNOWFLAKE_ACCOUNT and SNOWFLAKE_USER "
                "or pass --account and --user."
            ) from None
        base = SnowflakeConfig(account=args.account, user=args.user)

    return merge_config(
        base,
        account=args.account,
        user=args.user,
        password=args.password,
        role=args.role,
        warehouse=args.warehouse,
        database=args.database,
        schema=args.schema,
        authenticator=args.authenticator,
        private_key_path=args.private_key_path,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = resolve_config(args)

    report, connection = run_snowflake_audit(config, include_inventory=not args.no_inventory)
    connection.close()

    account = str(report.metadata.get("account") or report.metadata.get("account_id") or "unknown-account")
    run_dir = args.output_dir / f"account-{account}"
    audit_dir = run_dir / "audit-runs"
    formats = {"json", "text"}
    if not args.no_inventory:
        formats.add("inventory")

    written = write_snowflake_report(report, audit_dir, formats)
    preliminary_summary = {
        "account": account,
        "account_id": account,
        "audit_json": str(written["json"]),
    }
    findings_path = write_snowflake_findings_html(summary=preliminary_summary, run_dir=run_dir)
    summary = build_summary(
        report_metadata=report.metadata,
        written=written,
        run_dir=run_dir,
        findings_path=findings_path,
        index_path=run_dir / "snowflake-view.html",
    )
    write_snowflake_index_html(summary=summary, run_dir=run_dir)
    summary["snowflake_view_html"] = "snowflake-view.html"
    summary_path = run_dir / "snowflake-check-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.stdout:
        sys.stdout.write(render_text_report(report.to_dict()))

    finding_count = report.to_dict()["summary"]["finding_count"]
    print(f"Snowflake audit complete for account {account}")
    print(f"  View:      {run_dir / 'snowflake-view.html'}")
    print(f"  Findings:  {run_dir / 'findings.html'} ({finding_count} findings)")
    print(f"  Summary:   {summary_path}")
    return 1 if finding_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
