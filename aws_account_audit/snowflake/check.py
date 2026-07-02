from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from aws_account_audit import __version__
from aws_account_audit.snowflake.audit import (
    render_text_report,
    run_snowflake_audit,
    write_snowflake_report,
)
from aws_account_audit.snowflake.index import (
    build_summary,
    write_snowflake_findings_html,
    write_snowflake_index_html,
)
from aws_account_audit.snowflake.session import (
    SnowflakeConfig,
    describe_auth_plan,
    find_connections_toml,
    is_browser_authenticator,
    list_connection_names,
    load_config_from_connection,
    load_config_from_env,
    merge_config,
    normalize_authenticator,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a read-only Snowflake account audit with inventory and security findings.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--account", help="Snowflake account identifier (overrides SNOWFLAKE_ACCOUNT)"
    )
    parser.add_argument("--user", help="Snowflake user (overrides SNOWFLAKE_USER)")
    parser.add_argument("--password", help="Snowflake password (overrides SNOWFLAKE_PASSWORD)")
    parser.add_argument("--role", help="Snowflake role (overrides SNOWFLAKE_ROLE)")
    parser.add_argument("--warehouse", help="Snowflake warehouse (overrides SNOWFLAKE_WAREHOUSE)")
    parser.add_argument("--database", help="Snowflake database (overrides SNOWFLAKE_DATABASE)")
    parser.add_argument("--schema", help="Snowflake schema (overrides SNOWFLAKE_SCHEMA)")
    parser.add_argument(
        "--connection",
        help=(
            "Named Snowflake connection from connections.toml "
            "(overrides SNOWFLAKE_CONNECTION; uses default_connection_name when omitted)"
        ),
    )
    parser.add_argument(
        "--connections-file",
        type=Path,
        help="Path to connections.toml (default: ~/.snowflake/connections.toml)",
    )
    parser.add_argument(
        "--authenticator",
        help="Snowflake authenticator (overrides SNOWFLAKE_AUTHENTICATOR, e.g. externalbrowser)",
    )
    parser.add_argument(
        "--passcode",
        help="MFA passcode for username_password_mfa (overrides SNOWFLAKE_PASSCODE)",
    )
    parser.add_argument(
        "--private-key-path",
        help="Path to PEM private key (overrides SNOWFLAKE_PRIVATE_KEY_PATH)",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Print resolved auth settings and exit without connecting",
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


def _config_from_externalbrowser_env() -> SnowflakeConfig:
    account = os.environ.get("SNOWFLAKE_ACCOUNT", "").strip()
    user = os.environ.get("SNOWFLAKE_USER", "").strip()
    if not account or not user:
        raise ValueError("SNOWFLAKE_ACCOUNT and SNOWFLAKE_USER are required for externalbrowser")
    return SnowflakeConfig(
        account=account,
        user=user,
        role=os.environ.get("SNOWFLAKE_ROLE"),
        warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE"),
        database=os.environ.get("SNOWFLAKE_DATABASE"),
        schema=os.environ.get("SNOWFLAKE_SCHEMA"),
        authenticator="externalbrowser",
        client_store_temporary_credential=True,
    )


def _auth_hint(config: SnowflakeConfig) -> str:
    authenticator = normalize_authenticator(config.authenticator) or "snowflake"
    if is_browser_authenticator(authenticator):
        return (
            "Your Snowflake UI login likely uses browser SSO with MFA. Use externalbrowser "
            "and do not pass a password.\n"
            "Try:\n"
            "  unset SNOWFLAKE_PASSWORD\n"
            "  export SNOWFLAKE_AUTHENTICATOR=externalbrowser\n"
            "  python -m aws_account_audit.snowflake --connection <name>\n"
            "A browser window should open for IdP + MFA."
        )
    if authenticator == "username_password_mfa":
        return (
            "Snowflake native MFA requires username_password_mfa and a one-time passcode.\n"
            "Try:\n"
            "  export SNOWFLAKE_AUTHENTICATOR=username_password_mfa\n"
            "  export SNOWFLAKE_PASSCODE=<6-digit-code>\n"
            "  python -m aws_account_audit.snowflake --account ... --user ..."
        )
    if config.password and not config.authenticator:
        return (
            "Password auth failed. If your account has MFA enabled, UI login may use SSO "
            "instead of a reusable password.\n"
            "Try browser auth:\n"
            "  python -m aws_account_audit.snowflake --authenticator externalbrowser "
            "--account ... --user ...\n"
            "Or native MFA:\n"
            "  python -m aws_account_audit.snowflake --authenticator username_password_mfa "
            "--passcode <code> --account ... --user ... --password ..."
        )
    return "Check account identifier (org-account format), username, and authenticator settings."


def resolve_config(args: argparse.Namespace) -> SnowflakeConfig:
    connection_name = args.connection or os.environ.get("SNOWFLAKE_CONNECTION")
    connections_path = args.connections_file
    env_authenticator = normalize_authenticator(os.environ.get("SNOWFLAKE_AUTHENTICATOR"))

    if connection_name or connections_path:
        base = load_config_from_connection(
            connection_name,
            connections_path=connections_path,
        )
    elif env_authenticator == "externalbrowser":
        try:
            base = load_config_from_connection(connections_path=connections_path)
        except ValueError:
            base = _config_from_externalbrowser_env()
    else:
        try:
            base = load_config_from_env()
        except ValueError:
            try:
                base = load_config_from_connection(connections_path=connections_path)
            except ValueError:
                if not args.account or not args.user:
                    connections_file = find_connections_toml()
                    available = ""
                    if connections_file:
                        available = (
                            f" Available connections in {connections_file}: "
                            f"{', '.join(list_connection_names()) or 'none'}."
                        )
                    raise SystemExit(
                        "Snowflake credentials are required. Set SNOWFLAKE_ACCOUNT and "
                        "SNOWFLAKE_USER, use --connection with connections.toml, or pass "
                        f"--account and --user.{available}"
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
        connection_name=connection_name or base.connection_name,
        passcode=args.passcode,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = resolve_config(args)

    if args.show_config:
        print(describe_auth_plan(config))
        print("")
        print("connect kwargs:", config.connect_kwargs())
        return 0

    auth_mode = normalize_authenticator(config.authenticator) or "snowflake"
    if config.connection_name:
        print(
            f"Connecting with Snowflake connection {config.connection_name!r} "
            f"(authenticator={auth_mode})..."
        )
    elif is_browser_authenticator(auth_mode):
        print("Opening browser for Snowflake SSO/MFA (externalbrowser)...")
    elif auth_mode == "username_password_mfa" and not config.passcode:
        print("Using username_password_mfa; Snowflake may prompt for a passcode in the terminal.")

    if is_browser_authenticator(auth_mode) and config.password:
        print(
            "Note: password is set but will not be sent with externalbrowser. "
            "MFA is completed in the browser.",
        )

    try:
        report, connection = run_snowflake_audit(config, include_inventory=not args.no_inventory)
    except Exception as exc:
        message = str(exc)
        if "250001" in message or "incorrect username or password" in message.lower():
            print(_auth_hint(config), file=sys.stderr)
        elif is_browser_authenticator(auth_mode):
            print(_auth_hint(config), file=sys.stderr)
        raise SystemExit(message) from exc
    connection.close()

    account = str(
        report.metadata.get("account") or report.metadata.get("account_id") or "unknown-account"
    )
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
