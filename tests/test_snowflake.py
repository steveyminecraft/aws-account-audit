from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aws_account_audit.models import AuditReport, Finding, SectionResult
from aws_account_audit.snowflake import audit as snowflake_audit
from aws_account_audit.snowflake import collectors, inventory, query
from aws_account_audit.snowflake.check import main as snowflake_main, resolve_config
from aws_account_audit.snowflake.index import (
    build_summary,
    load_audit_data,
    render_snowflake_index_html,
    write_snowflake_findings_html,
    write_snowflake_index_html,
)
from aws_account_audit.snowflake.session import (
    SnowflakeConfig,
    load_config_from_env,
    merge_config,
)


class TestSnowflakeSession(unittest.TestCase):
    def test_connect_kwargs_includes_optional_fields(self) -> None:
        config = SnowflakeConfig(
            account="xy12345",
            user="AUDITOR",
            password="secret",
            role="SECURITYADMIN",
            warehouse="AUDIT_WH",
            database="SNOWFLAKE",
            schema="ACCOUNT_USAGE",
            authenticator="externalbrowser",
        )
        kwargs = config.connect_kwargs()
        self.assertEqual(kwargs["account"], "xy12345")
        self.assertEqual(kwargs["user"], "AUDITOR")
        self.assertEqual(kwargs["password"], "secret")
        self.assertEqual(kwargs["role"], "SECURITYADMIN")
        self.assertEqual(kwargs["warehouse"], "AUDIT_WH")
        self.assertEqual(kwargs["database"], "SNOWFLAKE")
        self.assertEqual(kwargs["schema"], "ACCOUNT_USAGE")
        self.assertEqual(kwargs["authenticator"], "externalbrowser")

    def test_load_config_from_env(self) -> None:
        env = {
            "SNOWFLAKE_ACCOUNT": "xy12345",
            "SNOWFLAKE_USER": "AUDITOR",
            "SNOWFLAKE_PASSWORD": "secret",
            "SNOWFLAKE_ROLE": "SECURITYADMIN",
            "SNOWFLAKE_WAREHOUSE": "AUDIT_WH",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            config = load_config_from_env()
        self.assertEqual(config.account, "xy12345")
        self.assertEqual(config.user, "AUDITOR")
        self.assertEqual(config.role, "SECURITYADMIN")

    def test_load_config_from_env_requires_account_and_user(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                load_config_from_env()

    def test_merge_config_cli_overrides_env(self) -> None:
        base = SnowflakeConfig(account="old", user="old", password="old", role="OLD")
        merged = merge_config(base, account="new", role="SECURITYADMIN")
        self.assertEqual(merged.account, "new")
        self.assertEqual(merged.user, "old")
        self.assertEqual(merged.password, "old")
        self.assertEqual(merged.role, "SECURITYADMIN")

    def test_connect_requires_optional_dependency(self) -> None:
        config = SnowflakeConfig(account="xy12345", user="AUDITOR", password="secret")
        with mock.patch(
            "aws_account_audit.snowflake.session._require_connector",
            side_effect=RuntimeError("missing snowflake-connector-python"),
        ):
            with self.assertRaises(RuntimeError):
                from aws_account_audit.snowflake.session import connect

                connect(config)


class TestSnowflakeQuery(unittest.TestCase):
    def test_execute_query_returns_rows(self) -> None:
        connection = mock.Mock()
        cursor = mock.Mock()
        connection.cursor.return_value = cursor
        cursor.fetchall.return_value = [{"NAME": "ALICE"}]

        rows, error = query.execute_query(connection, "SELECT 1")
        self.assertIsNone(error)
        self.assertEqual(rows, [{"NAME": "ALICE"}])
        cursor.close.assert_called_once()

    def test_execute_query_surfaces_errors(self) -> None:
        connection = mock.Mock()
        connection.cursor.side_effect = RuntimeError("permission denied")

        rows, error = query.execute_query(connection, "SELECT 1")
        self.assertEqual(rows, [])
        self.assertIn("permission denied", error or "")

    def test_execute_with_fallback_uses_primary_when_available(self) -> None:
        connection = mock.Mock()
        with mock.patch(
            "aws_account_audit.snowflake.query.execute_query",
            return_value=([{"name": "ALICE"}], None),
        ):
            rows, errors = query.execute_with_fallback(
                connection,
                "PRIMARY",
                lambda _conn: ([{"name": "BOB"}], None),
            )
        self.assertEqual(rows, [{"name": "ALICE"}])
        self.assertEqual(errors, [])

    def test_execute_with_fallback_uses_show_path_and_records_primary_error(self) -> None:
        connection = mock.Mock()
        with mock.patch(
            "aws_account_audit.snowflake.query.execute_query",
            return_value=([], "ACCOUNT_USAGE denied"),
        ):
            rows, errors = query.execute_with_fallback(
                connection,
                "PRIMARY",
                lambda _conn: ([{"name": "ALICE"}], None),
            )
        self.assertEqual(rows, [{"name": "ALICE"}])
        self.assertEqual(errors, ["ACCOUNT_USAGE denied"])

    def test_execute_with_fallback_returns_both_errors_when_fallback_fails(self) -> None:
        connection = mock.Mock()
        with mock.patch(
            "aws_account_audit.snowflake.query.execute_query",
            return_value=([], "primary failed"),
        ):
            rows, errors = query.execute_with_fallback(
                connection,
                "PRIMARY",
                lambda _conn: ([], "fallback failed"),
            )
        self.assertEqual(rows, [])
        self.assertEqual(errors, ["primary failed", "fallback failed"])

    def test_normalize_rows_lowercases_keys(self) -> None:
        normalized = query.normalize_rows([{"NAME": "ALICE", "Login_Name": "alice"}])
        self.assertEqual(normalized[0]["name"], "ALICE")
        self.assertEqual(normalized[0]["login_name"], "alice")


class TestSnowflakeFindings(unittest.TestCase):
    def test_flags_accountadmin_grant(self) -> None:
        findings = collectors.findings_for_user_grants(
            [{"grantee_name": "ALICE", "role": "ACCOUNTADMIN"}]
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_flags_securityadmin_grant_as_medium(self) -> None:
        findings = collectors.findings_for_user_grants(
            [{"grantee_name": "BOB", "role": "SECURITYADMIN"}]
        )
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_ignores_non_privileged_role_grants(self) -> None:
        findings = collectors.findings_for_user_grants(
            [{"grantee_name": "CAROL", "role": "ANALYST"}]
        )
        self.assertEqual(findings, [])

    def test_flags_password_user_without_mfa(self) -> None:
        findings = collectors.findings_for_users(
            [{"name": "BOB", "has_password": True, "has_mfa": False, "disabled": False}]
        )
        severities = {finding.severity for finding in findings}
        self.assertIn("MEDIUM", severities)

    def test_ext_authn_duo_counts_as_mfa(self) -> None:
        findings = collectors.findings_for_users(
            [
                {
                    "name": "BOB",
                    "has_password": True,
                    "has_mfa": False,
                    "ext_authn_duo": True,
                    "disabled": False,
                }
            ]
        )
        self.assertFalse(any(finding.title == "Password user without MFA" for finding in findings))

    def test_skips_disabled_users(self) -> None:
        findings = collectors.findings_for_users(
            [
                {
                    "name": "DISABLED",
                    "has_password": True,
                    "has_mfa": False,
                    "disabled": True,
                }
            ]
        )
        self.assertEqual(findings, [])

    def test_flags_privileged_default_role(self) -> None:
        findings = collectors.findings_for_users(
            [{"name": "ALICE", "default_role": "SYSADMIN", "disabled": False}]
        )
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("default role", findings[0].title.lower())

    def test_flags_password_only_authentication(self) -> None:
        findings = collectors.findings_for_users(
            [
                {
                    "name": "BOB",
                    "has_password": True,
                    "has_rsa_public_key": False,
                    "has_mfa": True,
                    "disabled": False,
                }
            ]
        )
        self.assertTrue(any(finding.severity == "LOW" for finding in findings))

    def test_flags_missing_network_policies(self) -> None:
        findings = collectors.findings_for_network_policies([])
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_no_finding_when_network_policies_exist(self) -> None:
        findings = collectors.findings_for_network_policies([{"name": "OFFICE_ONLY"}])
        self.assertEqual(findings, [])

    def test_flags_warehouse_without_auto_suspend(self) -> None:
        findings = collectors.findings_for_warehouses([{"name": "WH1", "auto_suspend": 0}])
        self.assertEqual(findings[0].severity, "LOW")

    def test_flags_null_auto_suspend(self) -> None:
        findings = collectors.findings_for_warehouses([{"name": "WH2", "auto_suspend": None}])
        self.assertEqual(len(findings), 1)

    def test_info_when_no_security_integrations(self) -> None:
        findings = collectors.findings_for_integrations(
            [{"name": "API", "category": "API", "enabled": True}]
        )
        self.assertEqual(findings[0].severity, "INFO")

    def test_no_integration_finding_when_security_integration_enabled(self) -> None:
        findings = collectors.findings_for_integrations(
            [{"name": "SSO", "category": "SECURITY", "enabled": True}]
        )
        self.assertEqual(findings, [])


class TestSnowflakeCollectors(unittest.TestCase):
    def test_collect_identity_populates_section(self) -> None:
        connection = mock.Mock()
        with mock.patch(
            "aws_account_audit.snowflake.collectors.execute_query",
            return_value=(
                [
                    {
                        "ACCOUNT": "xy12345",
                        "REGION": "AWS_EU_WEST_1",
                        "USER": "AUDITOR",
                        "ROLE": "SECURITYADMIN",
                    }
                ],
                None,
            ),
        ):
            section = collectors.collect_identity(connection)
        self.assertEqual(section.status, "ok")
        self.assertEqual(section.data["account"], "xy12345")
        self.assertEqual(section.data["user"], "AUDITOR")

    def test_collect_identity_records_errors(self) -> None:
        connection = mock.Mock()
        with mock.patch(
            "aws_account_audit.snowflake.collectors.execute_query",
            return_value=([], "identity query failed"),
        ):
            section = collectors.collect_identity(connection)
        self.assertEqual(section.status, "error")
        self.assertEqual(section.errors, ["identity query failed"])

    def test_collect_user_grants_adds_findings(self) -> None:
        connection = mock.Mock()
        with mock.patch(
            "aws_account_audit.snowflake.collectors.execute_with_fallback",
            return_value=(
                [{"grantee_name": "ALICE", "role": "ACCOUNTADMIN"}],
                [],
            ),
        ):
            section = collectors.collect_user_grants(connection)
        self.assertEqual(section.data["count"], 1)
        self.assertEqual(section.findings[0].severity, "HIGH")

    def test_collect_user_grants_show_fallback_loops_users(self) -> None:
        connection = mock.Mock()

        def _execute_query(
            _conn: mock.Mock, sql: str, **_kwargs: object
        ) -> tuple[list[dict], str | None]:
            if sql == "SHOW USERS":
                return ([{"name": "ALICE"}], None)
            if sql == "SHOW GRANTS TO USER ALICE":
                return ([{"grantee_name": "ALICE", "role": "SYSADMIN"}], None)
            return [], "unexpected"

        with mock.patch(
            "aws_account_audit.snowflake.collectors.execute_query",
            side_effect=_execute_query,
        ):

            def _fake_fallback(
                conn: mock.Mock,
                _primary: str,
                fallback: object,
            ) -> tuple[list[dict], list[str]]:
                rows, err = fallback(conn)  # type: ignore[operator]
                if err:
                    return [], [err]
                return rows, []

            with mock.patch(
                "aws_account_audit.snowflake.collectors.execute_with_fallback",
                side_effect=_fake_fallback,
            ):
                section = collectors.collect_user_grants(connection)
        self.assertEqual(section.data["count"], 1)
        self.assertEqual(section.findings[0].severity, "MEDIUM")

    def test_collect_security_aggregates_inventory_findings(self) -> None:
        connection = mock.Mock()
        inventory = {
            "users": [{"name": "BOB", "has_password": True, "has_mfa": False, "disabled": False}],
            "warehouses": [{"name": "WH1", "auto_suspend": 0}],
            "network_policies": [],
            "integrations": [],
        }
        section = collectors.collect_security(connection, inventory)
        self.assertGreaterEqual(len(section.findings), 3)
        self.assertEqual(section.data["user_count"], 1)


class TestSnowflakeInventory(unittest.TestCase):
    def test_render_inventory_html_includes_users(self) -> None:
        html = inventory.render_inventory_html(
            {"account": "xy12345", "user": "AUDITOR"},
            {"users": [{"name": "ALICE", "login_name": "alice", "disabled": False}]},
        )
        self.assertIn("ALICE", html)
        self.assertIn("Users", html)

    def test_render_inventory_report_lists_counts(self) -> None:
        text = inventory.render_inventory_report(
            {"account": "xy12345", "user": "AUDITOR"},
            {"users": [{"name": "ALICE", "login_name": "alice"}], "roles": []},
        )
        self.assertIn("Users: 1", text)
        self.assertIn("ALICE", text)

    def test_inventory_to_dict_includes_counts(self) -> None:
        payload = inventory.inventory_to_dict(
            {"account": "xy12345"},
            {"users": [{"name": "ALICE"}], "roles": []},
        )
        self.assertEqual(payload["counts"]["users"], 1)
        self.assertEqual(payload["counts"]["roles"], 0)

    def test_write_inventory_files_creates_json_html_and_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            written = inventory.write_inventory_files(
                {"account": "xy12345", "user": "AUDITOR"},
                {"users": [{"name": "ALICE", "login_name": "alice", "disabled": False}]},
                output_dir,
                "snowflake-xy12345-test",
            )
            self.assertTrue(written["inventory_json"].exists())
            self.assertTrue(written["inventory_html"].exists())
            self.assertTrue(written["inventory_text"].exists())
            payload = json.loads(written["inventory_json"].read_text(encoding="utf-8"))
            self.assertEqual(payload["counts"]["users"], 1)

    @mock.patch("aws_account_audit.snowflake.inventory._collect_databases")
    @mock.patch("aws_account_audit.snowflake.inventory._collect_network_policies")
    @mock.patch("aws_account_audit.snowflake.inventory._collect_integrations")
    @mock.patch("aws_account_audit.snowflake.inventory._collect_warehouses")
    @mock.patch("aws_account_audit.snowflake.inventory._collect_roles")
    @mock.patch("aws_account_audit.snowflake.inventory._collect_users")
    def test_collect_snowflake_inventory_merges_categories(
        self,
        users_mock: mock.Mock,
        roles_mock: mock.Mock,
        warehouses_mock: mock.Mock,
        integrations_mock: mock.Mock,
        policies_mock: mock.Mock,
        databases_mock: mock.Mock,
    ) -> None:
        users_mock.return_value = ([{"name": "ALICE"}], [])
        roles_mock.return_value = ([{"name": "ANALYST"}], [])
        warehouses_mock.return_value = ([{"name": "WH1"}], [])
        integrations_mock.return_value = ([{"name": "SSO"}], [])
        policies_mock.return_value = ([{"name": "OFFICE"}], [])
        databases_mock.return_value = ([{"name": "RAW"}], ["db warning"])

        inventory_data, errors = inventory.collect_snowflake_inventory(mock.Mock())
        self.assertEqual(inventory_data["users"][0]["name"], "ALICE")
        self.assertEqual(inventory_data["network_policies"][0]["name"], "OFFICE")
        self.assertEqual(errors, ["db warning"])


class TestSnowflakeAudit(unittest.TestCase):
    def test_render_text_report_lists_findings(self) -> None:
        payload = {
            "metadata": {
                "generated_at": "2025-06-30T00:00:00+00:00",
                "account": "xy12345",
                "user": "AUDITOR",
                "role": "SECURITYADMIN",
            },
            "summary": {
                "section_count": 1,
                "finding_count": 1,
                "findings_by_severity": {"HIGH": 1},
            },
            "findings": [
                Finding(
                    severity="HIGH",
                    category="access_control",
                    title="Privileged role granted to user: ACCOUNTADMIN",
                    detail="User ALICE has been granted the ACCOUNTADMIN role.",
                ).to_dict()
            ],
            "sections": [],
        }
        text = snowflake_audit.render_text_report(payload)
        self.assertIn("Snowflake Account Audit Report", text)
        self.assertIn("ACCOUNTADMIN", text)

    def test_write_snowflake_report_writes_json_text_and_inventory(self) -> None:
        report = AuditReport(
            metadata={
                "generated_at": "2025-06-30T00:00:00+00:00",
                "account": "xy12345",
                "user": "AUDITOR",
            },
            sections=[],
            resource_inventory={"users": [{"name": "ALICE", "login_name": "alice"}]},
        )
        with tempfile.TemporaryDirectory() as tmp:
            written = snowflake_audit.write_snowflake_report(
                report,
                Path(tmp),
                {"json", "text"},
            )
            self.assertTrue(written["json"].exists())
            self.assertTrue(written["text"].exists())
            payload = json.loads(written["json"].read_text(encoding="utf-8"))
            self.assertEqual(payload["metadata"]["account"], "xy12345")


class TestSnowflakeIndex(unittest.TestCase):
    def test_load_audit_data_returns_empty_when_missing(self) -> None:
        data = load_audit_data(None)
        self.assertEqual(data["findings"], [])

    def test_findings_and_index_pages_link_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            summary = {
                "account": "xy12345",
                "account_id": "xy12345",
                "audit_json": "audit-runs/snowflake-xy12345.json",
            }
            audit_path = run_dir / "audit-runs"
            audit_path.mkdir(parents=True)
            audit_file = audit_path / "snowflake-xy12345.json"
            audit_file.write_text(
                '{"findings":[{"severity":"HIGH","category":"access_control","title":"Test","detail":"detail"}],'
                '"summary":{"findings_by_severity":{"HIGH":1}}}',
                encoding="utf-8",
            )
            summary["audit_json"] = str(audit_file)
            findings_path = write_snowflake_findings_html(summary=summary, run_dir=run_dir)
            index_html = render_snowflake_index_html(summary=summary, run_dir=run_dir)
            findings_html = findings_path.read_text(encoding="utf-8")
            self.assertIn("findings.html", index_html)
            self.assertIn('href="snowflake-view.html"', findings_html)

    def test_build_summary_maps_relative_artifact_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            audit_dir = run_dir / "audit-runs"
            audit_dir.mkdir(parents=True)
            audit_json = audit_dir / "snowflake-xy12345.json"
            audit_json.write_text("{}", encoding="utf-8")
            findings_path = run_dir / "findings.html"
            findings_path.write_text("<html></html>", encoding="utf-8")
            summary = build_summary(
                report_metadata={"account": "xy12345", "generated_at": "2025-06-30T00:00:00+00:00"},
                written={"json": audit_json},
                run_dir=run_dir,
                findings_path=findings_path,
                index_path=run_dir / "snowflake-view.html",
            )
            self.assertEqual(summary["provider"], "snowflake")
            self.assertEqual(summary["audit_json"], "audit-runs/snowflake-xy12345.json")
            self.assertEqual(summary["findings_html"], "findings.html")

    def test_write_snowflake_index_html_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            path = write_snowflake_index_html(
                summary={"account": "xy12345", "findings_html": "findings.html"},
                run_dir=run_dir,
            )
            self.assertTrue(path.exists())
            self.assertIn("Snowflake account view", path.read_text(encoding="utf-8"))


class TestRunSnowflakeAudit(unittest.TestCase):
    @mock.patch("aws_account_audit.snowflake.audit.connect")
    @mock.patch("aws_account_audit.snowflake.audit.collect_snowflake_inventory")
    @mock.patch("aws_account_audit.snowflake.audit.collect_identity")
    @mock.patch("aws_account_audit.snowflake.audit.collect_user_grants")
    @mock.patch("aws_account_audit.snowflake.audit.collect_security")
    def test_run_audit_builds_report(
        self,
        security_mock: mock.Mock,
        grants_mock: mock.Mock,
        identity_mock: mock.Mock,
        inventory_mock: mock.Mock,
        connect_mock: mock.Mock,
    ) -> None:
        connection = mock.Mock()
        connect_mock.return_value = connection
        identity_mock.return_value = mock.Mock(
            name="identity",
            status="ok",
            data={"account": "xy12345", "user": "AUDITOR", "role": "SECURITYADMIN"},
            findings=[],
            errors=[],
        )
        grants_mock.return_value = mock.Mock(
            name="user_grants",
            status="ok",
            data={"count": 0, "grants": []},
            findings=[],
            errors=[],
        )
        security_mock.return_value = mock.Mock(
            name="security",
            status="ok",
            data={},
            findings=[],
            errors=[],
        )
        inventory_mock.return_value = ({"users": []}, [])

        config = SnowflakeConfig(account="xy12345", user="AUDITOR", password="secret")
        report, returned_connection = snowflake_audit.run_snowflake_audit(config)
        self.assertEqual(returned_connection, connection)
        self.assertEqual(report.metadata["account"], "xy12345")
        self.assertEqual(report.metadata["provider"], "snowflake")
        connection.close.assert_not_called()


class TestSnowflakeCli(unittest.TestCase):
    def test_resolve_config_uses_cli_over_env(self) -> None:
        env = {
            "SNOWFLAKE_ACCOUNT": "env-account",
            "SNOWFLAKE_USER": "env-user",
            "SNOWFLAKE_ROLE": "ENV_ROLE",
        }
        args = mock.Mock(
            account="cli-account",
            user=None,
            password=None,
            role="CLI_ROLE",
            warehouse=None,
            database=None,
            schema=None,
            authenticator=None,
            private_key_path=None,
        )
        with mock.patch.dict(os.environ, env, clear=True):
            config = resolve_config(args)
        self.assertEqual(config.account, "cli-account")
        self.assertEqual(config.user, "env-user")
        self.assertEqual(config.role, "CLI_ROLE")

    @mock.patch("aws_account_audit.snowflake.check.write_snowflake_index_html")
    @mock.patch("aws_account_audit.snowflake.check.write_snowflake_findings_html")
    @mock.patch("aws_account_audit.snowflake.check.write_snowflake_report")
    @mock.patch("aws_account_audit.snowflake.check.run_snowflake_audit")
    def test_main_writes_summary_and_returns_exit_code(
        self,
        run_mock: mock.Mock,
        write_report_mock: mock.Mock,
        write_findings_mock: mock.Mock,
        write_index_mock: mock.Mock,
    ) -> None:
        connection = mock.Mock()
        finding = Finding(
            severity="HIGH",
            category="access_control",
            title="Privileged role granted to user: ACCOUNTADMIN",
            detail="User ALICE has been granted the ACCOUNTADMIN role.",
        )
        report = AuditReport(
            metadata={
                "generated_at": "2025-06-30T00:00:00+00:00",
                "account": "xy12345",
                "account_id": "xy12345",
                "user": "AUDITOR",
            },
            sections=[
                SectionResult(
                    name="user_grants",
                    status="ok",
                    findings=[finding],
                )
            ],
        )
        run_mock.return_value = (report, connection)

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "account-xy12345"
            run_dir.mkdir(parents=True)
            audit_json = run_dir / "audit-runs" / "snowflake-xy12345.json"
            audit_json.parent.mkdir(parents=True)
            audit_json.write_text(json.dumps(report.to_dict()), encoding="utf-8")
            write_report_mock.return_value = {"json": audit_json}
            write_findings_mock.return_value = run_dir / "findings.html"
            write_index_mock.return_value = run_dir / "snowflake-view.html"

            exit_code = snowflake_main(
                [
                    "--account",
                    "xy12345",
                    "--user",
                    "AUDITOR",
                    "--password",
                    "secret",
                    "--output-dir",
                    tmp,
                ]
            )

            self.assertEqual(exit_code, 1)
            connection.close.assert_called_once()
            summary_path = run_dir / "snowflake-check-summary.json"
            self.assertTrue(summary_path.exists())

    @mock.patch("aws_account_audit.snowflake.check.write_snowflake_index_html")
    @mock.patch("aws_account_audit.snowflake.check.write_snowflake_findings_html")
    @mock.patch("aws_account_audit.snowflake.check.write_snowflake_report")
    @mock.patch("aws_account_audit.snowflake.check.run_snowflake_audit")
    def test_main_returns_zero_when_no_findings(
        self,
        run_mock: mock.Mock,
        write_report_mock: mock.Mock,
        write_findings_mock: mock.Mock,
        write_index_mock: mock.Mock,
    ) -> None:
        connection = mock.Mock()
        report = AuditReport(
            metadata={
                "generated_at": "2025-06-30T00:00:00+00:00",
                "account": "xy12345",
                "account_id": "xy12345",
                "user": "AUDITOR",
            },
            sections=[],
        )
        run_mock.return_value = (report, connection)

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "account-xy12345"
            run_dir.mkdir(parents=True)
            audit_json = run_dir / "audit-runs" / "snowflake-xy12345.json"
            audit_json.parent.mkdir(parents=True)
            audit_json.write_text("{}", encoding="utf-8")
            write_report_mock.return_value = {"json": audit_json}
            write_findings_mock.return_value = run_dir / "findings.html"
            write_index_mock.return_value = run_dir / "snowflake-view.html"

            exit_code = snowflake_main(
                [
                    "--account",
                    "xy12345",
                    "--user",
                    "AUDITOR",
                    "--password",
                    "secret",
                    "--output-dir",
                    tmp,
                ]
            )

        self.assertEqual(exit_code, 0)
