from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aws_account_audit import account_check as ac
from aws_account_audit.session import region_was_explicit


class TestSelectedRegionsFromArgv(unittest.TestCase):
    @mock.patch("aws_account_audit.session.enabled_regions")
    def test_main_limits_to_explicit_region_flag(self, enabled_mock: mock.Mock) -> None:
        enabled_mock.return_value = ["eu-west-1", "us-east-1"]
        regions = ac._selected_regions(
            None,
            "eu-west-1",
            None,
            None,
            region_was_explicit(["--profile", "default", "--region", "eu-west-1"]),
        )
        self.assertEqual(regions, ["eu-west-1"])
        enabled_mock.assert_not_called()

    @mock.patch("aws_account_audit.session.enabled_regions")
    def test_main_scans_all_regions_when_region_not_explicit(self, enabled_mock: mock.Mock) -> None:
        enabled_mock.return_value = ["eu-west-1", "us-east-1"]
        regions = ac._selected_regions(
            None,
            "eu-west-1",
            None,
            None,
            region_was_explicit(["--profile", "default"]),
        )
        self.assertEqual(regions, ["eu-west-1", "us-east-1"])
        enabled_mock.assert_called_once()


class TestCopyMapJsons(unittest.TestCase):
    def test_copy_map_jsons_copies_from_multiple_sources(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            src_a = base / "from-audit"
            src_b = base / "all-security-groups"
            dst = base / "combined-json"
            src_a.mkdir(parents=True, exist_ok=True)
            src_b.mkdir(parents=True, exist_ok=True)
            (src_a / "a.json").write_text('{"k":"v"}', encoding="utf-8")
            (src_b / "b.json").write_text('{"k":"v"}', encoding="utf-8")

            copied = ac._copy_map_jsons([src_a, src_b], dst)

            self.assertEqual(copied, 2)
            self.assertTrue((dst / "from-audit-a.json").exists())
            self.assertTrue((dst / "all-security-groups-b.json").exists())


class TestMainPipeline(unittest.TestCase):
    @mock.patch("aws_account_audit.account_check.generate_iam_outputs")
    @mock.patch("aws_account_audit.account_check.write_iam_data_json")
    @mock.patch("aws_account_audit.account_check.collect_iam_relationship_data")
    @mock.patch("aws_account_audit.account_check._run_audit_iam_shell")
    @mock.patch("aws_account_audit.account_check.account_graph_main")
    @mock.patch("aws_account_audit.account_check._copy_map_jsons")
    @mock.patch("aws_account_audit.account_check._run_all_sg_maps")
    @mock.patch("aws_account_audit.account_check._collect_security_group_targets")
    @mock.patch("aws_account_audit.account_check.from_audit_main")
    @mock.patch("aws_account_audit.account_check.write_report")
    @mock.patch("aws_account_audit.account_check.run_audit")
    @mock.patch("aws_account_audit.account_check._selected_regions")
    def test_main_runs_full_pipeline_and_writes_summary(
        self,
        selected_regions_mock: mock.Mock,
        run_audit_mock: mock.Mock,
        write_report_mock: mock.Mock,
        from_audit_main_mock: mock.Mock,
        collect_sg_mock: mock.Mock,
        run_all_sg_mock: mock.Mock,
        copy_map_jsons_mock: mock.Mock,
        account_graph_main_mock: mock.Mock,
        iam_shell_mock: mock.Mock,
        collect_iam_mock: mock.Mock,
        write_iam_data_mock: mock.Mock,
        generate_iam_mock: mock.Mock,
    ) -> None:
        selected_regions_mock.return_value = ["us-east-2"]
        run_audit_mock.return_value = SimpleNamespace(metadata={"account_id": "123456789012"})
        from_audit_main_mock.return_value = 0
        collect_sg_mock.return_value = [("us-east-2", "sg-1234")]
        run_all_sg_mock.return_value = 0
        copy_map_jsons_mock.return_value = 2
        account_graph_main_mock.return_value = 0
        iam_shell_mock.return_value = 0
        collect_iam_mock.return_value = {"account_id": "123456789012", "errors": []}
        generate_iam_mock.return_value = SimpleNamespace(summary=lambda: {"node_count": 1})

        with tempfile.TemporaryDirectory() as d:
            output_dir = Path(d) / "runs"
            audit_json = output_dir / "account-123456789012" / "audit-runs" / "audit.json"
            audit_text = output_dir / "account-123456789012" / "audit-runs" / "audit.log"
            audit_json.parent.mkdir(parents=True, exist_ok=True)
            audit_json.write_text("{}", encoding="utf-8")
            audit_text.write_text("ok", encoding="utf-8")
            write_report_mock.return_value = {"json": audit_json, "text": audit_text}

            rc = ac.main(["--output-dir", str(output_dir), "--profile", "default"])

            self.assertEqual(rc, 0)
            summary_path = output_dir / "account-123456789012" / "account-check-summary.json"
            self.assertTrue(summary_path.exists())
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["account_id"], "123456789012")
            self.assertEqual(payload["copied_map_json_files"], 2)
            self.assertIn("iam_audit_json", payload)
            run_audit_mock.assert_called_once()
            account_graph_main_mock.assert_called_once()
            collect_iam_mock.assert_called_once()
            generate_iam_mock.assert_called_once()
            iam_shell_mock.assert_called_once()
            write_iam_data_mock.assert_called_once()

    @mock.patch("aws_account_audit.account_check.generate_iam_outputs")
    @mock.patch("aws_account_audit.account_check.write_iam_data_json")
    @mock.patch("aws_account_audit.account_check.collect_iam_relationship_data")
    @mock.patch("aws_account_audit.account_check._run_audit_iam_shell")
    @mock.patch("aws_account_audit.account_check.account_graph_main")
    @mock.patch("aws_account_audit.account_check._copy_map_jsons")
    @mock.patch("aws_account_audit.account_check._run_all_sg_maps")
    @mock.patch("aws_account_audit.account_check._collect_security_group_targets")
    @mock.patch("aws_account_audit.account_check.from_audit_main")
    @mock.patch("aws_account_audit.account_check.write_report")
    @mock.patch("aws_account_audit.account_check.run_audit")
    @mock.patch("aws_account_audit.account_check._selected_regions")
    def test_main_writes_inventory_overlay_and_builds_graph(
        self,
        selected_regions_mock: mock.Mock,
        run_audit_mock: mock.Mock,
        write_report_mock: mock.Mock,
        from_audit_main_mock: mock.Mock,
        collect_sg_mock: mock.Mock,
        run_all_sg_mock: mock.Mock,
        copy_map_jsons_mock: mock.Mock,
        account_graph_main_mock: mock.Mock,
        iam_shell_mock: mock.Mock,
        collect_iam_mock: mock.Mock,
        write_iam_data_mock: mock.Mock,
        generate_iam_mock: mock.Mock,
    ) -> None:
        selected_regions_mock.return_value = ["eu-west-1"]
        run_audit_mock.return_value = SimpleNamespace(
            metadata={"account_id": "123456789012"},
            resource_inventory={
                "s3_buckets": [{"name": "my-bucket", "region": "eu-west-1"}],
            },
        )
        from_audit_main_mock.return_value = 0
        collect_sg_mock.return_value = []
        run_all_sg_mock.return_value = 0
        # No security-group maps copied; the overlay alone should keep the graph building.
        copy_map_jsons_mock.return_value = 0
        account_graph_main_mock.return_value = 0
        iam_shell_mock.return_value = 0
        collect_iam_mock.return_value = {"account_id": "123456789012", "errors": []}
        generate_iam_mock.return_value = SimpleNamespace(summary=lambda: {"node_count": 1})

        with tempfile.TemporaryDirectory() as d:
            output_dir = Path(d) / "runs"
            audit_json = output_dir / "account-123456789012" / "audit-runs" / "audit.json"
            audit_text = output_dir / "account-123456789012" / "audit-runs" / "audit.log"
            audit_json.parent.mkdir(parents=True, exist_ok=True)
            audit_json.write_text("{}", encoding="utf-8")
            audit_text.write_text("ok", encoding="utf-8")
            write_report_mock.return_value = {"json": audit_json, "text": audit_text}

            rc = ac.main(["--output-dir", str(output_dir), "--profile", "default"])

            self.assertEqual(rc, 0)
            account_graph_main_mock.assert_called_once()
            summary_path = output_dir / "account-123456789012" / "account-check-summary.json"
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["copied_map_json_files"], 1)
            overlay_path = Path(payload["inventory_overlay_json"])
            self.assertTrue(overlay_path.exists())
            overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
            node_ids = {node["node_id"] for node in overlay["nodes"]}
            self.assertIn("s3_bucket:my-bucket", node_ids)

    @mock.patch("aws_account_audit.account_check.generate_iam_outputs")
    @mock.patch("aws_account_audit.account_check.write_iam_data_json")
    @mock.patch("aws_account_audit.account_check.collect_iam_relationship_data")
    @mock.patch("aws_account_audit.account_check._run_audit_iam_shell")
    @mock.patch("aws_account_audit.account_check.account_graph_main")
    @mock.patch("aws_account_audit.account_check._copy_map_jsons")
    @mock.patch("aws_account_audit.account_check._run_all_sg_maps")
    @mock.patch("aws_account_audit.account_check._collect_security_group_targets")
    @mock.patch("aws_account_audit.account_check.from_audit_main")
    @mock.patch("aws_account_audit.account_check.write_report")
    @mock.patch("aws_account_audit.account_check.run_audit")
    @mock.patch("aws_account_audit.account_check._selected_regions")
    def test_main_skips_inventory_with_no_inventory_flag(
        self,
        selected_regions_mock: mock.Mock,
        run_audit_mock: mock.Mock,
        write_report_mock: mock.Mock,
        from_audit_main_mock: mock.Mock,
        collect_sg_mock: mock.Mock,
        run_all_sg_mock: mock.Mock,
        copy_map_jsons_mock: mock.Mock,
        account_graph_main_mock: mock.Mock,
        iam_shell_mock: mock.Mock,
        collect_iam_mock: mock.Mock,
        write_iam_data_mock: mock.Mock,
        generate_iam_mock: mock.Mock,
    ) -> None:
        selected_regions_mock.return_value = ["eu-west-1"]
        run_audit_mock.return_value = SimpleNamespace(
            metadata={"account_id": "123456789012"},
            resource_inventory=None,
        )
        from_audit_main_mock.return_value = 0
        collect_sg_mock.return_value = []
        run_all_sg_mock.return_value = 0
        copy_map_jsons_mock.return_value = 1
        account_graph_main_mock.return_value = 0
        iam_shell_mock.return_value = 0
        collect_iam_mock.return_value = {"account_id": "123456789012", "errors": []}
        generate_iam_mock.return_value = SimpleNamespace(summary=lambda: {"node_count": 1})

        with tempfile.TemporaryDirectory() as d:
            output_dir = Path(d) / "runs"
            audit_json = output_dir / "account-123456789012" / "audit-runs" / "audit.json"
            audit_text = output_dir / "account-123456789012" / "audit-runs" / "audit.log"
            audit_json.parent.mkdir(parents=True, exist_ok=True)
            audit_json.write_text("{}", encoding="utf-8")
            audit_text.write_text("ok", encoding="utf-8")
            write_report_mock.return_value = {"json": audit_json, "text": audit_text}

            rc = ac.main(
                ["--output-dir", str(output_dir), "--profile", "default", "--no-inventory"]
            )

            self.assertEqual(rc, 0)
            run_audit_mock.assert_called_once()
            self.assertFalse(run_audit_mock.call_args.kwargs.get("include_inventory", True))
            summary_path = output_dir / "account-123456789012" / "account-check-summary.json"
            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["inventory_overlay_json"], "")
            self.assertEqual(payload["copied_map_json_files"], 1)

    @mock.patch("aws_account_audit.account_check.generate_iam_outputs")
    @mock.patch("aws_account_audit.account_check.write_iam_data_json")
    @mock.patch("aws_account_audit.account_check.collect_iam_relationship_data")
    @mock.patch("aws_account_audit.account_check._run_audit_iam_shell")
    @mock.patch("aws_account_audit.account_check.account_graph_main")
    @mock.patch("aws_account_audit.account_check._copy_map_jsons")
    @mock.patch("aws_account_audit.account_check._run_all_sg_maps")
    @mock.patch("aws_account_audit.account_check._collect_security_group_targets")
    @mock.patch("aws_account_audit.account_check.from_audit_main")
    @mock.patch("aws_account_audit.account_check.write_report")
    @mock.patch("aws_account_audit.account_check.run_audit")
    @mock.patch("aws_account_audit.account_check._selected_regions")
    def test_main_returns_error_when_no_map_json_files(
        self,
        selected_regions_mock: mock.Mock,
        run_audit_mock: mock.Mock,
        write_report_mock: mock.Mock,
        from_audit_main_mock: mock.Mock,
        collect_sg_mock: mock.Mock,
        run_all_sg_mock: mock.Mock,
        copy_map_jsons_mock: mock.Mock,
        account_graph_main_mock: mock.Mock,
        iam_shell_mock: mock.Mock,
        collect_iam_mock: mock.Mock,
        write_iam_data_mock: mock.Mock,
        generate_iam_mock: mock.Mock,
    ) -> None:
        selected_regions_mock.return_value = ["us-east-2"]
        run_audit_mock.return_value = SimpleNamespace(metadata={"account_id": "123456789012"})
        from_audit_main_mock.return_value = 0
        collect_sg_mock.return_value = []
        run_all_sg_mock.return_value = 0
        copy_map_jsons_mock.return_value = 0
        account_graph_main_mock.return_value = 0
        iam_shell_mock.return_value = 0
        collect_iam_mock.return_value = {"account_id": "123456789012", "errors": []}
        generate_iam_mock.return_value = SimpleNamespace(summary=lambda: {"node_count": 0})

        with tempfile.TemporaryDirectory() as d:
            output_dir = Path(d) / "runs"
            audit_json = output_dir / "account-123456789012" / "audit-runs" / "audit.json"
            audit_text = output_dir / "account-123456789012" / "audit-runs" / "audit.log"
            audit_json.parent.mkdir(parents=True, exist_ok=True)
            audit_json.write_text("{}", encoding="utf-8")
            audit_text.write_text("ok", encoding="utf-8")
            write_report_mock.return_value = {"json": audit_json, "text": audit_text}

            rc = ac.main(["--output-dir", str(output_dir), "--profile", "default"])

            self.assertEqual(rc, 1)
            account_graph_main_mock.assert_not_called()
            generate_iam_mock.assert_not_called()

    @mock.patch("aws_account_audit.account_check.generate_iam_outputs")
    @mock.patch("aws_account_audit.account_check.write_iam_data_json")
    @mock.patch("aws_account_audit.account_check.collect_iam_relationship_data")
    @mock.patch("aws_account_audit.account_check._run_audit_iam_shell")
    @mock.patch("aws_account_audit.account_check.account_graph_main")
    @mock.patch("aws_account_audit.account_check._copy_map_jsons")
    @mock.patch("aws_account_audit.account_check._run_all_sg_maps")
    @mock.patch("aws_account_audit.account_check._collect_security_group_targets")
    @mock.patch("aws_account_audit.account_check.from_audit_main")
    @mock.patch("aws_account_audit.account_check.write_report")
    @mock.patch("aws_account_audit.account_check.run_audit")
    @mock.patch("aws_account_audit.account_check._selected_regions")
    def test_main_returns_error_when_mapping_stage_fails(
        self,
        selected_regions_mock: mock.Mock,
        run_audit_mock: mock.Mock,
        write_report_mock: mock.Mock,
        from_audit_main_mock: mock.Mock,
        collect_sg_mock: mock.Mock,
        run_all_sg_mock: mock.Mock,
        copy_map_jsons_mock: mock.Mock,
        account_graph_main_mock: mock.Mock,
        iam_shell_mock: mock.Mock,
        collect_iam_mock: mock.Mock,
        write_iam_data_mock: mock.Mock,
        generate_iam_mock: mock.Mock,
    ) -> None:
        selected_regions_mock.return_value = ["us-east-2"]
        run_audit_mock.return_value = SimpleNamespace(metadata={"account_id": "123456789012"})
        from_audit_main_mock.return_value = 1
        collect_sg_mock.return_value = [("us-east-2", "sg-1234")]
        run_all_sg_mock.return_value = 0
        copy_map_jsons_mock.return_value = 1
        account_graph_main_mock.return_value = 0
        iam_shell_mock.return_value = 0
        collect_iam_mock.return_value = {"account_id": "123456789012", "errors": []}
        generate_iam_mock.return_value = SimpleNamespace(summary=lambda: {"node_count": 1})

        with tempfile.TemporaryDirectory() as d:
            output_dir = Path(d) / "runs"
            audit_json = output_dir / "account-123456789012" / "audit-runs" / "audit.json"
            audit_text = output_dir / "account-123456789012" / "audit-runs" / "audit.log"
            audit_json.parent.mkdir(parents=True, exist_ok=True)
            audit_json.write_text("{}", encoding="utf-8")
            audit_text.write_text("ok", encoding="utf-8")
            write_report_mock.return_value = {"json": audit_json, "text": audit_text}

            rc = ac.main(["--output-dir", str(output_dir), "--profile", "default"])
            self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
