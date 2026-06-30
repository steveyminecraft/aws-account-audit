"""Tests for aws_account_audit.inventory reporting and file output."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aws_account_audit import inventory as inv
from aws_account_audit.models import AuditReport


def _inventory() -> dict[str, list[dict]]:
    return {
        "ec2_instances": [
            {
                "id": "i-1",
                "name": "web-1",
                "type": "t3.micro",
                "state": "running",
                "availability_zone": "eu-west-1a",
                "region": "eu-west-1",
                "private_ip": "10.0.0.5",
                "public_ip": "1.2.3.4",
            }
        ],
        "ebs_volumes": [
            {
                "id": "vol-1",
                "type": "gp3",
                "size_gb": 100,
                "availability_zone": "eu-west-1a",
                "region": "eu-west-1",
                "state": "in-use",
                "encrypted": True,
            }
        ],
        "rds_instances": [
            {
                "identifier": "prod-db",
                "engine": "postgres",
                "engine_version": "15.4",
                "instance_class": "db.t3.medium",
                "allocated_storage_gb": 50,
                "availability_zone": "eu-west-1a",
                "region": "eu-west-1",
                "status": "available",
                "publicly_accessible": False,
            }
        ],
        "load_balancers": [
            {
                "name": "web-alb",
                "type": "application",
                "scheme": "internet-facing",
                "state": "active",
                "availability_zones": ["eu-west-1a", "eu-west-1b"],
                "dns_name": "web-alb-123.elb.amazonaws.com",
                "region": "eu-west-1",
            }
        ],
        "lambda_functions": [
            {
                "name": "processor",
                "runtime": "python3.12",
                "memory_size_mb": 512,
                "code_size_bytes": 10485760,
                "version": "$LATEST",
                "architectures": ["arm64"],
                "region": "us-east-1",
            }
        ],
        "s3_buckets": [
            {
                "name": "my-bucket",
                "region": "eu-west-1",
                "creation_date": "2025-01-01",
                "is_public": False,
            }
        ],
        "dynamodb_tables": [{"name": "sessions", "region": "eu-west-1"}],
    }


class TestInventoryToDict(unittest.TestCase):
    def test_payload_has_inventory_key(self) -> None:
        payload = inv.inventory_to_dict({"account_id": "123"}, _inventory())
        self.assertIn("inventory", payload)
        self.assertIn("summary", payload)
        self.assertEqual(payload["summary"]["resource_count"], 7)


class TestRenderInventoryText(unittest.TestCase):
    def setUp(self) -> None:
        self.text = "\n".join(inv.render_inventory_text(_inventory()))

    def test_has_inventory_header(self) -> None:
        self.assertIn("Resource Inventory", self.text)

    def test_lists_ec2_instance_details(self) -> None:
        self.assertIn("i-1", self.text)
        self.assertIn("t3.micro", self.text)

    def test_lists_rds_version_and_class(self) -> None:
        self.assertIn("15.4", self.text)
        self.assertIn("db.t3.medium", self.text)

    def test_lists_s3_bucket(self) -> None:
        self.assertIn("my-bucket", self.text)


class TestWriteInventoryFiles(unittest.TestCase):
    def test_writes_separate_json_and_log(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            paths = inv.write_inventory_files(
                {
                    "account_id": "123",
                    "generated_at": "2026-06-30",
                    "regions_scanned": ["eu-west-1"],
                },
                _inventory(),
                Path(d),
                "audit-123-20260630",
            )
            self.assertTrue(paths["inventory_json"].exists())
            self.assertTrue(paths["inventory_text"].exists())
            payload = json.loads(paths["inventory_json"].read_text(encoding="utf-8"))
            self.assertIn("inventory", payload)
            self.assertIn("Resource Inventory", paths["inventory_text"].read_text(encoding="utf-8"))


class TestBuildInventoryGraph(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = inv.build_inventory_graph(_inventory(), account_id="123456789012")

    def test_has_network_map_schema_keys(self) -> None:
        for key in ("root", "region", "nodes", "edges", "ingress_paths", "errors"):
            self.assertIn(key, self.graph)
        self.assertEqual(self.graph["root"], "account:123456789012")

    def test_node_ids_and_kinds(self) -> None:
        nodes = {node["node_id"]: node for node in self.graph["nodes"]}
        self.assertEqual(nodes["ec2_instance:i-1"]["kind"], "ec2_instance")
        self.assertEqual(nodes["ebs_volume:vol-1"]["kind"], "ebs_volume")
        self.assertEqual(nodes["rds_instance:prod-db"]["kind"], "rds_instance")
        self.assertEqual(nodes["load_balancer:web-alb"]["kind"], "load_balancer")
        self.assertEqual(nodes["lambda_function:processor"]["kind"], "lambda_function")
        self.assertEqual(nodes["s3_bucket:my-bucket"]["kind"], "s3_bucket")
        self.assertEqual(nodes["dynamodb_table:sessions"]["kind"], "dynamodb_table")

    def test_labels_carry_type_size_version(self) -> None:
        labels = {node["node_id"]: node["label"] for node in self.graph["nodes"]}
        self.assertIn("t3.micro", labels["ec2_instance:i-1"])
        self.assertIn("100 GiB", labels["ebs_volume:vol-1"])
        self.assertIn("15.4", labels["rds_instance:prod-db"])
        self.assertIn("python3.12", labels["lambda_function:processor"])

    def test_region_anchors_created_once_per_region(self) -> None:
        region_nodes = [n for n in self.graph["nodes"] if n["kind"] == "region"]
        region_ids = {n["node_id"] for n in region_nodes}
        self.assertEqual(region_ids, {"region:eu-west-1", "region:us-east-1"})

    def test_edges_link_region_to_resource(self) -> None:
        edges = {(e["source"], e["target"]) for e in self.graph["edges"]}
        self.assertIn(("region:eu-west-1", "ec2_instance:i-1"), edges)
        self.assertIn(("region:us-east-1", "lambda_function:processor"), edges)

    def test_empty_inventory_yields_no_nodes(self) -> None:
        graph = inv.build_inventory_graph({}, account_id="123")
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["edges"], [])


class TestAuditReportInventorySeparation(unittest.TestCase):
    def test_to_dict_does_not_include_resource_inventory(self) -> None:
        report = AuditReport(
            metadata={"account_id": "123"},
            resource_inventory=_inventory(),
        )
        payload = report.to_dict()
        self.assertNotIn("resource_inventory", payload)
        self.assertNotIn("inventory", payload)


if __name__ == "__main__":
    unittest.main()
