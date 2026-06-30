"""Tests for resource summarizer helpers in aws_account_audit.inventory."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, call, patch

from aws_account_audit import inventory as inv


class TestSummarizeInstance(unittest.TestCase):
    def _instance(self) -> dict:
        return {
            "InstanceId": "i-0abc",
            "InstanceType": "t3.micro",
            "State": {"Name": "running"},
            "Placement": {"AvailabilityZone": "eu-west-1a"},
            "ImageId": "ami-123",
            "PlatformDetails": "Linux/UNIX",
            "PrivateIpAddress": "10.0.0.5",
            "PublicIpAddress": "1.2.3.4",
            "Tags": [{"Key": "Name", "Value": "web-1"}],
        }

    def test_includes_type(self) -> None:
        self.assertEqual(inv._summarize_instance(self._instance(), "eu-west-1")["type"], "t3.micro")

    def test_includes_location_az(self) -> None:
        self.assertEqual(
            inv._summarize_instance(self._instance(), "eu-west-1")["availability_zone"],
            "eu-west-1a",
        )

    def test_includes_name_from_tags(self) -> None:
        self.assertEqual(inv._summarize_instance(self._instance(), "eu-west-1")["name"], "web-1")

    def test_includes_region(self) -> None:
        self.assertEqual(
            inv._summarize_instance(self._instance(), "eu-west-1")["region"], "eu-west-1"
        )

    def test_missing_fields_do_not_raise(self) -> None:
        result = inv._summarize_instance({"InstanceId": "i-1"}, "eu-west-1")
        self.assertEqual(result["id"], "i-1")
        self.assertIsNone(result["availability_zone"])
        self.assertIsNone(result["name"])


class TestSummarizeVolume(unittest.TestCase):
    def _volume(self) -> dict:
        return {
            "VolumeId": "vol-0abc",
            "VolumeType": "gp3",
            "Size": 100,
            "AvailabilityZone": "eu-west-1b",
            "State": "in-use",
            "Encrypted": True,
            "Iops": 3000,
        }

    def test_includes_size(self) -> None:
        self.assertEqual(inv._summarize_volume(self._volume(), "eu-west-1")["size_gb"], 100)

    def test_includes_type(self) -> None:
        self.assertEqual(inv._summarize_volume(self._volume(), "eu-west-1")["type"], "gp3")

    def test_includes_location_az(self) -> None:
        self.assertEqual(
            inv._summarize_volume(self._volume(), "eu-west-1")["availability_zone"], "eu-west-1b"
        )


class TestSummarizeRds(unittest.TestCase):
    def _db(self) -> dict:
        return {
            "DBInstanceIdentifier": "prod-db",
            "Engine": "postgres",
            "EngineVersion": "15.4",
            "DBInstanceClass": "db.t3.medium",
            "AllocatedStorage": 50,
            "AvailabilityZone": "eu-west-1a",
            "MultiAZ": False,
            "DBInstanceStatus": "available",
            "PubliclyAccessible": False,
        }

    def test_includes_version(self) -> None:
        self.assertEqual(inv._summarize_rds(self._db(), "eu-west-1")["engine_version"], "15.4")

    def test_includes_type_class(self) -> None:
        self.assertEqual(
            inv._summarize_rds(self._db(), "eu-west-1")["instance_class"], "db.t3.medium"
        )

    def test_includes_size_storage(self) -> None:
        self.assertEqual(inv._summarize_rds(self._db(), "eu-west-1")["allocated_storage_gb"], 50)


class TestSummarizeLoadBalancer(unittest.TestCase):
    def _lb(self) -> dict:
        return {
            "LoadBalancerName": "web-alb",
            "DNSName": "web-alb-123.eu-west-1.elb.amazonaws.com",
            "Type": "application",
            "Scheme": "internet-facing",
            "State": {"Code": "active"},
            "AvailabilityZones": [{"ZoneName": "eu-west-1a"}, {"ZoneName": "eu-west-1b"}],
            "VpcId": "vpc-1",
        }

    def test_includes_type(self) -> None:
        self.assertEqual(
            inv._summarize_load_balancer(self._lb(), "eu-west-1")["type"], "application"
        )

    def test_includes_location_azs(self) -> None:
        self.assertEqual(
            inv._summarize_load_balancer(self._lb(), "eu-west-1")["availability_zones"],
            ["eu-west-1a", "eu-west-1b"],
        )


class TestSummarizeLambda(unittest.TestCase):
    def _fn(self) -> dict:
        return {
            "FunctionName": "processor",
            "Runtime": "python3.12",
            "MemorySize": 512,
            "CodeSize": 10485760,
            "Version": "$LATEST",
            "Architectures": ["arm64"],
            "Handler": "app.handler",
            "LastModified": "2026-06-01T00:00:00.000+0000",
        }

    def test_includes_runtime(self) -> None:
        self.assertEqual(inv._summarize_lambda(self._fn(), "us-east-1")["runtime"], "python3.12")

    def test_includes_size_memory(self) -> None:
        self.assertEqual(inv._summarize_lambda(self._fn(), "us-east-1")["memory_size_mb"], 512)

    def test_includes_code_size(self) -> None:
        self.assertEqual(
            inv._summarize_lambda(self._fn(), "us-east-1")["code_size_bytes"], 10485760
        )


class TestSummarizeRdsCluster(unittest.TestCase):
    def _cluster(self) -> dict:
        return {
            "DBClusterIdentifier": "aurora-prod",
            "Engine": "aurora-postgresql",
            "EngineVersion": "15.4",
            "EngineMode": "provisioned",
            "Status": "available",
            "DBClusterMembers": [{"DBInstanceIdentifier": "aurora-prod-1"}],
            "MultiAZ": True,
            "StorageEncrypted": True,
            "Endpoint": "aurora-prod.cluster-abc.eu-west-1.rds.amazonaws.com",
        }

    def test_includes_engine_mode_and_members(self) -> None:
        result = inv._summarize_rds_cluster(self._cluster(), "eu-west-1")
        self.assertEqual(result["engine_mode"], "provisioned")
        self.assertEqual(result["member_count"], 1)

    def test_includes_version(self) -> None:
        self.assertEqual(
            inv._summarize_rds_cluster(self._cluster(), "eu-west-1")["engine_version"], "15.4"
        )


class TestSummarizeEventBridge(unittest.TestCase):
    def test_bus_summary(self) -> None:
        result = inv._summarize_eventbridge_bus(
            {"Name": "default", "Arn": "arn:aws:events:eu-west-1:123:event-bus/default"},
            "eu-west-1",
        )
        self.assertEqual(result["name"], "default")

    def test_rule_summary_schedule(self) -> None:
        result = inv._summarize_eventbridge_rule(
            {
                "Name": "nightly",
                "State": "ENABLED",
                "ScheduleExpression": "rate(1 day)",
                "Description": "daily",
            },
            "eu-west-1",
            "default",
            2,
        )
        self.assertEqual(result["trigger"], "rate(1 day)")
        self.assertEqual(result["target_count"], 2)

    def test_rule_summary_truncates_long_pattern(self) -> None:
        pattern = '{"source": ["' + "x" * 100 + '"]}'
        result = inv._summarize_eventbridge_rule(
            {"Name": "on-event", "State": "ENABLED", "EventPattern": pattern},
            "eu-west-1",
            "default",
            1,
        )
        self.assertLessEqual(len(result["trigger"] or ""), 80)


class TestWafHelpers(unittest.TestCase):
    def test_default_action_allow(self) -> None:
        self.assertEqual(inv._waf_default_action({"Allow": {}}), "Allow")

    def test_default_action_block(self) -> None:
        self.assertEqual(inv._waf_default_action({"Block": {}}), "Block")

    def test_paginate_waf_uses_next_marker(self) -> None:
        list_web_acls = MagicMock()
        list_web_acls.side_effect = [
            {"WebACLs": [{"Name": "acl-1", "Id": "1"}], "NextMarker": "page-2"},
            {"WebACLs": [{"Name": "acl-2", "Id": "2"}]},
        ]
        items = inv._paginate_waf(list_web_acls, scope="CLOUDFRONT")
        self.assertEqual(len(items), 2)
        list_web_acls.assert_has_calls(
            [
                call(Scope="CLOUDFRONT", Limit=100),
                call(Scope="CLOUDFRONT", Limit=100, NextMarker="page-2"),
            ]
        )


class TestCollectAccountInventoryWaf(unittest.TestCase):
    def _run_collect(
        self, *, waf_return: tuple[list[dict], str | None]
    ) -> tuple[dict[str, list[dict]], list[str]]:
        empty = {category: [] for category in inv.CATEGORIES}
        with (
            patch.object(
                inv,
                "_collect_regional_inventory",
                return_value=(empty, []),
            ),
            patch.object(inv, "_collect_s3_buckets", return_value=([], [])),
            patch.object(inv, "_collect_waf_cloudfront", return_value=waf_return),
        ):
            return inv.collect_account_inventory(
                session=object(),
                regions=["us-east-1"],
                home_region="us-east-1",
            )

    def test_cloudfront_waf_none_error_does_not_crash(self) -> None:
        waf_acl = {"name": "cf-acl", "scope": "CLOUDFRONT", "region": "global"}
        inventory, errors = self._run_collect(waf_return=([waf_acl], None))
        self.assertEqual(inventory["waf_web_acls"], [waf_acl])
        self.assertEqual(errors, [])

    def test_cloudfront_waf_error_is_appended(self) -> None:
        _, errors = self._run_collect(
            waf_return=([], "wafv2.list_web_acls(CLOUDFRONT,global) failed")
        )
        self.assertEqual(errors, ["wafv2.list_web_acls(CLOUDFRONT,global) failed"])


class TestNameFromTags(unittest.TestCase):
    def test_returns_name_value(self) -> None:
        self.assertEqual(inv._name_from_tags([{"Key": "Name", "Value": "web-1"}]), "web-1")

    def test_returns_none_when_absent(self) -> None:
        self.assertIsNone(inv._name_from_tags([{"Key": "env", "Value": "prod"}]))


if __name__ == "__main__":
    unittest.main()
