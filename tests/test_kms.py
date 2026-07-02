from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest import mock

from aws_account_audit import kms
from aws_account_audit.collectors import collect_regional_kms
from aws_account_audit.models import Finding


class TestSummarizeKmsKey(unittest.TestCase):
    def test_normalizes_metadata(self) -> None:
        created = datetime(2025, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        used = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        item = kms.summarize_kms_key(
            {
                "Description": "app key",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "Origin": "AWS_KMS",
                "MultiRegion": False,
                "CreationDate": created,
            },
            region="eu-west-1",
            key_id="key-1",
            key_arn="arn:aws:kms:eu-west-1:123:key/key-1",
            aliases=["alias/app"],
            rotation_enabled=True,
            last_used_at=used,
        )
        self.assertEqual(item["alias"], "alias/app")
        self.assertEqual(item["rotation_enabled"], True)
        self.assertEqual(item["last_used_at"], used)


class TestKmsFindings(unittest.TestCase):
    def test_flags_rotation_disabled_on_customer_key(self) -> None:
        findings = kms.kms_findings_for_key(
            {
                "id": "key-1",
                "arn": "arn:aws:kms:eu-west-1:123:key/key-1",
                "alias": "alias/app",
                "key_manager": "CUSTOMER",
                "key_state": "Enabled",
                "rotation_enabled": False,
            }
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "MEDIUM")

    def test_pending_deletion_is_high(self) -> None:
        findings = kms.kms_findings_for_key(
            {
                "id": "key-1",
                "arn": "arn:aws:kms:eu-west-1:123:key/key-1",
                "key_manager": "AWS",
                "key_state": "PendingDeletion",
            }
        )
        self.assertEqual(findings[0][0], "HIGH")


class TestCollectRegionalKmsInventory(unittest.TestCase):
    @mock.patch("aws_account_audit.kms.client")
    @mock.patch("aws_account_audit.kms.safe_call")
    def test_collects_key_metadata_and_last_used(
        self,
        safe_call_mock: mock.Mock,
        client_mock: mock.Mock,
    ) -> None:
        kms_client = mock.Mock()
        trail_client = mock.Mock()
        client_mock.side_effect = [kms_client, trail_client]

        used = datetime(2025, 6, 1, tzinfo=timezone.utc)

        def _safe_call(label: str, func: mock.Mock, **_kwargs: object) -> tuple[object, None]:
            if label.startswith("kms.list_keys"):
                return (
                    {
                        "Keys": [
                            {
                                "KeyId": "key-1",
                                "KeyArn": "arn:aws:kms:eu-west-1:123:key/key-1",
                            }
                        ],
                        "Truncated": False,
                    },
                    None,
                )
            if label.startswith("kms.list_aliases"):
                return (
                    {
                        "Aliases": [
                            {
                                "AliasName": "alias/app",
                                "TargetKeyId": "key-1",
                            }
                        ],
                        "Truncated": False,
                    },
                    None,
                )
            if label.startswith("kms.describe_key"):
                return (
                    {
                        "KeyMetadata": {
                            "KeyId": "key-1",
                            "KeyManager": "CUSTOMER",
                            "KeyState": "Enabled",
                            "KeyUsage": "ENCRYPT_DECRYPT",
                            "KeySpec": "SYMMETRIC_DEFAULT",
                        }
                    },
                    None,
                )
            if label.startswith("kms.get_key_rotation_status"):
                return ({"KeyRotationEnabled": True}, None)
            if label.startswith("cloudtrail.lookup_events"):
                return (
                    {
                        "Events": [
                            {
                                "EventTime": used,
                                "Resources": [
                                    {
                                        "ResourceType": "AWS::KMS::Key",
                                        "ResourceName": "arn:aws:kms:eu-west-1:123:key/key-1",
                                    }
                                ],
                            }
                        ]
                    },
                    None,
                )
            raise AssertionError(f"unexpected safe_call: {label}")

        safe_call_mock.side_effect = _safe_call

        keys, errors = kms.collect_regional_kms_inventory(mock.Mock(), "eu-west-1")
        self.assertEqual(errors, [])
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["alias"], "alias/app")
        self.assertEqual(keys[0]["last_used_at"], used)


class TestCollectRegionalKmsCollector(unittest.TestCase):
    @mock.patch("aws_account_audit.collectors.collect_regional_kms_inventory")
    def test_emits_findings_from_inventory_rows(self, collect_mock: mock.Mock) -> None:
        collect_mock.return_value = (
            [
                {
                    "id": "key-1",
                    "arn": "arn:aws:kms:eu-west-1:123:key/key-1",
                    "alias": "alias/app",
                    "key_manager": "CUSTOMER",
                    "key_state": "Enabled",
                    "rotation_enabled": False,
                    "region": "eu-west-1",
                }
            ],
            [],
        )
        result = collect_regional_kms(mock.Mock(), "eu-west-1")
        self.assertEqual(result.data["count"], 1)
        self.assertEqual(len(result.findings), 1)
        self.assertIsInstance(result.findings[0], Finding)


if __name__ == "__main__":
    unittest.main()
