"""Tests for aws_account_audit.session.safe_call error handling."""

from __future__ import annotations

import unittest
from unittest import mock

from botocore.exceptions import ClientError

from aws_account_audit.session import (
    S3_POLICY_STATUS_ABSENT_CODES,
    S3_POLICY_STATUS_ABSENT_HINTS,
    get_bucket_policy_status,
    region_was_explicit,
    resolve_scan_regions,
    safe_call,
)


def _client_error(code: str, message: str = "boom") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Operation")


class TestSafeCall(unittest.TestCase):
    def test_returns_value_on_success(self) -> None:
        value, error = safe_call("op", lambda: 42)
        self.assertEqual(value, 42)
        self.assertIsNone(error)

    def test_no_such_bucket_policy_is_ignored_when_not_found_ok(self) -> None:
        def raise_no_policy() -> None:
            raise _client_error("NoSuchBucketPolicy", "The bucket policy does not exist")

        value, error = safe_call("s3.get_bucket_policy_status", raise_no_policy, not_found_ok=True)
        self.assertIsNone(value)
        self.assertIsNone(error)

    def test_other_client_error_is_reported(self) -> None:
        def raise_access_denied() -> None:
            raise _client_error("AccessDenied", "no access")

        value, error = safe_call(
            "s3.get_bucket_policy_status", raise_access_denied, not_found_ok=True
        )
        self.assertIsNone(value)
        self.assertIsNotNone(error)
        self.assertIn("AccessDenied", error)

    def test_not_found_hint_matches_message(self) -> None:
        def raise_weird_code() -> None:
            raise _client_error("SomeOtherCode", "The bucket policy does not exist")

        value, error = safe_call(
            "s3.get_bucket_policy_status",
            raise_weird_code,
            not_found_ok=True,
            not_found_hints=("bucket policy does not exist",),
        )
        self.assertIsNone(value)
        self.assertIsNone(error)

    def test_directory_bucket_not_supported_is_ignored(self) -> None:
        def raise_not_supported() -> None:
            raise _client_error(
                "NotImplemented",
                "This operation is not supported for directory buckets",
            )

        value, error = safe_call(
            "s3.get_bucket_policy_status",
            raise_not_supported,
            not_found_ok=True,
            not_found_codes=S3_POLICY_STATUS_ABSENT_CODES,
            not_found_hints=S3_POLICY_STATUS_ABSENT_HINTS,
        )
        self.assertIsNone(value)
        self.assertIsNone(error)


class TestGetBucketPolicyStatus(unittest.TestCase):
    def test_delegates_to_safe_call(self) -> None:
        s3 = mock.MagicMock()
        s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
        status, error = get_bucket_policy_status(s3, "my-bucket")
        self.assertEqual(status, {"IsPublic": False})
        self.assertIsNone(error)
        s3.get_bucket_policy_status.assert_called_once_with(Bucket="my-bucket")


class TestRegionWasExplicit(unittest.TestCase):
    def test_detects_region_flag(self) -> None:
        self.assertTrue(region_was_explicit(["--region", "eu-west-1"]))
        self.assertTrue(region_was_explicit(["--region=eu-west-1"]))
        self.assertFalse(region_was_explicit(["--profile", "default"]))
        self.assertFalse(region_was_explicit(None))


class TestResolveScanRegions(unittest.TestCase):
    @mock.patch("aws_account_audit.session.enabled_regions")
    def test_explicit_regions_list(self, enabled_mock: mock.Mock) -> None:
        result = resolve_scan_regions(
            profile=None,
            region="eu-west-1",
            regions=["us-east-1", "eu-west-1"],
            all_regions=None,
            region_explicit=False,
        )
        self.assertEqual(result, ["eu-west-1", "us-east-1"])
        enabled_mock.assert_not_called()

    @mock.patch("aws_account_audit.session.enabled_regions")
    def test_all_regions_flag(self, enabled_mock: mock.Mock) -> None:
        enabled_mock.return_value = ["eu-west-1", "us-east-2"]
        result = resolve_scan_regions(
            profile=None,
            region="eu-west-1",
            regions=None,
            all_regions=True,
            region_explicit=True,
        )
        self.assertEqual(result, ["eu-west-1", "us-east-2"])
        enabled_mock.assert_called_once()

    @mock.patch("aws_account_audit.session.enabled_regions")
    def test_no_all_regions_uses_home_region(self, enabled_mock: mock.Mock) -> None:
        result = resolve_scan_regions(
            profile=None,
            region="eu-west-1",
            regions=None,
            all_regions=False,
            region_explicit=False,
        )
        self.assertEqual(result, ["eu-west-1"])
        enabled_mock.assert_not_called()

    @mock.patch("aws_account_audit.session.enabled_regions")
    def test_explicit_region_without_all_regions(self, enabled_mock: mock.Mock) -> None:
        result = resolve_scan_regions(
            profile=None,
            region="eu-west-1",
            regions=None,
            all_regions=None,
            region_explicit=True,
        )
        self.assertEqual(result, ["eu-west-1"])
        enabled_mock.assert_not_called()

    @mock.patch("aws_account_audit.session.enabled_regions")
    def test_default_scans_all_enabled_regions(self, enabled_mock: mock.Mock) -> None:
        enabled_mock.return_value = ["eu-west-1", "us-east-1"]
        result = resolve_scan_regions(
            profile=None,
            region="eu-west-1",
            regions=None,
            all_regions=None,
            region_explicit=False,
        )
        self.assertEqual(result, ["eu-west-1", "us-east-1"])
        enabled_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
