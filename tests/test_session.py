"""Tests for aws_account_audit.session.safe_call error handling."""

from __future__ import annotations

import unittest

from botocore.exceptions import ClientError

from aws_account_audit.session import safe_call


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

        value, error = safe_call("s3.get_bucket_policy_status", raise_access_denied, not_found_ok=True)
        self.assertIsNone(value)
        self.assertIsNotNone(error)
        self.assertIn("AccessDenied", error)


if __name__ == "__main__":
    unittest.main()
