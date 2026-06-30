from __future__ import annotations

import unittest
from unittest import mock

from aws_account_audit import account_check as ac
from aws_account_audit.organizations import (
    OrganizationAccount,
    OrganizationInfo,
    assume_role_credentials,
    describe_organization,
    filter_organization_accounts,
    list_organization_accounts,
)


class TestFilterOrganizationAccounts(unittest.TestCase):
    def test_include_and_exclude(self) -> None:
        accounts = [
            OrganizationAccount(account_id="111", name="one", status="ACTIVE"),
            OrganizationAccount(account_id="222", name="two", status="ACTIVE"),
            OrganizationAccount(account_id="333", name="three", status="ACTIVE"),
        ]
        filtered = filter_organization_accounts(
            accounts,
            include_accounts=["111", "333"],
            exclude_accounts=["333"],
        )
        self.assertEqual([account.account_id for account in filtered], ["111"])


class TestDescribeOrganization(unittest.TestCase):
    @mock.patch("aws_account_audit.organizations.safe_call")
    def test_returns_organization_info(self, safe_call_mock: mock.Mock) -> None:
        safe_call_mock.return_value = (
            {
                "Organization": {
                    "Id": "o-abc123",
                    "MasterAccountId": "111111111111",
                    "Arn": "arn:aws:organizations::111111111111:organization/o-abc123",
                }
            },
            None,
        )
        info, error = describe_organization(mock.Mock(), "eu-west-1")
        self.assertIsNone(error)
        assert info is not None
        self.assertEqual(info.organization_id, "o-abc123")
        self.assertEqual(info.master_account_id, "111111111111")
        safe_call_mock.assert_called_once()


class TestListOrganizationAccounts(unittest.TestCase):
    @mock.patch("aws_account_audit.organizations.safe_call")
    def test_skips_non_active_accounts(self, safe_call_mock: mock.Mock) -> None:
        safe_call_mock.return_value = (
            [
                {"Id": "111", "Name": "active", "Status": "ACTIVE"},
                {"Id": "222", "Name": "suspended", "Status": "SUSPENDED"},
            ],
            None,
        )
        accounts, error = list_organization_accounts(mock.Mock(), "eu-west-1")
        self.assertIsNone(error)
        self.assertEqual([account.account_id for account in accounts], ["111"])
        safe_call_mock.assert_called_once()


class TestAssumeRoleCredentials(unittest.TestCase):
    @mock.patch("aws_account_audit.organizations.safe_call")
    def test_returns_env_ready_credentials(self, safe_call_mock: mock.Mock) -> None:
        safe_call_mock.return_value = (
            {
                "Credentials": {
                    "AccessKeyId": "AKIA",
                    "SecretAccessKey": "secret",
                    "SessionToken": "token",
                }
            },
            None,
        )
        credentials, error = assume_role_credentials(
            mock.Mock(),
            account_id="222222222222",
            role_name="AuditReadOnly",
            region="eu-west-1",
        )
        self.assertIsNone(error)
        assert credentials is not None
        self.assertEqual(credentials["AWS_ACCESS_KEY_ID"], "AKIA")
        self.assertEqual(credentials["AWS_SESSION_TOKEN"], "token")
        safe_call_mock.assert_called_once()


class TestOrganizationScanMain(unittest.TestCase):
    @mock.patch("aws_account_audit.account_check._run_single_account_check")
    @mock.patch("aws_account_audit.account_check.assume_role_credentials")
    @mock.patch("aws_account_audit.account_check.list_organization_accounts")
    @mock.patch("aws_account_audit.account_check.describe_organization")
    def test_scan_organization_runs_each_account(
        self,
        describe_mock: mock.Mock,
        list_mock: mock.Mock,
        assume_mock: mock.Mock,
        single_check_mock: mock.Mock,
    ) -> None:
        describe_mock.return_value = (
            OrganizationInfo(
                organization_id="o-abc123",
                master_account_id="111111111111",
            ),
            None,
        )
        list_mock.return_value = (
            [
                OrganizationAccount(account_id="111111111111", name="mgmt", status="ACTIVE"),
                OrganizationAccount(account_id="222222222222", name="prod", status="ACTIVE"),
            ],
            None,
        )
        assume_mock.return_value = (
            {
                "AWS_ACCESS_KEY_ID": "AKIA",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "AWS_SESSION_TOKEN": "token",
            },
            None,
        )
        single_check_mock.return_value = (0, {"account_id": "placeholder"})

        rc = ac.main(
            [
                "--scan-organization",
                "--profile",
                "default",
                "--region",
                "eu-west-1",
                "--output-dir",
                "/tmp/org-runs",
            ]
        )

        self.assertEqual(rc, 0)
        self.assertEqual(single_check_mock.call_count, 2)
        assume_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
