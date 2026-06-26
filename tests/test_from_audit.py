from __future__ import annotations

import unittest
from unittest import mock

from aws_network_map import from_audit


class ExtractTargetsTests(unittest.TestCase):
    def test_extract_targets_from_compute_section(self) -> None:
        report = {
            "sections": [
                {
                    "name": "resources:compute:us-east-2",
                    "data": {
                        "open_security_group_rules": [
                            {"group_id": "sg-aaa111"},
                            {"group_id": "sg-bbb222"},
                            {"group_id": "sg-aaa111"},
                        ]
                    },
                }
            ],
            "findings": [],
        }

        targets = from_audit._extract_targets(report, default_region="eu-west-1")

        self.assertEqual(targets, {"sg-aaa111": {"us-east-2"}, "sg-bbb222": {"us-east-2"}})

    def test_extract_targets_falls_back_to_finding_text(self) -> None:
        report = {
            "sections": [],
            "findings": [
                {
                    "category": "compute",
                    "detail": "Security group foo (sg-0123abcd) allows ingress from internet.",
                },
                {
                    "category": "iam",
                    "detail": "Non-compute detail with sg-deadbeef should be ignored.",
                },
            ],
        }

        targets = from_audit._extract_targets(report, default_region="eu-west-1")

        self.assertEqual(targets, {"sg-0123abcd": {"eu-west-1"}})


class RunMapCommandTests(unittest.TestCase):
    @mock.patch("aws_network_map.from_audit.subprocess.run")
    def test_run_map_command_uses_timeout_and_returns_exit_code(self, run_mock: mock.Mock) -> None:
        run_mock.return_value.returncode = 7

        result = from_audit._run_map_command(
            group_id="sg-0123abcd",
            region="us-east-2",
            output_base=from_audit.Path("network-maps/test-map"),
            profile="default",
            output_format="export",
            direction="LR",
            timeout_seconds=42,
            dry_run=False,
        )

        self.assertEqual(result, 7)
        run_mock.assert_called_once()
        _, kwargs = run_mock.call_args
        self.assertEqual(kwargs["timeout"], 42)


if __name__ == "__main__":
    unittest.main()
