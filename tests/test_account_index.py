from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aws_account_audit import account_index as ai


def _summary() -> dict:
    return {
        "account_id": "123456789012",
        "audit_json": "audit-runs/audit.json",
        "audit_text": "audit-runs/audit.log",
        "iam_audit_json": "iam-runs/iam-audit.json",
        "iam_graph_json": "iam-runs/iam-graph.json",
        "iam_graph_html": "iam-runs/iam-graph.html",
        "iam_graph_png": "iam-runs/iam-graph.png",
        "iam_graph_summary": {
            "user_count": 3,
            "group_count": 2,
            "role_count": 5,
            "policy_count": 7,
            "edge_count": 9,
        },
        "account_graph_json": "network-maps/account-graph.json",
        "account_graph_html": "network-maps/account-graph.html",
        "account_graph_png": "network-maps/account-graph.png",
    }


class TestRenderAccountIndexHtml(unittest.TestCase):
    def test_returns_doctype(self) -> None:
        html = ai.render_account_index_html(summary=_summary(), run_dir=Path("/tmp/run"))
        self.assertTrue(html.strip().lower().startswith("<!doctype html"))

    def test_contains_account_id(self) -> None:
        html = ai.render_account_index_html(summary=_summary(), run_dir=Path("/tmp/run"))
        self.assertIn("123456789012", html)

    def test_links_relative_to_run_dir(self) -> None:
        """Artifact links are relative to the run directory, not absolute."""
        run = Path("/tmp/run")
        summary = _summary()
        summary["iam_graph_html"] = "/tmp/run/iam-runs/iam-graph.html"
        html = ai.render_account_index_html(summary=summary, run_dir=run)
        self.assertIn('href="iam-runs/iam-graph.html"', html)
        self.assertNotIn('href="/tmp/run/iam-runs/iam-graph.html"', html)

    def test_links_to_separate_findings_page(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            run_root = Path(d)
            summary = _org_summary(run_root)
            account_summary = summary["accounts"][0]["summary"]
            run_dir = run_root / "account-123456789012"
            html = ai.render_account_index_html(
                summary={
                    **_summary(),
                    "audit_json": account_summary["audit_json"],
                    "findings_html": str(run_dir / "findings.html"),
                },
                run_dir=run_dir,
            )
            self.assertIn("card-grid", html)
            self.assertIn("Security findings", html)
            self.assertIn('href="findings.html"', html)
            self.assertIn("By severity", html)
            self.assertNotIn('id="findings-high"', html)

    def test_account_findings_page_renders_groups(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            run_root = Path(d)
            summary = _org_summary(run_root)
            account_summary = summary["accounts"][0]["summary"]
            run_dir = run_root / "account-123456789012"
            html = ai.render_account_findings_html(
                summary={
                    **_summary(),
                    "audit_json": account_summary["audit_json"],
                },
                run_dir=run_dir,
            )
            self.assertIn('id="findings-high"', html)
            self.assertIn("Role has AdministratorAccess", html)
            self.assertIn('href="#findings-high"', html)
            self.assertIn("Back to account view", html)

    def test_marks_interactive_views_as_full_view(self) -> None:
        html = ai.render_account_index_html(summary=_summary(), run_dir=Path("/tmp/run"))
        self.assertIn("full view", html)

    def test_missing_artifact_marked_not_generated(self) -> None:
        summary = _summary()
        summary["account_graph_png"] = None
        html = ai.render_account_index_html(summary=summary, run_dir=Path("/tmp/run"))
        self.assertIn("not generated", html)

    def test_escapes_account_id(self) -> None:
        summary = _summary()
        summary["account_id"] = "<script>"
        html = ai.render_account_index_html(summary=summary, run_dir=Path("/tmp/run"))
        title = html.split("<title>")[1].split("</title>")[0]
        self.assertNotIn("<script>", title)

    def test_network_links_rendered(self) -> None:
        run = Path("/tmp/run")
        links = [("from-audit/sg-1.html", run / "network-maps" / "from-audit" / "sg-1.html")]
        html = ai.render_account_index_html(summary=_summary(), run_dir=run, network_links=links)
        self.assertIn("from-audit/sg-1.html", html)


class TestCollectNetworkMapLinks(unittest.TestCase):
    def test_collects_html_from_known_subdirs(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            network = Path(d)
            (network / "from-audit").mkdir()
            (network / "all-security-groups").mkdir()
            (network / "from-audit" / "a.html").write_text("x", encoding="utf-8")
            (network / "all-security-groups" / "b.html").write_text("x", encoding="utf-8")
            (network / "from-audit" / "ignored.json").write_text("{}", encoding="utf-8")

            links = ai.collect_network_map_links(network)
            labels = [label for label, _ in links]

        self.assertIn("from-audit/a.html", labels)
        self.assertIn("all-security-groups/b.html", labels)
        self.assertNotIn("from-audit/ignored.json", labels)

    def test_missing_dirs_return_empty(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            links = ai.collect_network_map_links(Path(d))
        self.assertEqual(links, [])


class TestWriteAccountIndexHtml(unittest.TestCase):
    def test_writes_account_view_and_findings_files(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            run = Path(d) / "account-123"
            index_path, findings_path = ai.write_account_index_html(summary=_summary(), run_dir=run)
            self.assertTrue(index_path.exists())
            self.assertEqual(index_path.name, "account-view.html")
            index_html = index_path.read_text(encoding="utf-8")
            self.assertIn("123456789012", index_html)
            self.assertIn("card-grid", index_html)
            self.assertIn('href="findings.html"', index_html)
            self.assertIn("full view", index_html)
            self.assertTrue(findings_path.exists())
            self.assertEqual(findings_path.name, "findings.html")


def _org_summary(run_root: Path) -> dict:
    account_dir = run_root / "account-123456789012"
    account_dir.mkdir(parents=True, exist_ok=True)
    audit_dir = account_dir / "audit-runs"
    audit_dir.mkdir(parents=True, exist_ok=True)
    audit_json = audit_dir / "audit.json"
    audit_json.write_text(
        json.dumps(
            {
                "summary": {
                    "finding_count": 3,
                    "resource_count": 12,
                    "findings_by_severity": {"HIGH": 2, "MEDIUM": 1},
                },
                "findings": [
                    {
                        "severity": "HIGH",
                        "category": "iam",
                        "title": "Role has AdministratorAccess",
                        "detail": "IAM role AdminRole is attached to AdministratorAccess.",
                        "resource_arn": "arn:aws:iam::123456789012:role/AdminRole",
                    },
                    {
                        "severity": "HIGH",
                        "category": "security",
                        "title": "GuardDuty not enabled",
                        "detail": "No GuardDuty detector found.",
                        "resource_arn": None,
                    },
                    {
                        "severity": "MEDIUM",
                        "category": "iam",
                        "title": "Active IAM access key",
                        "detail": "User ci-bot has active access key.",
                        "resource_arn": None,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    account_view = account_dir / "account-view.html"
    account_view.write_text("<html>account</html>", encoding="utf-8")
    return {
        "organization_id": "o-abc123",
        "organization_arn": "arn:aws:organizations::123456789012:organization/o-abc123",
        "master_account_id": "123456789012",
        "role_name": "OrganizationAccountAccessRole",
        "accounts_requested": 2,
        "accounts_failed": 1,
        "accounts": [
            {
                "account_id": "123456789012",
                "account_name": "management",
                "scan_status": "failed",
                "summary": {
                    "audit_json": str(audit_json),
                    "account_view_html": str(account_view),
                    "iam_graph_summary": {"role_count": 5},
                },
            },
            {
                "account_id": "210987654321",
                "account_name": "member",
                "scan_status": "assume_role_failed",
                "error": "sts.assume_role: AccessDenied",
            },
        ],
    }


class TestRenderOrganizationIndexHtml(unittest.TestCase):
    def test_renders_org_table_with_account_links(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            run_root = Path(d)
            org_dir = run_root / "organization-o-abc123"
            summary = _org_summary(run_root)
            html = ai.render_organization_index_html(
                org_summary=summary,
                org_dir=org_dir,
                output_dir=run_root,
            )
            self.assertIn("Organization view: o-abc123", html)
            self.assertIn("123456789012", html)
            self.assertIn("HIGH: 2", html)
            self.assertIn("../account-123456789012/findings.html#findings-high", html)
            self.assertIn("organization-findings.html", html)
            self.assertIn("Open organization findings", html)
            self.assertIn("assume role failed", html)
            self.assertIn("AccessDenied", html)

    def test_writes_organization_view_and_findings_files(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            run_root = Path(d)
            org_dir = run_root / "organization-o-abc123"
            summary = _org_summary(run_root)
            index_path, findings_path = ai.write_organization_index_html(
                org_summary=summary,
                org_dir=org_dir,
                output_dir=run_root,
            )
            self.assertEqual(index_path.name, "organization-view.html")
            index_html = index_path.read_text(encoding="utf-8")
            self.assertIn("organization-check-summary.json", index_html)
            self.assertIn("organization-findings.html", index_html)
            self.assertEqual(findings_path.name, "organization-findings.html")
            self.assertIn("Role has AdministratorAccess", findings_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
