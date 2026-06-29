"""Tests for aws_account_audit.iam_graph (TDD – written before implementation).

Proposed public API
-------------------
  IamGraph (dataclass)
      nodes: dict[str, dict]      – node_id -> {"node_id", "kind", "label", "metadata"}
      edges: list[dict]           – {"source", "target", "label", "edge_type"}
      errors: list[str]           – non-fatal problems found during build

      summary() -> dict
          Returns {"node_count", "edge_count", "error_count",
                   "user_count", "group_count", "role_count", "policy_count"}.

  build_iam_graph(iam_data: dict) -> IamGraph
      Accepts the dict produced by collect_iam's SectionResult.data.
      Recognised keys: users, groups, roles,
                       admin_users, admin_groups, admin_roles.
      Node kinds created:
          "user"    – one per entry in users   (node_id: "user:<name>")
          "group"   – one per entry in groups  (node_id: "group:<name>")
          "role"    – one per entry in roles   (node_id: "role:<name>")
          "policy"  – "policy:AdministratorAccess" when ≥1 admin principal exists
      Edges:
          admin principal -> policy:AdministratorAccess
              label="admin", edge_type="attached_to"
      Admin names in admin_* that do not match any known principal are
      recorded in errors (no exception raised).
      Duplicate edges (same source+target+label) appear only once.

  render_iam_mermaid(graph: IamGraph, *, direction: str = "LR") -> str
      Mermaid flowchart string starting with "flowchart <direction>".

  render_iam_html(graph: IamGraph, *, direction: str = "LR") -> str
      Self-contained HTML page with an embedded Mermaid diagram.

  write_iam_html(graph: IamGraph, path: Path, *, direction: str = "LR") -> None
      Writes render_iam_html output to *path*, creating parent directories.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aws_account_audit import iam_graph as ig


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_iam_data(
    *,
    users: list[dict] | None = None,
    groups: list[dict] | None = None,
    roles: list[dict] | None = None,
    admin_users: list[str] | None = None,
    admin_groups: list[str] | None = None,
    admin_roles: list[str] | None = None,
) -> dict:
    """Build a minimal iam_data dict in the shape produced by collect_iam."""
    return {
        "users": users if users is not None else [],
        "groups": groups if groups is not None else [],
        "roles": roles if roles is not None else [],
        "admin_users": admin_users if admin_users is not None else [],
        "admin_groups": admin_groups if admin_groups is not None else [],
        "admin_roles": admin_roles if admin_roles is not None else [],
    }


def _user(name: str, arn: str | None = None) -> dict:
    return {"name": name, "arn": arn or f"arn:aws:iam::123456789012:user/{name}"}


def _group(name: str, arn: str | None = None) -> dict:
    return {"name": name, "arn": arn or f"arn:aws:iam::123456789012:group/{name}"}


def _role(name: str, arn: str | None = None) -> dict:
    return {"name": name, "arn": arn or f"arn:aws:iam::123456789012:role/{name}"}


# ---------------------------------------------------------------------------
# build_iam_graph – empty / minimal input
# ---------------------------------------------------------------------------


class TestBuildIamGraphEmpty(unittest.TestCase):
    def test_empty_data_returns_graph(self) -> None:
        """build_iam_graph({}) returns an IamGraph without raising."""
        result = ig.build_iam_graph({})
        self.assertIsNotNone(result)

    def test_empty_data_has_no_nodes(self) -> None:
        """An empty iam_data dict produces a graph with no nodes."""
        graph = ig.build_iam_graph({})
        self.assertEqual(graph.nodes, {})

    def test_empty_data_has_no_edges(self) -> None:
        """An empty iam_data dict produces a graph with no edges."""
        graph = ig.build_iam_graph({})
        self.assertEqual(graph.edges, [])

    def test_empty_data_has_no_errors(self) -> None:
        """An empty iam_data dict produces a graph with no errors."""
        graph = ig.build_iam_graph({})
        self.assertEqual(graph.errors, [])

    def test_missing_keys_do_not_raise(self) -> None:
        """build_iam_graph tolerates iam_data with only some keys present."""
        ig.build_iam_graph({"users": [_user("alice")]})
        ig.build_iam_graph({"roles": [_role("MyRole")]})
        ig.build_iam_graph({"groups": []})


# ---------------------------------------------------------------------------
# build_iam_graph – node creation
# ---------------------------------------------------------------------------


class TestBuildIamGraphNodes(unittest.TestCase):
    def setUp(self) -> None:
        self.data = _make_iam_data(
            users=[_user("alice"), _user("bob")],
            groups=[_group("developers"), _group("ops")],
            roles=[_role("LambdaExec"), _role("EC2Role")],
        )
        self.graph = ig.build_iam_graph(self.data)

    def test_user_nodes_created(self) -> None:
        """One node per user entry exists in the graph."""
        self.assertIn("user:alice", self.graph.nodes)
        self.assertIn("user:bob", self.graph.nodes)

    def test_user_node_has_correct_kind(self) -> None:
        """User nodes carry kind='user'."""
        self.assertEqual(self.graph.nodes["user:alice"]["kind"], "user")

    def test_user_node_label_contains_name(self) -> None:
        """User node label contains the user name."""
        self.assertIn("alice", self.graph.nodes["user:alice"]["label"])

    def test_group_nodes_created(self) -> None:
        """One node per group entry exists in the graph."""
        self.assertIn("group:developers", self.graph.nodes)
        self.assertIn("group:ops", self.graph.nodes)

    def test_group_node_has_correct_kind(self) -> None:
        """Group nodes carry kind='group'."""
        self.assertEqual(self.graph.nodes["group:developers"]["kind"], "group")

    def test_role_nodes_created(self) -> None:
        """One node per role entry exists in the graph."""
        self.assertIn("role:LambdaExec", self.graph.nodes)
        self.assertIn("role:EC2Role", self.graph.nodes)

    def test_role_node_has_correct_kind(self) -> None:
        """Role nodes carry kind='role'."""
        self.assertEqual(self.graph.nodes["role:LambdaExec"]["kind"], "role")

    def test_node_count_matches_principals(self) -> None:
        """Total node count equals the sum of users + groups + roles (no admin yet)."""
        self.assertEqual(len(self.graph.nodes), 6)

    def test_node_metadata_contains_arn(self) -> None:
        """Node metadata includes the ARN from the source record."""
        arn = self.graph.nodes["user:alice"]["metadata"]["arn"]
        self.assertIn("alice", arn)

    def test_no_admin_policy_node_without_admin_principals(self) -> None:
        """The AdministratorAccess policy node is absent when no admin principals exist."""
        self.assertNotIn("policy:AdministratorAccess", self.graph.nodes)


# ---------------------------------------------------------------------------
# build_iam_graph – admin edges
# ---------------------------------------------------------------------------


class TestBuildIamGraphAdminEdges(unittest.TestCase):
    def setUp(self) -> None:
        self.data = _make_iam_data(
            users=[_user("alice"), _user("bob")],
            groups=[_group("admins")],
            roles=[_role("BreakGlass")],
            admin_users=["alice"],
            admin_groups=["admins"],
            admin_roles=["BreakGlass"],
        )
        self.graph = ig.build_iam_graph(self.data)

    def test_admin_policy_node_created_when_admins_present(self) -> None:
        """policy:AdministratorAccess node exists when any admin principal is found."""
        self.assertIn("policy:AdministratorAccess", self.graph.nodes)

    def test_admin_policy_node_kind(self) -> None:
        """The AdministratorAccess policy node has kind='policy'."""
        self.assertEqual(self.graph.nodes["policy:AdministratorAccess"]["kind"], "policy")

    def test_admin_user_edge_created(self) -> None:
        """An edge from the admin user to policy:AdministratorAccess is created."""
        sources = [
            e["source"] for e in self.graph.edges if e["target"] == "policy:AdministratorAccess"
        ]
        self.assertIn("user:alice", sources)

    def test_non_admin_user_has_no_admin_edge(self) -> None:
        """Non-admin user bob has no edge to the admin policy node."""
        sources = [
            e["source"] for e in self.graph.edges if e["target"] == "policy:AdministratorAccess"
        ]
        self.assertNotIn("user:bob", sources)

    def test_admin_group_edge_created(self) -> None:
        """An edge from the admin group to policy:AdministratorAccess is created."""
        sources = [
            e["source"] for e in self.graph.edges if e["target"] == "policy:AdministratorAccess"
        ]
        self.assertIn("group:admins", sources)

    def test_admin_role_edge_created(self) -> None:
        """An edge from the admin role to policy:AdministratorAccess is created."""
        sources = [
            e["source"] for e in self.graph.edges if e["target"] == "policy:AdministratorAccess"
        ]
        self.assertIn("role:BreakGlass", sources)

    def test_admin_edge_label(self) -> None:
        """Each admin edge carries label='admin'."""
        admin_edges = [e for e in self.graph.edges if e["target"] == "policy:AdministratorAccess"]
        self.assertTrue(all(e["label"] == "admin" for e in admin_edges))

    def test_admin_edge_type(self) -> None:
        """Each admin edge carries edge_type='attached_to'."""
        admin_edges = [e for e in self.graph.edges if e["target"] == "policy:AdministratorAccess"]
        self.assertTrue(all(e["edge_type"] == "attached_to" for e in admin_edges))

    def test_admin_edge_count_matches_admin_principal_count(self) -> None:
        """Exactly one edge per known admin principal (1 user + 1 group + 1 role = 3)."""
        admin_edges = [e for e in self.graph.edges if e["target"] == "policy:AdministratorAccess"]
        self.assertEqual(len(admin_edges), 3)


# ---------------------------------------------------------------------------
# build_iam_graph – edge cases and error handling
# ---------------------------------------------------------------------------


class TestBuildIamGraphEdgeCases(unittest.TestCase):
    def test_unknown_admin_user_recorded_in_errors(self) -> None:
        """Admin user name not present in users list is added to errors, not raised."""
        data = _make_iam_data(
            users=[_user("alice")],
            admin_users=["ghost"],
        )
        graph = ig.build_iam_graph(data)
        self.assertTrue(any("ghost" in err for err in graph.errors))

    def test_unknown_admin_group_recorded_in_errors(self) -> None:
        """Admin group name not present in groups list is added to errors."""
        data = _make_iam_data(
            groups=[_group("devs")],
            admin_groups=["nonexistent-group"],
        )
        graph = ig.build_iam_graph(data)
        self.assertTrue(any("nonexistent-group" in err for err in graph.errors))

    def test_unknown_admin_role_recorded_in_errors(self) -> None:
        """Admin role name not present in roles list is added to errors."""
        data = _make_iam_data(
            roles=[_role("ValidRole")],
            admin_roles=["PhantomRole"],
        )
        graph = ig.build_iam_graph(data)
        self.assertTrue(any("PhantomRole" in err for err in graph.errors))

    def test_duplicate_admin_edge_not_created(self) -> None:
        """Duplicate entries in admin_users produce only one edge."""
        data = _make_iam_data(
            users=[_user("alice")],
            admin_users=["alice", "alice"],
        )
        graph = ig.build_iam_graph(data)
        matching = [
            e
            for e in graph.edges
            if e["source"] == "user:alice" and e["target"] == "policy:AdministratorAccess"
        ]
        self.assertEqual(len(matching), 1)

    def test_user_with_no_arn_field_still_creates_node(self) -> None:
        """Users missing 'arn' in their record still produce a node."""
        data = _make_iam_data(users=[{"name": "bare_user"}])
        graph = ig.build_iam_graph(data)
        self.assertIn("user:bare_user", graph.nodes)

    def test_users_with_special_characters_in_name(self) -> None:
        """User names containing dots, hyphens, and plus signs are accepted."""
        data = _make_iam_data(users=[_user("first.last+tag-01")])
        graph = ig.build_iam_graph(data)
        self.assertIn("user:first.last+tag-01", graph.nodes)

    def test_empty_admin_lists_produce_no_policy_node(self) -> None:
        """Passing empty admin_* lists yields no policy:AdministratorAccess node."""
        data = _make_iam_data(
            users=[_user("alice")],
            admin_users=[],
            admin_groups=[],
            admin_roles=[],
        )
        graph = ig.build_iam_graph(data)
        self.assertNotIn("policy:AdministratorAccess", graph.nodes)

    def test_large_principal_list_no_exception(self) -> None:
        """build_iam_graph handles 500 users without raising."""
        many_users = [_user(f"user{i:04d}") for i in range(500)]
        data = _make_iam_data(users=many_users)
        graph = ig.build_iam_graph(data)
        self.assertEqual(len(graph.nodes), 500)


# ---------------------------------------------------------------------------
# IamGraph – summary()
# ---------------------------------------------------------------------------


class TestIamGraphSummary(unittest.TestCase):
    def setUp(self) -> None:
        data = _make_iam_data(
            users=[_user("alice"), _user("bob")],
            groups=[_group("devs")],
            roles=[_role("LambdaExec"), _role("EC2Role")],
            admin_users=["alice"],
        )
        self.graph = ig.build_iam_graph(data)

    def test_summary_returns_dict(self) -> None:
        """summary() returns a dict."""
        self.assertIsInstance(self.graph.summary(), dict)

    def test_summary_node_count(self) -> None:
        """summary()['node_count'] matches len(nodes)."""
        s = self.graph.summary()
        self.assertIn("node_count", s)
        self.assertEqual(s["node_count"], len(self.graph.nodes))

    def test_summary_edge_count(self) -> None:
        """summary()['edge_count'] matches len(edges)."""
        s = self.graph.summary()
        self.assertIn("edge_count", s)
        self.assertEqual(s["edge_count"], len(self.graph.edges))

    def test_summary_error_count(self) -> None:
        """summary()['error_count'] matches len(errors)."""
        s = self.graph.summary()
        self.assertIn("error_count", s)
        self.assertEqual(s["error_count"], len(self.graph.errors))

    def test_summary_user_count(self) -> None:
        """summary()['user_count'] reflects the number of user nodes."""
        s = self.graph.summary()
        self.assertIn("user_count", s)
        self.assertEqual(s["user_count"], 2)

    def test_summary_group_count(self) -> None:
        """summary()['group_count'] reflects the number of group nodes."""
        s = self.graph.summary()
        self.assertIn("group_count", s)
        self.assertEqual(s["group_count"], 1)

    def test_summary_role_count(self) -> None:
        """summary()['role_count'] reflects the number of role nodes."""
        s = self.graph.summary()
        self.assertIn("role_count", s)
        self.assertEqual(s["role_count"], 2)

    def test_summary_policy_count(self) -> None:
        """summary()['policy_count'] reflects the number of policy nodes."""
        s = self.graph.summary()
        self.assertIn("policy_count", s)
        self.assertEqual(s["policy_count"], 1)

    def test_summary_empty_graph_all_zeros(self) -> None:
        """summary() on an empty graph returns all-zero counts."""
        graph = ig.build_iam_graph({})
        s = graph.summary()
        for key in (
            "node_count",
            "edge_count",
            "error_count",
            "user_count",
            "group_count",
            "role_count",
            "policy_count",
        ):
            self.assertEqual(s[key], 0, msg=f"{key} should be 0")


# ---------------------------------------------------------------------------
# render_iam_mermaid
# ---------------------------------------------------------------------------


class TestRenderIamMermaid(unittest.TestCase):
    def setUp(self) -> None:
        data = _make_iam_data(
            users=[_user("alice")],
            roles=[_role("LambdaExec")],
            admin_users=["alice"],
        )
        self.graph = ig.build_iam_graph(data)

    def test_returns_str(self) -> None:
        """render_iam_mermaid() returns a str."""
        self.assertIsInstance(ig.render_iam_mermaid(self.graph), str)

    def test_starts_with_flowchart(self) -> None:
        """Output begins with 'flowchart'."""
        mmd = ig.render_iam_mermaid(self.graph)
        self.assertTrue(mmd.strip().startswith("flowchart"))

    def test_default_direction_tb(self) -> None:
        """Default direction is TB."""
        mmd = ig.render_iam_mermaid(self.graph)
        self.assertIn("TB", mmd.splitlines()[0])

    def test_custom_direction_lr(self) -> None:
        """Passing direction='LR' sets direction to LR."""
        mmd = ig.render_iam_mermaid(self.graph, direction="LR")
        self.assertIn("LR", mmd.splitlines()[0])

    def test_node_label_present(self) -> None:
        """A principal name appears in the Mermaid output."""
        mmd = ig.render_iam_mermaid(self.graph)
        self.assertIn("alice", mmd)

    def test_empty_graph_produces_valid_flowchart(self) -> None:
        """render_iam_mermaid() on an empty graph returns at least the header line."""
        empty = ig.build_iam_graph({})
        mmd = ig.render_iam_mermaid(empty)
        self.assertIn("flowchart", mmd)

    def test_mermaid_id_sanitisation(self) -> None:
        """Node IDs with colons are safe for Mermaid (no raw colon in diagram node IDs)."""
        data = _make_iam_data(users=[_user("alice")])
        graph = ig.build_iam_graph(data)
        mmd = ig.render_iam_mermaid(graph)
        # The node declaration line must not expose a raw colon inside [] or ()
        # (Mermaid node IDs must be identifier-safe).
        node_decl_lines = [line for line in mmd.splitlines() if "[" in line or "(" in line]
        for line in node_decl_lines:
            node_id_part = line.strip().split("[")[0].split("(")[0]
            self.assertNotIn(":", node_id_part)


# ---------------------------------------------------------------------------
# render_iam_html
# ---------------------------------------------------------------------------


class TestRenderIamHtml(unittest.TestCase):
    def setUp(self) -> None:
        data = _make_iam_data(
            users=[_user("alice")],
            admin_users=["alice"],
        )
        self.graph = ig.build_iam_graph(data)

    def test_returns_str(self) -> None:
        """render_iam_html() returns a str."""
        self.assertIsInstance(ig.render_iam_html(self.graph), str)

    def test_starts_with_doctype(self) -> None:
        """Output begins with an HTML doctype declaration."""
        html = ig.render_iam_html(self.graph)
        self.assertTrue(html.strip().lower().startswith("<!doctype html"))

    def test_contains_mermaid_reference(self) -> None:
        """Output embeds the Mermaid library (script tag or class attribute)."""
        html = ig.render_iam_html(self.graph)
        self.assertIn("mermaid", html)

    def test_contains_principal_label(self) -> None:
        """A principal name from the graph appears in the rendered HTML."""
        html = ig.render_iam_html(self.graph)
        self.assertIn("alice", html)

    def test_empty_graph_does_not_raise(self) -> None:
        """render_iam_html() handles an empty IamGraph without error."""
        empty = ig.build_iam_graph({})
        result = ig.render_iam_html(empty)
        self.assertIsInstance(result, str)

    def test_direction_tb_reflected_in_output(self) -> None:
        """Passing direction='TB' causes TB to appear in the HTML."""
        html = ig.render_iam_html(self.graph, direction="TB")
        self.assertIn("TB", html)

    def test_html_escapes_special_chars(self) -> None:
        """Principal names containing < > & do not appear unescaped in the title."""
        data = _make_iam_data(users=[_user("<script>&")])
        graph = ig.build_iam_graph(data)
        html = ig.render_iam_html(graph)
        title_block = html.split("<title>")[1].split("</title>")[0]
        self.assertNotIn("<script>", title_block)


# ---------------------------------------------------------------------------
# write_iam_html
# ---------------------------------------------------------------------------


class TestWriteIamHtml(unittest.TestCase):
    def _graph(self) -> ig.IamGraph:
        return ig.build_iam_graph(_make_iam_data(users=[_user("alice")]))

    def test_creates_file(self) -> None:
        """write_iam_html() creates the target file on disk."""
        graph = self._graph()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iam.html"
            ig.write_iam_html(graph, out)
            self.assertTrue(out.exists())

    def test_content_matches_render(self) -> None:
        """File content equals render_iam_html() for the same graph and direction."""
        graph = self._graph()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iam.html"
            ig.write_iam_html(graph, out, direction="TB")
            written = out.read_text()
        expected = ig.render_iam_html(graph, direction="TB")
        self.assertEqual(written, expected)

    def test_creates_missing_parent_directories(self) -> None:
        """write_iam_html() creates parent directories that do not yet exist."""
        graph = self._graph()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "nested" / "deep" / "iam.html"
            ig.write_iam_html(graph, out)
            self.assertTrue(out.exists())

    def test_overwrites_existing_file(self) -> None:
        """Calling write_iam_html() twice replaces the previous file content."""
        graph_a = ig.build_iam_graph(_make_iam_data(users=[_user("alice")]))
        graph_b = ig.build_iam_graph(_make_iam_data(users=[_user("uniquebob")]))
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iam.html"
            ig.write_iam_html(graph_a, out)
            ig.write_iam_html(graph_b, out)
            content = out.read_text()
        self.assertIn("uniquebob", content)
        self.assertNotIn("alice", content)


class TestWriteIamJson(unittest.TestCase):
    def _graph(self) -> ig.IamGraph:
        graph = ig.build_iam_graph(_make_iam_data(users=[_user("alice")], admin_users=["alice"]))
        graph.account_id = "123456789012"
        return graph

    def test_creates_file(self) -> None:
        """write_iam_json() creates the target JSON file on disk."""
        graph = self._graph()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iam.json"
            ig.write_iam_json(graph, out)
            self.assertTrue(out.exists())

    def test_content_contains_expected_top_level_keys(self) -> None:
        """JSON output contains domain/account/summary/nodes/edges/errors keys."""
        graph = self._graph()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iam.json"
            ig.write_iam_json(graph, out)
            payload = json.loads(out.read_text())
        for key in ("domain", "account_id", "summary", "nodes", "edges", "errors"):
            self.assertIn(key, payload)

    def test_uses_account_id_in_domain(self) -> None:
        """Domain is namespaced with the graph account ID."""
        graph = self._graph()
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iam.json"
            ig.write_iam_json(graph, out)
            payload = json.loads(out.read_text())
        self.assertEqual(payload["domain"], "account:123456789012")

    def test_fallback_account_id_when_unset(self) -> None:
        """Missing account_id is normalized to unknown-account in JSON output."""
        graph = ig.build_iam_graph(_make_iam_data(users=[_user("alice")]))
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "iam.json"
            ig.write_iam_json(graph, out)
            payload = json.loads(out.read_text())
        self.assertEqual(payload["account_id"], "unknown-account")


if __name__ == "__main__":
    unittest.main()
