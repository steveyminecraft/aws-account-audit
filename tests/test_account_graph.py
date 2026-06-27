"""Tests for aws_network_map.account_graph (TDD - written before implementation).

Proposed public API
-------------------
  load_map_json(path: Path) -> dict
      Load and schema-validate one map JSON file produced by render_json().
      Raises FileNotFoundError for missing paths.
      Raises ValueError for invalid JSON or missing required top-level keys.

  merge_maps(maps: list[dict]) -> AccountGraph
      Merge a list of map dicts into a single AccountGraph.
      Deduplicates nodes (by node_id) and edges (by source+target+label).
      Concatenates ingress_paths and errors without deduplication.
      Records the root of every merged map in sources.

  AccountGraph (dataclass)
      nodes: dict[str, dict]          – node_id -> node payload
      edges: list[dict]               – deduplicated edge list
      ingress_paths: list[list[str]]  – all paths from all merged maps
      errors: list[str]               – all errors from all merged maps
      sources: list[str]              – root values of every merged map

      summary() -> dict
          Returns {"node_count", "edge_count", "path_count",
                   "error_count", "source_count"}.

  render_account_html(graph: AccountGraph, *, direction: str = "LR") -> str
      Produces a self-contained HTML page with an embedded Mermaid diagram.

  write_html(graph: AccountGraph, path: Path, *, direction: str = "LR") -> None
      Writes render_account_html output to *path*, creating parent dirs.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aws_network_map import account_graph as ag


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_map(
    root: str = "sg-aaa111",
    region: str = "us-east-1",
    *,
    extra_nodes: list[dict] | None = None,
    extra_edges: list[dict] | None = None,
    ingress_paths: list[list[str]] | None = None,
    errors: list[str] | None = None,
) -> dict:
    """Build a minimal map dict in the shape produced by NetworkGraph.to_dict()."""
    base_nodes = [
        {
            "node_id": f"security_group:{root}",
            "kind": "security_group",
            "label": f"SG {root}",
            "metadata": {"group_id": root},
        },
        {
            "node_id": "internet:0_0_0_0_0",
            "kind": "internet",
            "label": "Internet (0.0.0.0/0)",
            "metadata": {},
        },
    ]
    base_edges = [
        {
            "source": "internet:0_0_0_0_0",
            "target": f"security_group:{root}",
            "label": "tcp/22-22",
            "edge_type": "ingress",
        },
    ]
    return {
        "root": root,
        "region": region,
        "nodes": base_nodes + (extra_nodes or []),
        "edges": base_edges + (extra_edges or []),
        "ingress_paths": ingress_paths
        if ingress_paths is not None
        else [["internet:0_0_0_0_0", f"security_group:{root}"]],
        "errors": errors or [],
    }


# ---------------------------------------------------------------------------
# load_map_json
# ---------------------------------------------------------------------------


class TestLoadMapJson(unittest.TestCase):
    def _write(self, tmp: Path, data: object) -> Path:
        p = tmp / "map.json"
        p.write_text(json.dumps(data))
        return p

    def test_load_map_json_returns_dict_with_required_keys(self) -> None:
        """Loaded dict contains root, region, nodes, edges, ingress_paths, errors."""
        with tempfile.TemporaryDirectory() as d:
            path = self._write(Path(d), _make_map())
            result = ag.load_map_json(path)
        self.assertIn("root", result)
        self.assertIn("region", result)
        self.assertIn("nodes", result)
        self.assertIn("edges", result)
        self.assertIn("ingress_paths", result)
        self.assertIn("errors", result)

    def test_load_map_json_preserves_values(self) -> None:
        """Root and region values round-trip unchanged."""
        with tempfile.TemporaryDirectory() as d:
            path = self._write(Path(d), _make_map(root="sg-xyz", region="eu-west-1"))
            result = ag.load_map_json(path)
        self.assertEqual(result["root"], "sg-xyz")
        self.assertEqual(result["region"], "eu-west-1")

    def test_load_map_json_raises_file_not_found(self) -> None:
        """FileNotFoundError raised for a path that does not exist."""
        with self.assertRaises(FileNotFoundError):
            ag.load_map_json(Path("/nonexistent/does_not_exist.json"))

    def test_load_map_json_raises_on_invalid_json(self) -> None:
        """ValueError raised when the file contains malformed JSON."""
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text("{not valid json")
            with self.assertRaises(ValueError):
                ag.load_map_json(bad)

    def test_load_map_json_raises_on_missing_root_key(self) -> None:
        """ValueError raised when required key 'root' is absent."""
        data = _make_map()
        del data["root"]
        with tempfile.TemporaryDirectory() as d:
            path = self._write(Path(d), data)
            with self.assertRaises(ValueError):
                ag.load_map_json(path)

    def test_load_map_json_raises_on_missing_nodes_key(self) -> None:
        """ValueError raised when required key 'nodes' is absent."""
        data = _make_map()
        del data["nodes"]
        with tempfile.TemporaryDirectory() as d:
            path = self._write(Path(d), data)
            with self.assertRaises(ValueError):
                ag.load_map_json(path)


# ---------------------------------------------------------------------------
# merge_maps – structural correctness
# ---------------------------------------------------------------------------


class TestMergeMapsEmpty(unittest.TestCase):
    def test_merge_maps_empty_list_returns_empty_graph(self) -> None:
        """Merging an empty list yields an AccountGraph with no nodes, edges, or paths."""
        result = ag.merge_maps([])
        self.assertEqual(result.nodes, {})
        self.assertEqual(result.edges, [])
        self.assertEqual(result.ingress_paths, [])
        self.assertEqual(result.errors, [])
        self.assertEqual(result.sources, [])


class TestMergeMapsSingle(unittest.TestCase):
    def setUp(self) -> None:
        self.map_ = _make_map(root="sg-aaa111", region="us-east-1")
        self.graph = ag.merge_maps([self.map_])

    def test_single_map_nodes_all_present(self) -> None:
        """All node_ids from the source map appear in the merged graph."""
        source_ids = {n["node_id"] for n in self.map_["nodes"]}
        self.assertEqual(source_ids, set(self.graph.nodes.keys()))

    def test_single_map_edges_all_present(self) -> None:
        """All edges from the source map appear in the merged graph."""
        self.assertEqual(len(self.graph.edges), len(self.map_["edges"]))

    def test_single_map_ingress_paths_preserved(self) -> None:
        """Ingress paths are carried over unchanged."""
        self.assertEqual(self.graph.ingress_paths, self.map_["ingress_paths"])

    def test_single_map_source_recorded(self) -> None:
        """The root value of the source map appears in sources."""
        self.assertIn("sg-aaa111", self.graph.sources)


class TestMergeMapsDedupliation(unittest.TestCase):
    def setUp(self) -> None:
        # Both maps share the internet node and its edge to their respective SG,
        # but map_b also has a second SG.
        self.map_a = _make_map(root="sg-aaa111", region="us-east-1")
        self.map_b = _make_map(root="sg-bbb222", region="us-east-1")
        self.graph = ag.merge_maps([self.map_a, self.map_b])

    def test_shared_node_appears_exactly_once(self) -> None:
        """The internet node present in both maps is deduplicated to a single entry."""
        internet_id = "internet:0_0_0_0_0"
        self.assertIn(internet_id, self.graph.nodes)
        # Verify it's stored as a single dict, not a list
        self.assertIsInstance(self.graph.nodes[internet_id], dict)

    def test_distinct_nodes_from_both_maps_present(self) -> None:
        """Unique nodes from each map are all represented."""
        self.assertIn("security_group:sg-aaa111", self.graph.nodes)
        self.assertIn("security_group:sg-bbb222", self.graph.nodes)

    def test_total_node_count_after_dedup(self) -> None:
        """Node count = union of unique node_ids across both maps."""
        all_ids = {n["node_id"] for n in self.map_a["nodes"]} | {
            n["node_id"] for n in self.map_b["nodes"]
        }
        self.assertEqual(len(self.graph.nodes), len(all_ids))

    def test_duplicate_edge_deduplicated(self) -> None:
        """An identical edge (same source, target, label) appearing in two maps is stored once."""
        # Both maps emit internet -> their SG with label tcp/22-22.
        # They have different targets so no literal duplicate here; fabricate one.
        shared_edge = {
            "source": "internet:0_0_0_0_0",
            "target": "security_group:sg-aaa111",
            "label": "tcp/22-22",
            "edge_type": "ingress",
        }
        dupe_map = _make_map(root="sg-aaa111")
        dupe_map["edges"] = [shared_edge, shared_edge]  # explicit duplicate
        graph = ag.merge_maps([dupe_map])
        # Expect only one copy of the edge.
        matching = [
            e
            for e in graph.edges
            if e["source"] == "internet:0_0_0_0_0"
            and e["target"] == "security_group:sg-aaa111"
            and e["label"] == "tcp/22-22"
        ]
        self.assertEqual(len(matching), 1)

    def test_same_edge_across_two_maps_deduplicated(self) -> None:
        """When two maps produce the identical edge it appears only once in merged output."""
        # Build two maps with the exact same edge (internet -> sg-aaa111, tcp/22-22)
        # by reusing map_a twice.
        graph = ag.merge_maps([self.map_a, self.map_a])
        matching = [
            e
            for e in graph.edges
            if e["source"] == "internet:0_0_0_0_0" and e["target"] == "security_group:sg-aaa111"
        ]
        self.assertEqual(len(matching), 1)


class TestMergeMapsAggregation(unittest.TestCase):
    def test_ingress_paths_from_all_maps_concatenated(self) -> None:
        """Ingress paths from every source map accumulate in the merged graph."""
        map_a = _make_map(
            root="sg-aaa111", ingress_paths=[["internet:0_0_0_0_0", "security_group:sg-aaa111"]]
        )
        map_b = _make_map(
            root="sg-bbb222", ingress_paths=[["internet:0_0_0_0_0", "security_group:sg-bbb222"]]
        )
        graph = ag.merge_maps([map_a, map_b])
        self.assertIn(["internet:0_0_0_0_0", "security_group:sg-aaa111"], graph.ingress_paths)
        self.assertIn(["internet:0_0_0_0_0", "security_group:sg-bbb222"], graph.ingress_paths)

    def test_errors_from_all_maps_concatenated(self) -> None:
        """Error strings from every source map accumulate in order."""
        map_a = _make_map(root="sg-aaa111", errors=["error-alpha"])
        map_b = _make_map(root="sg-bbb222", errors=["error-beta"])
        graph = ag.merge_maps([map_a, map_b])
        self.assertIn("error-alpha", graph.errors)
        self.assertIn("error-beta", graph.errors)

    def test_sources_list_contains_all_roots(self) -> None:
        """sources contains the root of every map that was merged."""
        map_a = _make_map(root="sg-aaa111")
        map_b = _make_map(root="sg-bbb222")
        graph = ag.merge_maps([map_a, map_b])
        self.assertIn("sg-aaa111", graph.sources)
        self.assertIn("sg-bbb222", graph.sources)

    def test_sources_length_matches_input_count(self) -> None:
        """sources has one entry per merged map (no deduplication of roots)."""
        maps = [_make_map(root=f"sg-{i:03d}") for i in range(5)]
        graph = ag.merge_maps(maps)
        self.assertEqual(len(graph.sources), 5)


# ---------------------------------------------------------------------------
# AccountGraph – summary()
# ---------------------------------------------------------------------------


class TestAccountGraphSummary(unittest.TestCase):
    def setUp(self) -> None:
        map_a = _make_map(root="sg-aaa111", errors=["err1"])
        map_b = _make_map(root="sg-bbb222")
        self.graph = ag.merge_maps([map_a, map_b])

    def test_summary_returns_dict(self) -> None:
        """summary() returns a dict."""
        self.assertIsInstance(self.graph.summary(), dict)

    def test_summary_node_count_key(self) -> None:
        """summary() has 'node_count' matching len(nodes)."""
        s = self.graph.summary()
        self.assertIn("node_count", s)
        self.assertEqual(s["node_count"], len(self.graph.nodes))

    def test_summary_edge_count_key(self) -> None:
        """summary() has 'edge_count' matching len(edges)."""
        s = self.graph.summary()
        self.assertIn("edge_count", s)
        self.assertEqual(s["edge_count"], len(self.graph.edges))

    def test_summary_path_count_key(self) -> None:
        """summary() has 'path_count' matching len(ingress_paths)."""
        s = self.graph.summary()
        self.assertIn("path_count", s)
        self.assertEqual(s["path_count"], len(self.graph.ingress_paths))

    def test_summary_error_count_key(self) -> None:
        """summary() has 'error_count' matching len(errors)."""
        s = self.graph.summary()
        self.assertIn("error_count", s)
        self.assertEqual(s["error_count"], len(self.graph.errors))

    def test_summary_source_count_key(self) -> None:
        """summary() has 'source_count' matching len(sources)."""
        s = self.graph.summary()
        self.assertIn("source_count", s)
        self.assertEqual(s["source_count"], len(self.graph.sources))


# ---------------------------------------------------------------------------
# render_account_html
# ---------------------------------------------------------------------------


class TestRenderAccountHtml(unittest.TestCase):
    def setUp(self) -> None:
        self.graph = ag.merge_maps([_make_map(root="sg-aaa111", region="us-east-1")])

    def test_render_returns_str(self) -> None:
        """render_account_html() returns a str."""
        self.assertIsInstance(ag.render_account_html(self.graph), str)

    def test_render_starts_with_doctype(self) -> None:
        """Output begins with an HTML doctype declaration."""
        html = ag.render_account_html(self.graph)
        self.assertTrue(html.strip().lower().startswith("<!doctype html"))

    def test_render_contains_mermaid_script(self) -> None:
        """Output embeds the Mermaid JS library (script tag or class reference)."""
        html = ag.render_account_html(self.graph)
        self.assertIn("mermaid", html)

    def test_render_contains_node_label(self) -> None:
        """A node label from the graph appears in the rendered HTML."""
        html = ag.render_account_html(self.graph)
        self.assertIn("SG sg-aaa111", html)

    def test_render_escapes_html_special_chars_in_title(self) -> None:
        """Root values containing < > & are HTML-escaped in the page title."""
        nasty = _make_map(root="<script>&")
        graph = ag.merge_maps([nasty])
        html = ag.render_account_html(graph)
        self.assertNotIn("<script>", html.split("<title>")[1].split("</title>")[0])

    def test_render_empty_graph_does_not_raise(self) -> None:
        """render_account_html() handles an empty AccountGraph without error."""
        empty = ag.merge_maps([])
        result = ag.render_account_html(empty)
        self.assertIsInstance(result, str)

    def test_render_direction_tb_reflected_in_mermaid(self) -> None:
        """Passing direction='TB' causes the Mermaid flowchart direction to be TB."""
        html = ag.render_account_html(self.graph, direction="TB")
        self.assertIn("TB", html)


# ---------------------------------------------------------------------------
# write_html
# ---------------------------------------------------------------------------


class TestWriteHtml(unittest.TestCase):
    def test_write_html_creates_file(self) -> None:
        """write_html() creates the target file on disk."""
        graph = ag.merge_maps([_make_map()])
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "account.html"
            ag.write_html(graph, out)
            self.assertTrue(out.exists())

    def test_write_html_content_matches_render(self) -> None:
        """File content equals render_account_html() for the same graph and direction."""
        graph = ag.merge_maps([_make_map()])
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "account.html"
            ag.write_html(graph, out, direction="TB")
            written = out.read_text()
        expected = ag.render_account_html(graph, direction="TB")
        self.assertEqual(written, expected)

    def test_write_html_creates_missing_parent_dirs(self) -> None:
        """write_html() creates parent directories that do not yet exist."""
        graph = ag.merge_maps([_make_map()])
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "nested" / "deep" / "account.html"
            ag.write_html(graph, out)
            self.assertTrue(out.exists())

    def test_write_html_overwrites_existing_file(self) -> None:
        """Calling write_html() twice replaces the previous file content."""
        graph_a = ag.merge_maps([_make_map(root="sg-aaa111")])
        graph_b = ag.merge_maps([_make_map(root="sg-bbb222")])
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "account.html"
            ag.write_html(graph_a, out)
            ag.write_html(graph_b, out)
            content = out.read_text()
        self.assertIn("sg-bbb222", content)
        self.assertNotIn("sg-aaa111", content)


if __name__ == "__main__":
    unittest.main()
