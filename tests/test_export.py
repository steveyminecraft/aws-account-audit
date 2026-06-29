from __future__ import annotations

import unittest

from aws_network_map.export import _estimate_mermaid_counts, compute_png_dimensions


class TestComputePngDimensions(unittest.TestCase):
    def test_small_graph_uses_minimum_viewport(self) -> None:
        width, height, scale, timeout = compute_png_dimensions(3, 2)
        self.assertGreaterEqual(width, 3200)
        self.assertGreaterEqual(height, 2400)
        self.assertEqual(scale, 2.0)
        self.assertGreaterEqual(timeout, 120)

    def test_large_graph_increases_viewport_and_scale(self) -> None:
        small = compute_png_dimensions(10, 10)
        large = compute_png_dimensions(200, 300)
        self.assertLess(small[0], large[0])
        self.assertLess(small[1], large[1])
        self.assertLess(small[2], large[2])
        self.assertLess(small[3], large[3])

    def test_dimensions_are_capped(self) -> None:
        width, height, scale, timeout = compute_png_dimensions(1000, 2000)
        self.assertLessEqual(width, 24000)
        self.assertLessEqual(height, 20000)
        self.assertLessEqual(scale, 4.0)
        self.assertLessEqual(timeout, 600)


class TestEstimateMermaidCounts(unittest.TestCase):
    def test_counts_nodes_and_edges(self) -> None:
        mermaid = """flowchart TB
    subgraph sg1["Security groups"]
        n1["SG web"]
    end
    n1 -->|"443"| n2["EC2 app"]
"""
        nodes, edges = _estimate_mermaid_counts(mermaid)
        self.assertGreaterEqual(nodes, 1)
        self.assertEqual(edges, 1)


if __name__ == "__main__":
    unittest.main()
