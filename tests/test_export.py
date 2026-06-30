from __future__ import annotations

import json
import unittest
from pathlib import Path

from aws_network_map.export import (
    MAX_EFFECTIVE_DIMENSION,
    _estimate_mermaid_counts,
    _is_capture_failure,
    _png_attempt_plan,
    compute_png_dimensions,
)
from aws_network_map.graph_style import MERMAID_MAX_TEXT_SIZE, render_interactive_html


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


class TestPngAttemptPlan(unittest.TestCase):
    def test_primary_attempt_within_capture_ceiling(self) -> None:
        # A huge graph: ideal dims 24000 x 20000 at scale 4 would be 96000px effective.
        width, height, scale, _ = compute_png_dimensions(1000, 2000)
        attempts = _png_attempt_plan(width, height, scale)
        first_width, first_height, first_scale = attempts[0]
        self.assertLessEqual(first_width * first_scale, MAX_EFFECTIVE_DIMENSION)
        self.assertLessEqual(first_height * first_scale, MAX_EFFECTIVE_DIMENSION)

    def test_every_attempt_within_capture_ceiling(self) -> None:
        attempts = _png_attempt_plan(24000, 20000, 4.0)
        for attempt_width, attempt_height, attempt_scale in attempts:
            self.assertLessEqual(attempt_width * attempt_scale, MAX_EFFECTIVE_DIMENSION)
            self.assertLessEqual(attempt_height * attempt_scale, MAX_EFFECTIVE_DIMENSION)

    def test_attempts_are_progressively_smaller(self) -> None:
        attempts = _png_attempt_plan(24000, 20000, 4.0)
        areas = [w * h * s for w, h, s in attempts]
        self.assertGreater(len(attempts), 1)
        self.assertEqual(areas, sorted(areas, reverse=True))

    def test_small_graph_keeps_requested_scale(self) -> None:
        attempts = _png_attempt_plan(3200, 2400, 2.0)
        self.assertEqual(attempts[0], (3200, 2400, 2.0))

    def test_scale_never_below_one(self) -> None:
        attempts = _png_attempt_plan(24000, 20000, 4.0)
        for _, _, attempt_scale in attempts:
            self.assertGreaterEqual(attempt_scale, 1.0)


class TestIsCaptureFailure(unittest.TestCase):
    def test_detects_capture_screenshot_protocol_error(self) -> None:
        message = (
            "PNG export failed with exit code 1. ProtocolError: Protocol error "
            "(Page.captureScreenshot): Unable to capture screenshot"
        )
        self.assertTrue(_is_capture_failure(message))

    def test_detects_target_closed(self) -> None:
        self.assertTrue(_is_capture_failure("Error: Target closed"))

    def test_ignores_unrelated_errors(self) -> None:
        self.assertFalse(_is_capture_failure("Parse error on line 3: invalid syntax"))

    def test_handles_none(self) -> None:
        self.assertFalse(_is_capture_failure(None))


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


class TestMermaidLimits(unittest.TestCase):
    def test_mermaid_config_allows_large_diagrams(self) -> None:
        config_path = (
            Path(__file__).resolve().parents[1] / "aws_network_map" / "mermaid-config.json"
        )
        payload = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertGreaterEqual(payload["maxTextSize"], 500_000)

    def test_html_includes_max_text_size(self) -> None:
        html = render_interactive_html(
            title="Test graph",
            subtitle="Nodes: 1",
            mermaid='flowchart TB\n    a["node"]',
        )
        self.assertIn(f"maxTextSize: {MERMAID_MAX_TEXT_SIZE}", html)


if __name__ == "__main__":
    unittest.main()
