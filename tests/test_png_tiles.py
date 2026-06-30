from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aws_account_audit import png_tiles as pt


class TestAxisStarts(unittest.TestCase):
    def test_single_tile_when_within_max_dim(self) -> None:
        self.assertEqual(pt.axis_starts(3000, 4000, 400), [0])

    def test_exact_max_dim_is_single_tile(self) -> None:
        self.assertEqual(pt.axis_starts(4000, 4000, 400), [0])

    def test_last_start_aligns_to_end(self) -> None:
        starts = pt.axis_starts(10000, 4000, 400)
        self.assertEqual(starts[0], 0)
        self.assertEqual(starts[-1], 10000 - 4000)

    def test_consecutive_overlap_respected(self) -> None:
        starts = pt.axis_starts(10000, 4000, 400)
        step = 4000 - 400
        # Every interior gap should be <= step (so tiles overlap by >= overlap).
        for prev, nxt in zip(starts, starts[1:]):
            self.assertLessEqual(nxt - prev, step)

    def test_zero_length(self) -> None:
        self.assertEqual(pt.axis_starts(0, 4000, 400), [0])

    def test_invalid_max_dim_raises(self) -> None:
        with self.assertRaises(ValueError):
            pt.axis_starts(100, 0, 10)


class TestComputeTiles(unittest.TestCase):
    def test_tall_image_splits_vertically_only(self) -> None:
        tiles = pt.compute_tiles(3000, 15000, max_dim=4000, overlap=400)
        # width fits in one column, height needs multiple rows
        lefts = {left for (left, _t, _r, _b) in tiles}
        self.assertEqual(lefts, {0})
        self.assertGreater(len(tiles), 1)

    def test_tiles_cover_entire_image(self) -> None:
        width, height = 3000, 15000
        tiles = pt.compute_tiles(width, height, max_dim=4000, overlap=400)
        # Right/bottom of the last tile reaches the image bounds.
        self.assertEqual(max(r for (_l, _t, r, _b) in tiles), width)
        self.assertEqual(max(b for (_l, _t, _r, b) in tiles), height)

    def test_tiles_never_exceed_max_dim(self) -> None:
        tiles = pt.compute_tiles(9000, 9000, max_dim=4000, overlap=400)
        for left, top, right, bottom in tiles:
            self.assertLessEqual(right - left, 4000)
            self.assertLessEqual(bottom - top, 4000)

    def test_no_vertical_gap_between_rows(self) -> None:
        """Each row's top is within the previous tile's vertical span (no gaps)."""
        tiles = pt.compute_tiles(2000, 15000, max_dim=4000, overlap=400)
        tops = sorted({top for (_l, top, _r, _b) in tiles})
        bottoms = {top: 0 for top in tops}
        for left, top, right, bottom in tiles:
            bottoms[top] = bottom
        for prev_top, nxt_top in zip(tops, tops[1:]):
            self.assertLessEqual(nxt_top, bottoms[prev_top])


class TestShouldTile(unittest.TestCase):
    def test_small_image_not_tiled(self) -> None:
        self.assertFalse(pt.should_tile(3000, 4000, min_long_side=6000))

    def test_large_image_tiled(self) -> None:
        self.assertTrue(pt.should_tile(3000, 15000, min_long_side=6000))


class TestTilePng(unittest.TestCase):
    def _make_png(self, path: Path, size: tuple[int, int]) -> None:
        from PIL import Image

        Image.new("RGB", size, "white").save(path)

    def test_returns_empty_for_small_image(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "small.png"
            self._make_png(src, (1000, 1000))
            out = pt.tile_png(src, Path(d) / "sections", max_dim=4000, overlap=400)
        self.assertEqual(out, [])

    def test_creates_overlapping_sections(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "tall.png"
            self._make_png(src, (2000, 12000))
            out_dir = Path(d) / "sections"
            out = pt.tile_png(src, out_dir, max_dim=4000, overlap=400)
            self.assertGreater(len(out), 1)
            for path in out:
                self.assertTrue(path.exists())
                self.assertTrue(path.name.startswith("section-"))

    def test_section_filenames_are_zero_padded_and_ordered(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "tall.png"
            self._make_png(src, (2000, 50000))
            out = pt.tile_png(src, Path(d) / "sections", max_dim=4000, overlap=400)
            names = [p.name for p in out]
        self.assertEqual(names, sorted(names))
        self.assertTrue(
            all(
                len(n.split("-")[1].split(".")[0]) == len(names[0].split("-")[1].split(".")[0])
                for n in names
            )
        )


if __name__ == "__main__":
    unittest.main()
