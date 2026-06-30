"""Slice a large PNG into overlapping, readable sections.

Large IAM/account graphs render as a single PNG that is thousands of pixels on the
long axis. Some viewers downscale it to fit and the detail becomes unreadable. These
helpers cut such a PNG into overlapping tiles (a little repetition between tiles keeps
nodes that straddle a boundary fully visible in at least one section).

The geometry helpers (:func:`axis_starts`, :func:`compute_tiles`) are pure and need no
image library so they can be unit tested cheaply. :func:`tile_png` performs the actual
cropping with Pillow.
"""

from __future__ import annotations

from pathlib import Path

# Defaults chosen so a typical LR IAM graph splits into a handful of legible bands.
DEFAULT_MAX_DIM = 4000
DEFAULT_OVERLAP = 400
# Only bother tiling when the long side is meaningfully larger than a single tile.
DEFAULT_MIN_LONG_SIDE = 6000

Tile = tuple[int, int, int, int]  # (left, top, right, bottom)


def axis_starts(length: int, max_dim: int, overlap: int) -> list[int]:
    """Return tile start offsets covering ``length`` with overlap.

    Each tile spans at most ``max_dim`` pixels; consecutive tiles overlap by
    ``overlap`` pixels and the final tile is aligned to end exactly at ``length``.
    """
    if length <= 0:
        return [0]
    if max_dim <= 0:
        raise ValueError("max_dim must be positive")
    if length <= max_dim:
        return [0]
    step = max(1, max_dim - max(0, overlap))
    starts: list[int] = []
    pos = 0
    last_start = length - max_dim
    while pos < last_start:
        starts.append(pos)
        pos += step
    starts.append(last_start)
    return starts


def compute_tiles(
    width: int,
    height: int,
    *,
    max_dim: int = DEFAULT_MAX_DIM,
    overlap: int = DEFAULT_OVERLAP,
) -> list[Tile]:
    """Return crop boxes (left, top, right, bottom) tiling ``width`` x ``height``.

    Tiles are ordered top-to-bottom, then left-to-right (natural reading order).
    """
    xs = axis_starts(width, max_dim, overlap)
    ys = axis_starts(height, max_dim, overlap)
    tiles: list[Tile] = []
    for top in ys:
        for left in xs:
            right = min(left + max_dim, width)
            bottom = min(top + max_dim, height)
            tiles.append((left, top, right, bottom))
    return tiles


def should_tile(
    width: int,
    height: int,
    *,
    min_long_side: int = DEFAULT_MIN_LONG_SIDE,
) -> bool:
    """Return True when the image is large enough that tiling aids readability."""
    return max(width, height) > min_long_side


def tile_png(
    source: Path,
    out_dir: Path,
    *,
    max_dim: int = DEFAULT_MAX_DIM,
    overlap: int = DEFAULT_OVERLAP,
    prefix: str = "section",
) -> list[Path]:
    """Crop ``source`` into overlapping PNG sections written under ``out_dir``.

    Returns the list of written tile paths in reading order. When the source image
    fits within a single tile, no files are written and an empty list is returned.
    Requires Pillow; raises RuntimeError with guidance if it is not installed.
    """
    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover - exercised only without Pillow
        raise RuntimeError(
            "PNG tiling requires Pillow. Install it with `pip install pillow` "
            "or `pip install -e .` from aws-account-audit."
        ) from exc

    # Large graph exports legitimately exceed Pillow's decompression-bomb guard.
    Image.MAX_IMAGE_PIXELS = None

    with Image.open(source) as img:
        width, height = img.size
        tiles = compute_tiles(width, height, max_dim=max_dim, overlap=overlap)
        if len(tiles) <= 1:
            return []

        out_dir.mkdir(parents=True, exist_ok=True)
        pad = len(str(len(tiles)))
        written: list[Path] = []
        for index, box in enumerate(tiles, start=1):
            crop = img.crop(box)
            tile_path = out_dir / f"{prefix}-{index:0{pad}d}.png"
            crop.save(tile_path)
            written.append(tile_path)
    return written
