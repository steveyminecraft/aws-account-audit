from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from aws_network_map.graph import NetworkGraph
from aws_network_map.render import render_html, render_json, render_markdown, render_mermaid


def export_network_map(
    graph: NetworkGraph,
    output: Path,
    *,
    direction: str = "LR",
) -> dict[str, Path | None]:
    """Write .md, .png, .html, and .json exports for a network map."""
    base = output if not output.suffix else output.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)

    md_path = base.with_suffix(".md")
    png_path = base.with_suffix(".png")
    html_path = base.with_suffix(".html")
    json_path = base.with_suffix(".json")
    mmd_path = base.with_suffix(".mmd")

    html_path.write_text(render_html(graph, direction=direction))
    json_path.write_text(render_json(graph))

    mermaid = render_mermaid(graph, direction=direction)
    mmd_path.write_text(mermaid)

    md_path.write_text(
        render_markdown(
            graph,
            direction=direction,
            png_filename=png_path.name,
            html_filename=html_path.name,
            json_filename=json_path.name,
        )
    )

    png_ok, png_error = _render_png(
        mmd_path,
        png_path,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
    )
    mmd_path.unlink(missing_ok=True)

    written: dict[str, Path | None] = {
        "md": md_path,
        "html": html_path,
        "json": json_path,
        "png": png_path if png_ok else None,
    }
    if not png_ok:
        raise PngExportError(
            png_error or "PNG export failed.",
            written=written,
        )

    return written


def export_markdown_and_png(
    graph: NetworkGraph,
    output: Path,
    *,
    direction: str = "LR",
) -> dict[str, Path | None]:
    """Backward-compatible alias for export_network_map."""
    return export_network_map(graph, output, direction=direction)


def default_export_base(output_dir: Path, graph: NetworkGraph) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_root = graph.root.replace(":", "-").replace("/", "-")
    return output_dir / f"network-map-{safe_root}-{timestamp}"


class PngExportError(Exception):
    def __init__(self, message: str, *, written: dict[str, Path | None]) -> None:
        super().__init__(message)
        self.written = written

    @property
    def md_path(self) -> Path | None:
        return self.written.get("md")


# Chrome/Puppeteer cannot capture a screenshot larger than ~16384px on any axis.
# The effective screenshot size is roughly viewport_dimension * device_scale, so we keep
# width * scale and height * scale below this ceiling to avoid "Unable to capture
# screenshot" protocol errors on large account graphs.
MAX_EFFECTIVE_DIMENSION = 16000


def compute_png_dimensions(
    node_count: int,
    edge_count: int,
) -> tuple[int, int, float, int]:
    """Return viewport width, height, scale, and render timeout for a graph size."""
    nodes = max(int(node_count), 1)
    edges = max(int(edge_count), 0)

    width = min(24000, max(3200, nodes * 160 + edges * 28))
    height = min(20000, max(2400, nodes * 110 + edges * 20))

    scale = 2.0
    if nodes >= 40:
        scale = 2.5
    if nodes >= 80:
        scale = 3.0
    if nodes >= 150:
        scale = 3.5
    if nodes >= 250:
        scale = 4.0

    timeout_seconds = min(600, max(120, 90 + nodes * 2 + edges))
    return width, height, scale, timeout_seconds


def _png_attempt_plan(width: int, height: int, scale: float) -> list[tuple[int, int, float]]:
    """Build a list of (width, height, scale) render attempts, largest first.

    The first attempt caps the effective screenshot size (dimension * scale) to
    ``MAX_EFFECTIVE_DIMENSION`` by lowering the device scale, then shrinking the viewport
    if scale 1.0 is still too large. Later attempts progressively reduce size so a render
    still succeeds on very large graphs that Chrome cannot capture at full resolution.
    """
    attempts: list[tuple[int, int, float]] = []
    seen: set[tuple[int, int, float]] = set()

    def add(candidate_width: float, candidate_height: float, candidate_scale: float) -> None:
        normalized = (
            max(800, int(candidate_width)),
            max(600, int(candidate_height)),
            round(max(1.0, float(candidate_scale)), 2),
        )
        if normalized not in seen:
            seen.add(normalized)
            attempts.append(normalized)

    primary_width = float(width)
    primary_height = float(height)
    primary_scale = max(1.0, float(scale))

    longest = max(primary_width, primary_height) * primary_scale
    if longest > MAX_EFFECTIVE_DIMENSION:
        primary_scale = max(1.0, primary_scale * MAX_EFFECTIVE_DIMENSION / longest)

    longest = max(primary_width, primary_height) * primary_scale
    if longest > MAX_EFFECTIVE_DIMENSION:
        shrink = MAX_EFFECTIVE_DIMENSION / longest
        primary_width *= shrink
        primary_height *= shrink

    add(primary_width, primary_height, primary_scale)
    add(min(primary_width, 12000), min(primary_height, 12000), min(primary_scale, 1.5))
    add(min(primary_width, 10000), min(primary_height, 10000), 1.0)
    add(min(primary_width, 8000), min(primary_height, 8000), 1.0)
    return attempts


def _is_capture_failure(message: str | None) -> bool:
    """True when an mmdc failure looks like a Chrome screenshot/size limit error."""
    if not message:
        return False
    lowered = message.lower()
    markers = (
        "capturescreenshot",
        "unable to capture screenshot",
        "protocol error",
        "target closed",
        "page crashed",
        "navigation timeout",
    )
    return any(marker in lowered for marker in markers)


def _render_png(
    mermaid_source: Path,
    png_path: Path,
    *,
    node_count: int | None = None,
    edge_count: int | None = None,
    scale_override: float | None = None,
) -> tuple[bool, str | None]:
    png_path.parent.mkdir(parents=True, exist_ok=True)

    if node_count is None or edge_count is None:
        node_count, edge_count = _estimate_mermaid_counts(
            mermaid_source.read_text(encoding="utf-8")
        )

    width, height, scale, timeout_seconds = compute_png_dimensions(node_count, edge_count)
    if scale_override is not None and scale_override > 0:
        scale = float(scale_override)
        # High-resolution renders take longer; give the renderer more headroom.
        timeout_seconds = max(timeout_seconds, min(1200, int(120 + scale * 90)))

    attempts = _png_attempt_plan(width, height, scale)
    last_message: str | None = None

    for index, (attempt_width, attempt_height, attempt_scale) in enumerate(attempts):
        command = _png_render_command(
            mermaid_source,
            png_path,
            width=attempt_width,
            height=attempt_height,
            scale=attempt_scale,
        )
        if command is None:
            return False, (
                "PNG export requires @mermaid-js/mermaid-cli. "
                "Run `npm install` in aws-account-audit, or install mmdc globally."
            )

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            last_message = f"PNG export timed out after {timeout_seconds} seconds."
            continue
        except OSError as exc:
            return False, f"PNG export failed to start renderer: {exc}"

        if result.returncode == 0 and png_path.exists():
            return True, None

        details = (result.stderr or result.stdout or "").strip()
        last_message = f"PNG export failed with exit code {result.returncode}."
        if details:
            last_message = f"{last_message} {details}"

        # Only fall back to a smaller render when the failure is a Chrome capture/size
        # limit. Other errors (e.g. invalid Mermaid) will not be fixed by shrinking.
        is_last_attempt = index == len(attempts) - 1
        if not _is_capture_failure(last_message) or is_last_attempt:
            return False, last_message

    return False, last_message


def _estimate_mermaid_counts(mermaid: str) -> tuple[int, int]:
    node_count = 0
    edge_count = 0
    for line in mermaid.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("%%"):
            continue
        if stripped.startswith("flowchart ") or stripped.startswith("classDef "):
            continue
        if stripped.startswith("subgraph ") or stripped == "end":
            continue
        if "-->" in stripped:
            edge_count += 1
            continue
        if any(token in stripped for token in ('["', "[[", "((", "{{")):
            node_count += 1
    return max(node_count, 1), edge_count


def _png_render_command(
    mermaid_source: Path,
    png_path: Path,
    *,
    width: int,
    height: int,
    scale: float,
) -> list[str] | None:
    puppeteer_config = Path(__file__).resolve().parent / "puppeteer-config.json"
    mermaid_config = Path(__file__).resolve().parent / "mermaid-config.json"
    args = [
        "-i",
        str(mermaid_source),
        "-o",
        str(png_path),
        "-b",
        "white",
        "-w",
        str(width),
        "-H",
        str(height),
        "-s",
        str(scale),
        "-c",
        str(mermaid_config),
        "-p",
        str(puppeteer_config),
    ]

    if shutil.which("mmdc"):
        return ["mmdc", *args]

    project_root = Path(__file__).resolve().parents[1]
    local_mmdc = project_root / "node_modules" / ".bin" / "mmdc"
    if local_mmdc.exists():
        return [str(local_mmdc), *args]

    if shutil.which("npx"):
        return ["npx", "-y", "@mermaid-js/mermaid-cli", *args]

    return None
