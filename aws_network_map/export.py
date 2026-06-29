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


def _render_png(
    mermaid_source: Path,
    png_path: Path,
    *,
    node_count: int | None = None,
    edge_count: int | None = None,
) -> tuple[bool, str | None]:
    png_path.parent.mkdir(parents=True, exist_ok=True)

    if node_count is None or edge_count is None:
        node_count, edge_count = _estimate_mermaid_counts(
            mermaid_source.read_text(encoding="utf-8")
        )

    width, height, scale, timeout_seconds = compute_png_dimensions(node_count, edge_count)
    command = _png_render_command(
        mermaid_source,
        png_path,
        width=width,
        height=height,
        scale=scale,
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
        return False, f"PNG export timed out after {timeout_seconds} seconds."
    except OSError as exc:
        return False, f"PNG export failed to start renderer: {exc}"

    if result.returncode == 0 and png_path.exists():
        return True, None

    details = (result.stderr or result.stdout or "").strip()
    message = f"PNG export failed with exit code {result.returncode}."
    if details:
        message = f"{message} {details}"
    return False, message


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
