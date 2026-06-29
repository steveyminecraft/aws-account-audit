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

    png_ok, png_error = _render_png(mmd_path, png_path)
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


def _render_png(mermaid_source: Path, png_path: Path) -> tuple[bool, str | None]:
    png_path.parent.mkdir(parents=True, exist_ok=True)

    command = _png_render_command(mermaid_source, png_path)
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
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "PNG export timed out after 120 seconds."
    except OSError as exc:
        return False, f"PNG export failed to start renderer: {exc}"

    if result.returncode == 0 and png_path.exists():
        return True, None

    details = (result.stderr or result.stdout or "").strip()
    message = f"PNG export failed with exit code {result.returncode}."
    if details:
        message = f"{message} {details}"
    return False, message


def _png_render_command(mermaid_source: Path, png_path: Path) -> list[str] | None:
    puppeteer_config = Path(__file__).resolve().parent / "puppeteer-config.json"
    args = [
        "-i",
        str(mermaid_source),
        "-o",
        str(png_path),
        "-b",
        "white",
        "-w",
        "2800",
        "-H",
        "1800",
        "-s",
        "2",
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
