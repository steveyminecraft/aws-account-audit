from __future__ import annotations

import html
import json
import re
from typing import Any

from aws_network_map.graph import NetworkGraph


KIND_SHAPES = {
    "internet": ("{{", "}}"),
    "cidr": ("([", "])"),
    "ec2_instance": ("[", "]"),
    "rds_instance": ("[", "]"),
    "lambda_function": ("[", "]"),
    "load_balancer": ("[", "]"),
    "target_group": ("[", "]"),
    "security_group": ("[", "]"),
    "subnet": ("[", "]"),
    "vpc": ("[", "]"),
    "route_table": ("[", "]"),
    "nacl": ("[", "]"),
    "igw": ("[", "]"),
    "nat": ("[", "]"),
    "target": ("[", "]"),
}


def render_mermaid(graph: NetworkGraph, *, direction: str = "LR") -> str:
    lines = [f"flowchart {direction}"]
    root = graph.root

    for node in graph.nodes.values():
        left, right = KIND_SHAPES.get(node.kind, ("[", "]"))
        label = _escape_mermaid(node.label)
        if _is_focus_node(node, root):
            lines.append(f'    {_mermaid_id(node.node_id)}{left}"{label}"{right}:::root')
        else:
            lines.append(f'    {_mermaid_id(node.node_id)}{left}"{label}"{right}')

    for edge in graph.edges:
        edge_label = _escape_mermaid(edge.label)
        lines.append(
            f'    {_mermaid_id(edge.source)} -->|"{edge_label}"| {_mermaid_id(edge.target)}'
        )

    lines.extend(
        [
            "    classDef root fill:#ffe6a7,stroke:#b45309,stroke-width:2px",
        ]
    )
    return "\n".join(lines) + "\n"


def render_text(graph: NetworkGraph) -> str:
    lines = [
        "AWS Network Map",
        "=" * 72,
        f"Root resource: {graph.root}",
        f"Region:        {graph.region}",
        f"Nodes:         {len(graph.nodes)}",
        f"Edges:         {len(graph.edges)}",
        "",
    ]

    if graph.ingress_paths:
        lines.append("Ingress paths")
        lines.append("-" * 72)
        for index, path in enumerate(graph.ingress_paths, start=1):
            labels = []
            for node_id in path:
                node = graph.nodes.get(node_id)
                labels.append(node.label if node else node_id)
            lines.append(f"{index}. {' -> '.join(labels)}")
        lines.append("")

    lines.append("Connections")
    lines.append("-" * 72)
    for edge in graph.edges:
        source = graph.nodes[edge.source].label
        target = graph.nodes[edge.target].label
        lines.append(f"{source} --[{edge.label}]--> {target}")

    if graph.errors:
        lines.append("")
        lines.append("Errors")
        lines.append("-" * 72)
        for error in graph.errors:
            lines.append(f"- {error}")

    return "\n".join(lines) + "\n"


def render_json(graph: NetworkGraph) -> str:
    return json.dumps(graph.to_dict(), indent=2, default=str) + "\n"


def render_markdown(
    graph: NetworkGraph,
    *,
    direction: str = "LR",
    png_filename: str | None = None,
    html_filename: str | None = None,
    json_filename: str | None = None,
) -> str:
    mermaid = render_mermaid(graph, direction=direction)
    title = f"AWS Network Map: {graph.root}"
    lines = [
        f"# {title}",
        "",
        f"- **Resource:** `{graph.root}`",
        f"- **Region:** `{graph.region}`",
        f"- **Nodes:** {len(graph.nodes)}",
        f"- **Edges:** {len(graph.edges)}",
        "",
    ]

    export_links = []
    if html_filename:
        export_links.append(f"[Interactive HTML]({html_filename})")
    if json_filename:
        export_links.append(f"[JSON graph]({json_filename})")
    if export_links:
        lines.extend(["## Exports", "", " | ".join(export_links), ""])

    if png_filename:
        lines.extend(
            [
                "## Diagram",
                "",
                f"![{title}]({png_filename})",
                "",
            ]
        )

    lines.extend(
        [
            "## Mermaid source",
            "",
            "```mermaid",
            mermaid.rstrip(),
            "```",
            "",
        ]
    )

    if graph.ingress_paths:
        lines.extend(["## Ingress paths", ""])
        for index, path in enumerate(graph.ingress_paths, start=1):
            labels = []
            for node_id in path:
                node = graph.nodes.get(node_id)
                labels.append(node.label if node else node_id)
            lines.append(f"{index}. {' -> '.join(labels)}")
        lines.append("")

    lines.extend(["## Connections", ""])
    for edge in graph.edges:
        source = graph.nodes[edge.source].label
        target = graph.nodes[edge.target].label
        lines.append(f"- {source} -- `{edge.label}` --> {target}")

    if graph.errors:
        lines.extend(["", "## Warnings", ""])
        for error in graph.errors:
            lines.append(f"- {error}")

    lines.append("")
    return "\n".join(lines)


def render_html(graph: NetworkGraph, *, direction: str = "LR") -> str:
    mermaid = render_mermaid(graph, direction=direction)
    title = html.escape(f"Network map: {graph.root}")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <script type="module">
    import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
    mermaid.initialize({{ startOnLoad: true, theme: "neutral" }});
  </script>
  <style>
    body {{ font-family: sans-serif; margin: 2rem; }}
    pre {{ background: #f6f8fa; padding: 1rem; overflow-x: auto; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p>Region: {html.escape(graph.region)}</p>
  <pre class="mermaid">{html.escape(mermaid)}</pre>
</body>
</html>
"""


def _mermaid_id(node_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", node_id)
    if safe and safe[0].isdigit():
        safe = f"n_{safe}"
    return safe


def _escape_mermaid(value: str) -> str:
    return value.replace('"', "'")


def _is_focus_node(node: Any, root: str) -> bool:
    if root in node.node_id:
        return True
    return any(value == root for value in node.metadata.values())
