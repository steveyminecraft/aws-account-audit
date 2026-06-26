from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aws_account_audit.audit import run_audit, write_report
from aws_network_map import from_audit

REQUIRED_MAP_KEYS = {"root", "region", "nodes", "edges", "ingress_paths", "errors"}


@dataclass
class AccountGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    ingress_paths: list[list[str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "path_count": len(self.ingress_paths),
            "error_count": len(self.errors),
            "source_count": len(self.sources),
        }


def load_map_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(path)

    try:
        payload = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    missing = sorted(REQUIRED_MAP_KEYS.difference(payload.keys()))
    if missing:
        raise ValueError(f"Missing required key(s) in {path}: {', '.join(missing)}")

    return payload


def merge_maps(maps: list[dict[str, Any]]) -> AccountGraph:
    graph = AccountGraph()
    seen_edges: set[tuple[str, str, str]] = set()

    for payload in maps:
        graph.sources.append(str(payload.get("root", "")))
        graph.ingress_paths.extend(payload.get("ingress_paths", []))
        graph.errors.extend(payload.get("errors", []))

        for node in payload.get("nodes", []):
            node_id = node.get("node_id")
            if not node_id:
                continue
            graph.nodes.setdefault(node_id, dict(node))

        for edge in payload.get("edges", []):
            source = edge.get("source")
            target = edge.get("target")
            label = edge.get("label", "")
            if not source or not target:
                continue
            if source not in graph.nodes or target not in graph.nodes:
                graph.errors.append(f"Skipped edge with unknown node(s): {source} -> {target}")
                continue
            dedupe_key = (source, target, str(label))
            if dedupe_key in seen_edges:
                continue
            seen_edges.add(dedupe_key)
            graph.edges.append(dict(edge))

    return graph


def render_account_html(graph: AccountGraph, *, direction: str = "LR") -> str:
    root_label = ", ".join(graph.sources) if graph.sources else "account"
    mermaid_lines = [f"flowchart {direction}"]
    for node in graph.nodes.values():
        node_id = _mermaid_id(str(node.get("node_id", "")))
        label = _escape_mermaid(str(node.get("label", node.get("node_id", "unknown"))))
        mermaid_lines.append(f'    {node_id}["{label}"]')

    for edge in graph.edges:
        source = _mermaid_id(str(edge.get("source", "")))
        target = _mermaid_id(str(edge.get("target", "")))
        label = _escape_mermaid(str(edge.get("label", "")))
        mermaid_lines.append(f'    {source} -->|"{label}"| {target}')

    mermaid = "\n".join(mermaid_lines) + "\n"
    title = html.escape(f"Account graph: {root_label}")
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
  <p>Sources merged: {len(graph.sources)}</p>
  <p>Nodes: {len(graph.nodes)} | Edges: {len(graph.edges)}</p>
  <pre class="mermaid">{html.escape(mermaid)}</pre>
</body>
</html>
"""


def write_html(graph: AccountGraph, path: Path, *, direction: str = "LR") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_account_html(graph, direction=direction))


def _load_audit_metadata(audit_json: Path) -> dict[str, Any]:
    try:
        payload = json.loads(audit_json.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"Audit file is not valid JSON ({audit_json}): {exc}") from exc
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"Audit file is missing metadata: {audit_json}")
    return metadata


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a single account-wide graph from audit output and network maps.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--audit-json", type=Path, help="Existing audit JSON file to consume")
    source.add_argument(
        "--run-audit",
        action="store_true",
        help="Run a fresh audit before mapping",
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", default="eu-west-1", help="Audit home region")
    parser.add_argument("--regions", nargs="*", help="Explicit audit regions")
    parser.add_argument(
        "--all-regions",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Audit all enabled regions (default: true)",
    )
    parser.add_argument("--sections", nargs="*", help="Optional audit section filter")
    parser.add_argument("--max-workers", type=int, default=8, help="Audit worker count")
    parser.add_argument(
        "--audit-output-dir",
        type=Path,
        default=Path("audit-runs"),
        help="Directory for generated audit files",
    )
    parser.add_argument(
        "--map-dir",
        type=Path,
        default=Path("network-maps/from-audit-account"),
        help="Directory for per-resource map files",
    )
    parser.add_argument(
        "--skip-mapping",
        action="store_true",
        help="Skip running from_audit and only merge existing map JSON files",
    )
    parser.add_argument(
        "--default-region",
        default="eu-west-1",
        help="Fallback mapping region for from_audit",
    )
    parser.add_argument(
        "--map-format",
        choices=["mermaid", "text", "json", "html", "md", "export"],
        default="export",
        help="Format used by from_audit map generation",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=300,
        help="Per-map timeout for from_audit command",
    )
    parser.add_argument(
        "--direction",
        choices=["LR", "TB"],
        default="LR",
        help="Mermaid direction for output graph",
    )
    parser.add_argument(
        "--output-base",
        type=Path,
        default=Path("network-maps/account-graph"),
        help="Base output path for merged graph (.json/.html appended)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned steps without writing files",
    )
    return parser


def _find_map_json_files(map_dir: Path, output_json: Path) -> list[Path]:
    files = sorted(path for path in map_dir.glob("*.json") if path != output_json)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.run_audit:
        if args.dry_run:
            print(
                "DRY RUN: would execute aws_account_audit and write audit JSON",
                file=sys.stderr,
            )
            audit_json_path = args.audit_output_dir / "audit-dry-run.json"
            audit_metadata = {"account_id": "dry-run"}
        else:
            sections = set(args.sections) if args.sections else None
            report = run_audit(
                profile=args.profile,
                region=args.region,
                regions=args.regions,
                all_regions=args.all_regions,
                max_workers=args.max_workers,
                sections=sections,
            )
            written = write_report(report, args.audit_output_dir, {"json"})
            audit_json_path = written["json"]
            audit_metadata = report.metadata
            print(f"Wrote json report: {audit_json_path}", file=sys.stderr)
    else:
        audit_json_path = args.audit_json
        if audit_json_path is None or not audit_json_path.exists():
            print(f"Audit file not found: {audit_json_path}", file=sys.stderr)
            return 1
        try:
            audit_metadata = _load_audit_metadata(audit_json_path)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    output_base = args.output_base.with_suffix("")
    output_json = output_base.with_suffix(".json")
    output_html = output_base.with_suffix(".html")

    map_return_code = 0
    if not args.skip_mapping:
        map_argv = [
            "--audit-json",
            str(audit_json_path),
            "--output-dir",
            str(args.map_dir),
            "--default-region",
            args.default_region,
            "--format",
            args.map_format,
            "--direction",
            args.direction,
            "--timeout-seconds",
            str(args.timeout_seconds),
        ]
        if args.profile:
            map_argv.extend(["--profile", args.profile])
        if args.regions:
            map_argv.extend(["--regions", *args.regions])
        if args.dry_run:
            map_argv.append("--dry-run")

        map_return_code = from_audit.main(map_argv)
        if map_return_code != 0 and not args.dry_run:
            print("Warning: from_audit returned non-zero; attempting merge anyway.", file=sys.stderr)

    if args.dry_run:
        print(f"DRY RUN: would merge map JSON files from {args.map_dir}", file=sys.stderr)
        print(f"DRY RUN: would write {output_json} and {output_html}", file=sys.stderr)
        return 0

    if not args.map_dir.exists():
        print(f"Map directory not found: {args.map_dir}", file=sys.stderr)
        return 1

    payloads: list[dict[str, Any]] = []
    for path in _find_map_json_files(args.map_dir, output_json):
        try:
            payloads.append(load_map_json(path))
        except (FileNotFoundError, ValueError) as exc:
            print(f"Skipping {path}: {exc}", file=sys.stderr)

    if not payloads:
        print(f"No valid map JSON files found in {args.map_dir}", file=sys.stderr)
        return 1

    merged = merge_maps(payloads)
    summary = merged.summary()
    account_id = str(audit_metadata.get("account_id") or "unknown-account")
    output_payload = {
        "domain": f"account:{account_id}",
        "account_id": account_id,
        "summary": summary,
        "sources": merged.sources,
        "nodes": list(merged.nodes.values()),
        "edges": merged.edges,
        "ingress_paths": merged.ingress_paths,
        "errors": merged.errors,
    }

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(output_payload, indent=2))
    write_html(merged, output_html, direction=args.direction)

    print(f"Wrote merged graph JSON: {output_json}", file=sys.stderr)
    print(f"Wrote merged graph HTML: {output_html}", file=sys.stderr)
    print(
        f"Merged {len(payloads)} map file(s): {summary['node_count']} nodes, {summary['edge_count']} edges",
        file=sys.stderr,
    )
    if map_return_code != 0:
        print(
            f"Completed with mapping warning(s): from_audit exit code {map_return_code}",
            file=sys.stderr,
        )
        return 1
    return 0


def _mermaid_id(node_id: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", node_id)
    if safe and safe[0].isdigit():
        safe = f"n_{safe}"
    return safe


def _escape_mermaid(value: str) -> str:
    escaped = value.replace('"', "'")
    escaped = escaped.replace("[", "(").replace("]", ")")
    escaped = escaped.replace("\n", " ").replace("\r", " ")
    return escaped


if __name__ == "__main__":
    raise SystemExit(main())
