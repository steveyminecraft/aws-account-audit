from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aws_account_audit.session import create_session
from aws_network_map import __version__
from aws_network_map.export import PngExportError, default_export_base, export_network_map
from aws_network_map.render import render_html, render_json, render_markdown, render_mermaid, render_text
from aws_network_map.resolve import resolve_resource
from aws_network_map.tracers import build_graph


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Map ingress paths and network connections for an AWS resource.",
    )
    parser.add_argument(
        "--resource",
        required=True,
        help="Resource id, name, or ARN (i-..., sg-..., load balancer name, RDS id, Lambda ARN)",
    )
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--region",
        default="eu-west-1",
        help="Region to search first (default: eu-west-1)",
    )
    parser.add_argument(
        "--type",
        choices=[
            "ec2_instance",
            "security_group",
            "load_balancer",
            "alb",
            "rds_instance",
            "lambda_function",
        ],
        help="Force resource type when auto-detection is ambiguous",
    )
    parser.add_argument(
        "--search-all-regions",
        action="store_true",
        help="Search all enabled regions if the resource is not found in --region",
    )
    parser.add_argument(
        "--format",
        choices=["mermaid", "text", "json", "html", "md", "export"],
        default="export",
        help="Output format (default: export = .md, .png, .html, and .json files)",
    )
    parser.add_argument(
        "--direction",
        choices=["LR", "TB"],
        default="LR",
        help="Mermaid diagram direction (default: LR)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Output base path without extension for export/md formats",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("network-maps"),
        help="Directory for export output when --output is omitted (default: ./network-maps)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Also print the primary format to stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    session = create_session(args.profile)
    resource_type = args.type
    if resource_type == "alb":
        resource_type = "load_balancer"

    resolved, error = resolve_resource(
        session,
        args.resource,
        region=args.region,
        explicit_kind=resource_type,
        search_all_regions=args.search_all_regions,
    )
    if error or resolved is None:
        print(error or "Resource not found.", file=sys.stderr)
        return 1

    graph = build_graph(session, resolved)

    if args.format == "export":
        output_base = args.output or default_export_base(args.output_dir, graph)
        try:
            written = export_network_map(graph, output_base, direction=args.direction)
        except PngExportError as exc:
            for label in ("md", "html", "json"):
                path = exc.written.get(label)
                if path:
                    print(f"Wrote {label} map: {path}", file=sys.stderr)
            print(str(exc), file=sys.stderr)
            return 2

        for label in ("md", "png", "html", "json"):
            path = written.get(label)
            if path:
                print(f"Wrote {label} map: {path}", file=sys.stderr)
        if args.stdout:
            print(
                render_markdown(
                    graph,
                    direction=args.direction,
                    png_filename=written["png"].name if written.get("png") else None,
                    html_filename=written["html"].name if written.get("html") else None,
                    json_filename=written["json"].name if written.get("json") else None,
                )
            )
    else:
        if args.format == "mermaid":
            output = render_mermaid(graph, direction=args.direction)
        elif args.format == "text":
            output = render_text(graph)
        elif args.format == "json":
            output = render_json(graph)
        elif args.format == "html":
            output = render_html(graph, direction=args.direction)
        else:
            output = render_markdown(graph, direction=args.direction)

        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(output)
            print(f"Wrote {args.format} map: {args.output}", file=sys.stderr)

        print(output, end="")

    if graph.errors:
        print(f"Completed with {len(graph.errors)} warning(s).", file=sys.stderr)
    print(
        f"Mapped {resolved.kind} {resolved.resource_id} in {resolved.region} "
        f"(tool v{__version__})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
