from __future__ import annotations

import html as html_module
import json
import re
from typing import Iterable

# Mermaid classDef styles keyed by CSS class name.
CLASS_DEFS: dict[str, str] = {
    "root": "fill:#fef3c7,stroke:#d97706,stroke-width:3px",
    "internet": "fill:#fee2e2,stroke:#dc2626,stroke-width:2px",
    "cidr": "fill:#ffedd5,stroke:#ea580c,stroke-width:2px",
    "sg": "fill:#fce7f3,stroke:#db2777,stroke-width:2px",
    "network": "fill:#e0f2fe,stroke:#0284c7,stroke-width:2px",
    "compute": "fill:#dcfce7,stroke:#16a34a,stroke-width:2px",
    "lb": "fill:#ede9fe,stroke:#7c3aed,stroke-width:2px",
    "user": "fill:#dbeafe,stroke:#2563eb,stroke-width:2px",
    "group": "fill:#e0e7ff,stroke:#4f46e5,stroke-width:2px",
    "role": "fill:#f3e8ff,stroke:#9333ea,stroke-width:2px",
    "policy": "fill:#ffedd5,stroke:#ea580c,stroke-width:2px",
    "principal": "fill:#f3f4f6,stroke:#6b7280,stroke-width:2px",
    "admin": "fill:#fecaca,stroke:#dc2626,stroke-width:3px",
    "storage": "fill:#ccfbf1,stroke:#0d9488,stroke-width:2px",
    "region": "fill:#f1f5f9,stroke:#475569,stroke-width:3px",
}

NETWORK_KIND_CLASS: dict[str, str] = {
    "internet": "internet",
    "cidr": "cidr",
    "security_group": "sg",
    "vpc": "network",
    "subnet": "network",
    "route_table": "network",
    "nacl": "network",
    "igw": "network",
    "nat": "network",
    "network_interface": "network",
    "ec2_instance": "compute",
    "rds_instance": "compute",
    "lambda_function": "compute",
    "load_balancer": "lb",
    "target_group": "lb",
    "target": "compute",
    "ebs_volume": "storage",
    "s3_bucket": "storage",
    "dynamodb_table": "storage",
    "region": "region",
}

IAM_KIND_CLASS: dict[str, str] = {
    "user": "user",
    "group": "group",
    "role": "role",
    "policy": "policy",
    "principal": "principal",
}

NETWORK_LEGEND: tuple[tuple[str, str], ...] = (
    ("Focus resource", "root"),
    ("Internet / CIDR", "internet"),
    ("Security groups", "sg"),
    ("Network (VPC/subnet/routes)", "network"),
    ("Compute (EC2/RDS/Lambda)", "compute"),
    ("Load balancers", "lb"),
    ("Storage (EBS/S3/DynamoDB)", "storage"),
    ("Region", "region"),
)

IAM_LEGEND: tuple[tuple[str, str], ...] = (
    ("Users", "user"),
    ("Groups", "group"),
    ("Roles", "role"),
    ("Policies", "policy"),
    ("Trust principals", "principal"),
    ("Administrator access", "admin"),
)

# Mermaid rejects diagrams above 50k chars by default; account-wide maps exceed that.
MERMAID_MAX_TEXT_SIZE = 900_000


def class_def_lines(*, extra: dict[str, str] | None = None) -> list[str]:
    styles = dict(CLASS_DEFS)
    if extra:
        styles.update(extra)
    return [f"    classDef {name} {spec}" for name, spec in styles.items()]


def kind_class_for_network(kind: str) -> str | None:
    return NETWORK_KIND_CLASS.get(kind)


def kind_class_for_iam(kind: str, *, is_admin: bool = False) -> str | None:
    if is_admin:
        return "admin"
    return IAM_KIND_CLASS.get(kind)


# Matches a Mermaid flowchart edge line: ``  src -->|"label"| tgt`` or ``src --> tgt``.
_MERMAID_EDGE_RE = re.compile(r"^\s*([A-Za-z0-9_]+)\s*-->\s*(?:\|[^|]*\|\s*)?([A-Za-z0-9_]+)")

# Client-side highlighting: click a node to spotlight its connected chain, dim the rest.
# Kept as a plain string (single braces) so it is not reparsed by the HTML f-string.
_HIGHLIGHT_CSS = """
    .diagram-wrap svg g.node {{ cursor: pointer; }}
    .diagram-wrap svg.focus-active .node {{ opacity: 0.18; transition: opacity 0.15s ease; }}
    .diagram-wrap svg.focus-active .node.hl {{ opacity: 1; }}
    .diagram-wrap svg.focus-active path.flowchart-link {{
      opacity: 0.07;
      transition: opacity 0.15s ease;
    }}
    .diagram-wrap svg.focus-active path.flowchart-link.hl {{ opacity: 1; }}
    .diagram-wrap svg.focus-active .edgeLabel {{ opacity: 0.12; }}
    .diagram-wrap svg .node.hl rect,
    .diagram-wrap svg .node.hl polygon,
    .diagram-wrap svg .node.hl circle,
    .diagram-wrap svg .node.hl path {{ stroke-width: 3px; }}
""".replace("{{", "{").replace("}}", "}")

_HIGHLIGHT_SCRIPT = """
<script>
(function () {
  var EDGES = window.__GRAPH_EDGES__ || [];
  function ready(cb) {
    var tries = 0;
    var timer = setInterval(function () {
      var svg = document.querySelector('.diagram-wrap .mermaid svg');
      if (svg && svg.querySelector('g.node')) { clearInterval(timer); cb(svg); }
      else if (++tries > 200) { clearInterval(timer); }
    }, 50);
  }
  function nodeIdFromEl(el) {
    var m = /-flowchart-(.+)-\\d+$/.exec(el.id || '');
    return m ? m[1] : null;
  }
  ready(function (svg) {
    var nodeEls = {};
    svg.querySelectorAll('g.node').forEach(function (g) {
      var id = nodeIdFromEl(g);
      if (!id) return;
      (nodeEls[id] = nodeEls[id] || []).push(g);
    });
    var adj = {};
    EDGES.forEach(function (e) {
      (adj[e[0]] = adj[e[0]] || []).push(e[1]);
      (adj[e[1]] = adj[e[1]] || []).push(e[0]);
    });
    var paths = Array.prototype.slice.call(svg.querySelectorAll('path.flowchart-link'));
    var used = {};
    var edgeEls = EDGES.map(function (e) {
      var re = new RegExp('L_' + e[0] + '_' + e[1] + '_\\\\d+$');
      var el = null;
      for (var i = 0; i < paths.length; i++) {
        if (!used[i] && re.test(paths[i].id || '')) { el = paths[i]; used[i] = true; break; }
      }
      return { s: e[0], t: e[1], el: el };
    });
    function component(start) {
      var seen = {}; var stack = [start]; seen[start] = true;
      while (stack.length) {
        var n = stack.pop();
        (adj[n] || []).forEach(function (m) { if (!seen[m]) { seen[m] = true; stack.push(m); } });
      }
      return seen;
    }
    function clear() {
      svg.classList.remove('focus-active');
      svg.querySelectorAll('.hl, .dim').forEach(function (el) {
        el.classList.remove('hl', 'dim');
      });
    }
    function focus(nodeId) {
      var set = component(nodeId);
      svg.classList.add('focus-active');
      Object.keys(nodeEls).forEach(function (id) {
        var on = !!set[id];
        nodeEls[id].forEach(function (g) {
          g.classList.toggle('hl', on);
          g.classList.toggle('dim', !on);
        });
      });
      edgeEls.forEach(function (e) {
        if (!e.el) return;
        var on = !!(set[e.s] && set[e.t]);
        e.el.classList.toggle('hl', on);
        e.el.classList.toggle('dim', !on);
      });
    }
    Object.keys(nodeEls).forEach(function (id) {
      nodeEls[id].forEach(function (g) {
        g.addEventListener('click', function (ev) { ev.stopPropagation(); focus(id); });
      });
    });
    svg.addEventListener('click', function () { clear(); });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') { clear(); }
    });
  });
})();
</script>
"""


def parse_mermaid_edges(mermaid: str) -> list[list[str]]:
    """Extract ``[source, target]`` node-id pairs from Mermaid flowchart edge lines."""
    edges: list[list[str]] = []
    for line in mermaid.splitlines():
        match = _MERMAID_EDGE_RE.match(line)
        if match:
            edges.append([match.group(1), match.group(2)])
    return edges


def render_interactive_html(
    *,
    title: str,
    subtitle: str,
    mermaid: str,
    legend: Iterable[tuple[str, str]] | None = None,
) -> str:
    escaped_title = html_module.escape(title)
    escaped_subtitle = html_module.escape(subtitle)
    edges_json = json.dumps(parse_mermaid_edges(mermaid))
    interactivity = f"<script>window.__GRAPH_EDGES__ = {edges_json};</script>" + _HIGHLIGHT_SCRIPT
    legend_html = ""
    if legend:
        items = []
        for label, class_name in legend:
            style = CLASS_DEFS.get(class_name, "fill:#fff,stroke:#999")
            fill = style.split("fill:")[1].split(",")[0] if "fill:" in style else "#fff"
            stroke = style.split("stroke:")[1].split(",")[0] if "stroke:" in style else "#999"
            items.append(
                f'<span class="legend-item">'
                f'<span class="swatch" style="background:{fill};border-color:{stroke};"></span>'
                f"{html_module.escape(label)}</span>"
            )
        legend_html = f'<div class="legend">{"".join(items)}</div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escaped_title}</title>
  <script type="module">
    import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
    mermaid.initialize({{
      startOnLoad: true,
      maxTextSize: {MERMAID_MAX_TEXT_SIZE},
      theme: "base",
      themeVariables: {{
        fontSize: "15px",
        fontFamily: "Inter, Segoe UI, sans-serif",
        lineColor: "#475569",
        primaryTextColor: "#0f172a",
        primaryColor: "#dbeafe",
        secondaryColor: "#e0f2fe",
        tertiaryColor: "#f8fafc"
      }},
      flowchart: {{
        htmlLabels: true,
        curve: "basis",
        padding: 18,
        nodeSpacing: 42,
        rankSpacing: 56,
        useMaxWidth: false
      }}
    }});
  </script>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, Segoe UI, sans-serif;
      color: var(--text);
      background: var(--bg);
    }}
    header {{
      padding: 1.25rem 1.5rem;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
    }}
    h1 {{
      margin: 0 0 0.35rem;
      font-size: 1.35rem;
    }}
    .subtitle {{
      margin: 0;
      color: var(--muted);
      font-size: 0.95rem;
    }}
    .legend {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.65rem 1rem;
      margin-top: 0.85rem;
    }}
    .legend-item {{
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.85rem;
      color: var(--muted);
    }}
    .swatch {{
      width: 0.85rem;
      height: 0.85rem;
      border-radius: 0.2rem;
      border: 2px solid;
      display: inline-block;
    }}
    .diagram-wrap {{
      margin: 1rem;
      padding: 1rem;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      overflow: auto;
      min-height: 70vh;
    }}
    .mermaid {{
      min-width: max-content;
    }}
    .hint {{
      margin: 0.5rem 0 0;
      color: var(--muted);
      font-size: 0.82rem;
    }}
{_HIGHLIGHT_CSS}
  </style>
</head>
<body>
  <header>
    <h1>{escaped_title}</h1>
    <p class="subtitle">{escaped_subtitle}</p>
    <p class="hint">Click a node to highlight its connected chain &middot; click empty space or press Esc to reset</p>
    {legend_html}
  </header>
  <div class="diagram-wrap">
    <pre class="mermaid">{html_module.escape(mermaid)}</pre>
  </div>
  {interactivity}
</body>
</html>
"""
