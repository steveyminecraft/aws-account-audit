from __future__ import annotations

import html as html_module
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


def render_interactive_html(
    *,
    title: str,
    subtitle: str,
    mermaid: str,
    legend: Iterable[tuple[str, str]] | None = None,
) -> str:
    escaped_title = html_module.escape(title)
    escaped_subtitle = html_module.escape(subtitle)
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
  </style>
</head>
<body>
  <header>
    <h1>{escaped_title}</h1>
    <p class="subtitle">{escaped_subtitle}</p>
    {legend_html}
  </header>
  <div class="diagram-wrap">
    <pre class="mermaid">{html_module.escape(mermaid)}</pre>
  </div>
</body>
</html>
"""
