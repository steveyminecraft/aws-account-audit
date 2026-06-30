"""Detailed resource inventory (additive to the standard audit report).

Collects read-only lists of EC2, EBS, RDS, ELB, Lambda, S3, and DynamoDB resources
with location, size, type, and version fields where they apply. Results are written as
separate ``*-inventory.json`` and ``*-inventory.log`` files so the existing audit JSON
and text outputs stay unchanged.
"""

from __future__ import annotations

import html as html_module
import json
from datetime import datetime, timezone
from typing import Any, Callable

from aws_account_audit.models import utc_now_iso
from aws_account_audit.session import client, safe_call

# Inventory categories in display order.
CATEGORIES: tuple[str, ...] = (
    "ec2_instances",
    "ebs_volumes",
    "rds_instances",
    "rds_clusters",
    "load_balancers",
    "lambda_functions",
    "eventbridge_buses",
    "eventbridge_rules",
    "s3_buckets",
    "dynamodb_tables",
    "waf_web_acls",
)


def collect_account_inventory(
    session: Any,
    regions: list[str],
    *,
    home_region: str,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Collect detailed resource lists across ``regions`` (plus global S3).

    Returns a tuple of (inventory dict, non-fatal error strings).
    """
    inventory: dict[str, list[dict[str, Any]]] = {category: [] for category in CATEGORIES}
    errors: list[str] = []

    for region in regions:
        regional, regional_errors = _collect_regional_inventory(session, region)
        errors.extend(regional_errors)
        for category in CATEGORIES:
            if category == "s3_buckets":
                continue
            inventory[category].extend(regional.get(category, []))

    buckets, bucket_errors = _collect_s3_buckets(session, home_region)
    errors.extend(bucket_errors)
    inventory["s3_buckets"].extend(buckets)

    cloudfront_waf, waf_error = _collect_waf_cloudfront(session)
    if waf_error:
        errors.append(waf_error)
    inventory["waf_web_acls"].extend(cloudfront_waf)

    return inventory, errors


def inventory_to_dict(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    *,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Build the JSON payload for a standalone inventory file."""
    counts = {category: len(inventory.get(category, [])) for category in CATEGORIES}
    return {
        "metadata": metadata,
        "summary": {
            "resource_count": sum(counts.values()),
            "counts_by_type": counts,
        },
        "inventory": inventory,
        "errors": errors or [],
    }


def render_inventory_report(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    *,
    errors: list[str] | None = None,
) -> str:
    """Render a standalone human-readable inventory report."""
    lines: list[str] = []
    lines.append("AWS Account Resource Inventory")
    lines.append("=" * 72)
    lines.append(f"Generated: {metadata.get('generated_at')}")
    lines.append(f"Account:   {metadata.get('account_id')}")
    lines.append(f"Regions:   {', '.join(metadata.get('regions_scanned', []))}")
    lines.append("")
    lines.extend(render_inventory_text(inventory))
    if errors:
        lines.append("")
        lines.append("Collection errors")
        lines.append("-" * 72)
        for error in errors:
            lines.append(f"  - {error}")
    lines.append("")
    lines.append(f"Inventory complete at {utc_now_iso()}")
    return "\n".join(lines) + "\n"


def _inventory_table_html(spec: "_TableSpec", rows: list[dict[str, Any]]) -> str:
    """Render one inventory category as an HTML table card."""
    header_cells = "".join(f"<th>{html_module.escape(header)}</th>" for header in spec.headers)
    body_rows: list[str] = []
    for item in rows:
        cells = "".join(f"<td>{html_module.escape(str(cell))}</td>" for cell in spec.row(item))
        body_rows.append(f"<tr>{cells}</tr>")
    table_id = html_module.escape(spec.category)
    return (
        f'<section class="card" id="{table_id}">'
        f"<h2>{html_module.escape(spec.title)} "
        f'<span class="count">{len(rows)}</span></h2>'
        f'<div class="table-wrap"><table>'
        f"<thead><tr>{header_cells}</tr></thead>"
        f"<tbody>{''.join(body_rows)}</tbody>"
        f"</table></div></section>"
    )


def render_inventory_html(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    *,
    errors: list[str] | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render the resource inventory as a self-contained HTML page with tables."""
    account_id = str(metadata.get("account_id") or "unknown-account")
    generated_at = generated_at or datetime.now(timezone.utc)
    generated_label = generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    regions = ", ".join(metadata.get("regions_scanned", []) or []) or "-"

    counts = {category: len(inventory.get(category, [])) for category in CATEGORIES}
    total = sum(counts.values())

    stat_pairs: list[tuple[str, Any]] = [("Account", account_id), ("Total resources", total)]
    cards: list[str] = []
    for spec in _TABLE_SPECS:
        rows = inventory.get(spec.category, []) or []
        stat_pairs.append((spec.title, len(rows)))
        if rows:
            cards.append(_inventory_table_html(spec, rows))

    if not cards:
        cards.append(
            '<section class="card"><p class="empty">No resources discovered '
            "(check credentials, regions, or permissions).</p></section>"
        )

    if errors:
        error_items = "".join(f"<li>{html_module.escape(str(error))}</li>" for error in errors)
        cards.append(
            '<section class="card errors"><h2>Collection errors '
            f'<span class="count">{len(errors)}</span></h2>'
            f"<ul>{error_items}</ul></section>"
        )

    stats_html = "".join(
        f'<div class="stat"><span class="stat-value">{html_module.escape(str(value))}</span>'
        f'<span class="stat-label">{html_module.escape(str(label))}</span></div>'
        for label, value in stat_pairs
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Resource inventory: {html_module.escape(account_id)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f8fafc;
      --panel: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --border: #e2e8f0;
      --accent: #0d9488;
      --row-alt: #f1f5f9;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, "Segoe UI", sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.5;
    }}
    header {{
      padding: 1.5rem;
      background: var(--panel);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 5;
    }}
    h1 {{ margin: 0 0 0.35rem; font-size: 1.5rem; }}
    .subtitle {{ margin: 0; color: var(--muted); font-size: 0.9rem; }}
    .stats {{ display: flex; flex-wrap: wrap; gap: 0.6rem; margin-top: 1rem; }}
    .stat {{
      display: flex;
      flex-direction: column;
      padding: 0.45rem 0.8rem;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 0.6rem;
      min-width: 5rem;
    }}
    .stat-value {{ font-size: 1.15rem; font-weight: 600; }}
    .stat-label {{ font-size: 0.72rem; color: var(--muted); text-transform: uppercase; }}
    .filter {{
      margin-top: 1rem;
      width: 100%;
      max-width: 28rem;
      padding: 0.55rem 0.8rem;
      font-size: 0.95rem;
      border: 1px solid var(--border);
      border-radius: 0.6rem;
    }}
    main {{ display: flex; flex-direction: column; gap: 1rem; padding: 1.25rem; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 0.75rem;
      padding: 1rem 1.25rem;
    }}
    .card h2 {{ margin: 0 0 0.6rem; font-size: 1.05rem; display: flex; align-items: center; }}
    .count {{
      margin-left: 0.5rem;
      padding: 0.05rem 0.5rem;
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--accent);
      background: #ccfbf1;
      border-radius: 0.5rem;
    }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    th, td {{ padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid var(--border); }}
    th {{
      position: sticky;
      top: 0;
      background: var(--panel);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      color: var(--muted);
    }}
    tbody tr:nth-child(even) {{ background: var(--row-alt); }}
    tbody tr.hidden {{ display: none; }}
    .empty {{ color: var(--muted); font-style: italic; margin: 0; }}
    .errors .count {{ color: #b91c1c; background: #fee2e2; }}
  </style>
</head>
<body>
  <header>
    <h1>Resource inventory: {html_module.escape(account_id)}</h1>
    <p class="subtitle">
      {html_module.escape(str(total))} resources &middot; regions: {html_module.escape(regions)}
      &middot; generated {generated_label}
    </p>
    <div class="stats">{stats_html}</div>
    <input class="filter" type="search" placeholder="Filter rows (name, type, id, region)..."
      oninput="filterInventory(this.value)" aria-label="Filter inventory rows">
  </header>
  <main>
    {"".join(cards)}
  </main>
  <script>
    function filterInventory(query) {{
      const needle = query.trim().toLowerCase();
      document.querySelectorAll('tbody tr').forEach(function (row) {{
        const match = !needle || row.textContent.toLowerCase().includes(needle);
        row.classList.toggle('hidden', !match);
      }});
    }}
  </script>
</body>
</html>
"""


def build_inventory_graph(
    inventory: dict[str, list[dict[str, Any]]],
    account_id: str | None = None,
) -> dict[str, Any]:
    """Build an account-graph-mergeable map payload from the resource inventory.

    Returns a dict in the network-map JSON schema (root/region/nodes/edges/
    ingress_paths/errors) so it can be dropped alongside other map files and merged
    into the account-wide graph PNG/HTML/JSON. Each resource becomes a node grouped
    under a region anchor; node labels carry location, size, type, and version.
    """
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()

    def _add_node(node_id: str, kind: str, label: str, metadata: dict[str, Any]) -> None:
        if node_id in seen_nodes:
            return
        seen_nodes.add(node_id)
        nodes.append({"node_id": node_id, "kind": kind, "label": label, "metadata": metadata})

    def _region_anchor(region: str | None) -> str:
        region = region or "global"
        anchor_id = f"region:{region}"
        _add_node(anchor_id, "region", f"Region {region}", {"region": region})
        return anchor_id

    for spec in _GRAPH_SPECS:
        for item in inventory.get(spec.category, []) or []:
            raw_id = spec.id_of(item)
            if not raw_id:
                continue
            node_id = f"{spec.kind}:{raw_id}"
            _add_node(node_id, spec.kind, spec.label_of(item), dict(item))
            anchor_id = _region_anchor(item.get("region"))
            edges.append(
                {
                    "source": anchor_id,
                    "target": node_id,
                    "label": "hosts",
                    "edge_type": "inventory",
                }
            )

    return {
        "root": f"account:{account_id or 'unknown-account'}",
        "region": "all",
        "nodes": nodes,
        "edges": edges,
        "ingress_paths": [],
        "errors": [],
    }


def render_inventory_text(inventory: dict[str, list[dict[str, Any]]]) -> list[str]:
    """Render inventory tables as a list of text lines."""
    lines: list[str] = []
    lines.append("Resource Inventory")
    lines.append("-" * 72)

    total = sum(len(inventory.get(category, [])) for category in CATEGORIES)
    if total == 0:
        lines.append("No resources discovered (check credentials, regions, or permissions).")
        return lines

    for spec in _TABLE_SPECS:
        rows = inventory.get(spec.category, [])
        if not rows:
            continue
        lines.append("")
        lines.append(f"{spec.title} ({len(rows)})")
        lines.extend(_format_table(spec.headers, [spec.row(item) for item in rows]))

    return lines


def write_inventory_files(
    metadata: dict[str, Any],
    inventory: dict[str, list[dict[str, Any]]],
    output_dir: Any,
    base_name: str,
    *,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Write ``{base_name}-inventory.json`` and ``{base_name}-inventory.log``."""
    from pathlib import Path

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = inventory_to_dict(metadata, inventory, errors=errors)
    json_path = output_dir / f"{base_name}-inventory.json"
    text_path = output_dir / f"{base_name}-inventory.log"
    html_path = output_dir / f"{base_name}-inventory.html"
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    text_path.write_text(
        render_inventory_report(metadata, inventory, errors=errors),
        encoding="utf-8",
    )
    html_path.write_text(
        render_inventory_html(metadata, inventory, errors=errors),
        encoding="utf-8",
    )
    return {
        "inventory_json": json_path,
        "inventory_text": text_path,
        "inventory_html": html_path,
    }


def _collect_regional_inventory(
    session: Any, region: str
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    inventory: dict[str, list[dict[str, Any]]] = {category: [] for category in CATEGORIES}
    errors: list[str] = []

    ec2 = client(session, "ec2", region)
    elbv2 = client(session, "elbv2", region)
    lambda_client = client(session, "lambda", region)
    rds = client(session, "rds", region)
    dynamodb = client(session, "dynamodb", region)
    events = client(session, "events", region)
    waf = client(session, "wafv2", region)

    instances, instance_error = _collect_instances(ec2, region)
    if instance_error:
        errors.append(instance_error)
    inventory["ec2_instances"] = [_summarize_instance(item, region) for item in instances or []]

    volumes, volume_error = _paginate_call(
        ec2.describe_volumes, "Volumes", f"ec2.describe_volumes({region})"
    )
    if volume_error:
        errors.append(volume_error)
    inventory["ebs_volumes"] = [_summarize_volume(item, region) for item in volumes or []]

    load_balancers, lb_error = _paginate_call(
        elbv2.describe_load_balancers,
        "LoadBalancers",
        f"elbv2.describe_load_balancers({region})",
    )
    if lb_error:
        errors.append(lb_error)
    inventory["load_balancers"] = [
        _summarize_load_balancer(item, region) for item in load_balancers or []
    ]

    functions, lambda_error = _paginate_call(
        lambda_client.list_functions, "Functions", f"lambda.list_functions({region})"
    )
    if lambda_error:
        errors.append(lambda_error)
    inventory["lambda_functions"] = [_summarize_lambda(item, region) for item in functions or []]

    db_instances, rds_error = _paginate_call(
        rds.describe_db_instances, "DBInstances", f"rds.describe_db_instances({region})"
    )
    if rds_error:
        errors.append(rds_error)
    inventory["rds_instances"] = [_summarize_rds(item, region) for item in db_instances or []]

    db_clusters, cluster_error = _paginate_call(
        rds.describe_db_clusters, "DBClusters", f"rds.describe_db_clusters({region})"
    )
    if cluster_error:
        errors.append(cluster_error)
    inventory["rds_clusters"] = [_summarize_rds_cluster(item, region) for item in db_clusters or []]

    buses, bus_error = _paginate_call(
        events.list_event_buses, "EventBuses", f"events.list_event_buses({region})"
    )
    if bus_error:
        errors.append(bus_error)
    inventory["eventbridge_buses"] = [
        _summarize_eventbridge_bus(item, region) for item in buses or []
    ]

    rules: list[dict[str, Any]] = []
    for bus in buses or []:
        bus_name = bus.get("Name", "default")
        bus_rules, rules_error = _paginate_call(
            events.list_rules,
            "Rules",
            f"events.list_rules({region},{bus_name})",
            EventBusName=bus_name,
        )
        if rules_error:
            errors.append(rules_error)
            continue
        for rule in bus_rules or []:
            target_count = 0
            targets, targets_error = _paginate_call(
                events.list_targets_by_rule,
                "Targets",
                f"events.list_targets_by_rule({region},{bus_name},{rule.get('Name')})",
                Rule=rule["Name"],
                EventBusName=bus_name,
            )
            if targets_error:
                errors.append(targets_error)
            else:
                target_count = len(targets or [])
            rules.append(_summarize_eventbridge_rule(rule, region, bus_name, target_count))
    inventory["eventbridge_rules"] = rules

    regional_waf, waf_error = _collect_waf_web_acls(waf, region, scope="REGIONAL")
    if waf_error:
        errors.append(waf_error)
    inventory["waf_web_acls"] = regional_waf

    tables, ddb_error = _paginate_call(
        dynamodb.list_tables, "TableNames", f"dynamodb.list_tables({region})"
    )
    if ddb_error:
        errors.append(ddb_error)
    inventory["dynamodb_tables"] = [{"name": table, "region": region} for table in tables or []]

    return inventory, errors


def _collect_s3_buckets(session: Any, home_region: str) -> tuple[list[dict[str, Any]], list[str]]:
    s3 = client(session, "s3", home_region)
    errors: list[str] = []
    buckets, buckets_error = safe_call(
        "s3.list_buckets", lambda: s3.list_buckets().get("Buckets", [])
    )
    if buckets_error:
        return [], [buckets_error]

    details: list[dict[str, Any]] = []
    for bucket in buckets or []:
        name = bucket["Name"]
        location, location_error = safe_call(
            f"s3.get_bucket_location({name})",
            lambda name=name: (
                s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            ),
        )
        policy_status, policy_status_error = safe_call(
            f"s3.get_bucket_policy_status({name})",
            lambda name=name: s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus"),
            not_found_ok=True,
        )
        for error in (location_error, policy_status_error):
            if error:
                errors.append(error)
        details.append(
            {
                "name": name,
                "region": location,
                "creation_date": bucket.get("CreationDate"),
                "is_public": bool((policy_status or {}).get("IsPublic")),
            }
        )
    return details, errors


def _collect_waf_cloudfront(session: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """List CloudFront-scoped WAF Web ACLs (API home region is always us-east-1)."""
    waf = client(session, "wafv2", "us-east-1")
    return _collect_waf_web_acls(waf, "global", scope="CLOUDFRONT")


def _collect_waf_web_acls(
    waf: Any, region: str, *, scope: str
) -> tuple[list[dict[str, Any]], str | None]:
    summaries, error = safe_call(
        f"wafv2.list_web_acls({scope},{region})",
        lambda: _paginate_waf(waf.list_web_acls, scope=scope),
    )
    if error:
        return [], error

    details: list[dict[str, Any]] = []
    describe_errors: list[str] = []
    for summary in summaries or []:
        item, detail_error = _describe_waf_web_acl(waf, summary, region, scope=scope)
        if detail_error:
            describe_errors.append(detail_error)
            details.append(
                {
                    "name": summary.get("Name"),
                    "id": summary.get("Id"),
                    "scope": scope,
                    "description": summary.get("Description"),
                    "rule_count": None,
                    "default_action": None,
                    "region": region,
                }
            )
        elif item:
            details.append(item)
    combined_error = "; ".join(describe_errors) if describe_errors else None
    return details, combined_error


def _paginate_waf(func: Callable[..., Any], *, scope: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        params: dict[str, Any] = {"Scope": scope, "Limit": 100}
        if marker:
            params["Marker"] = marker
        response = func(**params)
        items.extend(response.get("WebACLs", []))
        marker = response.get("NextMarker")
        if not marker:
            break
    return items


def _describe_waf_web_acl(
    waf: Any, summary: dict[str, Any], region: str, *, scope: str
) -> tuple[dict[str, Any] | None, str | None]:
    name = summary.get("Name")
    acl_id = summary.get("Id")
    if not name or not acl_id:
        return None, None

    response, error = safe_call(
        f"wafv2.describe_web_acl({scope},{name})",
        lambda: waf.describe_web_acl(Name=name, Scope=scope, Id=acl_id),
    )
    if error:
        return None, error

    acl = (response or {}).get("WebACL", {})
    default_action = _waf_default_action(acl.get("DefaultAction"))
    return (
        {
            "name": name,
            "id": acl_id,
            "scope": scope,
            "description": summary.get("Description") or acl.get("Description"),
            "rule_count": len(acl.get("Rules") or []),
            "default_action": default_action,
            "region": region,
        },
        None,
    )


def _waf_default_action(action: dict[str, Any] | None) -> str | None:
    if not action:
        return None
    for key in ("Allow", "Block"):
        if key in action:
            return key
    return next(iter(action.keys()), None)


def _collect_instances(ec2: Any, region: str) -> tuple[list[dict[str, Any]] | None, str | None]:
    reservations, error = _paginate_call(
        ec2.describe_instances, "Reservations", f"ec2.describe_instances({region})"
    )
    if error:
        return None, error
    instances: list[dict[str, Any]] = []
    for reservation in reservations or []:
        instances.extend(reservation.get("Instances", []))
    return instances, None


def _paginate_call(
    func: Callable[..., Any], key: str, label: str, **kwargs: Any
) -> tuple[list[Any] | None, str | None]:
    items, error = safe_call(label, lambda: _paginate(func, key, **kwargs))
    if error:
        return None, error
    return items, None


def _paginate(func: Callable[..., Any], key: str, **kwargs: Any) -> list[Any]:
    items: list[Any] = []
    token_param: str | None = None
    token_value: str | None = None
    while True:
        params = dict(kwargs)
        if token_param and token_value:
            params[token_param] = token_value
        response = func(**params)
        items.extend(response.get(key, []))
        if response.get("NextToken"):
            token_param, token_value = "NextToken", response["NextToken"]
            continue
        if response.get("PaginationToken"):
            token_param, token_value = "PaginationToken", response["PaginationToken"]
            continue
        if response.get("IsTruncated") and response.get("Marker"):
            token_param, token_value = "Marker", response["Marker"]
            continue
        break
    return items


def _name_from_tags(tags: list[dict[str, Any]] | None) -> str | None:
    for tag in tags or []:
        if tag.get("Key") == "Name":
            return tag.get("Value")
    return None


def _summarize_instance(instance: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "id": instance["InstanceId"],
        "name": _name_from_tags(instance.get("Tags")),
        "type": instance.get("InstanceType"),
        "state": (instance.get("State") or {}).get("Name"),
        "availability_zone": (instance.get("Placement") or {}).get("AvailabilityZone"),
        "image_id": instance.get("ImageId"),
        "platform": instance.get("PlatformDetails") or instance.get("Platform"),
        "launch_time": instance.get("LaunchTime"),
        "private_ip": instance.get("PrivateIpAddress"),
        "public_ip": instance.get("PublicIpAddress"),
        "region": region,
    }


def _summarize_volume(volume: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "id": volume["VolumeId"],
        "type": volume.get("VolumeType"),
        "size_gb": volume.get("Size"),
        "availability_zone": volume.get("AvailabilityZone"),
        "state": volume.get("State"),
        "encrypted": volume.get("Encrypted"),
        "iops": volume.get("Iops"),
        "region": region,
    }


def _summarize_rds(item: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "identifier": item.get("DBInstanceIdentifier"),
        "engine": item.get("Engine"),
        "engine_version": item.get("EngineVersion"),
        "instance_class": item.get("DBInstanceClass"),
        "allocated_storage_gb": item.get("AllocatedStorage"),
        "availability_zone": item.get("AvailabilityZone"),
        "multi_az": item.get("MultiAZ"),
        "status": item.get("DBInstanceStatus"),
        "publicly_accessible": item.get("PubliclyAccessible"),
        "region": region,
    }


def _summarize_rds_cluster(item: dict[str, Any], region: str) -> dict[str, Any]:
    members = item.get("DBClusterMembers") or []
    return {
        "identifier": item.get("DBClusterIdentifier"),
        "engine": item.get("Engine"),
        "engine_version": item.get("EngineVersion"),
        "engine_mode": item.get("EngineMode"),
        "status": item.get("Status"),
        "member_count": len(members),
        "multi_az": item.get("MultiAZ"),
        "storage_encrypted": item.get("StorageEncrypted"),
        "endpoint": item.get("Endpoint"),
        "region": region,
    }


def _summarize_eventbridge_bus(item: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "name": item.get("Name"),
        "arn": item.get("Arn"),
        "region": region,
    }


def _summarize_eventbridge_rule(
    item: dict[str, Any], region: str, bus_name: str, target_count: int
) -> dict[str, Any]:
    schedule = item.get("ScheduleExpression")
    pattern = item.get("EventPattern")
    trigger = schedule or (_truncate(pattern, 80) if pattern else None)
    return {
        "name": item.get("Name"),
        "bus_name": bus_name,
        "state": item.get("State"),
        "trigger": trigger,
        "target_count": target_count,
        "description": item.get("Description"),
        "region": region,
    }


def _truncate(value: str, max_len: int) -> str:
    text = value.replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _summarize_load_balancer(item: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "name": item.get("LoadBalancerName"),
        "dns_name": item.get("DNSName"),
        "type": item.get("Type"),
        "scheme": item.get("Scheme"),
        "state": (item.get("State") or {}).get("Code"),
        "availability_zones": [
            az.get("ZoneName") for az in item.get("AvailabilityZones", []) if az.get("ZoneName")
        ],
        "vpc_id": item.get("VpcId"),
        "region": region,
    }


def _summarize_lambda(item: dict[str, Any], region: str) -> dict[str, Any]:
    return {
        "name": item["FunctionName"],
        "runtime": item.get("Runtime"),
        "memory_size_mb": item.get("MemorySize"),
        "code_size_bytes": item.get("CodeSize"),
        "version": item.get("Version"),
        "architectures": item.get("Architectures", []),
        "handler": item.get("Handler"),
        "last_modified": item.get("LastModified"),
        "region": region,
    }


def _text(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(part) for part in value) if value else "-"
    text = str(value)
    return text if text else "-"


def _format_bytes(value: Any) -> str:
    if value is None:
        return "-"
    try:
        size = float(value)
    except (TypeError, ValueError):
        return _text(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _format_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))

    def _format_row(cells: list[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    lines = [f"  {_format_row(headers)}"]
    lines.append(f"  {_format_row(['-' * width for width in widths])}")
    lines.extend(f"  {_format_row(row)}" for row in rows)
    return lines


def _join(*parts: Any) -> str:
    return " · ".join(str(part) for part in parts if part)


def _ec2_graph_label(item: dict[str, Any]) -> str:
    name = item.get("name") or item.get("id")
    detail = _join(item.get("type"), item.get("state"), item.get("availability_zone"))
    return f"EC2 {name} ({detail})" if detail else f"EC2 {name}"


def _ebs_graph_label(item: dict[str, Any]) -> str:
    size = f"{item.get('size_gb')} GiB" if item.get("size_gb") is not None else None
    detail = _join(item.get("type"), size, item.get("availability_zone"))
    return f"EBS {item.get('id')} ({detail})" if detail else f"EBS {item.get('id')}"


def _rds_graph_label(item: dict[str, Any]) -> str:
    engine = _join(item.get("engine"), item.get("engine_version"))
    size = f"{item.get('allocated_storage_gb')} GiB" if item.get("allocated_storage_gb") else None
    detail = _join(engine, item.get("instance_class"), size, item.get("availability_zone"))
    return f"RDS {item.get('identifier')} ({detail})" if detail else f"RDS {item.get('identifier')}"


def _rds_cluster_graph_label(item: dict[str, Any]) -> str:
    engine = _join(item.get("engine"), item.get("engine_version"), item.get("engine_mode"))
    members = (
        f"{item.get('member_count')} members" if item.get("member_count") is not None else None
    )
    detail = _join(engine, members, item.get("status"))
    return (
        f"RDS cluster {item.get('identifier')} ({detail})"
        if detail
        else f"RDS cluster {item.get('identifier')}"
    )


def _eventbridge_bus_graph_label(item: dict[str, Any]) -> str:
    return f"Event bus {item.get('name')}"


def _eventbridge_rule_graph_label(item: dict[str, Any]) -> str:
    detail = _join(item.get("state"), item.get("trigger"), f"{item.get('target_count')} targets")
    return f"Rule {item.get('name')} ({detail})" if detail else f"Rule {item.get('name')}"


def _waf_graph_label(item: dict[str, Any]) -> str:
    detail = _join(
        item.get("scope"),
        f"{item.get('rule_count')} rules" if item.get("rule_count") is not None else None,
        item.get("default_action"),
    )
    return f"WAF {item.get('name')} ({detail})" if detail else f"WAF {item.get('name')}"


def _lb_graph_label(item: dict[str, Any]) -> str:
    detail = _join(item.get("type"), item.get("scheme"), item.get("state"))
    return f"ELB {item.get('name')} ({detail})" if detail else f"ELB {item.get('name')}"


def _lambda_graph_label(item: dict[str, Any]) -> str:
    memory = f"{item.get('memory_size_mb')} MB" if item.get("memory_size_mb") is not None else None
    arch = ", ".join(item.get("architectures") or []) or None
    detail = _join(item.get("runtime"), memory, arch)
    return f"Lambda {item.get('name')} ({detail})" if detail else f"Lambda {item.get('name')}"


def _s3_graph_label(item: dict[str, Any]) -> str:
    return f"S3 {item.get('name')}"


def _dynamodb_graph_label(item: dict[str, Any]) -> str:
    return f"DynamoDB {item.get('name')}"


class _GraphSpec:
    def __init__(
        self,
        category: str,
        kind: str,
        id_of: Callable[[dict[str, Any]], Any],
        label_of: Callable[[dict[str, Any]], str],
    ) -> None:
        self.category = category
        self.kind = kind
        self.id_of = id_of
        self.label_of = label_of


_GRAPH_SPECS: tuple[_GraphSpec, ...] = (
    _GraphSpec("ec2_instances", "ec2_instance", lambda i: i.get("id"), _ec2_graph_label),
    _GraphSpec("ebs_volumes", "ebs_volume", lambda i: i.get("id"), _ebs_graph_label),
    _GraphSpec("rds_instances", "rds_instance", lambda i: i.get("identifier"), _rds_graph_label),
    _GraphSpec(
        "rds_clusters", "rds_cluster", lambda i: i.get("identifier"), _rds_cluster_graph_label
    ),
    _GraphSpec("load_balancers", "load_balancer", lambda i: i.get("name"), _lb_graph_label),
    _GraphSpec("lambda_functions", "lambda_function", lambda i: i.get("name"), _lambda_graph_label),
    _GraphSpec(
        "eventbridge_buses",
        "eventbridge_bus",
        lambda i: i.get("name"),
        _eventbridge_bus_graph_label,
    ),
    _GraphSpec(
        "eventbridge_rules",
        "eventbridge_rule",
        lambda i: f"{i.get('bus_name')}:{i.get('name')}",
        _eventbridge_rule_graph_label,
    ),
    _GraphSpec("s3_buckets", "s3_bucket", lambda i: i.get("name"), _s3_graph_label),
    _GraphSpec("dynamodb_tables", "dynamodb_table", lambda i: i.get("name"), _dynamodb_graph_label),
    _GraphSpec(
        "waf_web_acls",
        "waf_web_acl",
        lambda i: f"{i.get('scope')}:{i.get('id')}",
        _waf_graph_label,
    ),
)


class _TableSpec:
    def __init__(
        self,
        category: str,
        title: str,
        headers: list[str],
        row: Callable[[dict[str, Any]], list[str]],
    ) -> None:
        self.category = category
        self.title = title
        self.headers = headers
        self.row = row


_TABLE_SPECS: tuple[_TableSpec, ...] = (
    _TableSpec(
        "ec2_instances",
        "EC2 Instances",
        ["Name", "Instance ID", "Type", "State", "Location", "Private IP", "Public IP"],
        lambda i: [
            _text(i.get("name")),
            _text(i.get("id")),
            _text(i.get("type")),
            _text(i.get("state")),
            _text(i.get("availability_zone") or i.get("region")),
            _text(i.get("private_ip")),
            _text(i.get("public_ip")),
        ],
    ),
    _TableSpec(
        "ebs_volumes",
        "EBS Volumes",
        ["Volume ID", "Type", "Size", "Location", "State", "Encrypted"],
        lambda v: [
            _text(v.get("id")),
            _text(v.get("type")),
            f"{v.get('size_gb')} GiB" if v.get("size_gb") is not None else "-",
            _text(v.get("availability_zone") or v.get("region")),
            _text(v.get("state")),
            _text(v.get("encrypted")),
        ],
    ),
    _TableSpec(
        "rds_instances",
        "RDS Instances",
        ["Identifier", "Engine", "Version", "Class", "Storage", "Location", "Status", "Public"],
        lambda r: [
            _text(r.get("identifier")),
            _text(r.get("engine")),
            _text(r.get("engine_version")),
            _text(r.get("instance_class")),
            f"{r.get('allocated_storage_gb')} GiB"
            if r.get("allocated_storage_gb") is not None
            else "-",
            _text(r.get("availability_zone") or r.get("region")),
            _text(r.get("status")),
            _text(r.get("publicly_accessible")),
        ],
    ),
    _TableSpec(
        "rds_clusters",
        "RDS Clusters",
        ["Identifier", "Engine", "Version", "Mode", "Members", "Location", "Status", "Encrypted"],
        lambda c: [
            _text(c.get("identifier")),
            _text(c.get("engine")),
            _text(c.get("engine_version")),
            _text(c.get("engine_mode")),
            _text(c.get("member_count")),
            _text(c.get("region")),
            _text(c.get("status")),
            _text(c.get("storage_encrypted")),
        ],
    ),
    _TableSpec(
        "load_balancers",
        "Load Balancers (ELB)",
        ["Name", "Type", "Scheme", "State", "Location", "DNS Name"],
        lambda lb: [
            _text(lb.get("name")),
            _text(lb.get("type")),
            _text(lb.get("scheme")),
            _text(lb.get("state")),
            _text(lb.get("availability_zones") or lb.get("region")),
            _text(lb.get("dns_name")),
        ],
    ),
    _TableSpec(
        "lambda_functions",
        "Lambda Functions",
        ["Name", "Runtime", "Memory", "Code Size", "Arch", "Version", "Location"],
        lambda fn: [
            _text(fn.get("name")),
            _text(fn.get("runtime")),
            f"{fn.get('memory_size_mb')} MB" if fn.get("memory_size_mb") is not None else "-",
            _format_bytes(fn.get("code_size_bytes")),
            _text(fn.get("architectures")),
            _text(fn.get("version")),
            _text(fn.get("region")),
        ],
    ),
    _TableSpec(
        "eventbridge_buses",
        "EventBridge Event Buses",
        ["Name", "ARN", "Location"],
        lambda b: [
            _text(b.get("name")),
            _text(b.get("arn")),
            _text(b.get("region")),
        ],
    ),
    _TableSpec(
        "eventbridge_rules",
        "EventBridge Rules",
        ["Name", "Bus", "State", "Trigger", "Targets", "Location"],
        lambda r: [
            _text(r.get("name")),
            _text(r.get("bus_name")),
            _text(r.get("state")),
            _text(r.get("trigger")),
            _text(r.get("target_count")),
            _text(r.get("region")),
        ],
    ),
    _TableSpec(
        "s3_buckets",
        "S3 Buckets",
        ["Name", "Location", "Created", "Public"],
        lambda b: [
            _text(b.get("name")),
            _text(b.get("region")),
            _text(b.get("creation_date")),
            _text(b.get("is_public")),
        ],
    ),
    _TableSpec(
        "dynamodb_tables",
        "DynamoDB Tables",
        ["Name", "Location"],
        lambda t: [
            _text(t.get("name")),
            _text(t.get("region")),
        ],
    ),
    _TableSpec(
        "waf_web_acls",
        "WAF Web ACLs",
        ["Name", "Scope", "Rules", "Default Action", "Description", "Location"],
        lambda w: [
            _text(w.get("name")),
            _text(w.get("scope")),
            _text(w.get("rule_count")),
            _text(w.get("default_action")),
            _text(w.get("description")),
            _text(w.get("region")),
        ],
    ),
)
