from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aws_account_audit.session import caller_identity, client, create_session, safe_call
from aws_network_map.export import _render_png
from aws_network_map.graph_style import (
    IAM_LEGEND,
    class_def_lines,
    kind_class_for_iam,
    render_interactive_html,
)

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


@dataclass
class IamGraph:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    account_id: str | None = None

    def summary(self) -> dict[str, int]:
        by_kind = {"user": 0, "group": 0, "role": 0, "policy": 0}
        for node in self.nodes.values():
            kind = str(node.get("kind", ""))
            if kind in by_kind:
                by_kind[kind] += 1
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "error_count": len(self.errors),
            "user_count": by_kind["user"],
            "group_count": by_kind["group"],
            "role_count": by_kind["role"],
            "policy_count": by_kind["policy"],
        }


def build_iam_graph(iam_data: dict[str, Any]) -> IamGraph:
    graph = IamGraph()
    seen_edges: set[tuple[str, str, str]] = set()

    users = iam_data.get("users", []) or []
    groups = iam_data.get("groups", []) or []
    roles = iam_data.get("roles", []) or []

    _add_principal_nodes(graph, users, "user")
    _add_principal_nodes(graph, groups, "group")
    _add_principal_nodes(graph, roles, "role")

    admin_sources: list[tuple[str, str]] = []
    admin_sources.extend(("user", name) for name in iam_data.get("admin_users", []) or [])
    admin_sources.extend(("group", name) for name in iam_data.get("admin_groups", []) or [])
    admin_sources.extend(("role", name) for name in iam_data.get("admin_roles", []) or [])

    if admin_sources:
        _add_policy_node(
            graph,
            "policy:AdministratorAccess",
            "AdministratorAccess",
            {"arn": ADMIN_POLICY_ARN, "managed": True},
        )

    for kind, name in admin_sources:
        source_node_id = f"{kind}:{name}"
        if source_node_id not in graph.nodes:
            graph.errors.append(f"Unknown admin {kind}: {name}")
            continue
        _add_edge(
            graph, source_node_id, "policy:AdministratorAccess", "admin", "attached_to", seen_edges
        )

    for member in iam_data.get("user_group_memberships", []) or []:
        user_name = member.get("user")
        group_name = member.get("group")
        if not user_name or not group_name:
            continue
        src = f"user:{user_name}"
        dst = f"group:{group_name}"
        if src in graph.nodes and dst in graph.nodes:
            _add_edge(graph, src, dst, "member", "member_of", seen_edges)

    _add_managed_policy_edges(graph, iam_data.get("user_attached_policies", {}), "user", seen_edges)
    _add_managed_policy_edges(
        graph, iam_data.get("group_attached_policies", {}), "group", seen_edges
    )
    _add_managed_policy_edges(graph, iam_data.get("role_attached_policies", {}), "role", seen_edges)

    _add_inline_policy_edges(graph, iam_data.get("user_inline_policies", {}), "user", seen_edges)
    _add_inline_policy_edges(graph, iam_data.get("group_inline_policies", {}), "group", seen_edges)
    _add_inline_policy_edges(graph, iam_data.get("role_inline_policies", {}), "role", seen_edges)

    for role_name, principals in (iam_data.get("role_trust_principals", {}) or {}).items():
        role_node = f"role:{role_name}"
        if role_node not in graph.nodes:
            continue
        for principal in principals or []:
            principal_text = str(principal)
            principal_node = f"principal:{principal_text}"
            if principal_node not in graph.nodes:
                graph.nodes[principal_node] = {
                    "node_id": principal_node,
                    "kind": "principal",
                    "label": _compact_principal_label(principal_text),
                    "metadata": {"principal": principal_text},
                }
            _add_edge(graph, role_node, principal_node, "trusts", "trusts", seen_edges)

    graph.account_id = str(iam_data.get("account_id") or "") or None
    return graph


def render_iam_mermaid(graph: IamGraph, *, direction: str = "TB") -> str:
    lines = [f"flowchart {direction}"]
    mermaid_ids: dict[str, str] = {}
    admin_nodes = _admin_node_ids(graph)

    subgraph_order = [
        ("user", "Users"),
        ("group", "Groups"),
        ("role", "Roles"),
        ("policy", "Policies"),
        ("principal", "Trust principals"),
    ]
    nodes_by_kind: dict[str, list[dict[str, Any]]] = {kind: [] for kind, _ in subgraph_order}
    for node in graph.nodes.values():
        kind = str(node.get("kind", ""))
        if kind in nodes_by_kind:
            nodes_by_kind[kind].append(node)

    for kind, title in subgraph_order:
        nodes = sorted(nodes_by_kind[kind], key=lambda item: str(item.get("label", "")))
        if not nodes:
            continue
        subgraph_id = _mermaid_id(f"subgraph_{kind}", mermaid_ids)
        lines.append(f'    subgraph {subgraph_id}["{title}"]')
        for node in nodes:
            node_id = str(node.get("node_id", ""))
            mid = _mermaid_id(node_id, mermaid_ids)
            label = _escape_mermaid(str(node.get("label", node_id)))
            shape = _shape_for_kind(kind)
            css_class = kind_class_for_iam(kind, is_admin=node_id in admin_nodes)
            class_suffix = f":::{css_class}" if css_class else ""
            lines.append(f'        {mid}{shape[0]}"{label}"{shape[1]}{class_suffix}')
        lines.append("    end")

    for edge in graph.edges:
        source = _mermaid_id(str(edge.get("source", "")), mermaid_ids)
        target = _mermaid_id(str(edge.get("target", "")), mermaid_ids)
        label = _escape_mermaid(str(edge.get("label", "")))
        lines.append(f'    {source} -->|"{label}"| {target}')

    lines.extend(class_def_lines())
    return "\n".join(lines) + "\n"


def render_iam_html(graph: IamGraph, *, direction: str = "TB") -> str:
    mermaid = render_iam_mermaid(graph, direction=direction)
    account_label = graph.account_id or "unknown-account"
    summary = graph.summary()
    subtitle = (
        f"Account {account_label} | Users: {summary['user_count']} | "
        f"Groups: {summary['group_count']} | Roles: {summary['role_count']} | "
        f"Policies: {summary['policy_count']} | Edges: {summary['edge_count']}"
    )
    return render_interactive_html(
        title=f"IAM relationship graph: {account_label}",
        subtitle=subtitle,
        mermaid=mermaid,
        legend=IAM_LEGEND,
    )


def write_iam_html(graph: IamGraph, path: Path, *, direction: str = "TB") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_iam_html(graph, direction=direction), encoding="utf-8")


def write_iam_data_json(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def generate_iam_outputs(
    *,
    data: dict[str, Any],
    output_base: Path,
    direction: str = "TB",
) -> IamGraph:
    graph = build_iam_graph(data)
    if graph.account_id is None:
        graph.account_id = str(data.get("account_id") or "")

    graph.errors.extend(data.get("errors", []))

    output_base = output_base.with_suffix("")
    write_iam_json(graph, output_base.with_suffix(".json"))
    write_iam_html(graph, output_base.with_suffix(".html"), direction=direction)
    try:
        write_iam_png(graph, output_base.with_suffix(".png"), direction=direction)
    except RuntimeError:
        pass
    return graph


def write_iam_json(graph: IamGraph, path: Path) -> None:
    account_id = graph.account_id or "unknown-account"
    payload = {
        "domain": f"account:{account_id}",
        "account_id": account_id,
        "summary": graph.summary(),
        "nodes": list(graph.nodes.values()),
        "edges": graph.edges,
        "errors": graph.errors,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_iam_png(graph: IamGraph, path: Path, *, direction: str = "TB") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mmd_path = path.with_suffix(".mmd")
    mmd_path.write_text(render_iam_mermaid(graph, direction=direction), encoding="utf-8")
    png_ok, png_error = _render_png(
        mmd_path,
        path,
        node_count=len(graph.nodes),
        edge_count=len(graph.edges),
    )
    mmd_path.unlink(missing_ok=True)
    if not png_ok:
        raise RuntimeError(png_error or "PNG export failed.")


def collect_iam_relationship_data(
    *, profile: str | None = None, region: str = "eu-west-1"
) -> dict[str, Any]:
    session = create_session(profile)
    iam = client(session, "iam", region)
    identity, identity_error = safe_call(
        "sts.get_caller_identity", lambda: caller_identity(session, region)
    )
    users, users_error = safe_call("iam.list_users", lambda: _paginate(iam.list_users, "Users"))
    groups, groups_error = safe_call(
        "iam.list_groups", lambda: _paginate(iam.list_groups, "Groups")
    )
    roles, roles_error = safe_call("iam.list_roles", lambda: _paginate(iam.list_roles, "Roles"))

    errors = [err for err in [identity_error, users_error, groups_error, roles_error] if err]
    users = users or []
    groups = groups or []
    roles = roles or []

    user_summaries = [
        {"name": u.get("UserName", ""), "arn": u.get("Arn", "")} for u in users if u.get("UserName")
    ]
    group_summaries = [
        {"name": g.get("GroupName", ""), "arn": g.get("Arn", "")}
        for g in groups
        if g.get("GroupName")
    ]
    role_summaries = [
        {"name": r.get("RoleName", ""), "arn": r.get("Arn", "")} for r in roles if r.get("RoleName")
    ]

    data: dict[str, Any] = {
        "account_id": (identity or {}).get("Account"),
        "users": user_summaries,
        "groups": group_summaries,
        "roles": role_summaries,
        "admin_users": [],
        "admin_groups": [],
        "admin_roles": [],
        "user_group_memberships": [],
        "user_attached_policies": {},
        "group_attached_policies": {},
        "role_attached_policies": {},
        "user_inline_policies": {},
        "group_inline_policies": {},
        "role_inline_policies": {},
        "role_trust_principals": {},
        "errors": errors,
    }

    for user in user_summaries:
        user_name = user["name"]
        memberships, member_error = safe_call(
            f"iam.list_groups_for_user({user_name})",
            lambda user_name=user_name: _paginate(
                lambda **kwargs: iam.list_groups_for_user(UserName=user_name, **kwargs),
                "Groups",
            ),
        )
        if member_error:
            errors.append(member_error)
        for group in memberships or []:
            group_name = group.get("GroupName")
            if group_name:
                data["user_group_memberships"].append({"user": user_name, "group": group_name})

        attached, attached_error = safe_call(
            f"iam.list_attached_user_policies({user_name})",
            lambda user_name=user_name: _paginate(
                lambda **kwargs: iam.list_attached_user_policies(UserName=user_name, **kwargs),
                "AttachedPolicies",
            ),
        )
        if attached_error:
            errors.append(attached_error)
            attached = []
        data["user_attached_policies"][user_name] = attached or []
        if any(p.get("PolicyArn") == ADMIN_POLICY_ARN for p in attached or []):
            data["admin_users"].append(user_name)

        inline, inline_error = safe_call(
            f"iam.list_user_policies({user_name})",
            lambda user_name=user_name: _paginate(
                lambda **kwargs: iam.list_user_policies(UserName=user_name, **kwargs),
                "PolicyNames",
            ),
        )
        if inline_error:
            errors.append(inline_error)
            inline = []
        data["user_inline_policies"][user_name] = inline or []

    for group in group_summaries:
        group_name = group["name"]
        attached, attached_error = safe_call(
            f"iam.list_attached_group_policies({group_name})",
            lambda group_name=group_name: _paginate(
                lambda **kwargs: iam.list_attached_group_policies(GroupName=group_name, **kwargs),
                "AttachedPolicies",
            ),
        )
        if attached_error:
            errors.append(attached_error)
            attached = []
        data["group_attached_policies"][group_name] = attached or []
        if any(p.get("PolicyArn") == ADMIN_POLICY_ARN for p in attached or []):
            data["admin_groups"].append(group_name)

        inline, inline_error = safe_call(
            f"iam.list_group_policies({group_name})",
            lambda group_name=group_name: _paginate(
                lambda **kwargs: iam.list_group_policies(GroupName=group_name, **kwargs),
                "PolicyNames",
            ),
        )
        if inline_error:
            errors.append(inline_error)
            inline = []
        data["group_inline_policies"][group_name] = inline or []

    for role in role_summaries:
        role_name = role["name"]
        attached, attached_error = safe_call(
            f"iam.list_attached_role_policies({role_name})",
            lambda role_name=role_name: _paginate(
                lambda **kwargs: iam.list_attached_role_policies(RoleName=role_name, **kwargs),
                "AttachedPolicies",
            ),
        )
        if attached_error:
            errors.append(attached_error)
            attached = []
        data["role_attached_policies"][role_name] = attached or []
        if any(p.get("PolicyArn") == ADMIN_POLICY_ARN for p in attached or []):
            data["admin_roles"].append(role_name)

        inline, inline_error = safe_call(
            f"iam.list_role_policies({role_name})",
            lambda role_name=role_name: _paginate(
                lambda **kwargs: iam.list_role_policies(RoleName=role_name, **kwargs),
                "PolicyNames",
            ),
        )
        if inline_error:
            errors.append(inline_error)
            inline = []
        data["role_inline_policies"][role_name] = inline or []

        assume_doc = _role_assume_policy_for(role_name, roles)
        data["role_trust_principals"][role_name] = sorted(
            _extract_principals_from_assume_doc(assume_doc)
        )

    data["errors"] = errors
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate IAM relationship graph outputs.")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument(
        "--region", default="eu-west-1", help="Home region (for STS identity lookup)"
    )
    parser.add_argument(
        "--direction", choices=["LR", "TB"], default="TB", help="Mermaid diagram direction"
    )
    parser.add_argument(
        "--output-base",
        type=Path,
        default=Path("network-maps/iam-graph"),
        help="Base output path; writes .json/.html/.png",
    )
    args = parser.parse_args(argv)

    data = collect_iam_relationship_data(profile=args.profile, region=args.region)
    graph = generate_iam_outputs(
        data=data,
        output_base=args.output_base,
        direction=args.direction,
    )

    output_base = args.output_base.with_suffix("")
    json_path = output_base.with_suffix(".json")
    html_path = output_base.with_suffix(".html")
    png_path = output_base.with_suffix(".png")

    print(f"Wrote IAM graph JSON: {json_path}", file=sys.stderr)
    print(f"Wrote IAM graph HTML: {html_path}", file=sys.stderr)
    if png_path.exists():
        print(f"Wrote IAM graph PNG: {png_path}", file=sys.stderr)
    s = graph.summary()
    print(
        f"IAM graph summary: nodes={s['node_count']} edges={s['edge_count']} errors={s['error_count']}",
        file=sys.stderr,
    )
    return 0


def _add_principal_nodes(graph: IamGraph, principals: list[dict[str, Any]], kind: str) -> None:
    for principal in principals:
        name = str(
            principal.get("name")
            or principal.get("UserName")
            or principal.get("GroupName")
            or principal.get("RoleName")
            or ""
        )
        if not name:
            continue
        node_id = f"{kind}:{name}"
        graph.nodes[node_id] = {
            "node_id": node_id,
            "kind": kind,
            "label": f"{kind.capitalize()} {name}",
            "metadata": {"arn": principal.get("arn") or principal.get("Arn")},
        }


def _add_policy_node(graph: IamGraph, node_id: str, label: str, metadata: dict[str, Any]) -> None:
    graph.nodes.setdefault(
        node_id,
        {
            "node_id": node_id,
            "kind": "policy",
            "label": label,
            "metadata": metadata,
        },
    )


def _add_edge(
    graph: IamGraph,
    source: str,
    target: str,
    label: str,
    edge_type: str,
    seen_edges: set[tuple[str, str, str]],
) -> None:
    if source not in graph.nodes or target not in graph.nodes:
        return
    key = (source, target, label)
    if key in seen_edges:
        return
    seen_edges.add(key)
    graph.edges.append(
        {
            "source": source,
            "target": target,
            "label": label,
            "edge_type": edge_type,
        }
    )


def _add_managed_policy_edges(
    graph: IamGraph,
    mapping: dict[str, list[Any]] | Any,
    principal_kind: str,
    seen_edges: set[tuple[str, str, str]],
) -> None:
    mapping = mapping or {}
    for principal_name, policies in mapping.items():
        principal_node = f"{principal_kind}:{principal_name}"
        if principal_node not in graph.nodes:
            continue
        for policy in policies or []:
            if isinstance(policy, dict):
                arn = str(policy.get("PolicyArn") or "")
                policy_name = str(policy.get("PolicyName") or arn or "unknown-policy")
            else:
                arn = ""
                policy_name = str(policy)
            if arn == ADMIN_POLICY_ARN or policy_name == "AdministratorAccess":
                policy_node = "policy:AdministratorAccess"
            else:
                policy_node = f"policy:{policy_name}"
            _add_policy_node(graph, policy_node, policy_name, {"arn": arn, "managed": True})
            _add_edge(graph, principal_node, policy_node, "attached", "attached_to", seen_edges)


def _add_inline_policy_edges(
    graph: IamGraph,
    mapping: dict[str, list[Any]] | Any,
    principal_kind: str,
    seen_edges: set[tuple[str, str, str]],
) -> None:
    mapping = mapping or {}
    for principal_name, policies in mapping.items():
        principal_node = f"{principal_kind}:{principal_name}"
        if principal_node not in graph.nodes:
            continue
        for policy_name in policies or []:
            policy_name = str(policy_name)
            policy_node = f"inline_policy:{principal_kind}:{principal_name}:{policy_name}"
            _add_policy_node(
                graph,
                policy_node,
                f"{policy_name} (inline)",
                {
                    "managed": False,
                    "inline": True,
                    "owner": principal_name,
                    "owner_kind": principal_kind,
                },
            )
            _add_edge(graph, principal_node, policy_node, "inline", "inline_policy", seen_edges)


def _paginate(api_call: Any, result_key: str) -> list[Any]:
    items: list[Any] = []
    marker: str | None = None
    while True:
        kwargs: dict[str, Any] = {}
        if marker:
            kwargs["Marker"] = marker
        response = api_call(**kwargs)
        items.extend(response.get(result_key, []))
        if not response.get("IsTruncated"):
            break
        marker = response.get("Marker")
        if not marker:
            break
    return items


def _role_assume_policy_for(role_name: str, roles: list[dict[str, Any]]) -> dict[str, Any] | None:
    for role in roles:
        if role.get("RoleName") == role_name:
            assume_doc = role.get("AssumeRolePolicyDocument")
            if isinstance(assume_doc, dict):
                return assume_doc
            return None
    return None


def _extract_principals_from_assume_doc(doc: dict[str, Any] | None) -> set[str]:
    if not doc:
        return set()
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    principals: set[str] = set()
    for statement in statements:
        principal = statement.get("Principal")
        if principal is None:
            continue
        if principal == "*":
            principals.add("*")
            continue
        if isinstance(principal, str):
            principals.add(principal)
            continue
        if isinstance(principal, dict):
            for value in principal.values():
                if isinstance(value, list):
                    principals.update(str(v) for v in value)
                else:
                    principals.add(str(value))
    return principals


def _mermaid_id(node_id: str, seen: dict[str, str]) -> str:
    if node_id in seen:
        return seen[node_id]
    candidate = f"n{len(seen) + 1}"
    counter = 2
    while candidate in seen.values():
        candidate = f"n{len(seen) + counter}"
        counter += 1
    seen[node_id] = candidate
    return candidate


def _compact_principal_label(principal: str, *, max_len: int = 64) -> str:
    if len(principal) <= max_len:
        return principal
    if principal.startswith("arn:"):
        suffix = principal.rsplit(":", 1)[-1]
        prefix = "..."
        return f"{prefix}{suffix}"[:max_len]
    return f"{principal[: max_len - 3]}..."


def _escape_mermaid(value: str) -> str:
    escaped = value.replace('"', "'")
    escaped = escaped.replace("[", "(").replace("]", ")")
    escaped = escaped.replace("\n", " ").replace("\r", " ")
    return escaped


def _admin_node_ids(graph: IamGraph) -> set[str]:
    admin_nodes: set[str] = set()
    for edge in graph.edges:
        if edge.get("label") == "admin":
            source = str(edge.get("source", ""))
            if source:
                admin_nodes.add(source)
    return admin_nodes


def _shape_for_kind(kind: str) -> tuple[str, str]:
    if kind == "policy":
        return ("(", ")")
    if kind == "group":
        return ("[[", "]]")
    if kind == "role":
        return ("([", "])")
    if kind == "principal":
        return ("{{", "}}")
    return ("[", "]")


if __name__ == "__main__":
    raise SystemExit(main())
