from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Node:
    node_id: str
    kind: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Edge:
    source: str
    target: str
    label: str
    edge_type: str = "connects"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NetworkGraph:
    root: str
    region: str
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    ingress_paths: list[list[str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.node_id, node)

    def add_edge(self, edge: Edge) -> None:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise ValueError(f"Edge references unknown node: {edge.source} -> {edge.target}")
        duplicate = any(
            existing.source == edge.source
            and existing.target == edge.target
            and existing.label == edge.label
            for existing in self.edges
        )
        if not duplicate:
            self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "region": self.region,
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges],
            "ingress_paths": self.ingress_paths,
            "errors": self.errors,
        }
