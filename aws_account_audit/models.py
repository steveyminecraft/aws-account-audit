from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    resource_arn: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SectionResult:
    name: str
    status: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "data": self.data,
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": self.errors,
        }


@dataclass
class AuditReport:
    metadata: dict[str, Any]
    sections: list[SectionResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        findings = [
            finding.to_dict()
            for section in self.sections
            for finding in section.findings
        ]
        resource_count = sum(
            section.data.get("count", 0)
            for section in self.sections
            if section.name.startswith("resources:")
        )
        return {
            "metadata": self.metadata,
            "summary": {
                "section_count": len(self.sections),
                "finding_count": len(findings),
                "resource_count": resource_count,
                "findings_by_severity": _count_by_severity(findings),
            },
            "findings": findings,
            "sections": [section.to_dict() for section in self.sections],
        }


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return counts
