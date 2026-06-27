from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aws_account_audit.session import client, enabled_regions, safe_call


@dataclass(frozen=True)
class ResolvedResource:
    kind: str
    resource_id: str
    region: str
    arn: str | None = None
    name: str | None = None


RESOURCE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ec2_instance", re.compile(r"^i-[0-9a-f]{8,17}$", re.I)),
    ("security_group", re.compile(r"^sg-[0-9a-f]{8,17}$", re.I)),
    ("network_interface", re.compile(r"^eni-[0-9a-f]{8,17}$", re.I)),
    (
        "load_balancer",
        re.compile(r"^arn:aws:elasticloadbalancing:[^:]+:[^:]+:loadbalancer/.+$", re.I),
    ),
    (
        "target_group",
        re.compile(r"^arn:aws:elasticloadbalancing:[^:]+:[^:]+:targetgroup/.+$", re.I),
    ),
    ("rds_instance", re.compile(r"^arn:aws:rds:[^:]+:[^:]+:db:[^:]+$", re.I)),
    ("lambda_function", re.compile(r"^arn:aws:lambda:[^:]+:[^:]+:function:.+$", re.I)),
]


def infer_kind(resource: str, explicit_kind: str | None = None) -> str | None:
    if explicit_kind:
        return explicit_kind
    if resource.startswith("arn:"):
        for kind, pattern in RESOURCE_PATTERNS:
            if pattern.match(resource):
                return kind
        service = resource.split(":")[2] if len(resource.split(":")) > 2 else ""
        if service == "elasticloadbalancing":
            return "load_balancer"
        if service == "rds":
            return "rds_instance"
        if service == "lambda":
            return "lambda_function"
        if service == "ec2":
            return "ec2_generic"
        return None
    for kind, pattern in RESOURCE_PATTERNS:
        if pattern.match(resource):
            return kind
    if re.match(r"^[a-zA-Z0-9-]{1,32}$", resource):
        return "name_lookup"
    return None


def resolve_resource(
    session: Any,
    resource: str,
    *,
    region: str,
    explicit_kind: str | None = None,
    search_all_regions: bool = False,
) -> tuple[ResolvedResource | None, str | None]:
    kind = infer_kind(resource, explicit_kind)
    if kind is None:
        return None, f"Could not infer resource type for: {resource}"

    regions = [region]
    if search_all_regions:
        regions = enabled_regions(session, region)

    for scan_region in regions:
        resolved, error = _resolve_in_region(session, resource, kind, scan_region)
        if resolved:
            return resolved, None
        if error and scan_region == region:
            last_error = error
        else:
            last_error = error or f"Resource not found: {resource}"
    return None, last_error


def _resolve_in_region(
    session: Any,
    resource: str,
    kind: str,
    region: str,
) -> tuple[ResolvedResource | None, str | None]:
    if kind == "ec2_instance":
        return _resolve_ec2_instance(session, resource, region)
    if kind == "security_group":
        ec2 = client(session, "ec2", region)
        response, error = safe_call(
            f"ec2.describe_security_groups({resource})",
            lambda: ec2.describe_security_groups(GroupIds=[resource]),
        )
        if error:
            return None, error
        if not (response or {}).get("SecurityGroups"):
            return None, None
        sg = response["SecurityGroups"][0]
        return ResolvedResource(
            kind="security_group",
            resource_id=resource,
            region=region,
            name=sg.get("GroupName"),
        ), None
    if kind == "network_interface":
        return ResolvedResource("network_interface", resource, region), None
    if kind == "load_balancer":
        return _resolve_load_balancer(session, resource, region)
    if kind == "target_group":
        return ResolvedResource("target_group", resource, region, arn=resource), None
    if kind == "rds_instance":
        return _resolve_rds(session, resource, region)
    if kind == "lambda_function":
        return _resolve_lambda(session, resource, region)
    if kind == "name_lookup":
        return _resolve_by_name(session, resource, region)
    if kind == "alb":
        return _resolve_load_balancer_by_name(session, resource, region)
    return None, f"Unsupported resource kind: {kind}"


def _resolve_ec2_instance(
    session: Any, instance_id: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    ec2 = client(session, "ec2", region)
    response, error = safe_call(
        "ec2.describe_instances",
        lambda: ec2.describe_instances(InstanceIds=[instance_id]),
    )
    if error:
        return None, error
    reservations = (response or {}).get("Reservations", [])
    if not reservations or not reservations[0].get("Instances"):
        return None, None
    instance = reservations[0]["Instances"][0]
    name = _tag_name(instance.get("Tags", []))
    return ResolvedResource(
        kind="ec2_instance",
        resource_id=instance_id,
        region=region,
        arn=instance.get("InstanceId"),
        name=name,
    ), None


def _resolve_load_balancer(
    session: Any, arn: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    elbv2 = client(session, "elbv2", region)
    response, error = safe_call(
        "elbv2.describe_load_balancers",
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[arn]),
    )
    if error:
        return None, error
    balancers = (response or {}).get("LoadBalancers", [])
    if not balancers:
        return None, None
    balancer = balancers[0]
    return ResolvedResource(
        kind="load_balancer",
        resource_id=balancer["LoadBalancerArn"],
        region=region,
        arn=balancer["LoadBalancerArn"],
        name=balancer.get("LoadBalancerName"),
    ), None


def _resolve_load_balancer_by_name(
    session: Any, name: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    elbv2 = client(session, "elbv2", region)
    response, error = safe_call(
        "elbv2.describe_load_balancers", lambda: elbv2.describe_load_balancers()
    )
    if error:
        return None, error
    for balancer in (response or {}).get("LoadBalancers", []):
        if balancer.get("LoadBalancerName") == name:
            return ResolvedResource(
                kind="load_balancer",
                resource_id=balancer["LoadBalancerArn"],
                region=region,
                arn=balancer["LoadBalancerArn"],
                name=name,
            ), None
    return None, None


def _resolve_rds(
    session: Any, resource: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    rds = client(session, "rds", region)
    identifier = resource.split(":")[-1] if resource.startswith("arn:") else resource
    response, error = safe_call(
        "rds.describe_db_instances",
        lambda: rds.describe_db_instances(DBInstanceIdentifier=identifier),
    )
    if error:
        return None, error
    instances = (response or {}).get("DBInstances", [])
    if not instances:
        return None, None
    db = instances[0]
    return ResolvedResource(
        kind="rds_instance",
        resource_id=db["DBInstanceIdentifier"],
        region=region,
        arn=db.get("DBInstanceArn"),
        name=db["DBInstanceIdentifier"],
    ), None


def _resolve_lambda(
    session: Any, arn: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    lambda_client = client(session, "lambda", region)
    response, error = safe_call(
        "lambda.get_function",
        lambda: lambda_client.get_function(FunctionName=arn),
    )
    if error:
        return None, error
    config = (response or {}).get("Configuration", {})
    return ResolvedResource(
        kind="lambda_function",
        resource_id=config.get("FunctionArn", arn),
        region=region,
        arn=config.get("FunctionArn", arn),
        name=config.get("FunctionName"),
    ), None


def _resolve_by_name(
    session: Any, name: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    for resolver in (
        _resolve_load_balancer_by_name,
        _resolve_ec2_by_name,
        _resolve_rds_by_name,
    ):
        resolved, _ = resolver(session, name, region)
        if resolved:
            return resolved, None
    return None, None


def _resolve_ec2_by_name(
    session: Any, name: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    ec2 = client(session, "ec2", region)
    response, error = safe_call(
        "ec2.describe_instances",
        lambda: ec2.describe_instances(
            Filters=[
                {"Name": "tag:Name", "Values": [name]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopped", "stopping"],
                },
            ],
        ),
    )
    if error:
        return None, error
    for reservation in (response or {}).get("Reservations", []):
        for instance in reservation.get("Instances", []):
            return ResolvedResource(
                kind="ec2_instance",
                resource_id=instance["InstanceId"],
                region=region,
                name=name,
            ), None
    return None, None


def _resolve_rds_by_name(
    session: Any, name: str, region: str
) -> tuple[ResolvedResource | None, str | None]:
    return _resolve_rds(session, name, region)


def _tag_name(tags: list[dict[str, str]]) -> str | None:
    for tag in tags:
        if tag.get("Key") == "Name":
            return tag.get("Value")
    return None
