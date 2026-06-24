from __future__ import annotations

from typing import Any

from aws_account_audit.session import client, safe_call
from aws_network_map.graph import Edge, NetworkGraph, Node
from aws_network_map.network import (
    find_load_balancers_for_instance,
    node_id,
    trace_security_group_egress,
    trace_security_group_ingress,
    trace_subnet_path,
)
from aws_network_map.resolve import ResolvedResource


def trace_ec2_instance(session: Any, resolved: ResolvedResource) -> NetworkGraph:
    region = resolved.region
    ec2 = client(session, "ec2", region)
    graph = NetworkGraph(root=resolved.resource_id, region=region)

    response, error = safe_call(
        "ec2.describe_instances",
        lambda: ec2.describe_instances(InstanceIds=[resolved.resource_id]),
    )
    if error:
        graph.errors.append(error)
        return graph

    instances = []
    for reservation in (response or {}).get("Reservations", []):
        instances.extend(reservation.get("Instances", []))
    if not instances:
        graph.errors.append(f"Instance not found: {resolved.resource_id}")
        return graph

    instance = instances[0]
    instance_node_id = node_id("ec2_instance", resolved.resource_id)
    graph.add_node(
        Node(
            instance_node_id,
            "ec2_instance",
            resolved.name or f"EC2 {resolved.resource_id}",
            {
                "instance_id": resolved.resource_id,
                "instance_type": instance.get("InstanceType"),
                "state": (instance.get("State") or {}).get("Name"),
                "private_ip": instance.get("PrivateIpAddress"),
                "public_ip": instance.get("PublicIpAddress"),
            },
        )
    )

    subnet_ids: set[str] = set()
    security_groups: set[str] = set()
    for eni in instance.get("NetworkInterfaces", []):
        if eni.get("SubnetId"):
            subnet_ids.add(eni["SubnetId"])
        for group in eni.get("Groups", []):
            if group.get("GroupId"):
                security_groups.add(group["GroupId"])

    if instance.get("SubnetId"):
        subnet_ids.add(instance["SubnetId"])
    for group in instance.get("SecurityGroups", []):
        if group.get("GroupId"):
            security_groups.add(group["GroupId"])

    for subnet_id in subnet_ids:
        trace_subnet_path(session, graph, region, subnet_id, instance_node_id, ec2=ec2)

    for sg_id in security_groups:
        trace_security_group_ingress(session, graph, region, sg_id, instance_node_id, ec2=ec2)
        trace_security_group_egress(session, graph, region, sg_id, instance_node_id, ec2=ec2)

    find_load_balancers_for_instance(session, graph, region, resolved.resource_id, instance_node_id)

    if instance.get("PublicIpAddress"):
        from aws_network_map.network import add_internet_node

        internet_id = add_internet_node(graph)
        graph.add_edge(Edge(internet_id, instance_node_id, "public IP", "ingress"))

    return graph


def trace_security_group(session: Any, resolved: ResolvedResource) -> NetworkGraph:
    region = resolved.region
    ec2 = client(session, "ec2", region)
    graph = NetworkGraph(root=resolved.resource_id, region=region)

    sg_node_id = node_id("security_group", resolved.resource_id)
    sg_response, sg_error = safe_call(
        f"ec2.describe_security_groups({resolved.resource_id})",
        lambda: ec2.describe_security_groups(GroupIds=[resolved.resource_id]),
    )
    if sg_error:
        graph.errors.append(sg_error)
        return graph

    sg = (sg_response or {}).get("SecurityGroups", [{}])[0]
    graph.add_node(
        Node(
            sg_node_id,
            "security_group",
            f"SG {sg.get('GroupName', resolved.resource_id)}",
            {"group_id": resolved.resource_id, "vpc_id": sg.get("VpcId")},
        )
    )

    trace_security_group_ingress(
        session,
        graph,
        region,
        resolved.resource_id,
        sg_node_id,
        ec2=ec2,
        include_protects_edge=False,
    )

    eni_response, eni_error = safe_call(
        f"ec2.describe_network_interfaces({resolved.resource_id})",
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [resolved.resource_id]}],
        ),
    )
    if eni_error:
        graph.errors.append(eni_error)
        return graph

    for eni in (eni_response or {}).get("NetworkInterfaces", []):
        attachment = eni.get("Attachment") or {}
        instance_id = attachment.get("InstanceId")
        if instance_id:
            instance_node_id = node_id("ec2_instance", instance_id)
            graph.add_node(
                Node(
                    instance_node_id,
                    "ec2_instance",
                    f"EC2 {instance_id}",
                    {"instance_id": instance_id, "private_ip": eni.get("PrivateIpAddress")},
                )
            )
            graph.add_edge(Edge(sg_node_id, instance_node_id, "protects", "attach"))
            trace_security_group_egress(session, graph, region, resolved.resource_id, instance_node_id, ec2=ec2)

    return graph


def trace_load_balancer(session: Any, resolved: ResolvedResource) -> NetworkGraph:
    region = resolved.region
    elbv2 = client(session, "elbv2", region)
    graph = NetworkGraph(root=resolved.resource_id, region=region)

    lb_response, lb_error = safe_call(
        "elbv2.describe_load_balancers",
        lambda: elbv2.describe_load_balancers(LoadBalancerArns=[resolved.resource_id]),
    )
    if lb_error:
        graph.errors.append(lb_error)
        return graph

    balancers = (lb_response or {}).get("LoadBalancers", [])
    if not balancers:
        graph.errors.append(f"Load balancer not found: {resolved.resource_id}")
        return graph

    balancer = balancers[0]
    lb_node_id = node_id("load_balancer", balancer["LoadBalancerArn"])
    graph.add_node(
        Node(
            lb_node_id,
            "load_balancer",
            balancer.get("LoadBalancerName", balancer["LoadBalancerArn"]),
            {
                "dns_name": balancer.get("DNSName"),
                "scheme": balancer.get("Scheme"),
                "type": balancer.get("Type"),
            },
        )
    )

    from aws_network_map.network import add_internet_node

    if balancer.get("Scheme") == "internet-facing":
        internet_id = add_internet_node(graph)
        graph.add_edge(Edge(internet_id, lb_node_id, "client traffic", "ingress"))

    for sg_id in balancer.get("SecurityGroups", []):
        trace_security_group_ingress(session, graph, region, sg_id, lb_node_id)

    listener_response, listener_error = safe_call(
        "elbv2.describe_listeners",
        lambda: elbv2.describe_listeners(LoadBalancerArn=balancer["LoadBalancerArn"]),
    )
    if listener_error:
        graph.errors.append(listener_error)
    else:
        for listener in (listener_response or {}).get("Listeners", []):
            for action in listener.get("DefaultActions", []):
                tg_arn = (action.get("TargetGroupArn") or (action.get("ForwardConfig") or {}).get("TargetGroups", [{}])[0].get("TargetGroupArn"))
                if not tg_arn:
                    continue
                _attach_target_group(session, graph, region, tg_arn, lb_node_id)

    for subnet_id in balancer.get("AvailabilityZones", []):
        subnet = subnet_id.get("SubnetId")
        if subnet:
            trace_subnet_path(session, graph, region, subnet, lb_node_id)

    return graph


def trace_rds_instance(session: Any, resolved: ResolvedResource) -> NetworkGraph:
    region = resolved.region
    rds = client(session, "rds", region)
    graph = NetworkGraph(root=resolved.resource_id, region=region)

    response, error = safe_call(
        "rds.describe_db_instances",
        lambda: rds.describe_db_instances(DBInstanceIdentifier=resolved.resource_id),
    )
    if error:
        graph.errors.append(error)
        return graph

    db = (response or {}).get("DBInstances", [{}])[0]
    rds_node_id = node_id("rds_instance", resolved.resource_id)
    graph.add_node(
        Node(
            rds_node_id,
            "rds_instance",
            resolved.resource_id,
            {
                "engine": db.get("Engine"),
                "endpoint": (db.get("Endpoint") or {}).get("Address"),
                "port": (db.get("Endpoint") or {}).get("Port"),
                "publicly_accessible": db.get("PubliclyAccessible"),
            },
        )
    )

    for sg_id in db.get("VpcSecurityGroups", []):
        group_id = sg_id.get("VpcSecurityGroupId")
        if group_id:
            trace_security_group_ingress(session, graph, region, group_id, rds_node_id)
            trace_security_group_egress(session, graph, region, group_id, rds_node_id)

    if db.get("PubliclyAccessible"):
        from aws_network_map.network import add_internet_node

        internet_id = add_internet_node(graph)
        graph.add_edge(Edge(internet_id, rds_node_id, "public endpoint", "ingress"))

    subnet_group = db.get("DBSubnetGroup") or {}
    for subnet in subnet_group.get("Subnets", []):
        subnet_id = (subnet.get("SubnetIdentifier"))
        if subnet_id:
            trace_subnet_path(session, graph, region, subnet_id, rds_node_id)

    return graph


def trace_lambda_function(session: Any, resolved: ResolvedResource) -> NetworkGraph:
    region = resolved.region
    lambda_client = client(session, "lambda", region)
    graph = NetworkGraph(root=resolved.resource_id, region=region)

    response, error = safe_call(
        "lambda.get_function",
        lambda: lambda_client.get_function(FunctionName=resolved.resource_id),
    )
    if error:
        graph.errors.append(error)
        return graph

    config = (response or {}).get("Configuration", {})
    lambda_node_id = node_id("lambda_function", config.get("FunctionName", resolved.resource_id))
    graph.add_node(
        Node(
            lambda_node_id,
            "lambda_function",
            config.get("FunctionName", resolved.resource_id),
            {
                "runtime": config.get("Runtime"),
                "role": config.get("Role"),
            },
        )
    )

    vpc_config = config.get("VpcConfig") or {}
    for sg_id in vpc_config.get("SecurityGroupIds", []):
        trace_security_group_ingress(session, graph, region, sg_id, lambda_node_id)
        trace_security_group_egress(session, graph, region, sg_id, lambda_node_id)
    for subnet_id in vpc_config.get("SubnetIds", []):
        trace_subnet_path(session, graph, region, subnet_id, lambda_node_id)

    return graph


def _attach_target_group(session: Any, graph: NetworkGraph, region: str, tg_arn: str, lb_node_id: str) -> None:
    elbv2 = client(session, "elbv2", region)
    tg_response, tg_error = safe_call(
        "elbv2.describe_target_groups",
        lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn]),
    )
    if tg_error:
        graph.errors.append(tg_error)
        return

    target_groups = (tg_response or {}).get("TargetGroups", [])
    if not target_groups:
        return

    target_group = target_groups[0]
    tg_node_id = node_id("target_group", tg_arn)
    graph.add_node(
        Node(
            tg_node_id,
            "target_group",
            target_group.get("TargetGroupName", tg_arn),
            {
                "target_group_arn": tg_arn,
                "port": target_group.get("Port"),
                "protocol": target_group.get("Protocol"),
            },
        )
    )
    graph.add_edge(
        Edge(
            lb_node_id,
            tg_node_id,
            f"{target_group.get('Protocol', 'tcp')}/{target_group.get('Port', '?')}",
            "ingress",
        )
    )

    health_response, health_error = safe_call(
        "elbv2.describe_target_health",
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_arn),
    )
    if health_error:
        graph.errors.append(health_error)
        return

    for target in (health_response or {}).get("TargetHealthDescriptions", []):
        target_id = target.get("Target", {}).get("Id")
        if not target_id:
            continue
        if target_id.startswith("i-"):
            target_node_id = node_id("ec2_instance", target_id)
            graph.add_node(
                Node(
                    target_node_id,
                    "ec2_instance",
                    f"EC2 {target_id}",
                    {"instance_id": target_id},
                )
            )
        else:
            target_node_id = node_id("target", target_id)
            graph.add_node(Node(target_node_id, "target", target_id, {"target_id": target_id}))
        graph.add_edge(Edge(tg_node_id, target_node_id, "forwards to", "ingress"))


TRACERS = {
    "ec2_instance": trace_ec2_instance,
    "security_group": trace_security_group,
    "load_balancer": trace_load_balancer,
    "rds_instance": trace_rds_instance,
    "lambda_function": trace_lambda_function,
}


def build_graph(session: Any, resolved: ResolvedResource) -> NetworkGraph:
    tracer = TRACERS.get(resolved.kind)
    if tracer is None:
        graph = NetworkGraph(root=resolved.resource_id, region=resolved.region)
        graph.errors.append(f"No tracer implemented for kind: {resolved.kind}")
        return graph
    graph = tracer(session, resolved)
    _prune_orphan_nodes(graph)
    return graph


def _prune_orphan_nodes(graph: NetworkGraph) -> None:
    connected: set[str] = set()
    for edge in graph.edges:
        connected.add(edge.source)
        connected.add(edge.target)

    def is_focus(node_id: str) -> bool:
        node = graph.nodes[node_id]
        if graph.root in node_id:
            return True
        return any(value == graph.root for value in node.metadata.values())

    orphan_ids = [
        node_id
        for node_id in graph.nodes
        if node_id not in connected and not is_focus(node_id)
    ]
    for node_id in orphan_ids:
        del graph.nodes[node_id]
