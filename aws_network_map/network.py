from __future__ import annotations

from typing import Any

from aws_account_audit.session import client, safe_call
from aws_network_map.graph import Edge, NetworkGraph, Node


def node_id(kind: str, value: str) -> str:
    safe = value.replace(":", "_").replace("/", "_").replace(".", "_")
    return f"{kind}:{safe}"


def add_internet_node(graph: NetworkGraph) -> str:
    internet_id = node_id("internet", "0.0.0.0_0")
    graph.add_node(Node(internet_id, "internet", "Internet (0.0.0.0/0)"))
    return internet_id


def protocol_label(permission: dict[str, Any]) -> str:
    protocol = permission.get("IpProtocol", "all")
    if protocol == "-1":
        protocol = "all"
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if from_port is None and to_port is None:
        return str(protocol)
    return f"{protocol}/{from_port}-{to_port}"


def trace_security_group_ingress(
    session: Any,
    graph: NetworkGraph,
    region: str,
    security_group_id: str,
    target_node_id: str,
    *,
    ec2: Any | None = None,
    include_protects_edge: bool = True,
) -> None:
    ec2 = ec2 or client(session, "ec2", region)
    sg_response, sg_error = safe_call(
        f"ec2.describe_security_groups({security_group_id})",
        lambda: ec2.describe_security_groups(GroupIds=[security_group_id]),
    )
    if sg_error:
        graph.errors.append(sg_error)
        return

    groups = (sg_response or {}).get("SecurityGroups", [])
    if not groups:
        return

    sg = groups[0]
    sg_node_id = node_id("security_group", security_group_id)
    graph.add_node(
        Node(
            sg_node_id,
            "security_group",
            f"SG {sg.get('GroupName', security_group_id)}",
            {
                "group_id": security_group_id,
                "vpc_id": sg.get("VpcId"),
                "description": sg.get("Description"),
            },
        )
    )
    if include_protects_edge and sg_node_id != target_node_id:
        graph.add_edge(Edge(sg_node_id, target_node_id, "protects", "attach"))

    for permission in sg.get("IpPermissions", []):
        label = protocol_label(permission)
        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "0.0.0.0/0")
            if cidr in {"0.0.0.0/0", "::/0"}:
                internet_id = add_internet_node(graph)
                graph.add_edge(Edge(internet_id, sg_node_id, label, "ingress"))
                _append_path(graph, [internet_id, sg_node_id, target_node_id])
            else:
                cidr_id = node_id("cidr", cidr)
                graph.add_node(Node(cidr_id, "cidr", cidr))
                graph.add_edge(Edge(cidr_id, sg_node_id, label, "ingress"))
                _append_path(graph, [cidr_id, sg_node_id, target_node_id])

        for pair in permission.get("Ipv6Ranges", []):
            cidr = pair.get("CidrIpv6", "::/0")
            if cidr == "::/0":
                internet_id = add_internet_node(graph)
                graph.add_edge(Edge(internet_id, sg_node_id, label, "ingress"))
                _append_path(graph, [internet_id, sg_node_id, target_node_id])
            else:
                cidr_id = node_id("cidr", cidr)
                graph.add_node(Node(cidr_id, "cidr", cidr))
                graph.add_edge(Edge(cidr_id, sg_node_id, label, "ingress"))
                _append_path(graph, [cidr_id, sg_node_id, target_node_id])

        for source_sg in permission.get("UserIdGroupPairs", []):
            source_sg_id = source_sg.get("GroupId")
            if not source_sg_id or source_sg_id == security_group_id:
                continue
            source_node_id = _trace_source_security_group(
                session, graph, region, source_sg_id, ec2=ec2
            )
            graph.add_edge(Edge(source_node_id, sg_node_id, label, "ingress"))
            _append_path(graph, [source_node_id, sg_node_id, target_node_id])


def trace_security_group_egress(
    session: Any,
    graph: NetworkGraph,
    region: str,
    security_group_id: str,
    source_node_id: str,
    *,
    ec2: Any | None = None,
) -> None:
    ec2 = ec2 or client(session, "ec2", region)
    sg_response, sg_error = safe_call(
        f"ec2.describe_security_groups({security_group_id})",
        lambda: ec2.describe_security_groups(GroupIds=[security_group_id]),
    )
    if sg_error:
        graph.errors.append(sg_error)
        return

    groups = (sg_response or {}).get("SecurityGroups", [])
    if not groups:
        return

    sg = groups[0]
    sg_node_id = node_id("security_group", security_group_id)
    if sg_node_id not in graph.nodes:
        graph.add_node(
            Node(
                sg_node_id,
                "security_group",
                f"SG {sg.get('GroupName', security_group_id)}",
                {"group_id": security_group_id, "vpc_id": sg.get("VpcId")},
            )
        )

    for permission in sg.get("IpPermissionsEgress", []):
        label = protocol_label(permission)
        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "0.0.0.0/0")
            cidr_id = node_id("cidr", cidr) if cidr != "0.0.0.0/0" else add_internet_node(graph)
            if cidr != "0.0.0.0/0":
                graph.add_node(Node(cidr_id, "cidr", cidr))
            graph.add_edge(Edge(source_node_id, sg_node_id, "uses", "attach"))
            graph.add_edge(Edge(sg_node_id, cidr_id, label, "egress"))

        for dest_sg in permission.get("UserIdGroupPairs", []):
            dest_sg_id = dest_sg.get("GroupId")
            if not dest_sg_id:
                continue
            dest_node_id = node_id("security_group", dest_sg_id)
            if dest_node_id not in graph.nodes:
                dest_response, _ = safe_call(
                    f"ec2.describe_security_groups({dest_sg_id})",
                    lambda dest_sg_id=dest_sg_id: ec2.describe_security_groups(
                        GroupIds=[dest_sg_id]
                    ),
                )
                dest_name = dest_sg_id
                if dest_response and dest_response.get("SecurityGroups"):
                    dest_name = dest_response["SecurityGroups"][0].get("GroupName", dest_sg_id)
                graph.add_node(
                    Node(
                        dest_node_id, "security_group", f"SG {dest_name}", {"group_id": dest_sg_id}
                    )
                )
            graph.add_edge(Edge(source_node_id, sg_node_id, "uses", "attach"))
            graph.add_edge(Edge(sg_node_id, dest_node_id, label, "egress"))


def trace_subnet_path(
    session: Any,
    graph: NetworkGraph,
    region: str,
    subnet_id: str,
    target_node_id: str,
    *,
    ec2: Any | None = None,
) -> None:
    ec2 = ec2 or client(session, "ec2", region)
    subnet_response, subnet_error = safe_call(
        f"ec2.describe_subnets({subnet_id})",
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id]),
    )
    if subnet_error:
        graph.errors.append(subnet_error)
        return

    subnets = (subnet_response or {}).get("Subnets", [])
    if not subnets:
        return

    subnet = subnets[0]
    subnet_node_id = node_id("subnet", subnet_id)
    graph.add_node(
        Node(
            subnet_node_id,
            "subnet",
            f"Subnet {subnet_id}",
            {
                "subnet_id": subnet_id,
                "cidr": subnet.get("CidrBlock"),
                "az": subnet.get("AvailabilityZone"),
                "public": subnet.get("MapPublicIpOnLaunch"),
                "vpc_id": subnet.get("VpcId"),
            },
        )
    )
    graph.add_edge(Edge(subnet_node_id, target_node_id, "contains", "attach"))

    vpc_id = subnet.get("VpcId")
    if vpc_id:
        vpc_node_id = node_id("vpc", vpc_id)
        graph.add_node(Node(vpc_node_id, "vpc", f"VPC {vpc_id}", {"vpc_id": vpc_id}))
        graph.add_edge(Edge(vpc_node_id, subnet_node_id, "contains", "attach"))

    _trace_route_table(
        session, graph, region, subnet_id, subnet_node_id, subnet.get("VpcId"), ec2=ec2
    )
    _trace_nacl(session, graph, region, subnet.get("NetworkAclId"), subnet_node_id, ec2=ec2)


def _trace_route_table(
    session: Any,
    graph: NetworkGraph,
    region: str,
    subnet_id: str,
    subnet_node_id: str,
    vpc_id: str | None,
    *,
    ec2: Any,
) -> None:
    rt_response, rt_error = safe_call(
        f"ec2.describe_route_tables(subnet={subnet_id})",
        lambda: ec2.describe_route_tables(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}],
        ),
    )
    if rt_error:
        graph.errors.append(rt_error)
        return

    route_tables = (rt_response or {}).get("RouteTables", [])
    if not route_tables and vpc_id:
        main_response, main_error = safe_call(
            "ec2.describe_route_tables(main)",
            lambda: ec2.describe_route_tables(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "association.main", "Values": ["true"]},
                ],
            ),
        )
        if main_error:
            graph.errors.append(main_error)
            return
        route_tables = (main_response or {}).get("RouteTables", [])

    for route_table in route_tables:
        rt_id = route_table["RouteTableId"]
        rt_node_id = node_id("route_table", rt_id)
        graph.add_node(
            Node(rt_node_id, "route_table", f"Route table {rt_id}", {"route_table_id": rt_id})
        )
        graph.add_edge(Edge(rt_node_id, subnet_node_id, "routes", "attach"))

        internet_id = add_internet_node(graph)
        for route in route_table.get("Routes", []):
            destination = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
            if route.get("GatewayId", "").startswith("igw-"):
                igw_id = route["GatewayId"]
                igw_node_id = node_id("igw", igw_id)
                graph.add_node(Node(igw_node_id, "igw", f"IGW {igw_id}", {"gateway_id": igw_id}))
                graph.add_edge(Edge(internet_id, igw_node_id, destination or "default", "ingress"))
                graph.add_edge(Edge(igw_node_id, rt_node_id, "0.0.0.0/0", "route"))
            elif route.get("NatGatewayId", "").startswith("nat-"):
                nat_id = route["NatGatewayId"]
                nat_node_id = node_id("nat", nat_id)
                graph.add_node(
                    Node(nat_node_id, "nat", f"NAT {nat_id}", {"nat_gateway_id": nat_id})
                )
                graph.add_edge(Edge(nat_node_id, rt_node_id, destination or "default", "route"))


def _trace_nacl(
    session: Any,
    graph: NetworkGraph,
    region: str,
    nacl_id: str | None,
    subnet_node_id: str,
    *,
    ec2: Any,
) -> None:
    if not nacl_id:
        return

    nacl_response, nacl_error = safe_call(
        f"ec2.describe_network_acls({nacl_id})",
        lambda: ec2.describe_network_acls(NetworkAclIds=[nacl_id]),
    )
    if nacl_error:
        graph.errors.append(nacl_error)
        return

    acls = (nacl_response or {}).get("NetworkAcls", [])
    if not acls:
        return

    nacl = acls[0]
    nacl_node_id = node_id("nacl", nacl_id)
    graph.add_node(Node(nacl_node_id, "nacl", f"NACL {nacl_id}", {"network_acl_id": nacl_id}))
    graph.add_edge(Edge(nacl_node_id, subnet_node_id, "filters ingress", "attach"))

    internet_id = add_internet_node(graph)
    for entry in nacl.get("Entries", []):
        if entry.get("Egress"):
            continue
        if entry.get("RuleAction") != "allow":
            continue
        cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock")
        if not cidr:
            continue
        label = f"rule {entry.get('RuleNumber')} allow"
        if cidr in {"0.0.0.0/0", "::/0"}:
            graph.add_edge(Edge(internet_id, nacl_node_id, label, "ingress"))
        else:
            cidr_id = node_id("cidr", cidr)
            graph.add_node(Node(cidr_id, "cidr", cidr))
            graph.add_edge(Edge(cidr_id, nacl_node_id, label, "ingress"))


def _trace_source_security_group(
    session: Any,
    graph: NetworkGraph,
    region: str,
    security_group_id: str,
    *,
    ec2: Any,
) -> str:
    sg_node_id = node_id("security_group", security_group_id)
    if sg_node_id in graph.nodes:
        return sg_node_id

    sg_response, sg_error = safe_call(
        f"ec2.describe_security_groups({security_group_id})",
        lambda: ec2.describe_security_groups(GroupIds=[security_group_id]),
    )
    if sg_error:
        graph.errors.append(sg_error)
        graph.add_node(
            Node(sg_node_id, "security_group", security_group_id, {"group_id": security_group_id})
        )
        return sg_node_id

    sg = (sg_response or {}).get("SecurityGroups", [{}])[0]
    graph.add_node(
        Node(
            sg_node_id,
            "security_group",
            f"SG {sg.get('GroupName', security_group_id)}",
            {"group_id": security_group_id, "vpc_id": sg.get("VpcId")},
        )
    )

    eni_response, eni_error = safe_call(
        f"ec2.describe_network_interfaces({security_group_id})",
        lambda: ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [security_group_id]}],
        ),
    )
    if eni_error:
        graph.errors.append(eni_error)
        return sg_node_id

    for eni in (eni_response or {}).get("NetworkInterfaces", []):
        attachment = eni.get("Attachment") or {}
        instance_id = attachment.get("InstanceId")
        if instance_id:
            instance_node_id = node_id("ec2_instance", instance_id)
            if instance_node_id not in graph.nodes:
                graph.add_node(
                    Node(
                        instance_node_id,
                        "ec2_instance",
                        f"EC2 {instance_id}",
                        {"instance_id": instance_id, "private_ip": eni.get("PrivateIpAddress")},
                    )
                )
            graph.add_edge(Edge(instance_node_id, sg_node_id, "member of", "attach"))
            continue

        description = eni.get("Description") or ""
        if "ELB" in description:
            lb_hint = description.split(" ")[0]
            lb_node_id = node_id("load_balancer_hint", lb_hint)
            graph.add_node(Node(lb_node_id, "load_balancer", lb_hint, {"description": description}))
            graph.add_edge(Edge(lb_node_id, sg_node_id, "uses", "attach"))

    return sg_node_id


def _append_path(graph: NetworkGraph, path: list[str]) -> None:
    deduped: list[str] = []
    for node in path:
        if not deduped or deduped[-1] != node:
            deduped.append(node)
    if len(deduped) < 2:
        return
    if deduped not in graph.ingress_paths:
        graph.ingress_paths.append(deduped)


def find_load_balancers_for_instance(
    session: Any,
    graph: NetworkGraph,
    region: str,
    instance_id: str,
    target_node_id: str,
) -> None:
    elbv2 = client(session, "elbv2", region)
    tg_response, tg_error = safe_call(
        "elbv2.describe_target_groups", lambda: elbv2.describe_target_groups()
    )
    if tg_error:
        graph.errors.append(tg_error)
        return

    matching_target_groups: list[str] = []
    for target_group in (tg_response or {}).get("TargetGroups", []):
        tg_arn = target_group["TargetGroupArn"]
        health_response, health_error = safe_call(
            f"elbv2.describe_target_health({tg_arn})",
            lambda tg_arn=tg_arn: elbv2.describe_target_health(TargetGroupArn=tg_arn),
        )
        if health_error:
            graph.errors.append(health_error)
            continue

        for target in (health_response or {}).get("TargetHealthDescriptions", []):
            if target.get("Target", {}).get("Id") == instance_id:
                matching_target_groups.append(tg_arn)
                break

    if not matching_target_groups:
        return

    lb_response, lb_error = safe_call(
        "elbv2.describe_load_balancers", lambda: elbv2.describe_load_balancers()
    )
    if lb_error:
        graph.errors.append(lb_error)
        return

    for balancer in (lb_response or {}).get("LoadBalancers", []):
        lb_arn = balancer["LoadBalancerArn"]
        listener_response, listener_error = safe_call(
            f"elbv2.describe_listeners({lb_arn})",
            lambda lb_arn=lb_arn: elbv2.describe_listeners(LoadBalancerArn=lb_arn),
        )
        if listener_error:
            graph.errors.append(listener_error)
            continue

        linked_groups: set[str] = set()
        for listener in (listener_response or {}).get("Listeners", []):
            for action in listener.get("DefaultActions", []):
                tg_arn = action.get("TargetGroupArn")
                if tg_arn:
                    linked_groups.add(tg_arn)
                for forward in (action.get("ForwardConfig") or {}).get("TargetGroups", []):
                    if forward.get("TargetGroupArn"):
                        linked_groups.add(forward["TargetGroupArn"])

        for tg_arn in matching_target_groups:
            if tg_arn not in linked_groups:
                continue

            tg_meta = next(
                (
                    item
                    for item in (tg_response or {}).get("TargetGroups", [])
                    if item["TargetGroupArn"] == tg_arn
                ),
                {},
            )
            tg_node_id = node_id("target_group", tg_arn)
            graph.add_node(
                Node(
                    tg_node_id,
                    "target_group",
                    tg_meta.get("TargetGroupName", tg_arn),
                    {
                        "target_group_arn": tg_arn,
                        "port": tg_meta.get("Port"),
                        "protocol": tg_meta.get("Protocol"),
                    },
                )
            )
            graph.add_edge(Edge(tg_node_id, target_node_id, "forwards to", "ingress"))

            lb_node_id = node_id("load_balancer", lb_arn)
            graph.add_node(
                Node(
                    lb_node_id,
                    "load_balancer",
                    balancer.get("LoadBalancerName", lb_arn),
                    {
                        "dns_name": balancer.get("DNSName"),
                        "scheme": balancer.get("Scheme"),
                        "type": balancer.get("Type"),
                    },
                )
            )
            graph.add_edge(Edge(lb_node_id, tg_node_id, "listener", "ingress"))

            if balancer.get("Scheme") == "internet-facing":
                internet_id = add_internet_node(graph)
                graph.add_edge(Edge(internet_id, lb_node_id, "client traffic", "ingress"))
                _append_path(graph, [internet_id, lb_node_id, tg_node_id, target_node_id])

            for sg_id in balancer.get("SecurityGroups", []):
                trace_security_group_ingress(session, graph, region, sg_id, lb_node_id)
