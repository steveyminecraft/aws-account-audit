from __future__ import annotations

from typing import Any, Callable

from aws_account_audit.models import Finding, SectionResult
from aws_account_audit.session import client, get_bucket_policy_status, safe_call


def collect_identity(session: Any, region: str) -> SectionResult:
    result = SectionResult(name="identity", status="ok")
    identity, error = safe_call(
        "sts.get_caller_identity", lambda: client(session, "sts", region).get_caller_identity()
    )
    if error:
        result.status = "error"
        result.errors.append(error)
        return result

    result.data = identity or {}
    account_id = identity["Account"] if identity else ""

    org, org_error = safe_call(
        "organizations.describe_organization",
        lambda: client(session, "organizations", region).describe_organization(),
    )
    if org_error:
        result.data["organization"] = None
        result.errors.append(org_error)
    else:
        result.data["organization"] = org

    accounts, accounts_error = safe_call(
        "organizations.list_accounts",
        lambda: _paginate(
            client(session, "organizations", region).list_accounts,
            "Accounts",
        ),
    )
    if accounts_error:
        result.errors.append(accounts_error)
    else:
        result.data["organization_accounts"] = accounts or []

    if account_id:
        block, block_error = safe_call(
            "s3control.get_public_access_block",
            lambda: client(session, "s3control", region).get_public_access_block(
                AccountId=account_id
            ),
            not_found_ok=True,
        )
        if block_error:
            result.errors.append(block_error)
        elif block is None:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    category="storage",
                    title="S3 account public access block not configured",
                    detail="Account-level S3 public access block is missing.",
                )
            )
        else:
            result.data["s3_public_access_block"] = block.get("PublicAccessBlockConfiguration", {})

    return result


def collect_iam(session: Any, region: str) -> SectionResult:
    iam = client(session, "iam", region)
    result = SectionResult(name="iam", status="ok")

    users, users_error = safe_call("iam.list_users", lambda: _paginate(iam.list_users, "Users"))
    groups, groups_error = safe_call(
        "iam.list_groups", lambda: _paginate(iam.list_groups, "Groups")
    )
    roles, roles_error = safe_call("iam.list_roles", lambda: _paginate(iam.list_roles, "Roles"))

    for error in (users_error, groups_error, roles_error):
        if error:
            result.errors.append(error)

    users = users or []
    groups = groups or []
    roles = roles or []

    admin_policy = "arn:aws:iam::aws:policy/AdministratorAccess"
    admin_roles = _entities_with_policy(
        iam.list_attached_role_policies, "role", roles, admin_policy, "RoleName"
    )
    admin_users = _entities_with_policy(
        iam.list_attached_user_policies, "user", users, admin_policy, "UserName"
    )
    admin_groups = _entities_with_policy(
        iam.list_attached_group_policies, "group", groups, admin_policy, "GroupName"
    )

    active_keys = []
    for user in users:
        user_name = user["UserName"]
        keys, keys_error = safe_call(
            f"iam.list_access_keys({user_name})",
            lambda user_name=user_name: iam.list_access_keys(UserName=user_name)[
                "AccessKeyMetadata"
            ],
        )
        if keys_error:
            result.errors.append(keys_error)
            continue
        for key in keys or []:
            if key.get("Status") == "Active":
                active_keys.append(
                    {
                        "user": user_name,
                        "access_key_id": key["AccessKeyId"],
                        "create_date": key.get("CreateDate"),
                    }
                )

    password_policy, password_error = safe_call(
        "iam.get_account_password_policy",
        lambda: iam.get_account_password_policy()["PasswordPolicy"],
        not_found_ok=True,
    )
    if password_error:
        result.errors.append(password_error)
    elif password_policy is None:
        result.findings.append(
            Finding(
                severity="MEDIUM",
                category="iam",
                title="Account password policy not configured",
                detail="No IAM account password policy is set.",
            )
        )

    credential_report = _credential_report(iam, result)

    for role_name in admin_roles:
        result.findings.append(
            Finding(
                severity="HIGH",
                category="iam",
                title="Role has AdministratorAccess",
                detail=f"IAM role {role_name} is attached to AdministratorAccess.",
                resource_arn=f"arn:aws:iam::*:role/{role_name}",
            )
        )
    for user_name in admin_users:
        result.findings.append(
            Finding(
                severity="CRITICAL",
                category="iam",
                title="User has AdministratorAccess",
                detail=f"IAM user {user_name} is attached to AdministratorAccess.",
                resource_arn=f"arn:aws:iam::*:user/{user_name}",
            )
        )
    for group_name in admin_groups:
        result.findings.append(
            Finding(
                severity="HIGH",
                category="iam",
                title="Group has AdministratorAccess",
                detail=f"IAM group {group_name} is attached to AdministratorAccess.",
                resource_arn=f"arn:aws:iam::*:group/{group_name}",
            )
        )
    for key in active_keys:
        result.findings.append(
            Finding(
                severity="MEDIUM",
                category="iam",
                title="Active IAM access key",
                detail=f"User {key['user']} has active access key {key['access_key_id']}.",
            )
        )

    result.data = {
        "user_count": len(users),
        "group_count": len(groups),
        "role_count": len(roles),
        "users": [_summarize_user(user) for user in users],
        "groups": [{"name": group["GroupName"], "arn": group["Arn"]} for group in groups],
        "roles": [_summarize_role(role) for role in roles],
        "admin_roles": admin_roles,
        "admin_users": admin_users,
        "admin_groups": admin_groups,
        "active_access_keys": active_keys,
        "password_policy": password_policy,
        "credential_report_preview": credential_report,
    }
    return result


def collect_security_services(session: Any, region: str) -> SectionResult:
    result = SectionResult(name="security_services", status="ok")

    guardduty, guardduty_error = safe_call(
        "guardduty.list_detectors",
        lambda: client(session, "guardduty", region).list_detectors(),
    )
    if guardduty_error:
        result.errors.append(guardduty_error)
    elif not (guardduty or {}).get("DetectorIds"):
        result.findings.append(
            Finding(
                severity="HIGH",
                category="security",
                title="GuardDuty not enabled",
                detail=f"No GuardDuty detector found in {region}.",
            )
        )

    analyzers, analyzer_error = safe_call(
        "accessanalyzer.list_analyzers",
        lambda: client(session, "accessanalyzer", region).list_analyzers(),
    )
    if analyzer_error:
        result.errors.append(analyzer_error)
    elif not (analyzers or {}).get("analyzers"):
        result.findings.append(
            Finding(
                severity="MEDIUM",
                category="security",
                title="IAM Access Analyzer not enabled",
                detail=f"No Access Analyzer found in {region}.",
            )
        )

    trails, trails_error = safe_call(
        "cloudtrail.describe_trails",
        lambda: client(session, "cloudtrail", region).describe_trails(includeShadowTrails=False),
    )
    if trails_error:
        result.errors.append(trails_error)
    else:
        trail_list = (trails or {}).get("trailList", [])
        if not trail_list:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    category="security",
                    title="CloudTrail not configured",
                    detail="No CloudTrail trails were found.",
                )
            )
        for trail in trail_list:
            if not trail.get("IsMultiRegionTrail"):
                result.findings.append(
                    Finding(
                        severity="MEDIUM",
                        category="security",
                        title="CloudTrail is not multi-region",
                        detail=f"Trail {trail.get('Name')} is not multi-region.",
                        resource_arn=trail.get("TrailARN"),
                    )
                )
            if not trail.get("LogFileValidationEnabled"):
                result.findings.append(
                    Finding(
                        severity="LOW",
                        category="security",
                        title="CloudTrail log file validation disabled",
                        detail=f"Trail {trail.get('Name')} does not validate log files.",
                        resource_arn=trail.get("TrailARN"),
                    )
                )

    sso, sso_error = safe_call(
        "sso-admin.list_instances",
        lambda: client(session, "sso-admin", region).list_instances(),
    )
    if sso_error:
        result.errors.append(sso_error)

    result.data = {
        "guardduty": guardduty or {},
        "access_analyzers": (analyzers or {}).get("analyzers", []),
        "cloudtrail": (trails or {}).get("trailList", []),
        "identity_center_instances": (sso or {}).get("Instances", []),
    }
    return result


def collect_tagged_resources(session: Any, region: str) -> SectionResult:
    result = SectionResult(name=f"resources:tagging:{region}", status="ok")
    tagging = client(session, "resourcegroupstaggingapi", region)

    resources, error = safe_call(
        f"resourcegroupstaggingapi.get_resources({region})",
        lambda: _paginate(
            tagging.get_resources,
            "ResourceTagMappingList",
            ResourcesPerPage=100,
        ),
    )
    if error:
        result.status = "error"
        result.errors.append(error)
        return result

    resources = resources or []
    by_type: dict[str, list[dict[str, Any]]] = {}
    for item in resources:
        arn = item["ResourceARN"]
        resource_type = arn.split(":", 2)[2] if arn.count(":") >= 2 else "unknown"
        by_type.setdefault(resource_type, []).append(
            {
                "arn": arn,
                "tags": item.get("Tags", []),
            }
        )

    result.data = {
        "region": region,
        "count": len(resources),
        "by_type": {key: len(value) for key, value in sorted(by_type.items())},
        "resources": [
            {
                "arn": item["ResourceARN"],
                "tags": item.get("Tags", []),
            }
            for item in resources
        ],
    }
    return result


def collect_regional_compute(session: Any, region: str) -> SectionResult:
    ec2 = client(session, "ec2", region)
    result = SectionResult(name=f"resources:compute:{region}", status="ok")

    instances = _collect(ec2.describe_instances, "Reservations", result, "ec2.describe_instances")
    volumes = _collect(ec2.describe_volumes, "Volumes", result, "ec2.describe_volumes")
    snapshots = _collect(
        ec2.describe_snapshots, "Snapshots", result, "ec2.describe_snapshots", OwnerIds=["self"]
    )
    security_groups = _collect(
        ec2.describe_security_groups, "SecurityGroups", result, "ec2.describe_security_groups"
    )
    addresses = _collect(ec2.describe_addresses, "Addresses", result, "ec2.describe_addresses")

    open_sgs = []
    for sg in security_groups or []:
        for permission in sg.get("IpPermissions", []):
            for ip_range in permission.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    open_sgs.append(
                        {
                            "group_id": sg["GroupId"],
                            "group_name": sg.get("GroupName"),
                            "protocol": permission.get("IpProtocol"),
                            "from_port": permission.get("FromPort"),
                            "to_port": permission.get("ToPort"),
                        }
                    )

    for sg in open_sgs:
        result.findings.append(
            Finding(
                severity="MEDIUM",
                category="network",
                title="Security group allows ingress from 0.0.0.0/0",
                detail=(
                    f"Security group {sg['group_name']} ({sg['group_id']}) allows "
                    f"{sg['protocol']} {sg['from_port']}-{sg['to_port']} from the internet."
                ),
                resource_arn=f"arn:aws:ec2:{region}:*:security-group/{sg['group_id']}",
            )
        )

    result.data = {
        "region": region,
        "count": len(instances or []) + len(volumes or []) + len(addresses or []),
        "instances": [_summarize_instance(item) for item in instances or []],
        "volumes": [_summarize_volume(item) for item in volumes or []],
        "snapshots": len(snapshots or []),
        "security_groups": len(security_groups or []),
        "open_security_group_rules": open_sgs,
        "elastic_ips": [
            {
                "public_ip": item.get("PublicIp"),
                "allocation_id": item.get("AllocationId"),
                "instance_id": item.get("InstanceId"),
            }
            for item in addresses or []
        ],
    }
    return result


def collect_regional_network(session: Any, region: str) -> SectionResult:
    ec2 = client(session, "ec2", region)
    elbv2 = client(session, "elbv2", region)
    result = SectionResult(name=f"resources:network:{region}", status="ok")

    vpcs = _collect(ec2.describe_vpcs, "Vpcs", result, "ec2.describe_vpcs")
    subnets = _collect(ec2.describe_subnets, "Subnets", result, "ec2.describe_subnets")
    nat_gateways = _collect(
        ec2.describe_nat_gateways, "NatGateways", result, "ec2.describe_nat_gateways"
    )
    load_balancers = _collect(
        elbv2.describe_load_balancers, "LoadBalancers", result, "elbv2.describe_load_balancers"
    )

    result.data = {
        "region": region,
        "count": len(vpcs or []) + len(subnets or []) + len(load_balancers or []),
        "vpcs": [
            {
                "id": item["VpcId"],
                "cidr": item.get("CidrBlock"),
                "is_default": item.get("IsDefault"),
            }
            for item in vpcs or []
        ],
        "subnets": len(subnets or []),
        "nat_gateways": len(nat_gateways or []),
        "load_balancers": [
            {
                "name": item.get("LoadBalancerName"),
                "dns_name": item.get("DNSName"),
                "type": item.get("Type"),
                "scheme": item.get("Scheme"),
            }
            for item in load_balancers or []
        ],
    }
    return result


def collect_regional_serverless(session: Any, region: str) -> SectionResult:
    lambda_client = client(session, "lambda", region)
    ecs = client(session, "ecs", region)
    result = SectionResult(name=f"resources:serverless:{region}", status="ok")

    functions = _collect(lambda_client.list_functions, "Functions", result, "lambda.list_functions")
    clusters = _collect(ecs.list_clusters, "clusterArns", result, "ecs.list_clusters")

    cluster_details = []
    for cluster_arn in clusters or []:
        detail, detail_error = safe_call(
            f"ecs.describe_clusters({cluster_arn})",
            lambda cluster_arn=cluster_arn: ecs.describe_clusters(clusters=[cluster_arn])[
                "clusters"
            ],
        )
        if detail_error:
            result.errors.append(detail_error)
        elif detail:
            cluster_details.extend(detail)

    result.data = {
        "region": region,
        "count": len(functions or []) + len(cluster_details),
        "lambda_functions": [
            {
                "name": item["FunctionName"],
                "runtime": item.get("Runtime"),
                "last_modified": item.get("LastModified"),
            }
            for item in functions or []
        ],
        "ecs_clusters": [
            {
                "name": item.get("clusterName"),
                "status": item.get("status"),
                "running_tasks": item.get("runningTasksCount"),
            }
            for item in cluster_details
        ],
    }
    return result


def collect_regional_storage(session: Any, region: str) -> SectionResult:
    rds = client(session, "rds", region)
    dynamodb = client(session, "dynamodb", region)
    result = SectionResult(name=f"resources:storage:{region}", status="ok")

    db_instances = _collect(
        rds.describe_db_instances, "DBInstances", result, "rds.describe_db_instances"
    )
    tables = _collect(dynamodb.list_tables, "TableNames", result, "dynamodb.list_tables")

    result.data = {
        "region": region,
        "count": len(db_instances or []) + len(tables or []),
        "rds_instances": [
            {
                "identifier": item.get("DBInstanceIdentifier"),
                "engine": item.get("Engine"),
                "status": item.get("DBInstanceStatus"),
                "publicly_accessible": item.get("PubliclyAccessible"),
            }
            for item in db_instances or []
        ],
        "dynamodb_tables": tables or [],
    }

    for item in db_instances or []:
        if item.get("PubliclyAccessible"):
            result.findings.append(
                Finding(
                    severity="HIGH",
                    category="database",
                    title="Publicly accessible RDS instance",
                    detail=f"RDS instance {item.get('DBInstanceIdentifier')} is publicly accessible.",
                    resource_arn=item.get("DBInstanceArn"),
                )
            )
    return result


def collect_global_storage(session: Any, region: str) -> SectionResult:
    s3 = client(session, "s3", region)
    result = SectionResult(name="resources:storage:global", status="ok")

    buckets, buckets_error = safe_call(
        "s3.list_buckets", lambda: s3.list_buckets().get("Buckets", [])
    )
    if buckets_error:
        result.status = "error"
        result.errors.append(buckets_error)
        return result

    bucket_details = []
    for bucket in buckets or []:
        name = bucket["Name"]
        location, location_error = safe_call(
            f"s3.get_bucket_location({name})",
            lambda name=name: (
                s3.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            ),
        )
        public_block, public_block_error = safe_call(
            f"s3.get_public_access_block({name})",
            lambda name=name: s3.get_public_access_block(Bucket=name).get(
                "PublicAccessBlockConfiguration"
            ),
            not_found_ok=True,
        )
        policy_status, policy_status_error = get_bucket_policy_status(s3, name)
        for error in (location_error, public_block_error, policy_status_error):
            if error:
                result.errors.append(error)

        is_public = bool((policy_status or {}).get("IsPublic"))
        if is_public:
            result.findings.append(
                Finding(
                    severity="HIGH",
                    category="storage",
                    title="Public S3 bucket",
                    detail=f"S3 bucket {name} is public according to policy status.",
                    resource_arn=f"arn:aws:s3:::{name}",
                )
            )
        if public_block is None:
            result.findings.append(
                Finding(
                    severity="MEDIUM",
                    category="storage",
                    title="S3 bucket missing public access block",
                    detail=f"S3 bucket {name} has no bucket-level public access block.",
                    resource_arn=f"arn:aws:s3:::{name}",
                )
            )

        bucket_details.append(
            {
                "name": name,
                "creation_date": bucket.get("CreationDate"),
                "region": location,
                "public_access_block": public_block,
                "is_public": is_public,
            }
        )

    result.data = {
        "count": len(bucket_details),
        "buckets": bucket_details,
    }
    return result


def collect_global_dns(session: Any, region: str) -> SectionResult:
    route53 = client(session, "route53", region)
    result = SectionResult(name="resources:dns:global", status="ok")

    zones, zones_error = safe_call(
        "route53.list_hosted_zones",
        lambda: _paginate(route53.list_hosted_zones, "HostedZones"),
    )
    if zones_error:
        result.status = "error"
        result.errors.append(zones_error)
        return result

    result.data = {
        "count": len(zones or []),
        "hosted_zones": [
            {
                "id": zone["Id"],
                "name": zone["Name"],
                "private": zone.get("Config", {}).get("PrivateZone"),
                "record_count": zone.get("ResourceRecordSetCount"),
            }
            for zone in zones or []
        ],
    }
    return result


def collect_global_messaging(session: Any, region: str) -> SectionResult:
    result = SectionResult(name="resources:messaging:global", status="ok")
    cf = client(session, "cloudformation", region)

    stacks, stacks_error = safe_call(
        "cloudformation.list_stacks",
        lambda: _paginate(
            cf.list_stacks,
            "StackSummaries",
            StackStatusFilter=[
                "CREATE_COMPLETE",
                "UPDATE_COMPLETE",
                "UPDATE_ROLLBACK_COMPLETE",
                "IMPORT_COMPLETE",
                "IMPORT_ROLLBACK_COMPLETE",
            ],
        ),
    )
    if stacks_error:
        result.status = "error"
        result.errors.append(stacks_error)
        return result

    result.data = {
        "count": len(stacks or []),
        "cloudformation_stacks": [
            {
                "name": stack["StackName"],
                "status": stack["StackStatus"],
                "creation_time": stack.get("CreationTime"),
            }
            for stack in stacks or []
        ],
    }
    return result


def _collect(
    paginate_func: Callable[..., Any],
    key: str,
    result: SectionResult,
    label: str,
    **kwargs: Any,
) -> list[Any] | None:
    if key == "Reservations":
        reservations, error = safe_call(label, lambda: _paginate(paginate_func, key, **kwargs))
        if error:
            result.errors.append(error)
            return None
        instances = []
        for reservation in reservations or []:
            instances.extend(reservation.get("Instances", []))
        return instances

    items, error = safe_call(label, lambda: _paginate(paginate_func, key, **kwargs))
    if error:
        result.errors.append(error)
        return None
    return items


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


def _entities_with_policy(
    list_attached: Callable[..., Any],
    entity_type: str,
    entities: list[dict[str, Any]],
    policy_arn: str,
    name_key: str,
) -> list[str]:
    matches: list[str] = []
    for entity in entities:
        name = entity[name_key]
        attached, _ = safe_call(
            f"iam.list_attached_{entity_type}_policies({name})",
            lambda name=name: list_attached(**{f"{entity_type.capitalize()}Name": name}).get(
                "AttachedPolicies", []
            ),
        )
        for policy in attached or []:
            if policy.get("PolicyArn") == policy_arn:
                matches.append(name)
                break
    return matches


def _credential_report(iam: Any, result: SectionResult) -> list[dict[str, str]]:
    import time

    _, generate_error = safe_call(
        "iam.generate_credential_report", lambda: iam.generate_credential_report()
    )
    if generate_error:
        result.errors.append(generate_error)
        return []

    report = None
    for _ in range(5):
        report, report_error = safe_call(
            "iam.get_credential_report",
            lambda: iam.get_credential_report()["Content"],
        )
        if report_error and "ReportInProgress" in report_error:
            time.sleep(2)
            continue
        if report_error:
            result.errors.append(report_error)
            return []
        break

    if report is None:
        result.errors.append("iam.get_credential_report: report still in progress after retries")
        return []

    import base64
    import csv
    import io

    decoded: str
    if isinstance(report, (bytes, bytearray)):
        # IAM returns raw CSV bytes in modern botocore versions.
        try:
            decoded = report.decode("utf-8")
        except UnicodeDecodeError:
            try:
                decoded = base64.b64decode(report).decode("utf-8")
            except Exception as exc:
                result.errors.append(
                    f"iam.get_credential_report: failed to decode report bytes ({exc})"
                )
                return []
    else:
        # Keep backward compatibility with environments that return base64 text.
        try:
            decoded = base64.b64decode(report, validate=True).decode("utf-8")
        except Exception:
            decoded = str(report)
            if "," not in decoded or "\n" not in decoded:
                result.errors.append(
                    "iam.get_credential_report: report content is not valid CSV text"
                )
                return []

    reader = csv.DictReader(io.StringIO(decoded))
    return [dict(row) for row in list(reader)[:5]]


def _summarize_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": user["UserName"],
        "arn": user["Arn"],
        "create_date": user.get("CreateDate"),
        "password_last_used": user.get("PasswordLastUsed"),
    }


def _summarize_role(role: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": role["RoleName"],
        "arn": role["Arn"],
        "create_date": role.get("CreateDate"),
        "last_used": (role.get("RoleLastUsed") or {}).get("LastUsedDate"),
    }


def _summarize_instance(instance: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": instance["InstanceId"],
        "type": instance.get("InstanceType"),
        "state": (instance.get("State") or {}).get("Name"),
        "private_ip": instance.get("PrivateIpAddress"),
        "public_ip": instance.get("PublicIpAddress"),
    }


def _summarize_volume(volume: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": volume["VolumeId"],
        "size_gb": volume.get("Size"),
        "state": volume.get("State"),
        "encrypted": volume.get("Encrypted"),
    }
