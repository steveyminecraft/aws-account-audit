from __future__ import annotations

from typing import Any

from aws_account_audit.models import Finding, SectionResult
from aws_account_audit.snowflake.inventory import PRIVILEGED_ROLES
from aws_account_audit.snowflake.query import execute_query, execute_with_fallback, normalize_rows


def collect_identity(connection: Any) -> SectionResult:
    section = SectionResult(name="identity", status="ok")
    rows, error = execute_query(
        connection,
        """
        SELECT
            CURRENT_ACCOUNT() AS account,
            CURRENT_REGION() AS region,
            CURRENT_USER() AS user,
            CURRENT_ROLE() AS role,
            CURRENT_WAREHOUSE() AS warehouse,
            CURRENT_DATABASE() AS database,
            CURRENT_SCHEMA() AS schema
        """,
    )
    if error:
        section.status = "error"
        section.errors.append(error)
        return section

    identity = normalize_rows(rows)[0] if rows else {}
    section.data = {
        "account": identity.get("account"),
        "region": identity.get("region"),
        "user": identity.get("user"),
        "role": identity.get("role"),
        "warehouse": identity.get("warehouse"),
        "database": identity.get("database"),
        "schema": identity.get("schema"),
    }
    return section


def collect_user_grants(connection: Any) -> SectionResult:
    section = SectionResult(name="user_grants", status="ok")
    primary_sql = """
        SELECT grantee_name, role, granted_by, created_on
        FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        WHERE deleted_on IS NULL
        ORDER BY grantee_name, role
    """

    def _show_grants(conn: Any) -> tuple[list[dict[str, Any]], str | None]:
        users, user_error = execute_query(conn, "SHOW USERS")
        if user_error:
            return [], user_error
        grants: list[dict[str, Any]] = []
        for user_row in normalize_rows(users):
            user_name = user_row.get("name")
            if not user_name:
                continue
            rows, error = execute_query(
                conn,
                f"SHOW GRANTS TO USER {user_name}",
            )
            if error:
                return [], error
            grants.extend(normalize_rows(rows))
        return grants, None

    rows, errors = execute_with_fallback(connection, primary_sql, _show_grants)
    section.errors.extend(errors)
    if not rows and errors:
        section.status = "error"
        return section

    grants = [_normalize_grant_row(row) for row in normalize_rows(rows)]
    section.data = {"count": len(grants), "grants": grants}
    section.findings.extend(findings_for_user_grants(grants))
    return section


def collect_security(connection: Any, inventory: dict[str, list[dict[str, Any]]]) -> SectionResult:
    section = SectionResult(name="security", status="ok")
    users = inventory.get("users", [])
    warehouses = inventory.get("warehouses", [])
    network_policies = inventory.get("network_policies", [])
    integrations = inventory.get("integrations", [])

    section.data = {
        "user_count": len(users),
        "warehouse_count": len(warehouses),
        "network_policy_count": len(network_policies),
        "integration_count": len(integrations),
    }
    section.findings.extend(findings_for_users(users))
    section.findings.extend(findings_for_warehouses(warehouses))
    section.findings.extend(findings_for_network_policies(network_policies))
    section.findings.extend(findings_for_integrations(integrations))
    return section


def _normalize_grant_row(row: dict[str, Any]) -> dict[str, Any]:
    grantee = row.get("grantee_name") or row.get("grantee") or row.get("name")
    role = row.get("role") or row.get("granted_role") or row.get("privilege")
    return {
        "grantee_name": grantee,
        "role": role,
        "granted_by": row.get("granted_by"),
        "created_on": row.get("created_on"),
    }


def findings_for_user_grants(grants: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for grant in grants:
        role = str(grant.get("role") or "").upper()
        grantee = str(grant.get("grantee_name") or "unknown")
        if role not in PRIVILEGED_ROLES:
            continue
        severity = "HIGH" if role == "ACCOUNTADMIN" else "MEDIUM"
        findings.append(
            Finding(
                severity=severity,
                category="access_control",
                title=f"Privileged role granted to user: {role}",
                detail=f"User {grantee} has been granted the {role} role.",
                resource_arn=f"snowflake:user/{grantee}",
            )
        )
    return findings


def findings_for_users(users: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for user in users:
        name = str(user.get("name") or user.get("login_name") or "unknown")
        if user.get("disabled") in (True, "true", "TRUE"):
            continue

        default_role = str(user.get("default_role") or "").upper()
        if default_role in PRIVILEGED_ROLES:
            severity = "HIGH" if default_role == "ACCOUNTADMIN" else "MEDIUM"
            findings.append(
                Finding(
                    severity=severity,
                    category="access_control",
                    title=f"User default role is privileged: {default_role}",
                    detail=f"User {name} defaults to role {default_role} at login.",
                    resource_arn=f"snowflake:user/{name}",
                )
            )

        has_password = _truthy(user.get("has_password"))
        has_rsa = _truthy(user.get("has_rsa_public_key"))
        has_mfa = _truthy(user.get("has_mfa")) or _truthy(user.get("ext_authn_duo"))
        if has_password and not has_mfa:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    category="authentication",
                    title="Password user without MFA",
                    detail=f"User {name} can authenticate with a password but MFA is not enabled.",
                    resource_arn=f"snowflake:user/{name}",
                )
            )
        if has_password and not has_rsa:
            findings.append(
                Finding(
                    severity="LOW",
                    category="authentication",
                    title="Password-only authentication",
                    detail=f"User {name} has a password but no RSA public key configured.",
                    resource_arn=f"snowflake:user/{name}",
                )
            )
    return findings


def findings_for_warehouses(warehouses: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for warehouse in warehouses:
        name = str(warehouse.get("name") or "unknown")
        auto_suspend = warehouse.get("auto_suspend")
        if auto_suspend in (None, 0, "0"):
            findings.append(
                Finding(
                    severity="LOW",
                    category="cost",
                    title="Warehouse auto-suspend disabled",
                    detail=(
                        f"Warehouse {name} has auto_suspend={auto_suspend!r}; "
                        "compute may remain running when idle."
                    ),
                    resource_arn=f"snowflake:warehouse/{name}",
                )
            )
    return findings


def findings_for_network_policies(policies: list[dict[str, Any]]) -> list[Finding]:
    if policies:
        return []
    return [
        Finding(
            severity="MEDIUM",
            category="network",
            title="No network policies configured",
            detail=(
                "No Snowflake network policies were found. Consider restricting "
                "client IP ranges for console and driver access."
            ),
        )
    ]


def findings_for_integrations(integrations: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    enabled_security = [
        item
        for item in integrations
        if str(item.get("category") or "").upper() == "SECURITY" and _truthy(item.get("enabled"))
    ]
    if not enabled_security:
        findings.append(
            Finding(
                severity="INFO",
                category="authentication",
                title="No enabled security integrations",
                detail=(
                    "No enabled SECURITY-category integrations were found "
                    "(for example SSO or SCIM)."
                ),
            )
        )
    return findings


def _truthy(value: object) -> bool:
    if value is True:
        return True
    if value is False or value is None:
        return False
    return str(value).strip().lower() in {"true", "yes", "y", "1"}
