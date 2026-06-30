from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from aws_account_audit.session import client, safe_call


DEFAULT_ORG_ROLE_NAME = "OrganizationAccountAccessRole"
ACTIVE_ACCOUNT_STATUS = "ACTIVE"


@dataclass(frozen=True)
class OrganizationInfo:
    organization_id: str
    master_account_id: str
    arn: str | None = None


@dataclass(frozen=True)
class OrganizationAccount:
    account_id: str
    name: str
    status: str
    email: str | None = None


def _paginate(func: Callable[..., Any], key: str, **kwargs: Any) -> list[Any]:
    items: list[Any] = []
    token: str | None = None
    while True:
        call_kwargs = dict(kwargs)
        if token:
            call_kwargs["NextToken"] = token
        response = func(**call_kwargs)
        items.extend(response.get(key, []))
        token = response.get("NextToken")
        if not token:
            break
    return items


def describe_organization(session: Any, region: str) -> tuple[OrganizationInfo | None, str | None]:
    payload, error = safe_call(
        "organizations.describe_organization",
        lambda: client(session, "organizations", region).describe_organization(),
    )
    if error:
        return None, error
    org = (payload or {}).get("Organization") or {}
    organization_id = str(org.get("Id") or "")
    master_account_id = str(org.get("MasterAccountId") or "")
    if not organization_id or not master_account_id:
        return None, "organizations.describe_organization: missing organization or master account id"
    return (
        OrganizationInfo(
            organization_id=organization_id,
            master_account_id=master_account_id,
            arn=org.get("Arn"),
        ),
        None,
    )


def list_organization_accounts(
    session: Any,
    region: str,
    *,
    active_only: bool = True,
) -> tuple[list[OrganizationAccount], str | None]:
    accounts, error = safe_call(
        "organizations.list_accounts",
        lambda: _paginate(
            client(session, "organizations", region).list_accounts,
            "Accounts",
        ),
    )
    if error:
        return [], error

    result: list[OrganizationAccount] = []
    for account in accounts or []:
        status = str(account.get("Status") or "")
        if active_only and status != ACTIVE_ACCOUNT_STATUS:
            continue
        account_id = str(account.get("Id") or "")
        if not account_id:
            continue
        result.append(
            OrganizationAccount(
                account_id=account_id,
                name=str(account.get("Name") or account_id),
                status=status,
                email=account.get("Email"),
            )
        )
    result.sort(key=lambda item: item.account_id)
    return result, None


def credentials_to_env(credentials: dict[str, str]) -> dict[str, str]:
    return {
        "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
        "AWS_SESSION_TOKEN": credentials["SessionToken"],
    }


def assume_role_credentials(
    session: Any,
    *,
    account_id: str,
    role_name: str,
    region: str,
    session_name: str = "aws-account-audit",
) -> tuple[dict[str, str] | None, str | None]:
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    payload, error = safe_call(
        f"sts.assume_role({role_arn})",
        lambda: client(session, "sts", region).assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        ),
    )
    if error:
        return None, error
    credentials = (payload or {}).get("Credentials") or {}
    access_key_id = credentials.get("AccessKeyId")
    secret_access_key = credentials.get("SecretAccessKey")
    session_token = credentials.get("SessionToken")
    if not access_key_id or not secret_access_key or not session_token:
        return None, f"sts.assume_role({role_arn}): incomplete temporary credentials"
    return (
        credentials_to_env(
            {
                "AccessKeyId": access_key_id,
                "SecretAccessKey": secret_access_key,
                "SessionToken": session_token,
            }
        ),
        None,
    )


def filter_organization_accounts(
    accounts: list[OrganizationAccount],
    *,
    include_accounts: list[str] | None,
    exclude_accounts: list[str] | None,
) -> list[OrganizationAccount]:
    include = set(include_accounts or [])
    exclude = set(exclude_accounts or [])
    filtered: list[OrganizationAccount] = []
    for account in accounts:
        if include and account.account_id not in include:
            continue
        if account.account_id in exclude:
            continue
        filtered.append(account)
    return filtered
