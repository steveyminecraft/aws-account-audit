from __future__ import annotations

from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError


DEFAULT_REGION = "eu-west-1"
BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


def create_session(profile: str | None = None) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def client(
    session: boto3.Session,
    service: str,
    region: str | None = None,
) -> Any:
    return session.client(
        service,
        region_name=region,
        config=BOTO_CONFIG,
    )


def caller_identity(session: boto3.Session, region: str) -> dict[str, Any]:
    return client(session, "sts", region).get_caller_identity()


def enabled_regions(session: boto3.Session, region: str) -> list[str]:
    ec2 = client(session, "ec2", region)
    response = ec2.describe_regions(AllRegions=False)
    return sorted(item["RegionName"] for item in response["Regions"])


def safe_call(
    label: str,
    func: Any,
    *,
    not_found_ok: bool = False,
) -> tuple[Any | None, str | None]:
    try:
        return func(), None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if not_found_ok and code in {
            "NoSuchEntity",
            "ResourceNotFoundException",
            "NoSuchPublicAccessBlockConfiguration",
            "NoSuchBucketPolicy",
        }:
            return None, None
        return None, f"{label}: {code} - {exc.response['Error'].get('Message', str(exc))}"
    except EndpointConnectionError as exc:
        return None, f"{label}: endpoint unavailable - {exc}"
    except Exception as exc:  # noqa: BLE001 - audit tool must continue on partial failures
        return None, f"{label}: {exc}"
