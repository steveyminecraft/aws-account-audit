from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError


DEFAULT_REGION = "eu-west-1"
BOTO_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

# ClientError codes that mean "optional resource/config is absent" for not_found_ok calls.
NOT_FOUND_ERROR_CODES = frozenset(
    {
        "NoSuchEntity",
        "ResourceNotFoundException",
        "NoSuchPublicAccessBlockConfiguration",
        "NoSuchBucketPolicy",
    }
)

# Extra codes for S3 policy-status lookups (directory buckets, unsupported APIs).
S3_POLICY_STATUS_ABSENT_CODES = NOT_FOUND_ERROR_CODES | frozenset(
    {
        "NotImplemented",
        "UnsupportedOperation",
        "MethodNotAllowed",
    }
)

S3_POLICY_STATUS_ABSENT_HINTS = (
    "bucket policy does not exist",
    "not supported for directory buckets",
    "not supported by directory buckets",
)


def create_session(profile: str | None = None) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


@contextmanager
def temporary_credentials_env(credentials: dict[str, str] | None) -> Iterator[None]:
    """Temporarily set AWS credential environment variables for cross-account scans."""
    if not credentials:
        yield
        return

    previous: dict[str, str | None] = {}
    for key, value in credentials.items():
        previous[key] = os.environ.get(key)
        os.environ[key] = value
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


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


def region_was_explicit(argv: list[str] | None) -> bool:
    if not argv:
        return False
    for arg in argv:
        if arg == "--region" or arg.startswith("--region="):
            return True
    return False


def resolve_scan_regions(
    *,
    profile: str | None,
    region: str,
    regions: list[str] | None,
    all_regions: bool | None,
    region_explicit: bool,
) -> list[str]:
    """Choose which AWS regions to scan.

    Priority:
    1. ``regions`` when provided
    2. ``all_regions is True`` → all enabled regions
    3. ``all_regions is False`` → single ``region``
    4. ``region_explicit`` without ``all_regions`` → single ``region``
    5. default (no region flags) → all enabled regions
    """
    if regions:
        return sorted(set(regions))
    session = create_session(profile)
    if all_regions is True:
        return enabled_regions(session, region)
    if all_regions is False:
        return [region]
    if region_explicit:
        return [region]
    return enabled_regions(session, region)


def safe_call(
    label: str,
    func: Any,
    *,
    not_found_ok: bool = False,
    not_found_codes: frozenset[str] | None = None,
    not_found_hints: tuple[str, ...] = (),
) -> tuple[Any | None, str | None]:
    try:
        return func(), None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = exc.response.get("Error", {}).get("Message", "")
        codes = not_found_codes
        if codes is None and not_found_ok:
            codes = NOT_FOUND_ERROR_CODES
        if codes and code in codes:
            return None, None
        if (
            not_found_ok
            and not_found_hints
            and any(hint.lower() in message.lower() for hint in not_found_hints)
        ):
            return None, None
        return None, f"{label}: {code} - {message or str(exc)}"
    except EndpointConnectionError as exc:
        return None, f"{label}: endpoint unavailable - {exc}"
    except Exception as exc:  # noqa: BLE001 - audit tool must continue on partial failures
        return None, f"{label}: {exc}"


def get_bucket_policy_status(
    s3: Any,
    bucket_name: str,
) -> tuple[dict[str, Any] | None, str | None]:
    """Return PolicyStatus for a bucket, treating absent/unsupported policy as None."""
    return safe_call(
        f"s3.get_bucket_policy_status({bucket_name})",
        lambda bucket_name=bucket_name: s3.get_bucket_policy_status(Bucket=bucket_name).get(
            "PolicyStatus"
        ),
        not_found_ok=True,
        not_found_codes=S3_POLICY_STATUS_ABSENT_CODES,
        not_found_hints=S3_POLICY_STATUS_ABSENT_HINTS,
    )
