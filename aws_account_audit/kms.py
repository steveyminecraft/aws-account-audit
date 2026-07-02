"""KMS key inventory and audit helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from aws_account_audit.session import client, safe_call

# CloudTrail LookupEvents only returns the last 90 days; cap pages to bound runtime.
_CLOUDTRAIL_MAX_PAGES = 25


def collect_regional_kms_inventory(
    session: Any,
    region: str,
    *,
    include_last_used: bool = True,
) -> tuple[list[dict[str, Any]], list[str]]:
    """List KMS keys in ``region`` with metadata and optional last-used timestamps."""
    kms = client(session, "kms", region)
    errors: list[str] = []

    keys, list_error = _list_kms_keys(kms, region)
    if list_error:
        return [], [list_error]

    alias_map, alias_error = _list_kms_aliases(kms, region)
    if alias_error:
        errors.append(alias_error)

    last_used_by_arn: dict[str, datetime] = {}
    if include_last_used:
        cloudtrail = client(session, "cloudtrail", region)
        last_used_map, trail_error = _collect_kms_last_used_map(cloudtrail, region)
        if trail_error:
            errors.append(trail_error)
        else:
            last_used_by_arn = last_used_map

    details: list[dict[str, Any]] = []
    for key in keys or []:
        key_id = key.get("KeyId")
        key_arn = key.get("KeyArn")
        if not key_id:
            continue

        metadata, describe_error = _describe_kms_key(kms, key_id, region)
        if describe_error:
            errors.append(describe_error)
            if metadata is None:
                continue

        rotation_enabled, rotation_error = _get_key_rotation_enabled(kms, key_id, metadata, region)
        if rotation_error:
            errors.append(rotation_error)

        aliases = alias_map.get(key_id, [])
        last_used_at = None
        if key_arn:
            last_used_at = last_used_by_arn.get(key_arn) or last_used_by_arn.get(key_id)

        details.append(
            summarize_kms_key(
                metadata or {},
                region=region,
                key_id=key_id,
                key_arn=key_arn,
                aliases=aliases,
                rotation_enabled=rotation_enabled,
                last_used_at=last_used_at,
            )
        )

    return details, errors


def summarize_kms_key(
    metadata: dict[str, Any],
    *,
    region: str,
    key_id: str,
    key_arn: str | None,
    aliases: list[str],
    rotation_enabled: bool | None,
    last_used_at: datetime | None,
) -> dict[str, Any]:
    """Normalize KMS key metadata for inventory tables and audit sections."""
    return {
        "id": key_id,
        "arn": key_arn,
        "alias": ", ".join(aliases) if aliases else None,
        "description": metadata.get("Description"),
        "key_manager": metadata.get("KeyManager"),
        "key_state": metadata.get("KeyState"),
        "key_usage": metadata.get("KeyUsage"),
        "key_spec": metadata.get("KeySpec"),
        "origin": metadata.get("Origin"),
        "multi_region": metadata.get("MultiRegion"),
        "rotation_enabled": rotation_enabled,
        "creation_date": metadata.get("CreationDate"),
        "deletion_date": metadata.get("DeletionDate"),
        "last_used_at": last_used_at,
        "region": region,
    }


def kms_findings_for_key(
    key: dict[str, Any],
) -> list[tuple[str, str, str, str, str | None]]:
    """Return finding tuples ``(severity, category, title, detail, resource_arn)``."""
    findings: list[tuple[str, str, str, str, str | None]] = []
    key_manager = key.get("key_manager")
    key_state = key.get("key_state")
    resource_arn = key.get("arn")
    alias = key.get("alias") or key.get("id")

    if key_state == "PendingDeletion":
        findings.append(
            (
                "HIGH",
                "crypto",
                "KMS key pending deletion",
                f"KMS key {alias} is scheduled for deletion.",
                resource_arn,
            )
        )

    if key_manager != "CUSTOMER":
        return findings

    if key_state == "Disabled":
        findings.append(
            (
                "LOW",
                "crypto",
                "Customer KMS key disabled",
                f"Customer managed key {alias} is disabled.",
                resource_arn,
            )
        )

    if key_state == "Enabled" and key.get("rotation_enabled") is False:
        findings.append(
            (
                "MEDIUM",
                "crypto",
                "KMS key rotation disabled",
                f"Customer managed key {alias} does not have automatic rotation enabled.",
                resource_arn,
            )
        )

    return findings


def format_kms_datetime(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(value)


def _list_kms_keys(kms: Any, region: str) -> tuple[list[dict[str, Any]] | None, str | None]:
    items: list[dict[str, Any]] = []
    marker: str | None = None
    while True:
        params: dict[str, Any] = {}
        if marker:
            params["Marker"] = marker
        response, error = safe_call(
            f"kms.list_keys({region})",
            lambda params=params: kms.list_keys(**params),
        )
        if error:
            return None, error
        payload = response or {}
        items.extend(payload.get("Keys", []))
        if not payload.get("Truncated"):
            break
        marker = payload.get("NextMarker")
        if not marker:
            break
    return items, None


def _list_kms_aliases(kms: Any, region: str) -> tuple[dict[str, list[str]], str | None]:
    alias_map: dict[str, list[str]] = {}
    marker: str | None = None
    while True:
        params: dict[str, Any] = {}
        if marker:
            params["Marker"] = marker
        response, error = safe_call(
            f"kms.list_aliases({region})",
            lambda params=params: kms.list_aliases(**params),
        )
        if error:
            return {}, error
        payload = response or {}
        for alias in payload.get("Aliases", []):
            target_key_id = alias.get("TargetKeyId")
            alias_name = alias.get("AliasName")
            if not target_key_id or not alias_name:
                continue
            alias_map.setdefault(target_key_id, []).append(alias_name)
        if not payload.get("Truncated"):
            break
        marker = payload.get("NextMarker")
        if not marker:
            break
    return alias_map, None


def _describe_kms_key(
    kms: Any,
    key_id: str,
    region: str,
) -> tuple[dict[str, Any] | None, str | None]:
    response, error = safe_call(
        f"kms.describe_key({region},{key_id})",
        lambda: kms.describe_key(KeyId=key_id),
    )
    if error:
        return None, error
    metadata = (response or {}).get("KeyMetadata") or {}
    return metadata, None


def _get_key_rotation_enabled(
    kms: Any,
    key_id: str,
    metadata: dict[str, Any],
    region: str,
) -> tuple[bool | None, str | None]:
    if metadata.get("KeyManager") != "CUSTOMER":
        return None, None
    if metadata.get("KeyState") != "Enabled":
        return None, None

    response, error = safe_call(
        f"kms.get_key_rotation_status({region},{key_id})",
        lambda: kms.get_key_rotation_status(KeyId=key_id),
    )
    if error:
        return None, error
    return bool((response or {}).get("KeyRotationEnabled")), None


def _collect_kms_last_used_map(
    cloudtrail: Any,
    region: str,
) -> tuple[dict[str, datetime], str | None]:
    """Build key ARN/ID -> last EventTime from regional CloudTrail KMS API events."""
    last_used: dict[str, datetime] = {}
    next_token: str | None = None
    pages = 0

    while pages < _CLOUDTRAIL_MAX_PAGES:
        params: dict[str, Any] = {
            "LookupAttributes": [
                {"AttributeKey": "EventSource", "AttributeValue": "kms.amazonaws.com"}
            ],
        }
        if next_token:
            params["NextToken"] = next_token

        response, error = safe_call(
            f"cloudtrail.lookup_events({region},kms)",
            lambda params=params: cloudtrail.lookup_events(**params),
        )
        if error:
            return last_used, error

        payload = response or {}
        for event in payload.get("Events", []):
            event_time = event.get("EventTime")
            if not isinstance(event_time, datetime):
                continue
            for resource in event.get("Resources", []):
                if resource.get("ResourceType") != "AWS::KMS::Key":
                    continue
                resource_name = resource.get("ResourceName")
                if not resource_name:
                    continue
                existing = last_used.get(resource_name)
                if existing is None or event_time > existing:
                    last_used[resource_name] = event_time

        next_token = payload.get("NextToken")
        pages += 1
        if not next_token:
            break

    return last_used, None
