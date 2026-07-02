from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SnowflakeConfig:
    account: str
    user: str
    password: str | None = None
    role: str | None = None
    warehouse: str | None = None
    database: str | None = None
    schema: str | None = None
    authenticator: str | None = None
    private_key_path: str | None = None

    def connect_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "account": self.account,
            "user": self.user,
        }
        if self.password:
            kwargs["password"] = self.password
        if self.role:
            kwargs["role"] = self.role
        if self.warehouse:
            kwargs["warehouse"] = self.warehouse
        if self.database:
            kwargs["database"] = self.database
        if self.schema:
            kwargs["schema"] = self.schema
        if self.authenticator:
            kwargs["authenticator"] = self.authenticator
        if self.private_key_path:
            kwargs["private_key"] = _load_private_key(self.private_key_path)
        return kwargs


def _load_private_key(path: str) -> bytes:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization

    key_path = Path(path).expanduser()
    passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")
    password = passphrase.encode() if passphrase else None
    with key_path.open("rb") as handle:
        private_key = serialization.load_pem_private_key(
            handle.read(),
            password=password,
            backend=default_backend(),
        )
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_config_from_env() -> SnowflakeConfig:
    account = os.environ.get("SNOWFLAKE_ACCOUNT", "").strip()
    user = os.environ.get("SNOWFLAKE_USER", "").strip()
    if not account or not user:
        raise ValueError("SNOWFLAKE_ACCOUNT and SNOWFLAKE_USER environment variables are required")
    return SnowflakeConfig(
        account=account,
        user=user,
        password=os.environ.get("SNOWFLAKE_PASSWORD"),
        role=os.environ.get("SNOWFLAKE_ROLE"),
        warehouse=os.environ.get("SNOWFLAKE_WAREHOUSE"),
        database=os.environ.get("SNOWFLAKE_DATABASE"),
        schema=os.environ.get("SNOWFLAKE_SCHEMA"),
        authenticator=os.environ.get("SNOWFLAKE_AUTHENTICATOR"),
        private_key_path=os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH"),
    )


def merge_config(
    base: SnowflakeConfig,
    *,
    account: str | None = None,
    user: str | None = None,
    password: str | None = None,
    role: str | None = None,
    warehouse: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    authenticator: str | None = None,
    private_key_path: str | None = None,
) -> SnowflakeConfig:
    return SnowflakeConfig(
        account=account or base.account,
        user=user or base.user,
        password=password if password is not None else base.password,
        role=role if role is not None else base.role,
        warehouse=warehouse if warehouse is not None else base.warehouse,
        database=database if database is not None else base.database,
        schema=schema if schema is not None else base.schema,
        authenticator=authenticator if authenticator is not None else base.authenticator,
        private_key_path=(
            private_key_path if private_key_path is not None else base.private_key_path
        ),
    )


def connect(config: SnowflakeConfig) -> Any:
    connector, dict_cursor = _require_connector()
    return connector.connect(**config.connect_kwargs(), cursor_class=dict_cursor)


def _require_connector() -> tuple[Any, Any]:
    try:
        import snowflake.connector
        from snowflake.connector import DictCursor
    except ImportError as exc:
        raise RuntimeError(
            "snowflake-connector-python is required for Snowflake audits. "
            "Install with: pip install 'aws-account-audit[snowflake]'"
        ) from exc
    return snowflake.connector, DictCursor
