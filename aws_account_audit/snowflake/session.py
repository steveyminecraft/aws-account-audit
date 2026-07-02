from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PASSWORDLESS_AUTHENTICATORS = frozenset(
    {
        "externalbrowser",
        "oauth",
        "oauth_authorization_code",
        "programmatic_access_token",
        "workload_identity",
    }
)


@dataclass(frozen=True)
class SnowflakeConfig:
    account: str = ""
    user: str = ""
    password: str | None = None
    role: str | None = None
    warehouse: str | None = None
    database: str | None = None
    schema: str | None = None
    authenticator: str | None = None
    private_key_path: str | None = None
    connection_name: str | None = None
    passcode: str | None = None
    client_store_temporary_credential: bool | None = None

    def connect_kwargs(self) -> dict[str, Any]:
        authenticator = normalize_authenticator(self.authenticator)
        kwargs: dict[str, Any] = {}
        if self.account:
            kwargs["account"] = self.account
        if self.user:
            kwargs["user"] = self.user
        if self.password and uses_password_authenticator(authenticator):
            kwargs["password"] = self.password
        if self.role:
            kwargs["role"] = self.role
        if self.warehouse:
            kwargs["warehouse"] = self.warehouse
        if self.database:
            kwargs["database"] = self.database
        if self.schema:
            kwargs["schema"] = self.schema
        if authenticator:
            kwargs["authenticator"] = authenticator
        if self.passcode and authenticator == "username_password_mfa":
            kwargs["passcode"] = self.passcode
        if self.client_store_temporary_credential is not None:
            kwargs["client_store_temporary_credential"] = self.client_store_temporary_credential
        if self.private_key_path:
            kwargs["private_key"] = _load_private_key(self.private_key_path)
        return kwargs


def normalize_authenticator(value: str | None) -> str | None:
    if not value:
        return None
    return value.strip().lower()


def uses_password_authenticator(authenticator: str | None) -> bool:
    if not authenticator:
        return True
    if authenticator in PASSWORDLESS_AUTHENTICATORS:
        return False
    if authenticator.startswith("https://"):
        return False
    return authenticator in {"snowflake", "username_password_mfa"}


def is_browser_authenticator(authenticator: str | None) -> bool:
    normalized = normalize_authenticator(authenticator)
    return normalized in {"externalbrowser", "oauth", "oauth_authorization_code"}


def describe_auth_plan(config: SnowflakeConfig) -> str:
    authenticator = normalize_authenticator(config.authenticator) or "snowflake"
    lines = [
        f"connection_name: {config.connection_name or '-'}",
        f"account: {config.account or '-'}",
        f"user: {config.user or '-'}",
        f"authenticator: {authenticator}",
        f"password: {'set' if config.password else 'unset'}",
        f"passcode: {'set' if config.passcode else 'unset'}",
        f"will_send_password: {uses_password_authenticator(authenticator) and bool(config.password)}",
    ]
    if is_browser_authenticator(authenticator):
        lines.append("auth_flow: browser SSO (handles MFA via your IdP in a browser window)")
    elif authenticator == "username_password_mfa":
        lines.append("auth_flow: Snowflake password + MFA passcode")
    elif config.private_key_path:
        lines.append("auth_flow: key pair")
    else:
        lines.append("auth_flow: Snowflake username/password")
    return "\n".join(lines)


def find_connections_toml() -> Path | None:
    home = Path.home()
    snowflake_home = Path(os.environ.get("SNOWFLAKE_HOME", home / ".snowflake"))
    candidates = [
        snowflake_home / "connections.toml",
        home / ".snowflake" / "connections.toml",
    ]
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        candidates.append(Path(xdg_config_home) / "snowflake" / "connections.toml")
    else:
        candidates.append(home / ".config" / "snowflake" / "connections.toml")

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.expanduser()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_file():
            return resolved
    return None


def load_connections_toml(*, connections_path: Path | None = None) -> dict[str, Any]:
    path = connections_path or find_connections_toml()
    if path is None:
        raise ValueError("No Snowflake connections.toml file found")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def list_connection_names(*, connections_path: Path | None = None) -> list[str]:
    data = load_connections_toml(connections_path=connections_path)
    reserved = {"default_connection_name"}
    return sorted(
        key for key, value in data.items() if key not in reserved and isinstance(value, dict)
    )


def load_config_from_connection(
    connection_name: str | None = None,
    *,
    connections_path: Path | None = None,
) -> SnowflakeConfig:
    path = connections_path or find_connections_toml()
    if path is None:
        raise ValueError("No Snowflake connections.toml file found")

    data = load_connections_toml(connections_path=path)
    name = connection_name or data.get("default_connection_name")
    if not name:
        available = ", ".join(list_connection_names(connections_path=path)) or "none"
        raise ValueError(
            f"No connection name specified and no default_connection_name in {path}. "
            f"Available connections: {available}"
        )

    section = data.get(name)
    if not isinstance(section, dict):
        available = ", ".join(list_connection_names(connections_path=path)) or "none"
        raise ValueError(
            f"Connection {name!r} not found in {path}. Available connections: {available}"
        )

    return _config_from_connection_section(section, connection_name=str(name))


def _config_from_connection_section(
    section: dict[str, Any],
    *,
    connection_name: str,
) -> SnowflakeConfig:
    private_key = section.get("private_key_path") or section.get("private_key")
    store_credentials = section.get("client_store_temporary_credential")
    return SnowflakeConfig(
        account=str(section.get("account") or ""),
        user=str(section.get("user") or ""),
        password=section.get("password"),
        role=section.get("role"),
        warehouse=section.get("warehouse"),
        database=section.get("database"),
        schema=section.get("schema"),
        authenticator=section.get("authenticator"),
        private_key_path=str(private_key) if private_key else None,
        connection_name=connection_name,
        passcode=section.get("passcode"),
        client_store_temporary_credential=(
            bool(store_credentials) if store_credentials is not None else None
        ),
    )


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
        connection_name=os.environ.get("SNOWFLAKE_CONNECTION"),
        passcode=os.environ.get("SNOWFLAKE_PASSCODE"),
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
    connection_name: str | None = None,
    passcode: str | None = None,
    client_store_temporary_credential: bool | None = None,
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
        connection_name=connection_name if connection_name is not None else base.connection_name,
        passcode=passcode if passcode is not None else base.passcode,
        client_store_temporary_credential=(
            client_store_temporary_credential
            if client_store_temporary_credential is not None
            else base.client_store_temporary_credential
        ),
    )


def connect(config: SnowflakeConfig) -> Any:
    connector, dict_cursor = _require_connector()
    kwargs = config.connect_kwargs()
    if config.connection_name:
        return connector.connect(
            connection_name=config.connection_name,
            cursor_class=dict_cursor,
            **kwargs,
        )
    if not kwargs.get("account") or not kwargs.get("user"):
        raise ValueError(
            "Snowflake account and user are required. Set SNOWFLAKE_ACCOUNT/SNOWFLAKE_USER, "
            "use --connection with ~/.snowflake/connections.toml, or pass --account and --user."
        )
    return connector.connect(**kwargs, cursor_class=dict_cursor)


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
