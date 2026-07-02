from __future__ import annotations

from typing import Any, Callable

Row = dict[str, Any]


def execute_query(
    connection: Any,
    sql: str,
    *,
    params: tuple[Any, ...] | dict[str, Any] | None = None,
) -> tuple[list[Row], str | None]:
    """Run a read-only SQL statement and return rows as dicts."""
    try:
        cursor = connection.cursor()
        cursor.execute(sql, params or ())
        rows = cursor.fetchall()
        cursor.close()
        return list(rows or []), None
    except Exception as exc:  # noqa: BLE001 - surface connector errors to callers
        return [], f"{sql.strip().splitlines()[0][:120]}: {exc}"


def execute_with_fallback(
    connection: Any,
    primary_sql: str,
    fallback: Callable[[Any], tuple[list[Row], str | None]],
) -> tuple[list[Row], list[str]]:
    rows, error = execute_query(connection, primary_sql)
    if error is None:
        return rows, []
    fallback_rows, fallback_error = fallback(connection)
    if fallback_error is None:
        return fallback_rows, [error]
    return [], [error, fallback_error]


def normalize_row(row: Row) -> Row:
    return {str(key).lower(): value for key, value in row.items()}


def normalize_rows(rows: list[Row]) -> list[Row]:
    return [normalize_row(row) for row in rows]
