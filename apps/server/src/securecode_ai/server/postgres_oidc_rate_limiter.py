"""PostgreSQL-backed per-source OIDC attempt limiting.

The repository currently exposes a SQLite DB-API implementation for the OIDC
state ledger, but it has no PostgreSQL connection adapter.  This module keeps
the PostgreSQL-specific SQL behind a small transaction port.  The application
can bind that port to its PostgreSQL driver without making the login service
depend on a driver package.

The transaction port must run the callback in one PostgreSQL transaction and
must roll that transaction back when the callback raises.  A transaction-level
advisory lock protects the bounded bucket-count check across server replicas;
the row lock then protects the selected source window.  The source identifier
is accepted only as a lowercase SHA-256 hex digest, so raw network identifiers
never reach this durable store.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Sequence
from typing import Final, Protocol, TypeVar

from .oidc import OidcDenied

_DEFAULT_MAX_ENTRIES: Final = 100_000
_MAX_CLEANUP_ROWS: Final = 10_000
_DEFAULT_CLEANUP_ROWS: Final = 256
_SOURCE_HASH_LENGTH: Final = 64
_ADVISORY_LOCK_KEY: Final[int] = 0x534543555245434F

_T = TypeVar("_T")


class PostgresOidcRateLimitCursor(Protocol):
    """Minimal synchronous cursor required by the PostgreSQL adapter."""

    def execute(
        self,
        statement: str,
        parameters: Sequence[object] = (),
    ) -> object: ...

    def fetchone(self) -> tuple[object, ...] | None: ...


class PostgresOidcRateLimitExecution(Protocol):
    """Transaction boundary supplied by the PostgreSQL runtime.

    Implementations should open a transaction, provide a cursor to
    ``operation``, commit its result, and roll back before propagating any
    exception.  A psycopg connection wrapper can implement this without
    exposing the driver to the OIDC login service.
    """

    def transaction(
        self,
        operation: Callable[[PostgresOidcRateLimitCursor], _T],
    ) -> _T: ...


class PostgresOidcRateLimitConnection(Protocol):
    """Synchronous DB-API connection contract used by the execution adapter."""

    def cursor(self) -> PostgresOidcRateLimitCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


class DbApiPostgresOidcRateLimitExecution:
    """Open one connection and commit or roll back one source charge."""

    __slots__ = ("_connection_factory",)

    def __init__(
        self,
        connection_factory: Callable[[], PostgresOidcRateLimitConnection],
    ) -> None:
        if not callable(connection_factory):
            raise OidcDenied()
        self._connection_factory = connection_factory

    def transaction(
        self,
        operation: Callable[[PostgresOidcRateLimitCursor], _T],
    ) -> _T:
        if not callable(operation):
            raise OidcDenied()
        connection: PostgresOidcRateLimitConnection | None = None
        cursor: PostgresOidcRateLimitCursor | None = None
        try:
            connection = self._connection_factory()
            if not all(
                callable(getattr(connection, name, None))
                for name in ("cursor", "commit", "rollback", "close")
            ):
                raise OidcDenied()
            if getattr(connection, "autocommit", False) is True:
                raise OidcDenied()
            cursor = connection.cursor()
            if not callable(getattr(cursor, "execute", None)) or not callable(
                getattr(cursor, "fetchone", None)
            ):
                raise OidcDenied()
            result = operation(cursor)
            connection.commit()
            return result
        except BaseException:
            if connection is not None and callable(getattr(connection, "rollback", None)):
                with contextlib.suppress(BaseException):
                    connection.rollback()
            raise
        finally:
            close_cursor = getattr(cursor, "close", None)
            if cursor is not None and callable(close_cursor):
                try:
                    close_cursor()
                finally:
                    if connection is not None:
                        connection.close()
            elif connection is not None and callable(getattr(connection, "close", None)):
                connection.close()


class PostgresOidcSourceRateLimiter:
    """Atomically charge durable OIDC source windows in PostgreSQL.

    ``charge_source_attempt`` is the same source-rate port consumed by
    ``OidcLoginService`` for both its ``start`` and ``callback`` buckets.  The
    adapter does not own a connection or transaction: the injected execution
    port supplies those concerns and must use a dedicated PostgreSQL
    transaction for every charge.
    """

    __slots__ = ("_cleanup_rows", "_execution")

    def __init__(
        self,
        execution: PostgresOidcRateLimitExecution,
        *,
        cleanup_rows: int = _DEFAULT_CLEANUP_ROWS,
    ) -> None:
        if (
            not callable(getattr(execution, "transaction", None))
            or type(cleanup_rows) is not int
            or not 1 <= cleanup_rows <= _MAX_CLEANUP_ROWS
        ):
            raise OidcDenied()
        self._execution = execution
        self._cleanup_rows = cleanup_rows

    def charge_source_attempt(
        self,
        *,
        bucket: str,
        source_hash: str,
        now: int,
        limit: int,
        window_seconds: int,
    ) -> None:
        """Charge one ``start`` or ``callback`` attempt or fail closed."""

        if (
            type(bucket) is not str
            or bucket not in {"start", "callback"}
            or type(source_hash) is not str
            or len(source_hash) != _SOURCE_HASH_LENGTH
            or any(character not in "0123456789abcdef" for character in source_hash)
            or type(now) is not int
            or now < 0
            or type(limit) is not int
            or not 1 <= limit <= _DEFAULT_MAX_ENTRIES
            or type(window_seconds) is not int
            or not 1 <= window_seconds <= 3600
        ):
            raise OidcDenied()

        def charge(cursor: PostgresOidcRateLimitCursor) -> bool:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (_ADVISORY_LOCK_KEY,),
            )
            cursor.execute(
                """
                WITH expired AS (
                    SELECT bucket, source_hash
                    FROM oidc_login_source_rate_limit
                    WHERE window_started_at <= %s
                      AND window_started_at + window_seconds <= %s
                    ORDER BY window_started_at, bucket, source_hash
                    LIMIT %s
                )
                DELETE FROM oidc_login_source_rate_limit AS target
                USING expired
                WHERE target.bucket = expired.bucket
                  AND target.source_hash = expired.source_hash
                """,
                (now, now, self._cleanup_rows),
            )
            cursor.execute(
                """
                SELECT window_started_at, window_seconds, attempts
                FROM oidc_login_source_rate_limit
                WHERE bucket = %s AND source_hash = %s
                FOR UPDATE
                """,
                (bucket, source_hash),
            )
            row = cursor.fetchone()
            if row is None:
                cursor.execute("SELECT COUNT(*) FROM oidc_login_source_rate_limit")
                count_row = cursor.fetchone()
                if count_row is None or len(count_row) != 1 or type(count_row[0]) is not int:
                    raise OidcDenied()
                if count_row[0] >= _DEFAULT_MAX_ENTRIES:
                    return False
                cursor.execute(
                    """
                    INSERT INTO oidc_login_source_rate_limit
                        (bucket, source_hash, window_started_at, window_seconds, attempts)
                    VALUES (%s, %s, %s, %s, 1)
                    RETURNING attempts
                    """,
                    (bucket, source_hash, now, window_seconds),
                )
                inserted = cursor.fetchone()
                if inserted is None or len(inserted) != 1 or inserted[0] != 1:
                    raise OidcDenied()
                return True

            if len(row) != 3:
                raise OidcDenied()
            started, stored_window, attempts = row
            if (
                type(started) is not int
                or started < 0
                or type(stored_window) is not int
                or not 1 <= stored_window <= 3600
                or type(attempts) is not int
                or attempts < 1
                or now < started
            ):
                raise OidcDenied()
            if now - started >= window_seconds:
                cursor.execute(
                    """
                    UPDATE oidc_login_source_rate_limit
                    SET window_started_at = %s, window_seconds = %s, attempts = 1
                    WHERE bucket = %s AND source_hash = %s
                    RETURNING attempts
                    """,
                    (now, window_seconds, bucket, source_hash),
                )
            elif attempts >= limit:
                return False
            else:
                cursor.execute(
                    """
                    UPDATE oidc_login_source_rate_limit
                    SET attempts = attempts + 1
                    WHERE bucket = %s AND source_hash = %s
                    RETURNING attempts
                    """,
                    (bucket, source_hash),
                )
            updated = cursor.fetchone()
            if updated is None or len(updated) != 1 or type(updated[0]) is not int:
                raise OidcDenied()
            return True

        try:
            charged = self._execution.transaction(charge)
            if type(charged) is not bool or not charged:
                raise OidcDenied()
        except OidcDenied:
            raise
        except Exception:
            raise OidcDenied() from None


__all__ = [
    "DbApiPostgresOidcRateLimitExecution",
    "PostgresOidcRateLimitConnection",
    "PostgresOidcRateLimitCursor",
    "PostgresOidcRateLimitExecution",
    "PostgresOidcSourceRateLimiter",
]
