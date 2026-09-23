"""Validated configuration for the connected worker process."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .secure_files import read_ascii_secret

_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    control_plane_url: str
    token: str = field(repr=False)
    worker_id: str
    target: Path
    requested_run_id: str | None
    scm_resolution: tuple[str, str, str, str] | None
    request_timeout_seconds: float
    poll_seconds: float
    max_backoff_seconds: float
    artifact_hosts: frozenset[str]

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> RuntimeSettings:
        try:
            url = environment["SECURECODE_CONTROL_PLANE_URL"]
            token = _worker_token(environment)
            worker_id = environment["SECURECODE_WORKER_ID"]
            target = Path(environment["SECURECODE_WORKER_TARGET"])
            requested_run_id = environment.get("SECURECODE_WORKER_RUN_ID")
            gitlab_values = (
                environment.get("CI_PROJECT_ID"),
                environment.get("CI_MERGE_REQUEST_IID"),
                environment.get("CI_COMMIT_SHA"),
            )
            if requested_run_id is None and all(gitlab_values):
                scm_resolution = (
                    "gitlab",
                    _ci_value(gitlab_values[0]),
                    _ci_value(gitlab_values[1]),
                    _ci_value(gitlab_values[2]),
                )
            elif requested_run_id is None and any(gitlab_values):
                raise ValueError
            else:
                scm_resolution = None
            timeout = float(environment.get("SECURECODE_WORKER_REQUEST_TIMEOUT_SECONDS", "15"))
            poll = float(environment.get("SECURECODE_WORKER_POLL_SECONDS", "2"))
            maximum = float(environment.get("SECURECODE_WORKER_MAX_BACKOFF_SECONDS", "30"))
            parsed = urlsplit(url)
            default_host = parsed.hostname
            configured_hosts = environment.get("SECURECODE_WORKER_ARTIFACT_HOSTS")
            artifact_hosts = (
                frozenset(
                    item.strip().lower() for item in configured_hosts.split(",") if item.strip()
                )
                if configured_hosts is not None
                else frozenset({default_host})
                if default_host
                else frozenset()
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError("worker configuration is invalid") from None
        if (
            type(url) is not str
            or type(token) is not str
            or len(token) < 32
            or type(worker_id) is not str
            or _OPAQUE_ID.fullmatch(worker_id) is None
            or not target.is_absolute()
            or not target.is_dir()
            or target.is_symlink()
            or (requested_run_id is not None and _OPAQUE_ID.fullmatch(requested_run_id) is None)
            or (
                scm_resolution is not None
                and (
                    any(_OPAQUE_ID.fullmatch(item) is None for item in scm_resolution[:3])
                    or re.fullmatch(r"[0-9a-f]{40}", scm_resolution[3]) is None
                )
            )
            or not 1.0 <= timeout <= 120.0
            or not 0.1 <= poll <= 60.0
            or not poll <= maximum <= 300.0
            or not artifact_hosts
        ):
            raise ValueError("worker configuration is invalid")
        return cls(
            control_plane_url=url,
            token=token,
            worker_id=worker_id,
            target=target,
            requested_run_id=requested_run_id,
            scm_resolution=scm_resolution,
            request_timeout_seconds=timeout,
            poll_seconds=poll,
            max_backoff_seconds=maximum,
            artifact_hosts=artifact_hosts,
        )


def _ci_value(value: str | None) -> str:
    if type(value) is not str or not value:
        raise ValueError("worker CI identity is invalid")
    return value


def _worker_token(environment: Mapping[str, str]) -> str:
    direct = environment.get("SECURECODE_WORKER_TOKEN")
    file_name = environment.get("SECURECODE_WORKER_TOKEN_FILE")
    if (direct is None) == (file_name is None):
        raise ValueError("worker token source is invalid")
    if direct is not None:
        return direct
    if not isinstance(file_name, str):
        raise ValueError("worker token source is invalid")
    try:
        token = read_ascii_secret(Path(file_name), minimum=32, maximum=8192)
    except ValueError:
        raise ValueError("worker token source is invalid") from None
    return token


__all__ = ["RuntimeSettings"]
