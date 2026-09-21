"""Validated non-secret runtime settings for the server process."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    host: str
    port: int
    data_dir: str
    tmp_dir: str
    tls_cert_file: str | None = None
    tls_key_file: str | None = None


def load_settings(environment: Mapping[str, str] | None = None) -> RuntimeSettings:
    values = os.environ if environment is None else environment
    host = values.get("SECURECODE_SERVER_HOST", "127.0.0.1")
    port_text = values.get("SECURECODE_SERVER_PORT", "8080")
    data_dir = values.get("SECURECODE_DATA_DIR", "/var/lib/securecode")
    tmp_dir = values.get("SECURECODE_TMP_DIR", "/tmp/securecode")
    tls_cert_file = values.get("SECURECODE_TLS_CERT_FILE")
    tls_key_file = values.get("SECURECODE_TLS_KEY_FILE")
    tls_configured = tls_cert_file is not None and tls_key_file is not None
    if (
        host not in {"127.0.0.1", "0.0.0.0"}
        or not port_text.isascii()
        or not port_text.isdigit()
        or not 1 <= int(port_text) <= 65_535
        or not _absolute_clean_path(data_dir)
        or not _absolute_clean_path(tmp_dir)
        or data_dir == tmp_dir
        or (tls_cert_file is None) != (tls_key_file is None)
        or (
            tls_configured
            and (
                not _absolute_clean_path(tls_cert_file)
                or not _absolute_clean_path(tls_key_file)
                or tls_cert_file == tls_key_file
            )
        )
        or (host == "0.0.0.0" and not tls_configured)
    ):
        raise ValueError("runtime environment is invalid")
    return RuntimeSettings(
        host,
        int(port_text),
        data_dir,
        tmp_dir,
        tls_cert_file,
        tls_key_file,
    )


def _absolute_clean_path(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("/")
        and "\x00" not in value
        and "//" not in value
        and all(part not in {".", ".."} for part in value.split("/"))
    )


__all__ = ["RuntimeSettings", "load_settings"]
