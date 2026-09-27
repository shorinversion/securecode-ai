"""Executable control-plane HTTP service with graceful shutdown."""

from __future__ import annotations

import asyncio
import os
import signal
import ssl
import stat
import sys
from argparse import ArgumentParser
from collections.abc import Sequence
from pathlib import Path

from .bootstrap import build_local_app
from .http_server import AsgiHttpServer
from .runtime import RuntimeSettings, load_settings


async def serve() -> None:
    settings = load_settings()
    app = build_local_app(settings)
    server = AsgiHttpServer(app)
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    for value in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(value, stopping.set)
        except (NotImplementedError, RuntimeError):
            signal.signal(value, lambda *_args: loop.call_soon_threadsafe(stopping.set))
    try:
        await server.start(
            settings.host,
            settings.port,
            ssl_context=_tls_context(settings),
        )
        await stopping.wait()
    finally:
        await server.stop()


def _parser() -> ArgumentParser:
    return ArgumentParser(
        prog="securecode-server",
        description="Run the SecureCode AI control-plane HTTP service.",
    )


def _tls_context(settings: RuntimeSettings) -> ssl.SSLContext | None:
    cert_file = settings.tls_cert_file
    key_file = settings.tls_key_file
    if cert_file is None and key_file is None:
        return None
    if type(cert_file) is not str or type(key_file) is not str:
        raise ValueError("TLS configuration is invalid")
    certificate = Path(cert_file)
    private_key = Path(key_file)
    try:
        key_details = private_key.stat(follow_symlinks=False)
        cert_details = certificate.stat(follow_symlinks=False)
        if (
            certificate.is_symlink()
            or private_key.is_symlink()
            or not stat.S_ISREG(cert_details.st_mode)
            or not stat.S_ISREG(key_details.st_mode)
            or cert_details.st_size > 1_048_576
            or not 1 <= key_details.st_size <= 65_536
            or (os.name == "posix" and key_details.st_mode & 0o077)
        ):
            raise ValueError("TLS configuration is invalid")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_COMPRESSION
        context.load_cert_chain(certificate, private_key)
        return context
    except (OSError, ssl.SSLError):
        raise ValueError("TLS configuration is invalid") from None


def main(argv: Sequence[str] | None = None) -> int:
    _parser().parse_args(sys.argv[1:] if argv is None else argv)
    asyncio.run(serve())
    return 0


if __name__ == "__main__":
    main()
