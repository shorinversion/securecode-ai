"""Closed recognition of explicit Docker Desktop VM isolation evidence."""

from __future__ import annotations

import re

_ECI_MARKER = re.compile(
    r"(?:name=)?enhanced[-_ ]?container[-_ ]?isolation(?:[,;]enabled=true)?\Z",
    re.IGNORECASE,
)


def daemon_has_desktop_vm_isolation(
    info: dict[str, object], options: tuple[str, ...], *, windows_host: bool
) -> bool:
    operating_system = info.get("OperatingSystem")
    return (
        windows_host
        and type(operating_system) is str
        and "docker desktop" in operating_system.casefold()
        and info.get("OSType") == "linux"
        and any(_ECI_MARKER.fullmatch(item.strip()) for item in options)
    )


def container_has_required_hardening(inspected: dict[str, object]) -> bool:
    host = inspected.get("HostConfig")
    config = inspected.get("Config")
    if type(host) is not dict or type(config) is not dict:
        return False
    security = host.get("SecurityOpt")
    cap_drop = host.get("CapDrop")
    return (
        config.get("User") == "65532:65532"
        and host.get("NetworkMode") == "none"
        and host.get("ReadonlyRootfs") is True
        and host.get("Privileged") is False
        and type(host.get("PidsLimit")) is int
        and host["PidsLimit"] > 0
        and type(host.get("Memory")) is int
        and host["Memory"] > 0
        and host.get("MemorySwap") == host["Memory"]
        and type(host.get("NanoCpus")) is int
        and host["NanoCpus"] > 0
        and type(cap_drop) is list
        and any(type(item) is str and item.casefold() == "all" for item in cap_drop)
        and type(security) is list
        and any(
            type(item) is str and item.casefold() == "no-new-privileges:true" for item in security
        )
    )


def verified_container_not_found(arguments: tuple[str, ...], stderr: bytes) -> bool:
    if len(arguments) != 3 or arguments[:2] != ("container", "inspect"):
        return False
    name = arguments[2]
    try:
        message = stderr.decode("utf-8", errors="strict").strip()
    except UnicodeError:
        return False
    return message in {
        f"Error: No such container: {name}",
        f"Error: No such object: {name}",
        f"Error response from daemon: No such container: {name}",
        f"Error response from daemon: No such object: {name}",
    }


__all__ = [
    "container_has_required_hardening",
    "daemon_has_desktop_vm_isolation",
    "verified_container_not_found",
]
