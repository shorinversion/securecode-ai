"""Installed host-owned private-source Core composition.

The OS approval loader is the sole production authority entry point. This module
does not provision approval, promote evidence, start providers or scan worktree
file contents. Scripted peers can test plumbing, not provider qualification.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import subprocess
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Final

from securecode_ai.contracts import (
    ArtifactRef,
    ComponentPin,
    DataClass,
)
from securecode_ai.core.evidence_graph import EvidenceGraph

from .config import ConfigError, EffectiveConfiguration, resolve_configuration
from .local_product_host import (
    LocalProductHost,
)
from .product_audit import (
    GitProductAuditStateProbe,
    ProductAuditComposition,
)

_CREATE_NO_WINDOW: Final[int] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_GIT_EXIT_TIMEOUT_SECONDS: Final[float] = 2.0
_MAX_REPAIR_SUMMARY_BYTES: Final[int] = 1_048_576


class LocalProductConfigurationError(ValueError):
    """Closed invalid selector or whole-revision boundary."""


class LocalProductUnavailableError(ValueError):
    """Closed missing authority or incomplete execution."""


class LocalProductCancelledError(ValueError):
    """Closed cancellation observed before publication."""


class LocalProductSupersededError(ValueError):
    """Closed obsolete immutable revision."""


@dataclass(frozen=True, slots=True)
class LocalProductScanResult:
    composition: ProductAuditComposition
    rendered: bytes
    sarif_rendered: bytes
    exit_code: int
    state_probe: GitProductAuditStateProbe
    graph_artifact: bytes
    model_tokens: int
    model_cost_microunits: int
    cancel: Callable[[], None]

    def require_publication(self) -> None:
        observed = self.state_probe.observe(
            run_id=self.composition.run.run_id,
            execution_identity=self.composition.run.execution_identity,
        )
        if observed.cancelled:
            raise LocalProductCancelledError()
        if (
            observed.current_head_sha
            != self.composition.run.execution_identity.repository_revision.head_sha
        ):
            raise LocalProductSupersededError()
        if not observed.reporting_allowed:
            raise LocalProductUnavailableError()


@dataclass(frozen=True, slots=True)
class LocalProductRepairResult:
    """Source-free result of the optional suggestion-only repair sidecar."""

    summary: bytes
    exit_code: int
    model_tokens: int = 0
    model_cost_microunits: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.summary) is not bytes
            or not self.summary
            or len(self.summary) > _MAX_REPAIR_SUMMARY_BYTES
            or type(self.exit_code) is not int
            or self.exit_code not in {0, 2}
            or type(self.model_tokens) is not int
            or self.model_tokens < 0
            or type(self.model_cost_microunits) is not int
            or self.model_cost_microunits < 0
        ):
            raise LocalProductConfigurationError()


def _pin(name: str, version: str, digest: str) -> ComponentPin:
    return ComponentPin(
        schema_version="0.2.0", component_id=name, component_version=version, content_sha256=digest
    )


def _hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def _retain_evidence_graph(
    *, graph: EvidenceGraph, tenant_id: str, head_sha: str
) -> tuple[bytes, ArtifactRef]:
    """Bind finding metadata to the exact canonical graph retained for the run."""
    if (
        type(graph) is not EvidenceGraph
        or type(graph.graph_id) is not str
        or not graph.graph_id
        or graph.tenant_id != tenant_id
        or graph.head_sha != head_sha
    ):
        raise LocalProductUnavailableError()
    try:
        graph_bytes = json.dumps(
            graph.canonical_payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if hashlib.sha256(graph_bytes).hexdigest() != graph.graph_sha256:
            raise ValueError
        return (
            graph_bytes,
            ArtifactRef(
                schema_version="0.2.0",
                tenant_id=tenant_id,
                content_id=graph.graph_id,
                content_sha256=graph.graph_sha256,
                size_bytes=len(graph_bytes),
                data_class=DataClass.CONFIDENTIAL_SECURITY,
            ),
        )
    except (TypeError, ValueError):
        raise LocalProductUnavailableError() from None


class _LiteralLoopbackResolver:
    def resolve(self, authority: str, port: int) -> tuple[str, ...]:
        address = ipaddress.ip_address(authority)
        if not address.is_loopback:
            raise ValueError("local endpoint unavailable")
        return (str(address),)


def _git(
    checkout: Path,
    executable: Path,
    *arguments: str,
    cancelled: Callable[[], bool] | None = None,
) -> str:
    if cancelled is not None and not callable(cancelled):
        raise LocalProductConfigurationError()
    env = {
        key: os.environ[key]
        for key in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")
        if key in os.environ
    }
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_COUNT="0",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_OPTIONAL_LOCKS="0",
        GIT_NO_LAZY_FETCH="1",
        GIT_ALLOW_PROTOCOL="",
    )
    command = [
        str(executable),
        "--no-pager",
        "--no-replace-objects",
        "--no-optional-locks",
        "-C",
        str(checkout),
        *arguments,
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        creationflags=_CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    deadline = monotonic() + 10.0
    try:
        while True:
            if cancelled is not None and cancelled():
                _stop_git_process(process)
                raise LocalProductCancelledError()
            remaining = deadline - monotonic()
            if remaining <= 0:
                _stop_git_process(process)
                raise subprocess.TimeoutExpired(command, 10.0)
            try:
                output, _ = process.communicate(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            _stop_git_process(process)
    if process.returncode or output is None or len(output) > 65536:
        raise LocalProductUnavailableError()
    return output.decode("utf-8").strip()


def _stop_git_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        with suppress(OSError):
            process.kill()
    try:
        process.communicate(timeout=_GIT_EXIT_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            with suppress(OSError):
                process.kill()
        try:
            process.communicate(timeout=_GIT_EXIT_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            raise LocalProductUnavailableError() from None


def resolve_local_product_configuration(
    host: LocalProductHost,
    *,
    user: Mapping[str, object] | None = None,
    repository: Mapping[str, object] | None = None,
    environment: Mapping[str, str] | None = None,
    cli: Mapping[str, object] | None = None,
) -> EffectiveConfiguration:
    try:
        selected = resolve_configuration(
            registry=host.registry,
            defaults={
                "provider_profile": host.profile.selector,
                "policy_profile": host.policy.policy_id,
                "egress_profile": host.policy.profile.value,
            },
            user=user,
            repository=repository,
            environment=environment,
            cli=cli,
        )
        if (
            selected.provider_profile != host.profile
            or selected.policy_profile_id != host.policy.policy_id
            or selected.egress_profile is not host.policy.profile
        ):
            raise LocalProductConfigurationError()
        return selected
    except ConfigError:
        raise LocalProductConfigurationError() from None
