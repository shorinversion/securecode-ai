"""Installed product-scan dispatch, separate from legacy injected repair receipts."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from securecode_ai.adapters.local_product_host import (
    LocalProductHost,
    LocalProductHostError,
    load_local_product_host,
)
from securecode_ai.adapters.local_product_runner import (
    LocalProductConfigurationError,
    LocalProductScanResult,
    resolve_local_product_configuration,
    run_local_product_scan,
)
from securecode_ai.adapters.local_provider_gateway_server import (
    _ApprovedGatewayLifecycleError,
    _running_approved_gateway,
    gateway_observation_path,
)
from securecode_ai.adapters.product_provider_runtime import (
    ProductProviderConfigurationError,
    ProductProviderRuntime,
    load_product_provider_runtime,
)
from securecode_ai.core.classification import FindingSeverity
from securecode_ai.core.reports import ReportFormat

from .repair import RepairFormat


class ProductScanConfigurationError(ValueError):
    pass


class ProductScanUnavailableError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProductScanArguments:
    target: str
    report_format: RepairFormat
    output: Path | None
    config: Path | None = None
    fail_on: FindingSeverity | None = None


def parse_product_scan(tokens: tuple[str, ...]) -> ProductScanArguments:
    if not tokens or tokens[0] != "scan":
        raise ProductScanConfigurationError()
    target: str | None = None
    report_format = RepairFormat.JSON
    output: Path | None = None
    config: Path | None = None
    fail_on: FindingSeverity | None = None
    format_selected = False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--format":
            index += 1
            if index >= len(tokens) or format_selected:
                raise ProductScanConfigurationError()
            try:
                report_format = RepairFormat(tokens[index])
            except ValueError:
                raise ProductScanConfigurationError() from None
            if report_format is RepairFormat.DIFF:
                raise ProductScanConfigurationError()
            format_selected = True
        elif token == "--config":
            index += 1
            if index >= len(tokens) or config is not None or not tokens[index]:
                raise ProductScanConfigurationError()
            config = Path(tokens[index])
        elif token == "--output":
            index += 1
            if index >= len(tokens) or output is not None or not tokens[index]:
                raise ProductScanConfigurationError()
            output = Path(tokens[index])
        elif token == "--fail-on":
            index += 1
            if index >= len(tokens) or fail_on is not None:
                raise ProductScanConfigurationError()
            try:
                fail_on = FindingSeverity(tokens[index].upper())
            except ValueError:
                raise ProductScanConfigurationError() from None
        elif token.startswith("-") or target is not None or not token:
            raise ProductScanConfigurationError()
        else:
            target = token
        index += 1
    if target is None:
        raise ProductScanConfigurationError()
    return ProductScanArguments(target, report_format, output, config, fail_on)


def _selection_file(path: Path, *, optional: bool = False) -> dict[str, object]:
    try:
        if optional and not path.exists():
            return {}
        with path.open("rb") as selection:
            raw = selection.read(16385)
        if len(raw) > 16384 or b"\x00" in raw:
            raise ProductScanConfigurationError()

        def closed(pairs: list[tuple[str, object]]) -> dict[str, object]:
            document: dict[str, object] = {}
            for key, value in pairs:
                if key in document:
                    raise ProductScanConfigurationError()
                document[key] = value
            return document

        document = json.loads(raw.decode("utf-8"), object_pairs_hook=closed)
        if type(document) is not dict:
            raise ProductScanConfigurationError()
        return document
    except ProductScanConfigurationError:
        raise
    except Exception:
        raise ProductScanConfigurationError() from None


def execute_installed_product_scan(
    arguments: ProductScanArguments,
    *,
    environment: Mapping[str, str],
) -> LocalProductScanResult:
    # Approval protection and admission precede all lower-trust config reads.
    host = load_installed_product_host()
    return _execute_installed_product_scan(
        arguments,
        environment=environment,
        host=host,
        gateway_already_running=False,
    )


def _execute_installed_product_scan(
    arguments: ProductScanArguments,
    *,
    environment: Mapping[str, str],
    host: LocalProductHost,
    gateway_already_running: bool,
) -> LocalProductScanResult:
    if type(host) is not LocalProductHost or type(gateway_already_running) is not bool:
        raise ProductScanUnavailableError()
    repository = _selection_file(Path(arguments.target) / "securecode.json", optional=True)
    if os.name == "nt":
        user_root = environment.get("APPDATA")
        user_path = Path(user_root) / "SecureCodeAI" / "config.json" if user_root else None
    else:
        user_root = environment.get("XDG_CONFIG_HOME")
        user_path = (
            (Path(user_root) if user_root else Path.home() / ".config")
            / "securecode-ai"
            / "config.json"
        )
    user = _selection_file(user_path, optional=True) if user_path is not None else {}
    cli = _selection_file(arguments.config) if arguments.config is not None else {}
    try:
        provider_runtime: ProductProviderRuntime | None = None
        if _remote_provider_requested(host, environment):
            provider_runtime = load_product_provider_runtime(
                profile_path=environment.get("SECURECODE_REMOTE_PROFILE_FILE", ""),
                policy_path=environment.get("SECURECODE_REMOTE_POLICY_FILE", ""),
                environment=environment,
                tenant_id=environment.get("SECURECODE_REMOTE_TENANT_ID", ""),
                expected_profile_sha256=environment.get("SECURECODE_REMOTE_PROFILE_SHA256"),
                expected_policy_sha256=environment.get("SECURECODE_REMOTE_POLICY_SHA256"),
                expected_egress_sha256=environment.get("SECURECODE_REMOTE_EGRESS_SHA256"),
                expected_configuration_sha256=environment.get(
                    "SECURECODE_REMOTE_CONFIGURATION_SHA256"
                ),
            )
            configuration = provider_runtime.configuration
        else:
            configuration = resolve_local_product_configuration(
                host,
                user=user,
                repository=repository,
                environment=environment,
                cli=cli,
            )
        if provider_runtime is not None:
            try:
                return run_local_product_scan(
                    host=host,
                    target=arguments.target,
                    report_format=ReportFormat(arguments.report_format.value),
                    configuration=configuration,
                    provider_runtime=provider_runtime,
                )
            finally:
                provider_runtime.close()
        if gateway_already_running:
            return run_local_product_scan(
                host=host,
                target=arguments.target,
                report_format=ReportFormat(arguments.report_format.value),
                configuration=configuration,
            )
        with _running_approved_gateway(
            host.profile,
            host.ollama_version,
            observation_path=gateway_observation_path(environment),
        ):
            return run_local_product_scan(
                host=host,
                target=arguments.target,
                report_format=ReportFormat(arguments.report_format.value),
                configuration=configuration,
            )
    except LocalProductConfigurationError:
        raise ProductScanConfigurationError() from None
    except ProductProviderConfigurationError:
        raise ProductScanConfigurationError() from None
    except _ApprovedGatewayLifecycleError:
        raise ProductScanUnavailableError() from None


def load_installed_product_host() -> LocalProductHost:
    """Keep the platform trust-root call at the installed scan boundary."""

    try:
        return load_local_product_host()
    except LocalProductHostError:
        raise ProductScanUnavailableError() from None


def _remote_provider_requested(host: LocalProductHost, environment: Mapping[str, str]) -> bool:
    if (
        any(
            environment.get(name)
            for name in (
                "SECURECODE_REMOTE_PROFILE_FILE",
                "SECURECODE_REMOTE_POLICY_FILE",
                "SECURECODE_REMOTE_SPEND_DB",
            )
        )
        or environment.get("SECURECODE_REMOTE_PROVIDER") == "1"
    ):
        return True
    selector = environment.get("SECURECODE_PROVIDER_PROFILE")
    return selector is not None and selector != host.profile.selector


__all__ = [
    "ProductScanArguments",
    "ProductScanConfigurationError",
    "ProductScanUnavailableError",
    "load_installed_product_host",
    "parse_product_scan",
]
