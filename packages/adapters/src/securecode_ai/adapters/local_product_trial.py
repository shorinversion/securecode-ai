"""Trial analysis: the full product pipeline without a protected host approval.

``securecode scan`` requires an administrator-protected host approval record that pins a
reviewed provider evidence bundle.  A trial run skips that trust root so a reviewer can run
the same pipeline (deterministic scanners, model-native discovery, Auditor, Skeptic, finding
gate and report) on a checkout with one command.  The host authority is built in memory, so
a trial result is never a publishable or CI-blocking verdict.

Providers:

* ``deepseek`` (default): the owner-authorized DeepSeek profile with reasoning enabled and an
  in-memory spend cap.  Retention and training terms are not verified.
* ``local``: Ollama on 127.0.0.1:11434 through the approved loopback gateway.  Small local
  models often fail the strict Auditor/Skeptic protocol, which ends as ``INDETERMINATE``.
"""

from __future__ import annotations

import http.client
import json
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from securecode_ai.contracts import ComponentPin, EgressPolicyDocument, ProviderProfile
from securecode_ai.core.reports import ReportFormat
from securecode_ai.core.runtime import (
    DEFAULT_STAGE_CATALOGUE_PIN,
    build_default_workflow_definition,
)

from .config import (
    ConfigSource,
    EffectiveConfiguration,
    ProviderProfileRegistry,
    SelectionProvenance,
    parse_provider_profile,
    resolve_environment_credential,
)
from .local_product_host_host import LocalProductHost
from .local_product_runner_config import LocalProductScanResult, resolve_local_product_configuration
from .local_product_runner_execution import _run_local_product_scan
from .local_provider_gateway_server import _running_approved_gateway
from .openai_compatible_remote import REASONING_EFFORTS, OpenAICompatibleRemoteHttpsConnector
from .product_provider_runtime import ApprovedPublicResolver, ProductProviderRuntime
from .product_runtime import PRODUCT_AUDITOR_PROMPT_PIN, PRODUCT_DISCOVERY_PROMPT_PIN
from .product_skeptic import PRODUCT_SKEPTIC_PROMPT_PIN, SKEPTIC_WIRE_PIN
from .remote_provider_budget import InMemoryRemoteProviderBudget, RemoteProviderSpendPolicy

TRIAL_TENANT: Final = "local-trial"
DEEPSEEK_CONSENT_REF: Final = "consent://project-owner/deepseek-private-source/2026-09-27"
DEFAULT_LOCAL_MODEL: Final = "qwen2.5-coder:7b-instruct-q4_K_M"
_GATEWAY_PORT: Final = 18434
_OLLAMA_PORT: Final = 11434
_MODEL_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PURPOSES: Final = ("model_native_discovery", "candidate_investigation", "skeptic_review")
# Off-peak DeepSeek Flash list prices (USD micro-units per million tokens).
_INPUT_PRICE: Final = 150_000
_OUTPUT_PRICE: Final = 600_000
DEEPSEEK_PRICES_PER_MILLION: Final = (_INPUT_PRICE, _OUTPUT_PRICE)


class TrialAnalysisError(ValueError):
    """A trial run could not be configured; the message is safe to show."""


@dataclass(frozen=True, slots=True)
class TrialAnalysis:
    provider: str
    model_id: str
    result: LocalProductScanResult
    cost_microusd: int


def run_trial_analysis(
    target: str,
    *,
    provider: str,
    report_format: ReportFormat,
    environment: Mapping[str, str],
    max_cost_microusd: int = 1_000_000,
) -> TrialAnalysis:
    """Run the full product pipeline on ``target`` with an in-memory trial authority."""

    git = shutil.which("git")
    if git is None:
        raise TrialAnalysisError("git is required")
    git_path = Path(git)
    if provider == "deepseek":
        runtime = _deepseek_runtime(environment, max_cost_microusd)
        costs: list[int] = []
        host = _host(_local_profile(DEFAULT_LOCAL_MODEL, "0" * 64), runtime.policy)
        try:
            result = _run_local_product_scan(
                host,
                target,
                report_format,
                runtime.configuration,
                git_verifier=lambda _digest: git_path,
                provider_runtime=runtime,
                cost_observer=lambda receipt: costs.append(receipt.cost_microunits),
                authority_loader=lambda: host,
            )
        finally:
            runtime.close()
        return TrialAnalysis(provider, runtime.profile.model_id, result, sum(costs))
    if provider == "local":
        model_id = environment.get("SECURECODE_LOCAL_MODEL") or DEFAULT_LOCAL_MODEL
        if _MODEL_ID.fullmatch(model_id) is None:
            raise TrialAnalysisError("SECURECODE_LOCAL_MODEL is invalid")
        version, digest = _ollama_identity(model_id)
        profile = _local_profile(model_id, digest)
        host = _host(profile, _policy(profile, "private_model_zdr", approval=False))
        configuration = resolve_local_product_configuration(host)
        with _running_approved_gateway(host.profile, version):
            result = _run_local_product_scan(
                host,
                target,
                report_format,
                configuration,
                git_verifier=lambda _digest: git_path,
                authority_loader=lambda: host,
            )
        return TrialAnalysis(provider, model_id, result, 0)
    raise TrialAnalysisError("provider must be deepseek or local")


def _fixture(name: str) -> dict[str, object]:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "specs" / "contracts" / name
        if candidate.is_file():
            document = json.loads(candidate.read_text(encoding="utf-8"))
            if isinstance(document, dict):
                return document
    raise TrialAnalysisError("contract fixtures are not installed")


def _base_profile() -> dict[str, object]:
    return _fixture("provider-fixtures/valid.local-openai-compatible.json")


def _local_profile(model_id: str, digest: str) -> ProviderProfile:
    data = _base_profile()
    data.update(model_id=model_id, model_snapshot="sha256:" + digest)
    budgets = data["budgets"]
    endpoint = data["endpoint"]
    assert isinstance(budgets, dict) and isinstance(endpoint, dict)
    budgets["timeout_seconds"] = 30  # The loopback gateway admits at most 30 s.
    endpoint.update(base_url=f"http://127.0.0.1:{_GATEWAY_PORT}/v1", allowed_ports=[_GATEWAY_PORT])
    return parse_provider_profile(json.dumps(data).encode("utf-8"))


def _deepseek_profile(model_id: str) -> ProviderProfile:
    data = _base_profile()
    data.update(
        profile_id="deepseek-owner-authorized",
        provider_kind="openai_compatible_remote",
        execution_boundary="public_external",
        model_id=model_id,
        model_snapshot=None,
        credential_ref="env://DEEPSEEK_API_KEY",
        egress_profiles=["managed_scan_opt_in"],
        protocol_framing_token_upper_bound=4096,
    )
    data["endpoint"] = {
        "base_url": "https://api.deepseek.com",
        "authority": "api.deepseek.com",
        "allowed_ports": [443],
        "follow_redirects": False,
        "local_plaintext_exception": False,
    }
    terms = data["data_terms"]
    capabilities = data["capabilities"]
    budgets = data["budgets"]
    assert isinstance(terms, dict) and isinstance(capabilities, dict)
    assert isinstance(budgets, dict)
    terms.update(
        evidence_status="unverified",
        residency=[],
        retention_seconds=None,
        training_use="unknown",
        zero_data_retention=None,
        evidence_ref=DEEPSEEK_CONSENT_REF,
    )
    # deepseek-flash accepts a 1M-token context and up to 384K output tokens; one run keeps
    # a generous but bounded window.
    # Byte counts stand in for tokens, so a 72 KB file framed as a bounded view needs ~420K;
    # the provider accepts 1M tokens.
    capabilities.update(max_context_tokens=983_040, max_output_tokens=65_536)
    budgets.update(timeout_seconds=300, max_attempts=2, max_total_tokens=1_048_576)
    return parse_provider_profile(json.dumps(data).encode("utf-8"))


def _policy(profile: ProviderProfile, egress: str, *, approval: bool) -> EgressPolicyDocument:
    data = _fixture("policy/fixtures/egress.valid.private-model-source.json")
    data.update(tenant_scope=TRIAL_TENANT, profile=egress, policy_id="trial-analysis")
    rules = data["rules"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    rules[0].update(
        destinations=["profile://" + profile.profile_id],
        purposes=list(_PURPOSES),
        tenant_admin_approval=approval,
    )
    return EgressPolicyDocument.model_validate_json(json.dumps(data))


def _host(profile: ProviderProfile, policy: EgressPolicyDocument) -> LocalProductHost:
    policy_pin = ComponentPin(
        schema_version="0.2.0",
        component_id=policy.policy_id,
        component_version=policy.policy_version,
        content_sha256=policy.canonical_content_hash(),
    )
    manifest = {
        "workflow_sha256": build_default_workflow_definition(
            policy_pin=policy_pin
        ).component_pin.content_sha256,
        "stage_catalogue_sha256": DEFAULT_STAGE_CATALOGUE_PIN.content_sha256,
        "discovery_prompt_sha256": PRODUCT_DISCOVERY_PROMPT_PIN.content_sha256,
        "auditor_prompt_sha256": PRODUCT_AUDITOR_PROMPT_PIN.content_sha256,
        "skeptic_prompt_sha256": PRODUCT_SKEPTIC_PROMPT_PIN.content_sha256,
        "skeptic_schema_sha256": SKEPTIC_WIRE_PIN.content_sha256,
        "git_executable_sha256": "0" * 64,
    }
    trial = "0" * 64  # No protected record exists: the authority digests are explicit zeros.
    return LocalProductHost(
        profile,
        policy,
        ProviderProfileRegistry((profile,)),
        manifest,
        "0.0.0",
        trial,
        trial,
        trial,
        trial,
    )


def _deepseek_runtime(
    environment: Mapping[str, str], max_cost_microusd: int
) -> ProductProviderRuntime:
    key = environment.get("DEEPSEEK_API_KEY")
    if not key:
        raise TrialAnalysisError("DEEPSEEK_API_KEY is not set (environment or .env)")
    model_id = environment.get("DEEPSEEK_MODEL") or "deepseek-flash"
    if _MODEL_ID.fullmatch(model_id) is None:
        raise TrialAnalysisError("DEEPSEEK_MODEL is invalid")
    reasoning = environment.get("DEEPSEEK_REASONING_EFFORT") or "high"
    if reasoning not in REASONING_EFFORTS:
        raise TrialAnalysisError("DEEPSEEK_REASONING_EFFORT must be none, low, high or max")
    profile = _deepseek_profile(model_id)
    policy = _policy(profile, "managed_scan_opt_in", approval=True)
    registry = ProviderProfileRegistry((profile,))
    budget = InMemoryRemoteProviderBudget(
        (
            RemoteProviderSpendPolicy(
                tenant_id=TRIAL_TENANT,
                model_id=model_id,
                window_ms=3_600_000,
                max_calls_per_window=200,
                max_concurrent_calls=4,
                max_tokens_per_window=20_000_000,
                max_cost_microunits_per_window=max_cost_microusd,
                input_cost_microunits_per_million_tokens=_INPUT_PRICE,
                output_cost_microunits_per_million_tokens=_OUTPUT_PRICE,
            ),
        )
    )
    credentials = {"DEEPSEEK_API_KEY": key}
    configuration = EffectiveConfiguration(
        provider_profile=profile,
        policy_profile_id=policy.policy_id,
        egress_profile=policy.profile,
        provenance=(
            SelectionProvenance("egress_profile", ConfigSource.APPROVED_REGISTRY),
            SelectionProvenance("policy_profile", ConfigSource.APPROVED_REGISTRY),
            SelectionProvenance("provider_profile", ConfigSource.APPROVED_REGISTRY),
        ),
    )
    return ProductProviderRuntime(
        profile=profile,
        policy=policy,
        configuration=configuration,
        registry=registry,
        resolver=ApprovedPublicResolver(),
        connector=OpenAICompatibleRemoteHttpsConnector(
            profile=profile, spend_budget=budget, reasoning_effort=reasoning
        ),
        credential_supplier=lambda selected: resolve_environment_credential(
            selected, credentials, registry=registry
        ),
        spend_budget=budget,
    )


def _ollama_identity(model_id: str) -> tuple[str, str]:
    """Read the Ollama version and the exact model digest over literal loopback."""

    def get(path: str) -> dict[str, object]:
        connection = http.client.HTTPConnection("127.0.0.1", _OLLAMA_PORT, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read(1_048_576)
            if response.status != 200:
                raise TrialAnalysisError("Ollama is not answering on 127.0.0.1:11434")
            document = json.loads(body)
            if not isinstance(document, dict):
                raise ValueError
            return document
        except TrialAnalysisError:
            raise
        except Exception:
            raise TrialAnalysisError("Ollama is not running on 127.0.0.1:11434") from None
        finally:
            connection.close()

    version = get("/api/version").get("version")
    models = get("/api/tags").get("models")
    if not isinstance(version, str) or not isinstance(models, list):
        raise TrialAnalysisError("Ollama returned an unexpected answer")
    for model in models:
        if isinstance(model, dict) and model.get("name") == model_id:
            digest = model.get("digest")
            if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
                return version.split("-")[0], digest
    raise TrialAnalysisError(f"model {model_id} is not pulled; run: ollama pull {model_id}")


__all__ = [
    "DEEPSEEK_PRICES_PER_MILLION",
    "DEFAULT_LOCAL_MODEL",
    "TrialAnalysis",
    "TrialAnalysisError",
    "run_trial_analysis",
]
