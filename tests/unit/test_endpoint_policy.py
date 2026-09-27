"""Connect-time endpoint authorization and SSRF/rebinding tests for P1.8."""

from __future__ import annotations

import copy
import json
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import replace

import pytest
import securecode_ai.adapters as adapter_package
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    ConnectedChannel,
    CredentialLease,
    EndpointAuthorizationIssuer,
    EndpointError,
    HmacContentIdentifier,
    JsonObjectValidator,
    PreparedModelContext,
    ProviderAttempt,
    ProviderAttemptBinding,
    ProviderProfileRegistry,
    ProviderStreamState,
    resolve_environment_credential,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    DataClass,
    EgressContentRef,
    EgressManifest,
    EgressPolicyDocument,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ProviderProfile,
)
from securecode_ai.core import (
    EgressPolicyRegistry,
    ModelAuthorizationIssuer,
    PreflightEligibility,
    canonical_model_request_hash,
)

from .test_provider_preflight import (
    POLICIES,
    _issuer,
    _policy,
    _preflight_request,
    _profile,
    _request,
    _semantic_cases,
)


class ScriptedResolver:
    def __init__(self, *answers: tuple[str, ...]) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, int]] = []

    def resolve(self, authority: str, port: int) -> tuple[str, ...]:
        self.calls.append((authority, port))
        if not self.answers:
            raise RuntimeError("resolver script exhausted")
        return self.answers.pop(0)


class ExplodingProviderRegistry:
    def require_registered(self, supplied: ProviderProfile) -> ProviderProfile:
        del supplied
        raise RuntimeError("registry failure canary")


def _remote_source_profile() -> ProviderProfile:
    data = _profile("valid.local-openai-compatible.json").model_dump(mode="json")
    data.update(
        {
            "profile_id": "remote-source",
            "provider_kind": "openai_compatible_remote",
            "execution_boundary": "private_tenant_endpoint",
            "credential_ref": "env://REMOTE_SOURCE_KEY",
            "protocol_framing_token_upper_bound": 8192,
            "endpoint": {
                "base_url": "https://models.example.com/v1",
                "authority": "models.example.com",
                "allowed_ports": [443],
                "follow_redirects": False,
                "local_plaintext_exception": False,
            },
        }
    )
    data["data_terms"].update(
        {
            "evidence_status": "verified",
            "residency": ["tenant-region"],
            "training_use": "none_verified",
            "evidence_ref": "evidence://provider-terms/remote-source",
        }
    )
    return ProviderProfile.model_validate(data)


def _remote_policy() -> EgressPolicyDocument:
    data = json.loads((POLICIES / "egress.valid.private-model-source.json").read_bytes())
    data["policy_id"] = "private-remote-source"
    data["rules"][0]["destinations"] = ["profile://remote-source"]
    return EgressPolicyDocument.model_validate_json(json.dumps(data, sort_keys=True))


def _pre_send(profile: ProviderProfile, policy: EgressPolicyDocument):  # type: ignore[no-untyped-def]
    case = dict(_semantic_cases()[0])
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    issuer = _issuer(profile, policy)
    pre = issuer.authorize_pre_context(
        _preflight_request(request, case), profile=profile, policy=policy
    )
    manifest = EgressManifest.build(
        model_request=request,
        policy=request.execution_identity.policy,
        destination=f"profile://{profile.profile_id}",
        payload_content_id="kid:endpoint-payload-1",
        content=(
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:endpoint-content-1",
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        ),
        applied_transforms=("bounded_repository_view",),
        byte_count=1024,
    )
    return issuer, issuer.authorize_pre_send(pre, manifest)


def _endpoint_issuer(profile: ProviderProfile) -> EndpointAuthorizationIssuer:
    return EndpointAuthorizationIssuer(provider_registry=ProviderProfileRegistry((profile,)))


def test_remote_endpoint_binds_all_addresses_and_peer_before_use() -> None:
    profile = _remote_source_profile()
    model_issuer, pre_send = _pre_send(profile, _remote_policy())
    resolver = ScriptedResolver(
        ("93.184.216.34", "1.1.1.1"),
        ("1.1.1.1", "93.184.216.34"),
    )
    endpoint_issuer = _endpoint_issuer(profile)
    endpoint = endpoint_issuer.authorize(
        pre_send,
        model_issuer=model_issuer,
        profile=profile,
        resolver=resolver,
        now=100.0,
    )
    assert endpoint.connect_addresses == ("1.1.1.1", "93.184.216.34")
    assert endpoint.authority == "models.example.com"
    assert endpoint.port == 443
    verified = endpoint_issuer.verify_peer(
        endpoint,
        connected_peer="93.184.216.34",
        resolver=resolver,
        now=101.0,
    )
    with pytest.raises(AttributeError, match="immutable"):
        verified._peer_ip = "10.0.0.1"
    claim = endpoint_issuer.consume_verified(verified)
    assert claim["peer_ip"] == "93.184.216.34"
    assert claim["manifest_hash"] == pre_send.manifest_hash
    with pytest.raises(EndpointError):
        endpoint_issuer.consume_verified(verified)


@pytest.mark.parametrize(
    "answers",
    [
        (),
        ("127.0.0.1",),
        ("10.0.0.1",),
        ("169.254.169.254",),
        ("::1",),
        ("fe80::1",),
        ("::ffff:127.0.0.1",),
        ("fe80::1%25eth0",),
        ("2130706433",),
        ("93.184.216.34", "10.0.0.1"),
    ],
)
def test_remote_endpoint_rejects_empty_or_any_unsafe_resolution(
    answers: tuple[str, ...],
) -> None:
    profile = _remote_source_profile()
    model_issuer, pre_send = _pre_send(profile, _remote_policy())
    with pytest.raises(EndpointError):
        _endpoint_issuer(profile).authorize(
            pre_send,
            model_issuer=model_issuer,
            profile=profile,
            resolver=ScriptedResolver(answers),
            now=100.0,
        )


def test_dns_rebinding_and_peer_mismatch_reject_before_verified_claim() -> None:
    profile = _remote_source_profile()
    model_issuer, pre_send = _pre_send(profile, _remote_policy())
    resolver = ScriptedResolver(("93.184.216.34",), ("10.0.0.1",))
    endpoint_issuer = _endpoint_issuer(profile)
    endpoint = endpoint_issuer.authorize(
        pre_send,
        model_issuer=model_issuer,
        profile=profile,
        resolver=resolver,
        now=100.0,
    )
    with pytest.raises(EndpointError):
        endpoint_issuer.verify_peer(
            endpoint,
            connected_peer="93.184.216.34",
            resolver=resolver,
            now=101.0,
        )

    model_issuer, pre_send = _pre_send(profile, _remote_policy())
    resolver = ScriptedResolver(("93.184.216.34",), ("93.184.216.34",))
    endpoint_issuer = _endpoint_issuer(profile)
    endpoint = endpoint_issuer.authorize(
        pre_send,
        model_issuer=model_issuer,
        profile=profile,
        resolver=resolver,
        now=100.0,
    )
    with pytest.raises(EndpointError):
        endpoint_issuer.verify_peer(
            endpoint,
            connected_peer="1.1.1.1",
            resolver=resolver,
            now=101.0,
        )


def test_local_exact_literal_skips_dns_and_allows_only_that_peer() -> None:
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    model_issuer, pre_send = _pre_send(profile, policy)
    resolver = ScriptedResolver()
    endpoint_issuer = _endpoint_issuer(profile)
    endpoint = endpoint_issuer.authorize(
        pre_send,
        model_issuer=model_issuer,
        profile=profile,
        resolver=resolver,
        now=100.0,
    )
    assert resolver.calls == []
    assert endpoint.connect_addresses == ("127.0.0.1",)
    verified = endpoint_issuer.verify_peer(
        endpoint,
        connected_peer="127.0.0.1",
        resolver=resolver,
        now=101.0,
    )
    assert endpoint_issuer.consume_verified(verified)["peer_ip"] == "127.0.0.1"
    assert resolver.calls == []


def test_endpoint_authorizations_are_single_use_cross_issuer_safe_and_expiring() -> None:
    profile = _remote_source_profile()
    model_issuer, pre_send = _pre_send(profile, _remote_policy())
    resolver = ScriptedResolver(("93.184.216.34",), ("93.184.216.34",))
    first = _endpoint_issuer(profile)
    second = _endpoint_issuer(profile)
    endpoint = first.authorize(
        pre_send,
        model_issuer=model_issuer,
        profile=profile,
        resolver=resolver,
        now=100.0,
    )
    with pytest.raises(EndpointError):
        second.verify_peer(
            endpoint,
            connected_peer="93.184.216.34",
            resolver=resolver,
            now=101.0,
        )
    with pytest.raises(TypeError):
        copy.copy(endpoint)
    with pytest.raises(TypeError):
        copy.deepcopy(endpoint)
    with pytest.raises(AttributeError, match="immutable"):
        endpoint._addresses = ("10.0.0.1",)
    with pytest.raises(EndpointError):
        first.verify_peer(
            endpoint,
            connected_peer="93.184.216.34",
            resolver=resolver,
            now=1000.0,
        )


def test_model_pre_send_authorization_cannot_be_reused_for_reconnect() -> None:
    profile = _remote_source_profile()
    model_issuer, pre_send = _pre_send(profile, _remote_policy())
    first = _endpoint_issuer(profile)
    first.authorize(
        pre_send,
        model_issuer=model_issuer,
        profile=profile,
        resolver=ScriptedResolver(("93.184.216.34",)),
        now=100.0,
    )
    with pytest.raises(EndpointError):
        first.authorize(
            pre_send,
            model_issuer=model_issuer,
            profile=profile,
            resolver=ScriptedResolver(("93.184.216.34",)),
            now=101.0,
        )


class SpyChannel:
    def __init__(self, peer_ip: str) -> None:
        self.peer_ip = peer_ip


class SpyConnector:
    def __init__(self, *, peer_ip: str, attempt: ProviderAttempt | None = None) -> None:
        self.peer_ip = peer_ip
        self.attempt = attempt
        self.events: list[str] = []
        self.application_bytes = 0

    def connect(
        self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
    ) -> SpyChannel:
        del ip_address, port, server_name, timeout_ms
        self.events.append("connect")
        return SpyChannel(self.peer_ip)

    def send(
        self,
        channel: ConnectedChannel,
        *,
        credential: str | None,
        payload: bytes,
        model_id: str,
        timeout_ms: int,
        binding: ProviderAttemptBinding,
        call_budget: object,
    ) -> ProviderAttempt:
        del channel, credential, model_id, timeout_ms, call_budget
        self.events.append("send")
        self.application_bytes += len(payload)
        if self.attempt is None:
            raise RuntimeError("no scripted attempt")
        return replace(self.attempt, binding=binding)


def _remote_context(request: ModelRequest) -> PreparedModelContext:
    return PreparedModelContext(
        payload=b'{"bounded":"source"}',
        content=(
            EgressContentRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id="kid:harness-source-1",
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            ),
        ),
        applied_transforms=("bounded_repository_view",),
        request_id=request.request_id,
        tenant_id=request.tenant_id,
        content_identifier=HmacContentIdentifier(b"c" * 32),
    )


def _success_attempt(request: ModelRequest, profile: ProviderProfile) -> ProviderAttempt:
    body = json.dumps(
        {
            "id": "chatcmpl_safe",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": '{"candidates":[]}', "refusal": None},
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return ProviderAttempt(
        dialect=profile.api_dialect,
        http_status=200,
        response_bytes=body,
        transport_failure=None,
        stream_state=ProviderStreamState.COMPLETE,
        binding=ProviderAttemptBinding(
            request_hash=canonical_model_request_hash(request),
            profile_hash=profile.canonical_content_hash(),
            policy_hash="c" * 64,
            manifest_hash="d" * 64,
            attempt=request.attempt,
        ),
        elapsed_ms=20,
    )


@pytest.mark.parametrize(
    "policy_name",
    ["egress.valid.metadata-external.json", "egress.valid.air-gap.json"],
)
def test_harness_preflight_denial_invokes_no_context_credential_dns_or_connector(
    policy_name: str,
) -> None:
    case = _semantic_cases()[1]
    profile = _profile("valid.remote-openai.json")
    policy = _policy(policy_name)
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    model_issuer = _issuer(profile, policy)
    endpoint_issuer = _endpoint_issuer(profile)
    resolver = ScriptedResolver(("93.184.216.34",))
    connector = SpyConnector(peer_ip="93.184.216.34")
    calls = {"context": 0, "credential": 0}

    def context_builder() -> PreparedModelContext:
        calls["context"] += 1
        return _remote_context(request)

    def credential_supplier(profile: ProviderProfile) -> None:
        del profile
        calls["credential"] += 1
        raise AssertionError("credential lookup must not run")

    outcome = AuthorizedProviderHarness(
        model_issuer=model_issuer,
        endpoint_issuer=endpoint_issuer,
    ).execute_remote(
        preflight=_preflight_request(request, case),
        profile=profile,
        policy=policy,
        context_builder=context_builder,
        resolver=resolver,
        connector=connector,
        credential_supplier=credential_supplier,
        validator=JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"k" * 32),
            required_keys=("candidates",),
        ),
        now=100.0,
    )
    assert outcome.preflight.required_terminal_outcome is not None
    assert outcome.preflight.required_terminal_outcome.value == "INDETERMINATE"
    assert outcome.result is None
    assert calls == {"context": 0, "credential": 0}
    assert resolver.calls == []
    assert connector.events == []
    assert connector.application_bytes == 0


def test_harness_evaluator_exception_invokes_no_context_or_io() -> None:
    case = _semantic_cases()[0]
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    model_issuer = ModelAuthorizationIssuer(
        provider_registry=ExplodingProviderRegistry(),
        policy_registry=EgressPolicyRegistry((policy,)),
    )
    resolver = ScriptedResolver()
    connector = SpyConnector(peer_ip="127.0.0.1")
    calls = {"context": 0, "credential": 0}

    def context_builder() -> PreparedModelContext:
        calls["context"] += 1
        return _remote_context(request)

    def credential_supplier(selected: ProviderProfile) -> CredentialLease | None:
        del selected
        calls["credential"] += 1
        raise AssertionError("evaluator failure must precede credential lookup")

    outcome = AuthorizedProviderHarness(
        model_issuer=model_issuer,
        endpoint_issuer=_endpoint_issuer(profile),
    ).execute_remote(
        preflight=_preflight_request(request, case),
        profile=profile,
        policy=policy,
        context_builder=context_builder,
        resolver=resolver,
        connector=connector,
        credential_supplier=credential_supplier,
        validator=JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"k" * 32),
            required_keys=("candidates",),
        ),
        now=100.0,
    )
    assert outcome.preflight.required_terminal_outcome is not None
    assert outcome.preflight.required_terminal_outcome.value == "INDETERMINATE"
    assert outcome.result is None
    assert calls == {"context": 0, "credential": 0}
    assert resolver.calls == []
    assert connector.events == []
    assert connector.application_bytes == 0


def test_harness_verifies_peer_before_credential_and_application_send() -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    model_issuer = _issuer(profile, policy)
    endpoint_issuer = _endpoint_issuer(profile)
    resolver = ScriptedResolver(("93.184.216.34",), ("93.184.216.34",))
    connector = SpyConnector(peer_ip="93.184.216.34", attempt=_success_attempt(request, profile))
    events = connector.events

    def credential_supplier(selected: ProviderProfile) -> CredentialLease | None:
        events.append("credential")
        return resolve_environment_credential(
            selected,
            {"REMOTE_SOURCE_KEY": "credential-canary"},
            registry=ProviderProfileRegistry((profile,)),
        )

    outcome = AuthorizedProviderHarness(
        model_issuer=model_issuer,
        endpoint_issuer=endpoint_issuer,
    ).execute_remote(
        preflight=_preflight_request(request, case),
        profile=profile,
        policy=policy,
        context_builder=lambda: _remote_context(request),
        resolver=resolver,
        connector=connector,
        credential_supplier=credential_supplier,
        validator=JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"k" * 32),
            required_keys=("candidates",),
        ),
        now=100.0,
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.SUCCEEDED
    assert events == ["connect", "credential", "send"]
    assert connector.application_bytes > 0


def test_harness_peer_failure_has_zero_credential_and_application_bytes() -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    connector = SpyConnector(peer_ip="1.1.1.1")
    credential_calls = 0

    def credential_supplier(selected: ProviderProfile) -> CredentialLease | None:
        nonlocal credential_calls
        del selected
        credential_calls += 1
        raise AssertionError("peer failure must precede credential lookup")

    outcome = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy),
        endpoint_issuer=_endpoint_issuer(profile),
    ).execute_remote(
        preflight=_preflight_request(request, case),
        profile=profile,
        policy=policy,
        context_builder=lambda: _remote_context(request),
        resolver=ScriptedResolver(("93.184.216.34",), ("93.184.216.34",)),
        connector=connector,
        credential_supplier=credential_supplier,
        validator=JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"k" * 32),
            required_keys=("candidates",),
        ),
        now=100.0,
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.PROVIDER_ERROR
    assert connector.events == ["connect"]
    assert credential_calls == 0
    assert connector.application_bytes == 0


def test_remote_harness_idempotency_prevents_duplicate_and_conflicting_effects() -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    connector = SpyConnector(
        peer_ip="93.184.216.34",
        attempt=_success_attempt(request, profile),
    )
    harness = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy),
        endpoint_issuer=_endpoint_issuer(profile),
    )
    resolver = ScriptedResolver(("93.184.216.34",), ("93.184.216.34",))

    def credential_supplier(selected: ProviderProfile) -> CredentialLease | None:
        return resolve_environment_credential(
            selected,
            {"REMOTE_SOURCE_KEY": "credential-canary"},
            registry=ProviderProfileRegistry((profile,)),
        )

    validator = JsonObjectValidator(
        validator=request.output_schema,
        data_class=DataClass.CONFIDENTIAL_SECURITY,
        content_identifier=HmacContentIdentifier(b"v" * 32),
        required_keys=("candidates",),
    )
    arguments = {
        "preflight": _preflight_request(request, case),
        "profile": profile,
        "policy": policy,
        "context_builder": lambda: _remote_context(request),
        "resolver": resolver,
        "connector": connector,
        "credential_supplier": credential_supplier,
        "validator": validator,
        "now": 100.0,
    }
    first = harness.execute_remote(**arguments)  # type: ignore[arg-type]
    duplicate = harness.execute_remote(**arguments)  # type: ignore[arg-type]
    assert first is duplicate
    assert connector.events == ["connect", "send"]

    admitted_preflight = _preflight_request(request, case)
    for mutation in (
        {"required_max_bytes": admitted_preflight.required_max_bytes - 1},
        {"required_data_class": DataClass.CONFIDENTIAL_SECURITY},
        {"planned_transforms": ("bounded_repository_view", "secret_redaction")},
    ):
        semantic_conflict = dict(arguments)
        semantic_conflict["preflight"] = admitted_preflight.model_copy(update=mutation)
        rejected = harness.execute_remote(**semantic_conflict)  # type: ignore[arg-type]
        assert rejected.result is not None
        assert rejected.result.status is ModelCallStatus.PROVIDER_ERROR
        assert connector.events == ["connect", "send"]

    conflict = request.model_copy(update={"request_id": "conflicting-request"})
    conflict_args = dict(arguments)
    conflict_args["preflight"] = _preflight_request(conflict, case)
    conflict_args["context_builder"] = lambda: _remote_context(conflict)
    outcome = harness.execute_remote(**conflict_args)  # type: ignore[arg-type]
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.PROVIDER_ERROR
    assert connector.events == ["connect", "send"]


@pytest.mark.parametrize("force_wait_timeout", [False, True])
def test_remote_harness_concurrent_duplicate_has_exactly_one_effect(
    force_wait_timeout: bool,
) -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    if force_wait_timeout:
        request = request.model_copy(
            update={"budget": request.budget.model_copy(update={"timeout_ms": 20})}
        )
    entered = threading.Event()
    release = threading.Event()
    start = threading.Barrier(3)

    class BlockingConnector(SpyConnector):
        def connect(
            self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
        ) -> SpyChannel:
            entered.set()
            assert release.wait(timeout=5), "test did not release the provider call"
            return super().connect(
                ip_address=ip_address,
                port=port,
                server_name=server_name,
                timeout_ms=timeout_ms,
            )

    connector = BlockingConnector(
        peer_ip="93.184.216.34", attempt=_success_attempt(request, profile)
    )
    harness = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy), endpoint_issuer=_endpoint_issuer(profile)
    )
    arguments = {
        "preflight": _preflight_request(request, case),
        "profile": profile,
        "policy": policy,
        "context_builder": lambda: _remote_context(request),
        "resolver": ScriptedResolver(("93.184.216.34",), ("93.184.216.34",)),
        "connector": connector,
        "credential_supplier": lambda selected: resolve_environment_credential(
            selected,
            {"REMOTE_SOURCE_KEY": "credential-canary"},
            registry=ProviderProfileRegistry((profile,)),
        ),
        "validator": JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"r" * 32),
            required_keys=("candidates",),
        ),
        "now": 100.0,
    }

    def execute():  # type: ignore[no-untyped-def]
        start.wait(timeout=5)
        return harness.execute_remote(**arguments)  # type: ignore[arg-type]

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(execute)
        second_future = pool.submit(execute)
        start.wait(timeout=5)
        assert entered.wait(timeout=5)
        if force_wait_timeout:
            completed, _ = wait(
                (first_future, second_future), timeout=2, return_when=FIRST_COMPLETED
            )
            assert len(completed) == 1
        release.set()
        first = first_future.result(timeout=5)
        second = second_future.result(timeout=5)

    assert first is second
    if force_wait_timeout:
        assert first.result is not None
        assert first.result.status is ModelCallStatus.PROVIDER_ERROR
    else:
        assert first.result is not None
        assert first.result.status is ModelCallStatus.SUCCEEDED
    assert connector.events == ["connect", "send"]
    assert connector.application_bytes == len(b'{"bounded":"source"}')


def test_remote_idempotency_binds_full_preflight_and_reserves_denials() -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    connector = SpyConnector(peer_ip="93.184.216.34", attempt=_success_attempt(request, profile))
    harness = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy), endpoint_issuer=_endpoint_issuer(profile)
    )
    resolver = ScriptedResolver(("93.184.216.34",), ("93.184.216.34",))
    common = {
        "profile": profile,
        "policy": policy,
        "context_builder": lambda: _remote_context(request),
        "resolver": resolver,
        "connector": connector,
        "credential_supplier": lambda selected: resolve_environment_credential(
            selected,
            {"REMOTE_SOURCE_KEY": "credential-canary"},
            registry=ProviderProfileRegistry((profile,)),
        ),
        "validator": JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"s" * 32),
            required_keys=("candidates",),
        ),
        "now": 100.0,
    }
    denied = _preflight_request(request, case).model_copy(
        update={"required_data_class": DataClass.RESTRICTED}
    )
    denial = harness.execute_remote(preflight=denied, **common)  # type: ignore[arg-type]
    assert denial.preflight.eligibility is not PreflightEligibility.ELIGIBLE
    assert connector.events == []

    conflict = harness.execute_remote(
        preflight=_preflight_request(request, case),
        **common,  # type: ignore[arg-type]
    )
    assert conflict.result is not None
    assert conflict.result.status is ModelCallStatus.PROVIDER_ERROR
    assert connector.events == []
    assert resolver.calls == []


@pytest.mark.parametrize(
    "error",
    [OSError("connect failed"), TimeoutError("timed out"), KeyError("sdk failure")],
)
def test_connector_failures_are_typed_and_send_zero_application_bytes(
    error: Exception,
) -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)

    class FailingConnector(SpyConnector):
        def connect(
            self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
        ) -> SpyChannel:
            del ip_address, port, server_name, timeout_ms
            self.events.append("connect")
            raise error

    connector = FailingConnector(peer_ip="93.184.216.34")
    outcome = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy), endpoint_issuer=_endpoint_issuer(profile)
    ).execute_remote(
        preflight=_preflight_request(request, case),
        profile=profile,
        policy=policy,
        context_builder=lambda: _remote_context(request),
        resolver=ScriptedResolver(("93.184.216.34",)),
        connector=connector,
        credential_supplier=lambda selected: None,
        validator=JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"t" * 32),
            required_keys=("candidates",),
        ),
        now=100.0,
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.PROVIDER_ERROR
    assert connector.events == ["connect"]
    assert connector.application_bytes == 0


def test_unexpected_context_exception_completes_shared_reservation() -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    harness = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy), endpoint_issuer=_endpoint_issuer(profile)
    )
    connector = SpyConnector(peer_ip="93.184.216.34")

    def exploding_context() -> PreparedModelContext:
        raise KeyError("context failure canary")

    arguments = {
        "preflight": _preflight_request(request, case),
        "profile": profile,
        "policy": policy,
        "context_builder": exploding_context,
        "resolver": ScriptedResolver(("93.184.216.34",)),
        "connector": connector,
        "credential_supplier": lambda selected: None,
        "validator": JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"u" * 32),
            required_keys=("candidates",),
        ),
        "now": 100.0,
    }
    first = harness.execute_remote(**arguments)  # type: ignore[arg-type]
    duplicate = harness.execute_remote(**arguments)  # type: ignore[arg-type]
    assert first is duplicate
    assert first.result is not None
    assert first.result.status is ModelCallStatus.PROVIDER_ERROR
    assert connector.events == []


def test_context_bytes_are_snapshotted_and_bound_before_connector_callbacks() -> None:
    case = dict(_semantic_cases()[0])
    profile = _remote_source_profile()
    policy = _remote_policy()
    case["required_execution_boundary"] = profile.execution_boundary.value
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    holder: dict[str, PreparedModelContext] = {}

    class MutatingConnector(SpyConnector):
        def connect(
            self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
        ) -> SpyChannel:
            holder["context"]._buffer.extend(b"mutation-after-authorization")
            return super().connect(
                ip_address=ip_address,
                port=port,
                server_name=server_name,
                timeout_ms=timeout_ms,
            )

    def build_context() -> PreparedModelContext:
        context = _remote_context(request)
        holder["context"] = context
        return context

    connector = MutatingConnector(
        peer_ip="93.184.216.34",
        attempt=_success_attempt(request, profile),
    )
    outcome = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy),
        endpoint_issuer=_endpoint_issuer(profile),
    ).execute_remote(
        preflight=_preflight_request(request, case),
        profile=profile,
        policy=policy,
        context_builder=build_context,
        resolver=ScriptedResolver(("93.184.216.34",), ("93.184.216.34",)),
        connector=connector,
        credential_supplier=lambda selected: resolve_environment_credential(
            selected,
            {"REMOTE_SOURCE_KEY": "credential-canary"},
            registry=ProviderProfileRegistry((profile,)),
        ),
        validator=JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"v" * 32),
            required_keys=("candidates",),
        ),
        now=100.0,
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.SUCCEEDED
    assert connector.application_bytes == len(b'{"bounded":"source"}')


def test_raw_connector_is_not_public_and_send_requires_verified_binding() -> None:
    assert not hasattr(adapter_package, "ProviderConnector")
    profile = _remote_source_profile()
    policy = _remote_policy()
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    connector = SpyConnector(
        peer_ip="93.184.216.34",
        attempt=_success_attempt(request, profile),
    )
    with pytest.raises(TypeError):
        connector.send(  # type: ignore[call-arg]
            SpyChannel("93.184.216.34"),
            credential=None,
            payload=b"bounded",
            model_id=profile.model_id,
            timeout_ms=1000,
        )
