"""Synthetic protected-boundary plumbing, never live admission evidence."""

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

import pytest
from pydantic import BaseModel
from securecode_ai.adapters import local_product_host as host_module
from securecode_ai.adapters import local_product_host_windows as host_windows
from securecode_ai.adapters import openai_compatible_local
from securecode_ai.adapters.local_product_host_linux import _assert_linux_object_protected
from securecode_ai.adapters.local_product_host_primitives import _ProtectedAnchor
from securecode_ai.adapters.local_product_host_windows import _assert_no_low_trust_write
from securecode_ai.adapters.local_provider_admission import HostAdmissionPins
from securecode_ai.adapters.product_model import AUDITOR_WIRE_PIN, MODEL_NATIVE_DISCOVERY_WIRE_PIN
from securecode_ai.adapters.product_runtime import (
    PRODUCT_AUDITOR_PROMPT_PIN,
    PRODUCT_DISCOVERY_PROMPT_PIN,
)
from securecode_ai.adapters.product_skeptic import PRODUCT_SKEPTIC_PROMPT_PIN, SKEPTIC_WIRE_PIN
from securecode_ai.contracts import (
    ComponentPin,
    EgressPolicyDocument,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ProviderProfile,
)
from securecode_ai.core.runtime import (
    DEFAULT_STAGE_CATALOGUE_PIN,
    build_default_workflow_definition,
)

from tests.unit import test_local_provider_admission as synthetic
from tests.unit.test_provider_preflight import _policy, _profile, _request


class _AceCountHolder(Protocol):
    ace_count: int


class _PointerValueHolder(Protocol):
    value: int | None


class _ByRefAceCount(Protocol):
    _obj: _AceCountHolder


class _ByRefPointer(Protocol):
    _obj: _PointerValueHolder


def synthetic_anchor(port: int = 11434) -> _ProtectedAnchor:
    """Build separately simulated admin inputs using real admission validation."""
    original_updated, original_request, original_profile = (
        synthetic._updated,
        _request,
        _profile,
    )

    def bind_request(value: ModelRequest) -> ModelRequest:
        prompt, schema = (
            (PRODUCT_AUDITOR_PROMPT_PIN, AUDITOR_WIRE_PIN)
            if value.role is ModelRole.AUDITOR
            else (PRODUCT_DISCOVERY_PROMPT_PIN, MODEL_NATIVE_DISCOVERY_WIRE_PIN)
        )
        return original_updated(value, prompt=prompt, output_schema=schema)

    def updated[Model: BaseModel](value: Model, **updates: object) -> Model:
        result = original_updated(value, **updates)
        if isinstance(result, ModelRequest):
            return cast(Model, bind_request(result))
        return result

    def profile(name: str) -> ProviderProfile:
        value = original_profile(name)
        endpoint = original_updated(
            value.endpoint, base_url=f"http://127.0.0.1:{port}/v1", allowed_ports=(port,)
        )
        return cast(ProviderProfile, original_updated(value, endpoint=endpoint))

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(synthetic, "_updated", updated)

        def request(
            selected_profile: ProviderProfile,
            policy: EgressPolicyDocument,
            mode: ModelPurpose,
        ) -> ModelRequest:
            return bind_request(original_request(selected_profile, policy, mode))

        patch.setattr(synthetic, "_request", request)
        patch.setattr(synthetic, "_profile", profile)
        approved, bundle = synthetic._fixture()
    binding = original_updated(
        bundle.bindings,
        connector_sha256=hashlib.sha256(
            Path(openai_compatible_local.__file__).read_bytes()
        ).hexdigest(),
        discovery_prompt_sha256=PRODUCT_DISCOVERY_PROMPT_PIN.content_sha256,
        discovery_schema_sha256=MODEL_NATIVE_DISCOVERY_WIRE_PIN.content_sha256,
        auditor_prompt_sha256=PRODUCT_AUDITOR_PROMPT_PIN.content_sha256,
        auditor_schema_sha256=AUDITOR_WIRE_PIN.content_sha256,
    )
    bundle = original_updated(bundle, bindings=binding)
    pins = HostAdmissionPins(
        bindings=binding,
        approved_bundle_sha256=bundle.content_sha256,
        review_receipt=bundle.review_receipt,
        producer_id=bundle.producer_id,
        independent_reviewer_id=bundle.independent_reviewer_id,
    )
    data = _policy("egress.valid.private-model-source.json").model_dump(mode="json")
    data["rules"][0]["destinations"] = ["profile://" + approved.profile_id]
    data["rules"][0]["purposes"] = [
        "model_native_discovery",
        "candidate_investigation",
        "skeptic_review",
    ]
    policy = EgressPolicyDocument.model_validate_json(json.dumps(data))
    policy_pin = ComponentPin(
        schema_version="0.2.0",
        component_id=policy.policy_id,
        component_version=policy.policy_version,
        content_sha256=policy.canonical_content_hash(),
    )
    git = Path("C:/Program Files/Git/mingw64/bin/git.exe" if os.name == "nt" else "/usr/bin/git")
    manifest = {
        "workflow_sha256": build_default_workflow_definition(
            policy_pin=policy_pin
        ).component_pin.content_sha256,
        "stage_catalogue_sha256": DEFAULT_STAGE_CATALOGUE_PIN.content_sha256,
        "discovery_prompt_sha256": PRODUCT_DISCOVERY_PROMPT_PIN.content_sha256,
        "auditor_prompt_sha256": PRODUCT_AUDITOR_PROMPT_PIN.content_sha256,
        "skeptic_prompt_sha256": PRODUCT_SKEPTIC_PROMPT_PIN.content_sha256,
        "skeptic_schema_sha256": SKEPTIC_WIRE_PIN.content_sha256,
        "git_executable_sha256": hashlib.sha256(git.read_bytes()).hexdigest(),
    }
    record = {
        "schema_version": "1.0.0",
        "approved_profile": approved.model_dump(mode="json"),
        "policy": policy.model_dump(mode="json"),
        "bundle": bundle.model_dump(mode="json"),
        "pins": pins.model_dump(mode="json"),
        "profile_sha256": approved.canonical_content_hash(),
        "policy_sha256": policy.canonical_content_hash(),
        "bundle_sha256": bundle.content_sha256,
    }
    raw_record, raw_manifest = host_module._canonical(record), host_module._canonical(manifest)
    return _ProtectedAnchor(
        raw_record,
        hashlib.sha256(raw_record).hexdigest(),
        raw_manifest,
        hashlib.sha256(raw_manifest).hexdigest(),
    )


def test_simulated_anchor_reaches_real_review_and_sealed_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = synthetic_anchor()
    monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: anchor)
    host = host_module.load_local_product_host()
    assert host.profile.profile_id == "test-host-gateway"
    assert host.registry.require_registered(host.profile) == host.profile
    assert host.approval_record_sha256 == anchor.approval_record_sha256
    assert host.artifact_manifest_sha256 == anchor.artifact_manifest_sha256
    assert host.approved_bundle_sha256 == json.loads(anchor.approval_record)["bundle_sha256"]


@pytest.mark.parametrize(
    "kind", ["record-digest", "manifest-digest", "duplicate", "nested-nul", "connector"]
)
def test_anchor_import_mutations_reject_without_runtime(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    from dataclasses import replace

    anchor = synthetic_anchor()
    if kind == "record-digest":
        anchor = replace(anchor, approval_record_sha256="0" * 64)
    elif kind == "manifest-digest":
        anchor = replace(anchor, artifact_manifest_sha256="0" * 64)
    else:
        raw = anchor.approval_record
        if kind == "duplicate":
            raw = raw.replace(
                b'{"approved_profile":{', b'{"approved_profile":{"profile_id":"duplicate",', 1
            )
        else:
            data = json.loads(raw)
            if kind == "nested-nul":
                data["bundle"]["producer_id"] += "\x00"
            else:
                data["pins"]["bindings"]["connector_sha256"] = "0" * 64
            raw = host_module._canonical(data)
        anchor = replace(
            anchor, approval_record=raw, approval_record_sha256=hashlib.sha256(raw).hexdigest()
        )
    monkeypatch.setattr(host_module, "_read_platform_anchor", lambda: anchor)
    with pytest.raises(host_module.LocalProductHostError):
        host_module.load_local_product_host()


def test_unproven_protection_precedes_import_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny() -> None:
        raise host_module.LocalProductHostError()

    monkeypatch.setattr(host_module, "_read_platform_anchor", deny)
    monkeypatch.setattr(host_module, "_parse_record", lambda raw: pytest.fail("import consumed"))
    with pytest.raises(host_module.LocalProductHostError):
        host_module.load_local_product_host()


@pytest.mark.parametrize(
    "kind", ["owner", "group-write", "other-write", "symlink", "hardlink", "acl"]
)
def test_linux_opened_object_protection_rejects_lower_trust_or_indirection(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    import stat
    from types import SimpleNamespace

    observed = SimpleNamespace(
        st_uid=1000 if kind == "owner" else 0,
        st_mode=stat.S_IFLNK
        if kind == "symlink"
        else stat.S_IFREG
        | 0o600
        | (0o020 if kind == "group-write" else 0o002 if kind == "other-write" else 0),
        st_nlink=2 if kind == "hardlink" else 1,
    )
    monkeypatch.setattr(host_module.os, "fstat", lambda descriptor: observed)
    monkeypatch.setattr(
        host_module.os,
        "listxattr",
        lambda descriptor: ["system.posix_acl_access"] if kind == "acl" else [],
        raising=False,
    )
    with pytest.raises(host_module.LocalProductHostError):
        _assert_linux_object_protected(9, directory=False)


@pytest.mark.parametrize("deny_at", [0, 1, 2, 3])
def test_linux_descriptor_chain_denies_before_anchor_payload(
    monkeypatch: pytest.MonkeyPatch, deny_at: int
) -> None:
    opened: list[tuple[str, int, int | None]] = []
    closed: list[int] = []
    checks: list[tuple[int, bool]] = []
    with monkeypatch.context() as patch:
        for name, value in {
            "O_CLOEXEC": 0x80000,
            "O_NOFOLLOW": 0x20000,
            "O_DIRECTORY": 0x10000,
            "O_NONBLOCK": 0x800,
        }.items():
            patch.setattr(host_module.os, name, value, raising=False)

        def open_object(path: str, flags: int, *, dir_fd: int | None = None) -> int:
            opened.append((path, flags, dir_fd))
            return len(opened)

        def assert_protected(descriptor: int, *, directory: bool) -> None:
            checks.append((descriptor, directory))
            if len(checks) - 1 == deny_at:
                raise host_module.LocalProductHostError()

        patch.setattr(host_module.os, "open", open_object)
        patch.setattr(host_module.os, "close", closed.append)
        patch.setattr(host_module.os, "read", lambda *args: pytest.fail("anchor payload consumed"))
        patch.setattr(host_module, "_assert_linux_object_protected", assert_protected)
        with pytest.raises(host_module.LocalProductHostError):
            host_module._read_linux_anchor()
    assert [entry[0] for entry in opened] == ["/", "etc", "securecode-ai", "approval-anchor.json"][
        : deny_at + 1
    ]
    assert all(flags & 0x20000 for _path, flags, _parent in opened)
    assert closed == list(range(deny_at + 1, 0, -1))


def test_linux_retains_bounded_same_anchor_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    anchor = synthetic_anchor()
    document = {
        "approval_record": anchor.approval_record.decode(),
        "approval_record_sha256": anchor.approval_record_sha256,
        "artifact_manifest": anchor.artifact_manifest.decode(),
        "artifact_manifest_sha256": anchor.artifact_manifest_sha256,
    }
    raw = host_module._canonical(document)
    pieces = iter((raw[:8000], raw[8000:], b""))
    opened: list[tuple[str, int | None]] = []
    closed: list[int] = []
    with monkeypatch.context() as patch:
        for name, value in {
            "O_CLOEXEC": 0x80000,
            "O_NOFOLLOW": 0x20000,
            "O_DIRECTORY": 0x10000,
            "O_NONBLOCK": 0x800,
        }.items():
            patch.setattr(host_module.os, name, value, raising=False)

        def open_object(path: str, flags: int, *, dir_fd: int | None = None) -> int:
            opened.append((path, dir_fd))
            return len(opened)

        patch.setattr(host_module.os, "open", open_object)
        patch.setattr(host_module.os, "close", closed.append)
        patch.setattr(host_module.os, "read", lambda *args: next(pieces))
        patch.setattr(host_module, "_assert_linux_object_protected", lambda *args, **kwargs: None)
        retained = host_module._read_linux_anchor()
    assert retained == anchor
    assert opened == [("/", None), ("etc", 1), ("securecode-ai", 2), ("approval-anchor.json", 3)]
    assert closed == [4, 3, 2, 1]


def test_fixed_git_executable_forged_digest_is_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name == "nt":
        monkeypatch.setattr(
            host_module, "_assert_windows_key_protected", lambda *args, **kwargs: None
        )
    with pytest.raises(host_module.LocalProductHostError):
        host_module.verify_local_git_executable("0" * 64)


def test_fixed_git_executable_unproven_protection_denies_before_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny(*args: object, **kwargs: object) -> None:
        raise host_module.LocalProductHostError()

    if os.name == "nt":
        monkeypatch.setattr(host_module, "_assert_windows_key_protected", deny)
    else:
        monkeypatch.setattr(host_module, "_assert_linux_object_protected", deny)
    monkeypatch.setattr(
        Path, "open", lambda *args, **kwargs: pytest.fail("executable bytes consumed")
    )
    with pytest.raises(host_module.LocalProductHostError):
        host_module.verify_local_git_executable("a" * 64)


@pytest.mark.parametrize(
    "mask, ancestor, denied",
    [
        (4, True, False),
        (4, False, True),
        (2, True, True),
        (0x40, True, True),
        (0x10000, True, True),
        (0x40000, True, True),
        (0x80000, True, True),
        (0x100, True, True),
    ],
)
def test_windows_ancestor_creation_cannot_grant_replacement_or_dll_planting(
    monkeypatch: pytest.MonkeyPatch, mask: int, ancestor: bool, denied: bool
) -> None:
    import ctypes
    from types import SimpleNamespace

    ace = (ctypes.c_ubyte * 20)()
    ctypes.c_uint32.from_buffer(ace, 4).value = mask

    class NativeFunction:
        def __init__(self, action: Callable[..., int]) -> None:
            self.action = action

        def __call__(self, *arguments: object) -> int:
            return self.action(*arguments)

    def get_info(dacl: object, output: object, size: object, category: object) -> int:
        cast(_ByRefAceCount, output)._obj.ace_count = 1
        return 1

    def get_ace(dacl: object, index: object, output: object) -> int:
        cast(_ByRefPointer, output)._obj.value = ctypes.addressof(ace)
        return 1

    advapi = SimpleNamespace(
        GetAclInformation=NativeFunction(get_info), GetAce=NativeFunction(get_ace)
    )
    monkeypatch.setattr(host_windows, "_windows_sid_text", lambda *args: "S-1-5-21-custom-user")
    if denied:
        with pytest.raises(host_module.LocalProductHostError):
            _assert_no_low_trust_write(
                advapi, 1, file_object=True, allow_ancestor_directory_creation=ancestor
            )
    else:
        _assert_no_low_trust_write(
            advapi, 1, file_object=True, allow_ancestor_directory_creation=ancestor
        )
