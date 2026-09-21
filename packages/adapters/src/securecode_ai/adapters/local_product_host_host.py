"""Host admission composition and platform dispatch."""

from __future__ import annotations

import hashlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from securecode_ai.contracts import EgressPolicyDocument, EgressProfileId, ProviderProfile

from .config import ProviderProfileRegistry, parse_provider_profile
from .local_product_host_linux import _read_linux_anchor
from .local_product_host_primitives import (
    LocalProductHostError,
    _parse_manifest,
    _ProtectedAnchor,
    _reject,
)
from .local_product_host_primitives import (
    _canonical as _canonical,
)
from .local_product_host_primitives import (
    _parse_record as _parse_record,
)
from .local_product_host_windows import _read_windows_anchor
from .local_provider_admission import (
    HostAdmissionPins,
    LocalProviderEvidenceBundle,
    TrustedLocalProviderAdmission,
)


@dataclass(frozen=True, slots=True)
class LocalProductHost:
    profile: ProviderProfile
    policy: EgressPolicyDocument
    registry: ProviderProfileRegistry
    artifact_manifest: dict[str, str]
    approval_record_sha256: str
    artifact_manifest_sha256: str
    approved_bundle_sha256: str


def load_local_product_host() -> LocalProductHost:
    """Load an independently protected host anchor before repository access."""

    try:
        anchor = _read_platform_anchor()
        if (
            hashlib.sha256(anchor.approval_record).hexdigest() != anchor.approval_record_sha256
            or hashlib.sha256(anchor.artifact_manifest).hexdigest()
            != anchor.artifact_manifest_sha256
        ):
            _reject()
        record = _parse_record(anchor.approval_record)
        manifest = _parse_manifest(anchor.artifact_manifest)
        profile_document = record["approved_profile"]
        policy_document = record["policy"]
        bundle_document = record["bundle"]
        pins_document = record["pins"]
        if any(
            type(value) is not dict
            for value in (profile_document, policy_document, bundle_document, pins_document)
        ):
            _reject()
        profile = parse_provider_profile(_canonical(profile_document))
        policy = EgressPolicyDocument.model_validate_json(_canonical(policy_document))
        bundle = LocalProviderEvidenceBundle.model_validate_json(_canonical(bundle_document))
        pins = HostAdmissionPins.model_validate_json(_canonical(pins_document))
        from . import openai_compatible_local
        from .product_model import AUDITOR_WIRE_PIN, MODEL_NATIVE_DISCOVERY_WIRE_PIN
        from .product_runtime import PRODUCT_AUDITOR_PROMPT_PIN, PRODUCT_DISCOVERY_PROMPT_PIN

        installed = {
            "connector_sha256": hashlib.sha256(
                Path(openai_compatible_local.__file__).read_bytes()
            ).hexdigest(),
            "discovery_prompt_sha256": PRODUCT_DISCOVERY_PROMPT_PIN.content_sha256,
            "discovery_schema_sha256": MODEL_NATIVE_DISCOVERY_WIRE_PIN.content_sha256,
            "auditor_prompt_sha256": PRODUCT_AUDITOR_PROMPT_PIN.content_sha256,
            "auditor_schema_sha256": AUDITOR_WIRE_PIN.content_sha256,
        }
        if any(getattr(pins.bindings, name) != digest for name, digest in installed.items()):
            _reject()
        if (
            profile.canonical_content_hash() != record["profile_sha256"]
            or policy.canonical_content_hash() != record["policy_sha256"]
            or bundle.content_sha256 != record["bundle_sha256"]
            or pins.approved_bundle_sha256 != bundle.content_sha256
            or policy.profile is not EgressProfileId.PRIVATE_MODEL_ZDR
        ):
            _reject()
        admission = TrustedLocalProviderAdmission(
            approved_profile=_canonical(profile_document), pins=pins
        )
        registry = admission.admit(admission.review(bundle))
        approved = registry.select(profile.selector)
        if approved.canonical_content_hash() != profile.canonical_content_hash():
            _reject()
        return LocalProductHost(
            approved,
            policy,
            registry,
            manifest,
            anchor.approval_record_sha256,
            anchor.artifact_manifest_sha256,
            bundle.content_sha256,
        )
    except LocalProductHostError:
        raise
    except Exception:
        _reject()


def _read_platform_anchor() -> _ProtectedAnchor:
    if os.name == "nt":
        return _read_windows_anchor()
    if os.name == "posix" and sys.platform == "linux":
        return _read_linux_anchor()
    _reject()
