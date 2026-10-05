"""Shared rules for labelling evidence that leaves the host in a model context."""

from __future__ import annotations

from collections.abc import Iterable

from securecode_ai.contracts import ArtifactRef, DataClass

from .model_types import HmacContentIdentifier

DATA_CLASS_RANK = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL_METADATA: 1,
    DataClass.CONFIDENTIAL_SECURITY: 2,
    DataClass.CONFIDENTIAL_SOURCE: 3,
    DataClass.RESTRICTED: 4,
}


def keyed_entries(
    entries: tuple[tuple[str, ArtifactRef, bytes], ...], key: bytes
) -> tuple[tuple[str, ArtifactRef, bytes], ...]:
    """Give every artifact a keyed opaque content id.

    Host-derived facts (for example a value-free secret projection) carry a readable
    content id; egress admits only keyed ``kid:`` ids, so one is derived from the
    content with the run's content key.
    """

    if all(artifact.content_id.startswith("kid:") for _, artifact, _ in entries):
        return entries
    identifier = HmacContentIdentifier(key)
    try:
        return tuple(
            (
                evidence_id,
                artifact
                if artifact.content_id.startswith("kid:")
                else artifact.model_copy(
                    update={
                        "content_id": identifier.identify(
                            tenant_id=artifact.tenant_id, payload=content
                        )
                    }
                ),
                content,
            )
            for evidence_id, artifact, content in entries
        )
    finally:
        identifier.close()


def egress_data_class(classes: Iterable[DataClass]) -> DataClass:
    """Label a model context with the highest class it contains.

    Model egress is authorized either for a public corpus or for confidential source.
    A context made only of value-free host facts is labelled as source: raising a
    label never widens what may leave the host.
    """

    highest = max(classes, key=DATA_CLASS_RANK.__getitem__)
    if highest in {DataClass.INTERNAL_METADATA, DataClass.CONFIDENTIAL_SECURITY}:
        return DataClass.CONFIDENTIAL_SOURCE
    return highest
