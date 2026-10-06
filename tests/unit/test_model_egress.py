from __future__ import annotations

import hashlib

import pytest
from securecode_ai.adapters.model_egress import egress_data_class, keyed_entries
from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ArtifactRef, DataClass


def _artifact(content_id: str, content: bytes, data_class: DataClass) -> ArtifactRef:
    return ArtifactRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id="tenant-a",
        content_id=content_id,
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        data_class=data_class,
    )


def test_host_facts_get_keyed_content_ids_and_keyed_ones_are_kept() -> None:
    fact = b'{"kind":"location-only"}'
    source = b"answer = 42\n"
    entries = (
        ("evidence-fact", _artifact("host-fact-1", fact, DataClass.INTERNAL_METADATA), fact),
        ("evidence-src", _artifact("kid:existing", source, DataClass.CONFIDENTIAL_SOURCE), source),
    )

    keyed = keyed_entries(entries, b"k" * 32)
    again = keyed_entries(entries, b"k" * 32)

    assert keyed[0][1].content_id.startswith("kid:")
    assert keyed[0][1].content_id == again[0][1].content_id
    assert keyed[0][1].content_id != keyed_entries(entries, b"j" * 32)[0][1].content_id
    assert keyed[1] == entries[1]
    assert keyed_entries(keyed, b"k" * 32) == keyed


@pytest.mark.parametrize(
    ("classes", "expected"),
    [
        ((DataClass.PUBLIC,), DataClass.PUBLIC),
        ((DataClass.INTERNAL_METADATA,), DataClass.CONFIDENTIAL_SOURCE),
        ((DataClass.PUBLIC, DataClass.CONFIDENTIAL_SECURITY), DataClass.CONFIDENTIAL_SOURCE),
        ((DataClass.CONFIDENTIAL_SOURCE, DataClass.RESTRICTED), DataClass.RESTRICTED),
    ],
)
def test_context_label_is_never_lower_than_its_content(
    classes: tuple[DataClass, ...], expected: DataClass
) -> None:
    assert egress_data_class(classes) is expected
