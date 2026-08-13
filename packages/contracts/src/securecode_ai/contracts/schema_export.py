"""Deterministically render the checked-in public domain JSON Schemas."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from .base import CONTRACT_SCHEMA_VERSION, WireModel
from .domain import PUBLIC_ROOT_MODELS as DOMAIN_PUBLIC_ROOT_MODELS
from .events import AuditEvent

PUBLIC_ROOT_MODELS: dict[str, type[WireModel]] = {
    **DOMAIN_PUBLIC_ROOT_MODELS,
    "audit-event": AuditEvent,
}

JSON_SCHEMA_DIALECT: Final = "https://json-schema.org/draft/2020-12/schema"
SEMANTIC_VALIDATOR: Final = "securecode_ai.contracts.schema_export:validate_public_document"
SEMANTIC_RULES: Final = {
    "audit-event": (
        "SC-EVENT-004",
        "SC-EVENT-009",
        "SC-EVENT-011",
    ),
    "audit-run": (
        "SC-DOM-002",
        "SC-DOM-003",
        "SC-DOM-004",
        "SC-DOM-012",
        "SC-DOM-013",
        "SC-DOM-014",
        "SC-WF-016",
        "SC-WF-017",
    ),
    "evidence": ("SC-DOM-005", "SC-DOM-006", "SC-DOM-010"),
    "finding-case": ("SC-DOM-004", "SC-DOM-006", "SC-DOM-011", "SC-DOM-013"),
    "patch-candidate": ("SC-DOM-004", "SC-DOM-010"),
    "validation-result": ("SC-DOM-005", "SC-DOM-010"),
}
DEFAULT_SCHEMA_DIRECTORY: Final = (
    Path(__file__).resolve().parent / "schemas" / f"v{CONTRACT_SCHEMA_VERSION}"
)


def render_schema_documents() -> dict[str, bytes]:
    """Return stable filenames and canonical compact schema bytes."""

    rendered: dict[str, bytes] = {}
    for slug, model in sorted(PUBLIC_ROOT_MODELS.items()):
        document = model.model_json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        )
        document["$schema"] = JSON_SCHEMA_DIALECT
        document["$id"] = (
            f"https://schemas.securecode.ai/domain/{CONTRACT_SCHEMA_VERSION}/{slug}.schema.json"
        )
        document["$comment"] = (
            "Draft 2020-12 validates the closed structural surface. Full conformance requires "
            "the named strict Pydantic semantic validator; neither artifact is a competing source."
        )
        document["x-securecode-semantic-validator"] = SEMANTIC_VALIDATOR
        document["x-securecode-semantic-rules"] = list(SEMANTIC_RULES[slug])
        payload = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        rendered[f"{slug}.schema.json"] = f"{payload}\n".encode()
    return rendered


def validate_public_document(slug: str, payload: str | bytes | bytearray) -> object:
    """Apply the authoritative strict semantic validator named by each schema."""

    try:
        model = PUBLIC_ROOT_MODELS[slug]
    except KeyError as error:
        raise ValueError(f"unknown public contract root: {slug}") from error
    return model.model_validate_json(payload)


def write_schema_documents(output_directory: Path) -> tuple[Path, ...]:
    """Write only the deterministic public schema set to an existing/new directory."""

    output_directory.mkdir(parents=True, exist_ok=True)
    expected = render_schema_documents()
    unexpected = {
        path for path in output_directory.glob("*.schema.json") if path.name not in expected
    }
    if unexpected:
        names = ", ".join(sorted(path.name for path in unexpected))
        raise ValueError(f"unexpected checked-in schema files: {names}")
    written: list[Path] = []
    for filename, content in expected.items():
        destination = output_directory / filename
        destination.write_bytes(content)
        written.append(destination)
    return tuple(written)


def compare_schema_documents(output_directory: Path) -> tuple[str, ...]:
    """Return stable diagnostics for missing, extra or byte-drifted schema artifacts."""

    expected = render_schema_documents()
    actual_names = {path.name for path in output_directory.glob("*.schema.json")}
    diagnostics: list[str] = []
    for missing in sorted(set(expected) - actual_names):
        diagnostics.append(f"missing:{missing}")
    for extra in sorted(actual_names - set(expected)):
        diagnostics.append(f"extra:{extra}")
    for filename in sorted(set(expected) & actual_names):
        if (output_directory / filename).read_bytes() != expected[filename]:
            diagnostics.append(f"drift:{filename}")
    return tuple(diagnostics)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_SCHEMA_DIRECTORY,
        help="target directory for the public JSON Schema files",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare exact bytes without writing",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output_directory: Path = args.output
    if args.check:
        diagnostics = compare_schema_documents(output_directory)
        if diagnostics:
            print("SCHEMA_CHECK=FAIL " + " ".join(diagnostics))
            return 1
        print("SCHEMA_CHECK=PASS")
        return 0
    written = write_schema_documents(output_directory)
    print(f"SCHEMA_WRITE=PASS files={len(written)}")
    return 0


def schema_file_hashes(documents: Mapping[str, bytes] | None = None) -> dict[str, str]:
    """Return hashes for evidence without making hashing part of the wire contract."""

    import hashlib

    source = render_schema_documents() if documents is None else documents
    return {name: hashlib.sha256(content).hexdigest() for name, content in sorted(source.items())}


if __name__ == "__main__":
    raise SystemExit(main())
