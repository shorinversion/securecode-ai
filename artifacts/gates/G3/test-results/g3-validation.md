# G3 validation results

- Source commit: `c3f682bac863e6c46ea159f437179e643d4c3eeb`
- Canonical command: `uv run --locked --offline --no-sync --group quality python -I scripts/quality.py`
- Canonical terminal result: `QUALITY=PASS`
- Specification snapshot gate: `SPEC_GATE=PASS`
- Ruff format: 113 files formatted
- Ruff lint: PASS
- mypy: PASS; no issues in 113 source files
- Unit/integration/security suite: 1448 collected; 1443 passed; 5 skipped;
  319.47 seconds
- Core branch coverage: 82.43% (required >=80%)
- Runtime: Windows, Python 3.13.11, pytest 9.1.1

The suite covers P3.1–P3.13 positive and negative contracts, including evidence
binding, immutable Skeptic input, bounded progress, injection containment,
tool authorization, deterministic replay, escalation preservation, mandatory
zero-signal model discovery, dual-lane lineage, direct local transport and
source-free real-model qualification.

Skipped platform oracles:

- `tests/unit/test_repository_intake.py:204` — POSIX descriptor-relative race oracle
- `tests/unit/test_repository_intake.py:231` — POSIX descriptor-relative race oracle
- `tests/unit/test_repository_intake.py:256` — POSIX descriptor binding oracle
- `tests/unit/test_repository_intake.py:285` — POSIX concurrent-write oracle
- `tests/unit/test_repository_intake.py:385` — FIFO creation is unavailable
