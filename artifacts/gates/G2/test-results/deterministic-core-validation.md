# G2 deterministic-core validation results

- Source commit: `34f3fcaf598f152753920cb32717ccbc720bd215`
- Canonical quality terminal result: `QUALITY=PASS`
- Specification snapshot gate: `SPEC_GATE=PASS`
- Ruff format: 87 files already formatted
- Ruff lint: PASS
- mypy: PASS; no issues in 87 source files
- Unit suite: 1301 collected; 1296 passed, 5 skipped; 287.96 seconds
- Core branch coverage: 86.80% (required >=80%)
- Runtime: Windows, Python 3.13.11, pytest 9.1.1

Skipped platform oracles:

- `tests/unit/test_repository_intake.py:204` — POSIX descriptor-relative race oracle
- `tests/unit/test_repository_intake.py:231` — POSIX descriptor-relative race oracle
- `tests/unit/test_repository_intake.py:256` — POSIX descriptor binding oracle
- `tests/unit/test_repository_intake.py:285` — POSIX concurrent-write oracle
- `tests/unit/test_repository_intake.py:385` — FIFO creation is unavailable
