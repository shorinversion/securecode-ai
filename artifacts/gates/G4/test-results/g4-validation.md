# G4 validation results

- Source commit: `f76c4c803b3ca185e0c68c310a5d4674c49ba391`
- Canonical command: `uv run --locked --offline --no-sync --group quality python -I scripts/quality.py`
- Canonical terminal result: `QUALITY=PASS`
- Specification snapshot gate: `SPEC_GATE=PASS`
- Ruff format and lint: PASS
- mypy: PASS; no issues in 137 source files
- Unit suite: 1519 collected; 1514 passed; 5 skipped; 348.01 seconds
- Core branch coverage: 81.20% (required at least 80%)
- Integration command: `.venv\\Scripts\\python.exe -I -m pytest -q tests/integration/test_cwe89_repair.py tests/integration/test_mvp_demo.py`
- Integration result: 6 passed in 0.59 seconds
- Clean demo: seven report/receipt artifacts written to a new temporary output
  directory; vulnerable/safe/fixed signal counts were 1/0/0; network was not used;
  product outcome remained `NOT_EVALUATED` and product pass remained false.

Skipped platform oracles:

- `tests/unit/test_repository_intake.py:204` - POSIX descriptor-relative race oracle
- `tests/unit/test_repository_intake.py:231` - POSIX descriptor-relative race oracle
- `tests/unit/test_repository_intake.py:256` - POSIX descriptor binding oracle
- `tests/unit/test_repository_intake.py:285` - POSIX concurrent-write oracle
- `tests/unit/test_repository_intake.py:385` - FIFO creation is unavailable

The integrated paths cover the reference vulnerable flow, safe negative control,
immutable source checkout, all twelve validation stages, typed failure receipts,
offline profiles, and clean notebook/report replay.
