# G4 integrated validation summary

- Implementation checkpoint: `f76c4c803b3ca185e0c68c310a5d4674c49ba391`
- Protected G3 base: `7240c2c6ebcee1087f51a89b84f3482510973190`
- Canonical command: `uv run --locked --offline --no-sync --group quality python -I scripts/quality.py`
- Specification snapshot, Ruff format, Ruff lint and mypy: `PASS`
- Unit suite: 1519 collected; 1514 passed; 5 platform skips; 348.01 seconds
- Core branch coverage: 81.20% (required at least 80%)
- G4 integration: 6 passed in 0.59 seconds
- Clean demo replay: `reference_outcome=COMPLETED`, `product_outcome=NOT_EVALUATED`
- Terminal result: `QUALITY=PASS`

The demo is a pinned synthetic CWE-89 reference. It does not claim general
accuracy, release readiness or product PASS.
