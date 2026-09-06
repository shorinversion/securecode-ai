# G3 integrated validation summary

- Implementation checkpoint: `c3f682bac863e6c46ea159f437179e643d4c3eeb`
- Protected base: `d8edb4c4fe30af4c6b7f2d27d48ed917b7464356`
- Canonical command: `uv run --locked --offline --no-sync --group quality python -I scripts/quality.py`
- Terminal result: `QUALITY=PASS`
- Specification snapshot: `SPEC_GATE=PASS`
- Ruff 0.15.22 format/lint: PASS; 113 files formatted
- mypy 2.3.0: PASS; no issues in 113 source files
- pytest 9.1.1: 1448 collected; 1443 passed; 5 skipped; 319.47 seconds
- Core branch coverage: 82.43% (required >=80%)
- Runtime: Windows, Python 3.13.11

Real local qualification used `qwen2.5-coder:7b-instruct-q4_K_M` through
Ollama 0.16.2 and recorded four model receipts plus two RepositoryView tool
receipts. The source-free qualification state is `REAL_EVIDENCE_RECORDED`;
record SHA-256 is
`e0b715509eeb2857ed4aa7878be0bc24f7e543d01da50d2327d288d225f75f81`.
The external source-free record SHA-256 is
`874d1bc1f7c1e860d7848955e472256486ee9c0d723f8e710a8f6cedfa11068d`.
