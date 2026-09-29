# Notebooks

- [`securecode_demo.ipynb`](securecode_demo.ipynb) — the main demonstration, stored with
  outputs: the loader and tools (AST, hardcoded secrets, vulnerable dependencies via OSV,
  CWE patterns) on a small Python/JS/Go project, the unified `Evidence` contract, the Auditor
  and Architect on a local Qwen model with a validated Auto-Fix patch, the OWASP Top 10
  report and the benchmark metrics.
- [`mvp_cwe89_demo.ipynb`](mvp_cwe89_demo.ipynb) — the earlier offline CWE-89 reference.

Run from the repository root:

```bash
uv run --with nbconvert --with ipykernel jupyter nbconvert --to notebook --execute --inplace notebooks/securecode_demo.ipynb
```

`SECURECODE_DEMO_PROVIDER` selects the model: `local` (Ollama with
`qwen2.5-coder:7b-instruct-q4_K_M`, default), `deepseek` (`DEEPSEEK_API_KEY` or the root
`.env`) or `offline`. `SECURECODE_DEMO_OSV=0` skips the OSV query, which sends package names
and versions only. Notebooks call public project interfaces and are not an alternate
implementation of the audit pipeline.
