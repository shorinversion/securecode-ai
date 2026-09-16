# P7.17 development benchmark

The analyzed product candidate is
`ea9fc70427acadb5b06206144c5ea95c42c8b9ce`. The frozen development matrix
contains 312 cells over all 24 reviewed cases: deterministic once and each
stochastic configuration three times. Every planned cell is present exactly
once in the raw JSONL and no cell is `not_run`.

| Configuration | Executed | Failed | TP | FP | FN | TN | Precision | Recall | F1 | F2 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deterministic only | 24 | 0 | 1 | 0 | 11 | 12 | 1.0 | 0.08333 | 0.15385 | 0.10204 |
| scanner-seeded investigation | 69 | 3 | 0 | 0 | 36 | 36 | null | 0.0 | null | null |
| model-native only | 0 | 72 | 0 | 0 | 36 | 0 | null | 0.0 | null | null |
| one-shot LLM | 48 | 24 | 9 | 3 | 27 | 24 | 0.75 | 0.25 | 0.375 | 0.28846 |
| full hybrid | 0 | 72 | 0 | 0 | 36 | 0 | null | 0.0 | null | null |

Scanner-seeded investigation made three model calls for the only sealed scanner
seed and failed closed on all three invalid structured outputs. Its remaining
69 zero-seed cells executed without invoking independent model discovery.
Model-native-only and full hybrid each attempted all 72 planned calls, but every
response failed the exact structured-finding contract. One-shot attempted all
72 calls and retained 24 invalid structured outputs as failures.

Because 171 model cells failed, the study remains incomplete even though every
planned cell was attempted and recorded. The result compares the current bound
prompt contracts; it is not a comparative quality verdict or a release result.
The full-hybrid SC-EVAL-018 reconciliation is internally complete, but all 72
full-hybrid cells failed structured-output validation: its zero-scanner stratum
is incomplete and deterministic-candidate Auditor receipt coverage is 0/3.

Reproduce from the repository root:

```powershell
.venv\Scripts\python.exe scripts\development_corpus.py --manifest evaluation\development\corpus-manifest.yaml --print-tree-hash
.venv\Scripts\python.exe scripts\run_development_benchmark.py --plan evaluation\development\run-plan.yaml --records evaluation\development\results\run-records.jsonl --aggregate evaluation\development\results\aggregate.json
.venv\Scripts\python.exe scripts\recompute_development_benchmark.py --plan evaluation\development\run-plan.yaml --records evaluation\development\results\run-records.jsonl --output evaluation\development\results\recomputed.json
```

The aggregate and independent recomputation are byte-identical at SHA-256
`deae563fe08580a2ed3dc447ba19d020f31e63797eb8b83c8b6737ad3a674407`.
No repair was attempted. The development E2E remediation numerator is zero and
all per-configuration remediation rates are zero over their frozen vulnerable
denominators; attempted-patch quality rates remain null at denominator zero.
This is a development diagnostic only, with no calibration, confirmatory,
release or security claim.
