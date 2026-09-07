# P7.17 first development benchmark

The frozen matrix contains 312 cells: deterministic once and each stochastic
configuration three times over 24 reviewed cases. All cells are present in the
raw JSONL. Only the loopback `one_shot_llm` configuration executed: 48/72 calls
produced a closed valid result and 24/72 failed closed as invalid output.

Policy-matched one-shot counts are TP=9, FP=3, FN=27 and TN=24, with nine safe
non-success cells kept as `missing_safe`. Precision is 0.75, recall 0.25,
F1 0.375 and F2 0.28846. The other 240 planned cells are explicit `not_run`;
therefore the study is incomplete and cannot support a comparative conclusion.

Reproduce from the repository root:

```powershell
.venv\Scripts\python.exe scripts/development_corpus.py --manifest evaluation/development/corpus-manifest.yaml --print-tree-hash
.venv\Scripts\python.exe scripts/run_development_benchmark.py --plan evaluation/development/run-plan.yaml --records evaluation/development/results/run-records.jsonl --aggregate evaluation/development/results/aggregate.json
.venv\Scripts\python.exe scripts/recompute_development_benchmark.py --plan evaluation/development/run-plan.yaml --records evaluation/development/results/run-records.jsonl --output evaluation/development/results/recomputed.json
```

The aggregate and independent recomputation must be byte-identical. This is a
development diagnostic only, with no release, calibration, confirmatory or
security claim.

No repair was attempted. The development E2E remediation numerator is zero;
the vulnerable denominators are 12 for deterministic and 36 for each
stochastic configuration (micro denominator 156). Each configuration rate is
therefore 0.0. Frozen attempted-patch repair rates remain null at denominator
zero.
