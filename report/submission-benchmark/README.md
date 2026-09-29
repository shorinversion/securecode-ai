# SecureCode AI: expanded submission benchmark

**Результат анализа завершён 27 сентября 2026 года.** Все шесть конфигураций имеют проверяемые результаты на 600 кейсах, но часть сравнений является архивной или вычислена как парная композиция. Это диагностический бенчмарк, а не подтверждение точности полного SecureCode AI pipeline и не доказательство превосходства над SAST.

**Analysis completed on 27 September 2026.** All six configurations have auditable results on 600 cases, but some comparisons reuse archived outputs or are paired post-hoc compositions. This is a diagnostic benchmark, not an accuracy claim for the complete SecureCode AI pipeline and not evidence of superiority over SAST.

## Краткий вывод

На held-out части hybrid-композиция получила recall 27.8%, Semgrep 32.5%. Разница hybrid минус Semgrep равна -4.7 процентного пункта; lineage-cluster bootstrap 95% interval составляет от -13.9 до +4.7 п.п. Интервал включает ноль. Hybrid-композиция также завершила только 130 из 240 held-out cases, поскольку deterministic scanner завершился ошибкой на 110 кейсах этой части.

В полном корпусе сканер завершился на 347 из 600 кейсов. Оставшиеся 253 ошибки сохранены в знаменателе как `scanner-failed`. Поэтому результат не подтверждает, что SecureCode AI полезнее статического анализатора. Он показывает конкретные текущие ограничения, а не успешность релизного критерия.

## Executive result

On the held-out split, the derived hybrid lane reached 27.8% recall and Semgrep reached 32.5%. The hybrid-minus-Semgrep difference is -4.7 percentage points; the lineage-cluster bootstrap 95% interval is -13.9 to +4.7 pp and includes zero. The hybrid composition completed only 130 of 240 held-out cases because the deterministic scanner failed on 110 cases in that split.

Across the full corpus, the scanner completed 347 of 600 cases. The other 253 failures remain visible as `scanner-failed`. These results do not show that SecureCode AI is more useful than static analysis. They document current limits and do not meet a release-quality claim.

## Corpus and protocol

- 600 public CVEfixes v1.0.8 file revisions: 200 Python, 200 JavaScript/TypeScript and 200 Go.
- The public source dataset is [CVEfixes v1.0.8 on Zenodo](https://zenodo.org/records/13118970). This repository retains only the source-free manifest, not the SQLite database or project source.
- 300 vulnerable/fixed lineage pairs. Splits are development 240, calibration 120 and held-out 240, with no lineage crossing a split. Each language has 80/40/80 cases.
- Dataset content digest: `sha256:24003f707114d46af60391bfd15ee8d8ad11c4e649309a3f24296c66268dd9c6`.
- Metadata manifest SHA-256: `82459c8c5112105535f0424d715777a03dbc00e82160e264ed8059aac1db897c`.
- A source cache check recomputed all 600 source hashes with zero mismatches. The cache and source blobs are not included in this report. The dataset manifest records `NOASSERTION` for licensing.
- The manifest's NOASSERTION value is not a redistribution grant. Verify the dataset terms and the license of each upstream source before redistributing source files.
- The archived candidate source manifest records 603 repository files, SHA-256 `d12e34b2623a0747c1800aab344fb72dd34ef9f68e95609dc5653c20621939b1`. It was based on HEAD `88595ae7f50be5906defee9d06e6186ce66ee1f8` plus those content-pinned worktree files. The benchmark was not recomputed against this final worktree; the metrics below remain archived for the prior candidate. The archived DeepSeek direct lanes use the earlier profile pin `c3074e7d816a295675a6ad09612c4567606ac8b5242e4b237a7ba781fff994d0`, retained in `model-profile.json`.
- Current-tree focused checks: 140 product audit/scanner/worker/portfolio tests passed; 155 AST/CST, secret/dependency, repository-tool, multilanguage, Auditor-contract and repair tests passed. Ruff format/check and mypy passed on all eight changed production/test files. The full pytest run did not return a final count within the five-minute tool window. These targeted checks do not update the archived benchmark candidate or replace full-tree quality.
- Model repetitions stay grouped by lineage in 5,000 deterministic bootstrap samples. Repeated cells are not treated as independent source cases.

## Results across all cases

Cells from 3-repeat model lanes are shown together, so their confusion counts are three times the case-level counts. Semgrep's raw output has 1,800 rows, but the three predictions for each case were verified identical, so only repetition 1 is scored. The `valid` column is completed scored cells divided by all scored cells. Hybrid rows marked `scanner-failed` retain their model prediction for diagnostic scoring, while the failed status remains in the completion denominator. The hybrid and scanner-seeded rows were generated after the direct runs by reusing paired outputs; they made no new model requests.

| Configuration | Cases x repetitions | Cells | TP | FP | TN | FN | Precision | Recall | F1 | Valid | New API calls |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Deterministic only | 600 x 1 | 600 | 59 | 61 | 239 | 241 | 49.2% | 19.7% | 28.1% | 57.8% | 0 |
| Scanner-seeded, derived | 600 x 1 | 600 | 14 | 14 | 286 | 286 | 50.0% | 4.7% | 8.5% | 57.8% | 0 |
| DeepSeek model-native, archived direct lane | 600 x 3 | 1,800 | 151 | 148 | 752 | 749 | 50.5% | 16.8% | 25.2% | 100% | 1,800 |
| DeepSeek one-shot, archived direct lane | 600 x 3 | 1,800 | 204 | 188 | 712 | 696 | 52.0% | 22.7% | 31.6% | 100% | 1,800 |
| Full hybrid, derived paired union | 600 x 3 | 1,800 | 288 | 289 | 611 | 612 | 49.9% | 32.0% | 39.0% | 57.8% | 0 |
| Semgrep 1.177.0, pinned baseline | 600 requested, 1 scored | 600 | 103 | 103 | 197 | 197 | 50.0% | 34.3% | 40.7% | 100% | 0 |

The precision, recall and F1 cluster-bootstrap intervals for every lane are in [`aggregate.json`](aggregate.json). Full metrics by language, split and all 79 CWE groups are in [`stratified-metrics.csv`](stratified-metrics.csv). The machine-readable hash record is [`aggregate-output-manifest.json`](aggregate-output-manifest.json). Read the standalone [HTML report](report.html) or printable [PDF report](../../site/benchmark.pdf).

## Held-out results by language

All rows below use the 80 held-out cases per language. Model and hybrid metrics pool three predictions per case; Semgrep uses the first of three identical repetitions. The hybrid completion rate exposes scanner failures rather than silently treating them as completed scans.

| Language | Lane | Completed | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Python | Model-native | 100% | 25 | 31 | 89 | 95 | 44.6% | 20.8% | 28.4% |
| Python | One-shot | 100% | 38 | 38 | 82 | 82 | 50.0% | 31.7% | 38.8% |
| Python | Full hybrid, derived | 73.8% | 51 | 55 | 65 | 69 | 48.1% | 42.5% | 45.1% |
| Python | Semgrep | 100% | 18 | 18 | 22 | 22 | 50.0% | 45.0% | 47.4% |
| JavaScript/TypeScript | Model-native | 100% | 7 | 8 | 112 | 113 | 46.7% | 5.8% | 10.4% |
| JavaScript/TypeScript | One-shot | 100% | 13 | 14 | 106 | 107 | 48.1% | 10.8% | 17.7% |
| JavaScript/TypeScript | Full hybrid, derived | 70.0% | 31 | 32 | 88 | 89 | 49.2% | 25.8% | 33.9% |
| JavaScript/TypeScript | Semgrep | 100% | 13 | 14 | 26 | 27 | 48.1% | 32.5% | 38.8% |
| Go | Model-native | 100% | 15 | 12 | 108 | 105 | 55.6% | 12.5% | 20.4% |
| Go | One-shot | 100% | 21 | 17 | 103 | 99 | 55.3% | 17.5% | 26.6% |
| Go | Full hybrid, derived | 18.8% | 18 | 15 | 105 | 102 | 54.5% | 15.0% | 23.5% |
| Go | Semgrep | 100% | 8 | 7 | 33 | 32 | 53.3% | 20.0% | 29.1% |

The numbers above score the three repeated model or Semgrep predictions together for the same 80 cases per language. The full split-by-language and split-by-CWE table in the CSV retains exact cell denominators.

## Provenance and cost

- Deterministic-only was freshly run from the pinned manifest in twelve validated 50-case shards. Merged output SHA-256: `27bae515b20a1f20d929ea7d0d1e6ee9dff7a2d66462697933a8d54d1711e7cf`.
- Model-native and one-shot outputs were complete archived direct classifications, not newly rerun in this pass. Their output SHA-256 values are `78faeca8574564702b82abfffa7b39a6a67a5209a92838dbaddf93d50bbb7272` and `5b567b6493d2e20437acd6b5efde02c83c7b21ef34fc2b23c4bf84235ca8b467`.
- Semgrep output SHA-256: `209f4bfc996d44a926fdf4d8b0fe1f40467b039b212dc01f89cf1528d36688b6`. Version 1.177.0 used `semgrep/semgrep-rules` commit `a84ff9cc2453ca91d581380de4b8b3f272f6f4be`. Its score is a broad any-finding-in-file policy, not a CWE-aligned comparison.
- Three Semgrep rows per case were present in the archived output and had identical class labels and completion statuses. The report keeps the full raw output hash, verifies the repeated values, and scores repetition 1 only.
- `scanner_seeded` reuses 120 model-native predictions on deterministic-positive cases. `full_hybrid` is a Boolean union of the same-case model-native prediction and deterministic signal for each repetition. Both are post-hoc analyses, recorded in [`lane-composition.json`](lane-composition.json), with zero new API requests. They are not runs of the full SecureCode agent pipeline.
- Raw-cell API cost for the scored model-native and one-shot outputs is $2.564667 + $2.567055 = $5.131722. The cumulative final-scope ledger records 6,921 settled attempts costing $10.270833 and 11 pending reservations of $0.037515, for $10.308348 settled-plus-reserved exposure. This ledger includes retries, prior corrected runs and an interrupted duplicate rerun; it is broader than cost of the scored output cells. The separate development ledger records $0.000248 settled.
- A redundant remote rerun ended before any result file was written: 1,300 of 1,304 attempts settled for $2.242200, with four pending reservations of $0.007296. These calls are excluded from benchmark scores.
- The model profile pins DeepSeek V4.1 Flash, alias `deepseek-flash`, temperature 0, JSON mode and reasoning disabled. The recorded off-peak prices are $0.15/M uncached input tokens and $0.60/M output tokens, checked against the [official pricing page](https://api-docs.deepseek.com/quick_start/pricing/) on 27 September 2026.
- Archived direct model outputs predate the current scanner exception-accounting fix. Their archived plan and profile hashes remain available as [`run-plan-direct-baselines.json`](evidence/run-plan-direct-baselines.json) and [`model-profile.json`](evidence/model-profile.json).

## Demo evidence

The current real-local rerun is recorded in [`evidence/current-real-local-p917.json`](evidence/current-real-local-p917.json). Ollama 0.34.4 served `qwen2.5-coder:7b-instruct-q4_K_M` (`Q4_K_M`, digest `dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`) through literal loopback. The model and deterministic lane agreed on one Python CWE-89 candidate at `app.py:4`; the separate local repair request completed but did not emit a patch (`NOT_PROPOSED`). The result is `INDETERMINATE`; patch applicability, syntax, and security regression checks were not performed, and the source checkout stayed unchanged.

An earlier, separate local run is retained in [`report/m-a2026/evidence/p917-real-local/p917-local-demo.json`](../m-a2026/evidence/p917-real-local/p917-local-demo.json). That run used Ollama 0.16.2 and recorded a proposed patch plus successful ephemeral parse/rescan, without changing the original checkout. It did not run behavioral security tests, and its patch bytes are not published. Do not merge it with the current run. Neither one-case run is benchmark evidence or a general repair claim. The [M-A2026 PDF and HTML](../m-a2026/README.md) document an earlier 312-cell development study and remain a separate historical snapshot.

## Interpretation and limitations

1. The full-hybrid recall is 2.3 percentage points below Semgrep across all cases and 4.7 points below on held-out. The paired 95% interval includes zero. The release target of at least 90% lower-bound precision and at least 5 points recall improvement over SAST is not met.
2. The model-native and one-shot lanes classify public source directly with an API. They do not execute the complete product chain of scanners, EvidenceGraph, Auditor, Skeptic, validation and verdict.
3. The scanner-seeded and full-hybrid configurations are paired post-hoc compositions. Their results are useful ablations, but they are not live end-to-end product runs.
4. Deterministic scanner failures affect 253/600 cases. The scanner completed 154/200 Python, 148/200 JavaScript/TypeScript and 45/200 Go cases. Failed cells remain explicit in the CSV and completion denominators.
5. Semgrep's broad file-level any-finding rule has a different granularity from CWE-specific product findings. This is not a fully equivalent SAST baseline.
6. No full repair study was performed. Zero unsafe-patch counters mean no such measurements were recorded, not that patches are safe.
7. The corpus is public, one-file-per-case, and not balanced across 79 CWE labels. Private-repository generalization is unknown. Its license field is `NOASSERTION`; source code is not redistributed here.
8. RAM/VRAM and end-to-end scan time were not measured. Reported latency is the model or scanner call latency captured in individual cells.
9. This report is not a G7/G9 review, release decision, v1.0 claim or production-readiness claim. The bundled M-A2026 snapshot still has status `NOT_READY`.

## Reproduce the analysis

From the repository root, with the existing locked local environment:

```powershell
uv run --locked --offline --no-sync --group quality python report/submission-benchmark/aggregate_benchmark.py
```

The command validates each output row against the frozen source-free manifest, verifies case labels and repetition counts, computes aggregate/stratified metrics and cluster-bootstrap intervals, and rewrites the aggregate hash manifest. It does not execute CVEfixes source or contact DeepSeek/Semgrep. The deterministic scan outputs and archived raw lane files are required inputs.
