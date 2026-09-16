# Limitations

The deterministic baseline is the shipped sealed Python CST/AST plus CWE-89
scanner. It has no path, command or authorization rules, so its low recall over
the four-category corpus is expected coverage evidence rather than a broad SAST
quality estimate.

All five configurations are integrated and all 312 planned cells were attempted
and recorded. The study is still incomplete: exact structured-output validation
failed for 3 scanner-seeded, 72 model-native, 24 one-shot and 72 full-hybrid
cells. Failed vulnerable cells remain FN and failed safe cells remain
`missing_safe`; none are silently treated as clean or removed from denominators.

The model adapters are development-only. One-shot and model-native send all
comment/docstring-stripped source projections; model-native uses a distinct
independent-discovery prompt without scanner facts. Scanner-seeded sends only
the projections named by sealed scanner facts and makes no model call when the
seed set is empty. Full hybrid sends all projections plus the exact sealed seed
facts. Opaque aliases use label-blind SHA-256 ordering. Corpus code is read as
data and never executed on the host. Host proxy use and redirects are disabled;
no non-loopback endpoint is accepted.

The run used Ollama 0.16.2 and
`qwen2.5-coder:7b-instruct-q4_K_M` at digest
`dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75ed87571486f4364`.
Across 219 model calls the run recorded 31,857 prompt tokens and 3,415 generated
tokens. One-shot used 8,841/1,044 tokens and 100.13 measured seconds;
model-native 10,353/1,266 and 116.62 seconds; full hybrid 12,168/1,036 and
101.83 seconds; scanner-seeded 495/69 and 5.39 seconds, with only three actual
model calls. Provider cost and RAM/VRAM/CPU measurements are unknown, not zero.
Seed support is unavailable; temperature was zero but bitwise reproducibility
is not claimed.

DeepSeek was not called in this candidate: the active project workflow forbids
DeepSeek services. Older external exploratory results bind different code and
are excluded from this run rather than mixed into current evidence.

The small corpus has a topology confound: current inter-file cases are
vulnerable while safe controls are single-file. Alias permutation prevents a
fixed primary-file position from leaking the oracle, but file count can still
correlate with the label. Adding safe inter-file controls requires a separately
reviewed corpus change; these results must not be used for calibration.

The run binds local-native Windows 11 AMD64, CPython 3.13.11, the exact
`uv.lock`, corpus, candidate, model, all four prompt templates, policy, schema
1.1 and evaluator component hashes. No evaluation container image was used. No
repair was attempted, so repair and validation-ladder evidence is unavailable;
P7.17 is not complete and the aggregate cannot establish G7 or G9.

The SC-EVAL-018 section preserves each predeclared repetition as a separate
matrix cell and reconciles all attributed full-hybrid TP/FP plus unattributed
FN/TN/missing-safe to the global matrix. All full-hybrid model responses were
invalid, so the zero-scanner stratum is incomplete and the three
deterministic-candidate cells have no valid Auditor receipt. The report exposes
that 0/3 coverage as a failure; it does not infer an origin-specific recall or
drop the candidates.

The integrated M-A2026 candidate passed the canonical local quality wrapper:
specification snapshot, formatting, lint, strict types and 1,613 tests passed,
with ten expected platform or opt-in Docker skips and 81.61% Core branch
coverage. The separate opt-in Docker suite passed all 22 corpus tests. These
checks validate the integrated candidate mechanics; they do not make this
incomplete development study confirmatory or release evidence.
