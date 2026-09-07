# Limitations

The shipped deterministic path does not yet emit policy-matched `CONFIRMED`
findings for this corpus. Scanner-seeded investigation, model-native discovery
and full hybrid execution are also not integrated, so those four configurations
stay `not_run` and remain in their planned denominators.

The one-shot adapter is development-only. It sends a comment/docstring-stripped
source projection to the pinned loopback Ollama model, with opaque file aliases
assigned by a label-blind SHA-256 ordering for location matching. Corpus code is read as data and never executed on the
host. Host proxy use and redirects are disabled; no non-loopback endpoint is
accepted.

The canonical one-shot run used 8,841 prompt tokens and 1,044 generated tokens
across all 72 calls; token facts were retained for all 24 invalid outputs.
Total call wall time was 98.89 seconds, p50 1.220 seconds and p95 1.822 seconds.
Twenty-four calls returned invalid structured output. Provider
cost and RAM/VRAM/CPU measurements are unknown, not zero. Ollama does not offer
a study seed here; temperature was fixed to zero but bitwise reproducibility is
not claimed.

The small corpus has an unavoidable topology confound: every current inter-file
case is vulnerable, while all safe controls are single-file. Alias permutation
prevents a fixed primary-file position from leaking the oracle, but file count
can still correlate with the label. Adding safe inter-file controls requires a
separate reviewed corpus change; these results must not be used for calibration.

The run manifest binds local-native Windows 11 AMD64, CPython 3.13.11, the exact
`uv.lock` digest, all benchmark/evaluator components, and reproduction commands.
No evaluation container image was used; `evaluation_image` is explicitly null.

An earlier exploratory run exposed expectation-bearing docstrings and used one
repetition. Its binary counts are contaminated and were rejected before this
canonical run; they are not P7.17 evidence. No repair was attempted, so repair,
validation-ladder evidence is unavailable. The development E2E rate is zero
over every vulnerable planned cell because no repair was attempted; frozen
attempted-patch rates are null at denominator zero.
