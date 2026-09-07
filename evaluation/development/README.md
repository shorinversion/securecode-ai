# Development educational corpus

This self-authored CC0-1.0 corpus is a narrow P7.6 preparation input for the
first P7.17 diagnostic study. It is not a completed broader P7.6/G7 gate, a
confirmatory benchmark, calibration data, a release claim, or a substitute for
locked inputs. The manifest fixes exactly 24 Python cases across authorization,
path, SQL, and command lineages before any P7.17 observation.

Each case records acquisition instructions, exclusions, status of its candidate
ground truth, source SHA-256 and Git-blob SHA-1 identity, explicit untrusted
source/sink/policy invariant, scanner applicability and receipt, and a case
semantic digest. The corpus digest transitively binds all such metadata, the
oracle bytes, the closed behavioral rule set, and frozen membership. External
sources remain excluded until SC-EVAL-007 resolves their license, immutable
revision, hash, and acquisition procedure.

Digest values use explicit `sha256:` / `sha1:` type prefixes and the starting
revision uses `git:`. The validator removes only the expected prefix before an
exact lowercase-length check and byte-for-byte recomputation; bare high-entropy
strings are not accepted as provenance.

Validate only metadata and bytes from the repository root:

```powershell
python scripts/development_corpus.py --manifest evaluation/development/corpus-manifest.yaml
```

The validator rejects duplicate JSON keys, open/unknown keys, source or Git
identity drift, incomplete provenance, changed membership, incorrect
label/stratum relationships, lineage leakage, scanner-receipt drift, and any
case/corpus semantic-digest drift. It never imports, compiles, or executes a
case or oracle.

`securecode-python-cwe89@1.0` is applicable only to the declared SQL cases:
its source-only evidence model is `request.args.get` → interpolation →
`execute`. The manifest has completed zero-signal receipts for its stated blind
spots and a nonzero direct HTTP-to-SQL positive control. A zero receipt is not a
clean verdict and does not affect the required model-native lane.

The trusted host supervisor retains the manifest, rules, probes, labels and
assertions. The mounted generic worker receives none of them: each Docker run
gets only the worker and the exact primary case source plus an optional
`support.py` dependency, all as separate read-only mounts. It returns one
closed observation frame; only the supervisor evaluates the security property.
It derives outcomes first, then cross-checks `expected_label`; labels never
select an oracle result. A two-phase protocol sends an unpredictable challenge
only after the observation frame and requires the still-running child wrapper
to acknowledge it. Missing, extra, out-of-order, malformed, early-exit,
challenge-mismatch, nonzero, stderr, or timed-out protocol results fail closed.
This is a bounded early-exit/frame-forgery guarantee, not a Python sandbox
against arbitrary deliberately deceptive code; frozen reviewed source bytes,
hidden host predicates and later independent remediation review remain required.
The pinned image digest must already exist locally;
`--pull never` forbids image acquisition, and the wrapper enforces a
60-second wall timeout with named-container cleanup:

```powershell
python scripts/development_corpus.py --manifest evaluation/development/corpus-manifest.yaml --verify-oracles-docker
```

The container has no credentials, network, host socket, writable corpus mount,
or broad development-root mount. It is read-only, runs as uid 65534, drops all
capabilities, uses no-new-privileges, has pids/CPU/RAM bounds and a bounded
noexec tmpfs. The wrapper accepts exactly one complete JSON observation. A
timed-out container is forcibly removed; failed or timed-out cleanup is an
explicit failure. SQL and command probes require bound parameters and
shell-disabled closed argv respectively; SQL PoC+ includes a second payload
that rejects a candidate hard-coded only for the first one. The image is
`python@sha256:e16ab55c341bfd0e7da665bc2d48939cff890b43a41867fe6e1f0690638ceb7c`.

The focused test suite is host data-only by default. To opt in to the same
Docker verification during tests, use:

```powershell
$env:SECURECODE_RUN_DOCKER_ORACLE = '1'
uv run pytest tests/unit/test_development_corpus.py -q --basetemp .test-tmp-p76-docker
Remove-Item Env:SECURECODE_RUN_DOCKER_ORACLE
```
