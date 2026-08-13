# SecureCode AI — system threat model

Версия: `0.2`  
Статус: `accepted for G0 baseline`  
Дата: 12 августа 2026 года  
Владелец: Primary Integrator; security acceptance owner — AppSec reviewer.

Этот документ дополняет focused model
[PROMPT_INJECTION.md](PROMPT_INJECTION.md) и покрывает весь продукт. Он не
является заявлением о compliance или гарантии отсутствия уязвимостей.

## 1. Scope и security objectives

В scope входят offline CLI, CI worker, backend control plane, GitHub/GitLab
adapters, model endpoints, persistent stores, artifacts, sandbox validation и
изолированный P7 Evaluation Lab с optimizer/generated-program execution.

Приоритетные objectives:

1. недоверенный repository не управляет policy, evaluator, credentials или
   privileged tools;
2. код, secrets и tenant data не выходят за разрешённую data boundary;
3. finding, patch, waiver и SCM status относятся к точному repository/HEAD SHA;
4. только положительно подтверждённое mandatory coverage разрешает `PASS`;
5. выполнение untrusted build/test изолировано, ограничено и уничтожается;
6. решения и provenance нельзя незаметно подменить или отрицать;
7. отказ компонента ограничивается budget и не превращается в false clean.

## 2. Assets и actors

| Asset | Максимальный impact | Защита |
|---|---|---|
| Proprietary source, prompts, diffs, logs | C: high | classification, runner locality, encryption, retention |
| Secrets, SCM/model credentials, private keys | C/I: critical | `DC4`, secret references, redaction, short-lived tokens |
| Evidence, findings, patch/validation result | I: high | SHA/content hashes, append-only provenance, independent validation |
| Policy, evaluator, schemas, workflow | I: critical | versioning, protected paths, review, signed release evidence |
| Tenant identity, approvals and waivers | C/I: high | authn/z, tenant scope, expiry, audit |
| CI check and PR/MR comments | I/A: high | webhook verification, SHA gate, idempotency |
| Service capacity and model budget | A/cost: high | quotas, bounded loops, circuit breakers |
| Supply-chain artifacts | C/I/A: high | lockfiles, SBOM, provenance, digest-pinned images |
| Locked expectations, evaluator, prompt/skill candidates, synthetic cases | I/C: critical | split isolation, protected paths, immutable candidate provenance, human promotion |

Threat actors: malicious contributor; malicious or compromised maintainer;
tenant user/admin; platform insider; external unauthenticated attacker;
compromised SCM, runner, model provider, scanner, dependency or base image; and
compromised optimizer/generated program, poisoned synthetic-case source; and
accidental operator/developer error.

## 3. Data-flow and trust boundaries

```text
TB1 Internet/SCM
  webhook + metadata
        ↓
TB2 Control plane ── metadata/policy/artifact refs ── TB3 PostgreSQL/BlobStore
        │ workflow task, never raw checkout by default
        ↓
TB4 Customer CI runner / worker
  checkout → inventory/scanners → EvidencePackage → model endpoint (policy)
        │                                      ↘ TB6 Approved provider
        ↓
TB5 Ephemeral sandbox
  patch apply → build/tests/security tests → redacted validation evidence
        ↓
TB2 → SHA-bound check/comment/report → TB1

TB7 Isolated Evaluation Lab
  train/dev + immutable CodeIndex → no-network generated-program sandbox
  → versioned candidate → held-out/security/human promotion gate
```

- `TB1`: all SCM text, refs and events are untrusted until authenticated and
  bound to fetched repository state.
- `TB2`: control plane is trusted for routing/audit, not for receiving source in
  `no_code_egress`.
- `TB3`: each record/object is tenant-scoped; storage administrators remain a
  residual insider risk.
- `TB4`: runner may contain customer credentials and code; repository content
  cannot access them merely by being scanned.
- `TB5`: arbitrary repository code can execute only here under explicit policy.
- `TB7`: optimizers and generated programs have no production credentials,
  locked-test expectations, network, writable evaluator/policy/spec paths or
  direct production alias; promotion crosses an explicit human-reviewed gate.
- `TB6`: provider capability, retention and residency are verified configuration,
  never inferred from an API-compatible URL.

## 4. Capability model

Agents receive typed, task-specific capabilities rather than a generic shell or
URL fetcher. Auditor and Skeptic are read-only. Architect may emit a diff but
cannot apply it outside the sandbox. Validator consumes a candidate and cannot
rewrite policy, test oracle or evaluator. Network, filesystem and SCM writes are
deterministic host operations guarded by policy and schema validation.

Any content from code, comments, docs, filenames, commits, SCM discussion,
scanner output, build logs or model output has `instruction_authority=NONE`.

## 5. Risk register

`P/I`: likelihood and impact before controls (`L/M/H/C`). Residual risk is
accepted only for the named phase and is reviewed at every gate.

| ID | STRIDE/privacy | Threat/abuse case | P/I | Required mitigation | Verification oracle | Residual/owner |
|---|---|---|---|---|---|---|
| `TM-001` | S/T | Forged/replayed webhook starts a run | H/H | HMAC/signature, timestamp window, delivery-id inbox, idempotent start | invalid/replayed fixtures create 0/1 semantic run respectively | L / Platform |
| `TM-002` | T | Ref/SHA substitution or stale run updates newer check | M/C | fetch exact SHA, record base/head, publish only current HEAD, supersede old run | race test never changes new check | L / SCM adapter |
| `TM-003` | T/E | Symlink, submodule, LFS, archive or path escape reads host | H/C | no-follow inventory, canonical workspace boundary, deny active hooks, size/depth limits | traversal corpus cannot access canary outside workspace | M / Core |
| `TM-004` | D | Decompression/history/context bomb exhausts resources | H/H | file/repo/token/node/time/output budgets and early inventory | each bomb stops with bounded explicit outcome | L / Core |
| `TM-005` | T/E | Parser/scanner/config/plugin exploit or output poisoning | M/C | pinned isolated tools, config denylist, typed adapters, timeouts, untrusted output labels | malicious tool fixtures cannot mutate policy/host | M / Tool owners |
| `TM-006` | E/I | Repository lifecycle scripts execute during dependency/build step | H/C | no install/build outside sandbox; ignore repository bootstrap config by default | sentinel lifecycle script never runs in analysis plane | L / Sandbox |
| `TM-007` | I/E | Direct/indirect prompt injection changes policy or suppresses finding | H/C | authority labels, minimal context, typed outputs, least privilege, independent gates | injection corpus produces no unauthorized transition | M / AI security |
| `TM-008` | D/I | Refusal/filter/empty/invalid response becomes no-finding | M/C | separate `ModelCallStatus`, verdict and run outcome; bounded fallback | `non_success_to_pass_count == 0` | L / Orchestrator |
| `TM-009` | E | LLM selects arbitrary shell/network/tool arguments | H/C | allowlisted granular tools, strict argument schemas, deterministic authorization | denied tool/argument cases execute zero side effects | L / Core |
| `TM-010` | I | Architect/evaluator modifies tests, policy or protected evidence | M/C | path allowlists, separate writer/evaluator, protected-path diff gate | tamper fixtures fail before validation approval | L / Validator |
| `TM-011` | E/C | Sandbox escape via root/container socket/host mount | M/C | rootless local OCI; gVisor pilot; no socket/host mounts/capabilities; non-root/seccomp | escape canaries cannot reach host; runtimeClass verified | M / Platform |
| `TM-012` | C/D | Network/DNS exfiltration, fork/process/disk/output bomb | H/C | default-deny egress, enforcing CNI/proxy, cgroup/resource limits, teardown | network and resource abuse suite is contained | M / Platform |
| `TM-013` | C | Secret leaks through prompt/output/log/trace/report/comment/DNS | H/C | `DC4` quarantine, redaction before egress/sink, canary scans, no raw telemetry | canary absent from all captured sinks | M / Security |
| `TM-014` | E/C | SSRF via provider URL, redirect or DNS rebinding | H/C | canonical allowlist, HTTPS/local exception, resolve/revalidate IP, deny metadata/private targets | redirect/rebinding/private-IP suite denied | L / Egress |
| `TM-015` | E/C/I | BOLA/IDOR or cache/artifact cross-tenant leak | M/C | tenant in every key, application authz, PostgreSQL forced RLS defense-in-depth, separate artifact prefix | forged tenant IDs and cache keys disclose nothing | M / Backend |
| `TM-016` | E/I | Waiver/suppression abused or applied to another scope/SHA | M/H | RBAC, exact scope/SHA, reason, expiry, two-person policy for critical cases | replay/cross-scope/expired waiver denied | L / AppSec |
| `TM-017` | T/R | Evidence, audit event or artifact is deleted/substituted | M/H | append-only events, content hashes, versioned policy, immutable approved exports | tampered bytes/hash or missing predecessor rejected | M / Platform |
| `TM-018` | T | Malicious diff writes outside checkout or semantic backdoor passes weak tests | H/C | strict unified-diff parser, path boundary, PoC+, existing tests, post-scan, human gate | path/tamper/regression fixtures rejected | M / Validator |
| `TM-019` | T/C | Provider/model alias downgrade, replay or shared-memory poisoning | M/H | pinned profile/snapshot where possible, native request IDs, no cross-tenant memory/cache, capability check | downgrade/replay/cache-isolation tests fail closed | M / Provider owner |
| `TM-020` | D | Correlated provider outage/refusal causes retry amplification | H/H | bounded attempts, circuit breaker, budget, explicit indeterminate/escalation | call count/cost stays within run budget | L / Orchestrator |
| `TM-021` | T/E | Compromised dependency, action, scanner, rule or base image | M/C | locked dependencies, digest pins, SBOM/provenance/signature, isolated updates and review | modified/untrusted artifact fails verification | M / Supply chain |
| `TM-022` | T/I | HTML/Markdown/SARIF/terminal escape exploits reviewer/UI | M/H | context-aware escaping, safe links, schema validation, terminal control stripping | rendering corpus is inert in each sink | L / Reporters |
| `TM-023` | D | Webhook storm/noisy tenant starves others | H/H | per-tenant quotas, admission control, fair queues, cancellation and backpressure | load fixture preserves configured fairness/SLO | M / Platform |
| `TM-024` | R | Insider changes policy/evaluator or deletes evidence | M/C | least privilege, two-person review, protected release evidence, external audit export | privileged change creates immutable audit signal | M / Governance |
| `TM-025` | T/E/C | Offline optimizer or RLM-generated program reads locked expectations/protected files, exfiltrates source, expands capabilities or self-promotes | H/C | isolated train/dev workspace, immutable read-only CodeIndex, no network/credentials, protected paths, bounded execution, independent promotion review | candidate with locked-test access, unauthorized operation, leak or self-promotion is rejected with zero production change | M / Evaluation |
| `TM-026` | T/R | Synthetic cases poison evaluation through wrong oracle, duplicates or train/test lineage leakage | M/H | fixed seed/generator hash, executable oracle, independent root-cause review, lineage grouping and rejection archive | no accepted case lacks oracle/provenance; split checker finds zero lineage intersection | L / Evaluation |

### 5.1. LINDDUN-like privacy register

This is a scoped privacy-threat analysis, not a compliance claim. Repository
identity, locations, evidence topology and timing can identify or link a project
even when raw source is absent.

| ID | Privacy property | Threat/abuse case | Required control | Verification oracle | Residual/owner |
|---|---|---|---|---|---|
| `PV-001` | Linkability | Stable repository/finding identifiers correlate activity across tenant, provider, telemetry or exports | tenant/purpose-scoped identifiers; no cross-purpose global fingerprint; classified provenance | same input in two tenants/purposes yields unlinkable external identifiers and no shared cache hit | M / Privacy owner |
| `PV-002` | Identifiability + detectability | Paths, CWE combinations, timings, existence probes or comments reveal a private repository/person | minimize/aggregate telemetry; safe paths; tenant authz; non-disclosing `404`; bounded SCM publication | cross-tenant ID/path and traffic-shape fixtures reveal neither existence nor identity beyond approved sink | M / Backend |
| `PV-003` | Non-repudiation/excess audit | Immutable audit data unnecessarily exposes individual developer activity or raw source | immutable only non-source approved exports; role/purpose-scoped access; retention/appeal policy | ordinary user cannot browse unrelated actor history; WORM source rule is rejected; approved export records purpose | M / Governance |
| `PV-004` | Unawareness/purpose misuse | Source-derived data is reused for training, analytics or a new destination without tenant awareness | explicit provider data terms, purpose-bound egress, admin authorization and user/admin documentation | undeclared training/analytics purpose or destination produces zero bytes; policy change records actor/time/purpose | L / Platform admin |
| `PV-005` | Non-compliance/deletion | Expired data survives in cache, backup, derived artifact or provider retention; deletion is overstated | class/type/profile retention, descendant inventory, provider evidence, deletion result without physical-erasure promise | expired object and descendants are inaccessible; reconciliation records remaining external limits and outcome | M / Data owner |

Purpose limitation, minimization, tenant-visible export/delete controls and these
oracles apply even when raw source is not stored.

## 6. Supply-chain and operations controls

- dependencies and container images are locked; production images use digests;
- CI actions/workflows are pinned and reviewed; release artifacts receive SBOM,
  provenance and signatures before `G8`;
- rule/model/prompt/evaluator changes are versioned and cannot silently alter a
  previous run;
- incident response supports kill switch, credential revocation, tenant
  containment, forensic preservation, notification and tested restoration;
- backup and export paths are tested with tenant isolation and retention rules;
- sandbox compromise is assumed possible: it has no signing keys, SCM write
  tokens, provider admin credentials or control-plane database credentials.

## 7. Gate acceptance

This threat model satisfies `P0.10` definition work only when:

1. every `TM-*` maps to at least one normative requirement and planned test;
   every `PV-*` has the same requirement/task/test traceability;
2. all `critical` impacts have a preventive control plus detection/recovery;
3. `TM-001/002/003/007/008/009/011/012/013/014/015/018/021` appear in the
   first security conformance backlog;
4. the G0 reviewer records residual risks and does not mark implementation
   controls as already proven;
5. changes to architecture/data flow trigger threat-model review.

Primary reference framing: [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final),
[SLSA threats](https://slsa.dev/spec/v1.2/threats),
[OWASP GenAI Top 10](https://genai.owasp.org/llm-top-10/) and
[NIST AI 100-2](https://csrc.nist.gov/pubs/ai/100/2/e2025/final). These sources
inform the catalogue; they do not certify SecureCode AI.
