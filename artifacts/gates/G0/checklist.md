# G0 checklist

Gate: `G0 Definition Ready`  
Baseline: `0.2.0`  
Review date: 13 августа 2026 года

| Check | Evidence | Result |
|---|---|---|
| Original brief preserved | `docs/PROJECT_BRIEF.md` | PASS |
| Material scope changes recorded | `CHANGELOG.md` CR register, `D-001–D-028` | PASS |
| Personas/top journeys | `docs/PRODUCT.md` §2 | PASS |
| Release scope/non-goals | `docs/PRODUCT.md` §11, `D-019` | PASS |
| Python-first/final 3-language decision | `D-017`, `SC-PROD-002` | PASS |
| GitHub-first/minimum permissions | `D-018`, `specs/contracts/scm.md` | PASS |
| Runtime/storage/artifact/sandbox decisions | `D-020–D-023`, system spec | PASS |
| Full threat model | `docs/security/THREAT_MODEL.md`, prompt-injection subset | PASS — design evidence |
| Data/egress/retention | `D-024`, security spec and JSON schemas | PASS |
| Frozen MVP evaluation | `D-025`, `D-028`, protocol/dataset hash/metrics/threshold policy | PASS — definition only |
| Traceability | `specs/traceability/requirements.yaml` | PASS |
| Normative baseline | `specs/` lifecycle frozen, stable IDs/oracles | PASS |
| Machine syntax | JSON/YAML parse; dataset hash matches | PASS |
| Local Markdown references | link-resolution check | PASS |
| Independent product/architecture/security review | `independent-reviews.md`: exact-hash CR-014–016 delta verdicts | PASS — three independent roles |
| Normative content hash | `test-results/prefreeze-validation.md`, `specs/baseline.yaml` | PASS — `dedb43be…54b5c9` |
| Baseline repository commit | `f5cd4ef2a0f7130d16cb2c206091908be71b0702`, strict predecessor/content verification | PASS — immutable predecessor |

No implementation/test claim is made by a definition PASS. Planned oracles
become executable evidence in P1–P9.
