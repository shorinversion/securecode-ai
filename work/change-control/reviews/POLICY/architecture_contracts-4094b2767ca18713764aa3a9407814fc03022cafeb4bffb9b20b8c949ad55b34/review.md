# CR-053 architecture and contracts review

Verdict: PASS

Reviewer: `codex-terra-architecture-cr053`

Reviewed commit: `364604a67466af78920ce16e8c4ed2e4a21e61fb`

Review subject: `4094b2767ca18713764aa3a9407814fc03022cafeb4bffb9b20b8c949ad55b34`

Promotion subject: `f4d06668f6323987d9eb23b53eaa8172bb30de9a991a833c20c097d2c737b826`

The proposal is a single-parent child of its declared base `3aec841ed5331dfbb67ce3aab99acc2a3d7f999a`; its changed paths equal the closed proposal allowlist. The review subject, evidence bundle, both manifest target-base and final hashes, and the promotion subject independently reproduce.

The target change makes the integrated promotion base candidate-first: an evidence document present in the candidate, including the required `decision.md`, is used as that target's manifest base. The base fallback remains only for promotion paths absent from the candidate. This preserves the explicit `docs/PLAN.md` early-candidate rejection and prevents a candidate decision from being silently replaced with its older base value.

The manifest remains exact-byte-bound and fail-closed: it requires the closed target set, validates every current base and decoded final hash, and binds the length-prefixed promotion subject. The regression test asserts that only absent `docs/PLAN.md` reads from the base; no protected-path weakening, policy bypass, or contract-scope expansion is introduced.

No test runs were performed, as required by the review packet.
