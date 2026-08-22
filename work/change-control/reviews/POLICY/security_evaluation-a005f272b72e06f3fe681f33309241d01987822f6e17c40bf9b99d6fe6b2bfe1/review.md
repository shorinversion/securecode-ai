# CR-043 security and evaluation review

Verdict: PASS

The exact proposal, sequential predecessor reviews and all declared identities
verify. Decoded final hashes match for the CI evaluator and focused tests.

The amendment admits exactly two complete dependency states for the adapters
package: the legacy exact Core-only list, or that same Core dependency followed
by `tree-sitter>=0.25,<0.26` and `tree-sitter-python>=0.25,<0.26`. Equality is
ordered and exact, so reordering, duplication, spelling aliases, URL/direct
references, widened or prerelease ranges, omitted members and additional
grammars fail closed. Existing closed project keys, build backend, module
ownership and workspace-source checks remain unchanged.

The policy-first legacy state is limited to this transition and does not permit
P2.3 to select arbitrary dependencies. The later package change must use the
reviewed final state, while existing root metadata and lock validation continue
to require the sole PyPI index, approved artifact host and SHA-256 integrity for
registry artifacts. Ordinary locked installation and protected CI remain
required. No secret scanner, baseline, workflow, permission, accepted spec or
gate behavior changes.

I executed the decoded final evaluator in memory against both admitted states
and adversarial reorder, duplicate, direct-URL, widened-range, prerelease-range,
normalized-name alias and extra-grammar mutations; every mutation was rejected.
No fail-open dependency, source, integrity, transition or evaluation blocker.
