# CR-043 architecture and contracts review

Verdict: PASS

The decoded amendment is architecturally coherent. Tree-sitter and its Python
grammar are third-party parsing mechanisms, so they belong in the adapters
package beside its existing dependency on Core. The change does not introduce
an adapter dependency into Core or contracts, alter the public contract layer,
or create a second implementation path for the P2.3 symbol index.

The policy transition is closed to exactly two dependency states for the
adapters package: the current Core-only state and the reviewed state containing
Core plus `tree-sitter>=0.25,<0.26` and
`tree-sitter-python>=0.25,<0.26`. This policy-first transition permits the
later P2.3 package and lock update without temporarily weakening CI. All other
package metadata, dependency names, versions and sources remain rejected.

Existing lock validation continues to require the single root `uv.lock`, the
approved PyPI index, approved artifact host and SHA-256 integrity metadata for
every registry artifact. Workspace sources and the adapters-to-Core ownership
edge remain exact. The proposal changes only the CI policy and its focused
tests; no package metadata, lockfile, implementation, accepted specification,
workflow, permission or gate contract changes here.

The positive test covers both admitted transition states and the negative test
rejects an additional grammar dependency. Together with the existing closed
workspace-metadata and lock/source tests, this is sufficient for the bounded
policy amendment. The subsequent P2.3 implementation must still atomically
update package metadata and `uv.lock` and pass the ordinary protected gates.

Reviewed proposal: `2e99265ec56f1847150488b8d3e08a5f3e9941de`.
Review subject: `a005f272b72e06f3fe681f33309241d01987822f6e17c40bf9b99d6fe6b2bfe1`.
Evidence bundle: `6397b503e72305c0bc278d91c48f5605f003bbaf99f47855543cd0d761d0b7f4`.
Promotion subject: `ae69732b25e5cf6cadfed6cc7bb2df12ae538b6cc3a39ee06f4640725a7bd2d2`.
