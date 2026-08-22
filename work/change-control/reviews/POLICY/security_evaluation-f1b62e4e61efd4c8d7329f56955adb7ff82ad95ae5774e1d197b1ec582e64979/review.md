# CR-044 security and evaluation review

Verdict: PASS

The exact proposal, sequential predecessor reviews and all declared identities
verify. The manifest has one decoded target, `tests/unit/test_ci_policy.py`,
whose base and final hashes match; evaluator bytes are unchanged.

The repair does not derive its expectations from the checkout. It replaces the
fixture list first with the exact legacy Core-only state and then with the exact
reviewed Core plus Tree-sitter runtime plus Python grammar state, requiring
acceptance for each. It finally appends the unreviewed JavaScript grammar and
still requires rejection. Slice replacement prevents duplicate dependencies in
the post-P2.3 checkout without broadening the accepted values or weakening the
negative oracle.

Fixture normalization cannot conceal actual repository drift: the separate
accepted-policy-input test continues to load and validate the unmodified
workspace metadata and lock inputs. Existing mutation tests still cover source,
artifact hash, root/quality/optional dependency, uv option and build-backend
drift. No evaluator, dependency authority, lock/source/integrity, secret scan,
workflow, permission, specification or gate behavior changes.

I executed the decoded repaired regression directly and independently executed
the current-input acceptance oracle; both passed. No fail-open fixture-masking
or negative-coverage blocker.
