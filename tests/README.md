# Test ownership

The planned test layers are `unit`, `contract`, `integration`, `security` and
`fixtures`. Tests verify implementation against frozen specifications; an
implementation task cannot weaken normative requirements, evaluators or gate
evidence to make a test pass.

Executable test infrastructure begins in `P1.3`. The `P1.11` candidate adds a
test-only factory for six opaque, byte-pinned demonstration repositories. It
does not perform repository intake or analysis and is not shipped in any
first-party wheel. The factory cannot read the separately committed evaluator
golden; only the independent test oracle compares completed tree hashes.
