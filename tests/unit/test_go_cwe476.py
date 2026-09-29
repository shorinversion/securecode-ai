"""Regression tests for the Go CWE-476 nullable-pointer scanner."""

from __future__ import annotations

from securecode_ai.adapters.cst_go import _go_language
from securecode_ai.adapters.go_cwe476 import _bindings
from tree_sitter import Language, Parser

SOURCE = b"""package demo

type User struct {
    Name string
}

func (user *User) Show() string {
    return user.Name
}
"""


def test_pointer_receiver_binding_records_its_name() -> None:
    # Regression: _Binding was constructed without its ``name`` field, so any
    # pointer binding raised TypeError (surfacing as INTEGRITY_FAILURE).
    root = Parser(Language(_go_language())).parse(SOURCE).root_node
    method = next(node for node in root.named_children if node.type == "method_declaration")
    bindings = _bindings(method, SOURCE, (method,))
    assert set(bindings) == {"user"}
    binding = bindings["user"]
    assert binding.name == "user"
    # A receiver is caller-controlled: it is tracked, but is not a local nil proof.
    assert binding.nullable is False


def _index(source: bytes):  # type: ignore[no-untyped-def]
    import hashlib

    from securecode_ai.adapters.cst import build_go_symbol_index

    return build_go_symbol_index(
        repository_id="example/go-cwe476",
        revision="d" * 40,
        path="user.go",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


def test_only_locally_proven_nil_pointer_dereferences_are_reported() -> None:
    # Regression: signal ids carry a ``go-cwe476-`` prefix that the validator rejected, and
    # Node identity comparisons made every plain function scope silent.  Pointer parameters
    # and receivers are not nil proofs; flagging them fired on almost every Go file.
    from securecode_ai.adapters.go_cwe476 import scan_go_cwe476

    source = b"""package demo

type User struct{ Name string }

func FromParameter(user *User) string {
    return user.Name
}

func (user *User) Method() string {
    return user.Name
}

func Reassigned(user *User) string {
    user = nil
    return user.Name
}

func FromCall() string {
    var user *User = lookup()
    return user.Name
}

func FromVariable() string {
    var user *User
    return user.Name
}

func Guarded(user *User) string {
    if user == nil {
        return ""
    }
    return user.Name
}
"""
    result = scan_go_cwe476(_index(source))

    assert len(result.signals) == 2
    assert all(signal.signal_id.startswith("go-cwe476-") for signal in result.signals)
