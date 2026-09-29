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
    assert binding.nullable is True
