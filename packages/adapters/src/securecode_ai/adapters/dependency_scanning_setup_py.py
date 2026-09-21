"""Strict static extraction of exact dependency pins from setup.py."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

_EXACT = re.compile(
    r"\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?)"
    r"(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*(?P<version>"
    r"[A-Za-z0-9](?:[A-Za-z0-9.!+_-]{0,126}[A-Za-z0-9])?)\s*\Z"
)
_DEPENDENCY_KEYS = frozenset({"install_requires", "extras_require", "tests_require"})
_UNSUPPORTED_DEPENDENCY_KEYS = frozenset({"dependency_links", "setup_requires"})


@dataclass(frozen=True, slots=True)
class StaticSetupPin:
    raw_name: str
    version: str
    start_byte: int
    end_byte: int


def parse_static_setup_py(source: bytes) -> tuple[StaticSetupPin, ...]:
    """Accept one literal setuptools.setup call and never execute repository code."""

    try:
        text = source.decode("utf-8", errors="strict")
        module = ast.parse(text, filename="setup.py", mode="exec")
    except (SyntaxError, UnicodeDecodeError, ValueError):
        raise ValueError("SETUP_PY_INVALID") from None
    calls = [node for node in ast.walk(module) if isinstance(node, ast.Call) and _setup_like(node)]
    if len(calls) != 1:
        raise ValueError("SETUP_PY_INVALID")
    call = calls[0]
    style = _setup_style(call)
    if style is None or call.args:
        raise ValueError("SETUP_PY_INVALID")
    setup_statement = _setup_statement(module, call)
    if setup_statement is None or not _valid_module(module, setup_statement, style):
        raise ValueError("SETUP_PY_INVALID")
    keywords: dict[str, ast.expr] = {}
    for keyword in call.keywords:
        if keyword.arg is None or keyword.arg in keywords:
            raise ValueError("SETUP_PY_INVALID")
        keywords[keyword.arg] = keyword.value
    if _UNSUPPORTED_DEPENDENCY_KEYS.intersection(keywords):
        raise ValueError("SETUP_PY_INVALID")
    if any(not _literal(value) for key, value in keywords.items() if key not in _DEPENDENCY_KEYS):
        raise ValueError("SETUP_PY_INVALID")
    nodes = []
    nodes.extend(_dependency_list(keywords.get("install_requires")))
    nodes.extend(_dependency_list(keywords.get("tests_require")))
    nodes.extend(_extras(keywords.get("extras_require")))
    return tuple(_pin(node, source) for node in nodes)


def _setup_like(call: ast.Call) -> bool:
    return (isinstance(call.func, ast.Name) and call.func.id == "setup") or (
        isinstance(call.func, ast.Attribute) and call.func.attr == "setup"
    )


def _setup_style(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name) and call.func.id == "setup":
        return "from-import"
    if (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "setup"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "setuptools"
    ):
        return "module-import"
    return None


def _setup_statement(module: ast.Module, call: ast.Call) -> ast.Expr | None:
    for statement in module.body:
        if isinstance(statement, ast.Expr) and statement.value is call:
            return statement
    return None


def _valid_module(module: ast.Module, setup_statement: ast.Expr, style: str) -> bool:
    imports = 0
    for index, statement in enumerate(module.body):
        if statement is setup_statement:
            continue
        if (
            isinstance(statement, ast.Expr)
            and index == 0
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        ):
            continue
        if isinstance(statement, ast.ImportFrom):
            if (
                style != "from-import"
                or statement.module != "setuptools"
                or statement.level != 0
                or len(statement.names) != 1
                or statement.names[0].name != "setup"
                or statement.names[0].asname is not None
            ):
                return False
            imports += 1
            continue
        if isinstance(statement, ast.Import):
            if (
                style != "module-import"
                or len(statement.names) != 1
                or statement.names[0].name != "setuptools"
                or statement.names[0].asname is not None
            ):
                return False
            imports += 1
            continue
        return False
    return imports == 1


def _dependency_list(value: ast.expr | None) -> list[ast.Constant]:
    if value is None:
        return []
    if not isinstance(value, ast.List):
        raise ValueError("SETUP_PY_INVALID")
    output = []
    for item in value.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            raise ValueError("SETUP_PY_INVALID")
        output.append(item)
    return output


def _extras(value: ast.expr | None) -> list[ast.Constant]:
    if value is None:
        return []
    if not isinstance(value, ast.Dict) or len(value.keys) != len(value.values):
        raise ValueError("SETUP_PY_INVALID")
    output = []
    for key, dependencies in zip(value.keys, value.values, strict=True):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str) or not key.value:
            raise ValueError("SETUP_PY_INVALID")
        output.extend(_dependency_list(dependencies))
    return output


def _literal(value: ast.expr) -> bool:
    if isinstance(value, ast.Constant):
        return type(value.value) in {str, int, float, bool, type(None)}
    if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return all(_literal(item) for item in value.elts)
    if isinstance(value, ast.Dict):
        return all(
            key is not None and _literal(key) and _literal(item)
            for key, item in zip(value.keys, value.values, strict=True)
        )
    return False


def _pin(node: ast.Constant, source: bytes) -> StaticSetupPin:
    assert isinstance(node.value, str)
    match = _EXACT.fullmatch(node.value)
    if match is None or node.end_lineno is None or node.end_col_offset is None:
        raise ValueError("SETUP_PY_INVALID")
    line_starts = _line_starts(source)
    start = line_starts[node.lineno - 1] + node.col_offset
    end = line_starts[node.end_lineno - 1] + node.end_col_offset
    segment = source[start:end]
    raw_name = match.group("name")
    version = match.group("version")
    name_offset = segment.find(raw_name.encode("ascii"))
    version_offset = segment.find(version.encode("ascii"), name_offset + len(raw_name))
    if name_offset < 0 or version_offset < 0:
        raise ValueError("SETUP_PY_INVALID")
    return StaticSetupPin(
        raw_name,
        version,
        start + name_offset,
        start + version_offset + len(version),
    )


def _line_starts(source: bytes) -> tuple[int, ...]:
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(source) if value == 10)
    return tuple(starts)


__all__ = ["StaticSetupPin", "parse_static_setup_py"]
