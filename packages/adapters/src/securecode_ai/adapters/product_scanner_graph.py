"""Program graph and scanner-receipt binding helpers."""

from __future__ import annotations

import ast
import hashlib
import json
import posixpath
import re
from typing import Final

from tree_sitter import Language, Node, Parser

from securecode_ai.core.discovery import IgnorePolicy, discover_repository
from securecode_ai.core.repository import (
    RepositoryFile,
    RepositoryInventory,
    repository_tree_sha256,
)
from securecode_ai.core.scanning import ScannerExecution, ScannerRunStatus
from securecode_ai.core.symbols import Symbol, SymbolIndex, SymbolKind

from . import cst_ecmascript, cst_go, cwe89, cwe89_multilanguage, python_ast
from .native_sources import NativeSourceCatalogue
from .program_graph import ProgramCallFact, build_program_graph

_TOP_LEVEL_CALLABLE_KINDS: Final = frozenset(
    {SymbolKind.FUNCTION, SymbolKind.ASYNC_FUNCTION}
)
_CALLABLE_SYMBOL_KINDS: Final = frozenset(
    {
        SymbolKind.FUNCTION,
        SymbolKind.ASYNC_FUNCTION,
        SymbolKind.METHOD,
        SymbolKind.ASYNC_METHOD,
    }
)
_MAX_PROGRAM_CALL_FACTS: Final = 20_000
_MAX_PROGRAM_CALL_SITES: Final = 50_000
_MAX_PROGRAM_CALL_TREE_NODES: Final = 500_000


def _program_graph_scanner_results(
    catalogue: NativeSourceCatalogue,
) -> tuple[cwe89.Cwe89ScanResult | cwe89_multilanguage.MultilanguageCwe89ScanResult, ...]:
    results = []
    scanners = {
        "javascript": cwe89_multilanguage.scan_javascript_cwe89,
        "typescript": cwe89_multilanguage.scan_typescript_cwe89,
        "go": cwe89_multilanguage.scan_go_cwe89,
    }
    for index in catalogue.indexes:
        if index.language == "python":
            result = cwe89.scan_python_cwe89(index, python_ast.analyze_python_ast(index))
        else:
            scanner = scanners.get(index.language)
            if scanner is None:
                raise ValueError("program graph language is unavailable")
            result = scanner(index)
        results.append(result)
    return tuple(results)


def _program_graph_call_facts(catalogue: NativeSourceCatalogue) -> tuple[ProgramCallFact, ...]:
    """Resolve bounded cross-file calls only through static language bindings."""
    indexes = catalogue.indexes
    if not indexes:
        return ()
    identity = (indexes[0].repository_id, indexes[0].revision)
    if any(
        (index.repository_id, index.revision) != identity
        or hashlib.sha256(index.source).hexdigest() != index.content_sha256
        for index in indexes
    ):
        raise ValueError("ProgramGraph call source identity is invalid")
    index_by_path = {index.path: index for index in indexes}
    functions_by_language_name: dict[str, dict[str, list[tuple[SymbolIndex, Symbol]]]] = {}
    for index in indexes:
        language_names = functions_by_language_name.setdefault(index.language, {})
        for symbol in index.symbols:
            if symbol.kind in _TOP_LEVEL_CALLABLE_KINDS:
                language_names.setdefault(symbol.name, []).append((index, symbol))
    pairs: set[tuple[str, str]] = set()
    call_sites = 0
    tree_nodes = 0
    indeterminate = False
    go_package_cache: dict[str, tuple[Node, str]] = {}

    def admit(caller_index: SymbolIndex, caller: Symbol, target_index: SymbolIndex, target: Symbol) -> None:
        nonlocal indeterminate
        if target_index.path == caller_index.path:
            return
        if (
            caller_index.repository_id != target_index.repository_id
            or caller_index.revision != target_index.revision
            or caller_index.language != target_index.language
            or caller.kind not in _CALLABLE_SYMBOL_KINDS
            or target.kind not in _CALLABLE_SYMBOL_KINDS
        ):
            indeterminate = True
            return
        pair = (caller.symbol_id, target.symbol_id)
        if pair not in pairs:
            if len(pairs) >= _MAX_PROGRAM_CALL_FACTS:
                raise ValueError("ProgramGraph call fact budget exceeded")
            pairs.add(pair)

    for index in indexes:
        if index.language == "python":
            source = index.source
            tree = ast.parse(source)
            module_named: dict[str, list[tuple[SymbolIndex, str]]] = {}
            ambiguous_named_aliases: set[str] = set()
            module_aliases: dict[str, list[SymbolIndex]] = {}
            ambiguous_module_aliases: set[str] = set()
            for statement in tree.body:
                if isinstance(statement, ast.ImportFrom):
                    targets = _resolve_python_import_candidates(
                        index, statement.module, statement.level, index_by_path
                    )
                    if len(targets) > 1:
                        ambiguous_named_aliases.update(
                            item.asname or item.name
                            for item in statement.names
                            if item.name != "*"
                        )
                        continue
                    if not targets:
                        for item in statement.names:
                            if item.name != "*":
                                module_named.setdefault(item.asname or item.name, [])
                        continue
                    target_index = targets[0]
                    for item in statement.names:
                        if item.name == "*":
                            continue
                        module_named.setdefault(item.asname or item.name, []).append(
                            (target_index, item.name)
                        )
                elif isinstance(statement, ast.Import):
                    for item in statement.names:
                        if item.asname is None:
                            continue
                        targets = _resolve_python_import_candidates(
                            index, item.name, 0, index_by_path
                        )
                        alias = item.asname
                        if len(targets) == 1:
                            module_aliases.setdefault(alias, []).append(targets[0])
                        elif len(targets) > 1:
                            ambiguous_module_aliases.add(alias)
            call_stack: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
            while call_stack:
                node, scope = call_stack.pop()
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                    scope = node
                if isinstance(node, ast.Call):
                    call_sites += 1
                    if call_sites > _MAX_PROGRAM_CALL_SITES:
                        raise ValueError("ProgramGraph call-site budget exceeded")
                    start, end = _python_node_bytes(node, source)
                    caller = _callable_for_bytes(index, start, end)
                    if caller is not None and isinstance(node.func, ast.Name):
                        bindings = module_named.get(node.func.id, ())
                        locals_for_scope = _python_scope_bindings(scope) if scope is not None else set()
                        if node.func.id in ambiguous_named_aliases and node.func.id not in locals_for_scope:
                            indeterminate = True
                        if node.func.id not in locals_for_scope and bindings:
                            resolved = []
                            for target_index, target_name in bindings:
                                candidates = _symbols_named(target_index, target_name, top_level=True)
                                if len(candidates) == 1:
                                    resolved.append((target_index, candidates[0]))
                                elif len(candidates) > 1:
                                    indeterminate = True
                            if len(resolved) == 1:
                                admit(index, caller, *resolved[0])
                            elif len(resolved) > 1:
                                indeterminate = True
                    elif caller is not None and isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name):
                            alias = node.func.value.id
                            locals_for_scope = _python_scope_bindings(scope) if scope is not None else set()
                            if alias not in locals_for_scope:
                                if alias in ambiguous_module_aliases:
                                    indeterminate = True
                                targets = module_aliases.get(alias, ())
                                if len(targets) == 1:
                                    candidates = _symbols_named(
                                        targets[0], node.func.attr, top_level=True
                                    )
                                    if len(candidates) == 1:
                                        admit(index, caller, targets[0], candidates[0])
                                    elif len(candidates) > 1:
                                        indeterminate = True
                children = list(ast.iter_child_nodes(node))
                tree_nodes += len(children)
                if tree_nodes > _MAX_PROGRAM_CALL_TREE_NODES:
                    raise ValueError("ProgramGraph call parser budget exceeded")
                call_stack.extend((child, scope) for child in reversed(children))
            continue

        grammar = (
            cst_go._go_language()
            if index.language == "go"
            else cst_ecmascript._typescript_language(tsx=index.path.endswith(".tsx"))
            if index.language == "typescript"
            else cst_ecmascript._javascript_language()
        )
        root = Parser(Language(grammar)).parse(index.source).root_node
        if index.language == "go":
            package = _go_package_name(root, index.source)
            go_package_cache[index.path] = (root, package)
            package_functions: dict[str, list[tuple[SymbolIndex, Symbol]]] = {}
            for target_index in indexes:
                if target_index.language != "go" or target_index.path == index.path:
                    continue
                cached_target = go_package_cache.get(target_index.path)
                if cached_target is None:
                    target_root = Parser(Language(cst_go._go_language())).parse(
                        target_index.source
                    ).root_node
                    target_package = _go_package_name(target_root, target_index.source)
                    go_package_cache[target_index.path] = (target_root, target_package)
                else:
                    _, target_package = cached_target
                if (
                    posixpath.dirname(target_index.path) == posixpath.dirname(index.path)
                    and target_package == package
                ):
                    for symbol in target_index.symbols:
                        if symbol.kind in _TOP_LEVEL_CALLABLE_KINDS:
                            package_functions.setdefault(symbol.name, []).append(
                                (target_index, symbol)
                            )
            stack: list[Node] = [root]
            while stack:
                node = stack.pop()
                tree_nodes += 1
                if tree_nodes > _MAX_PROGRAM_CALL_TREE_NODES:
                    raise ValueError("ProgramGraph call parser budget exceeded")
                if node.type == "call_expression":
                    call_sites += 1
                    if call_sites > _MAX_PROGRAM_CALL_SITES:
                        raise ValueError("ProgramGraph call-site budget exceeded")
                    function = node.child_by_field_name("function")
                    caller = _callable_for_bytes(index, node.start_byte, node.end_byte)
                    if caller is not None and function is not None:
                        if function.type == "identifier":
                            name = index.source[function.start_byte:function.end_byte].decode(
                                "utf-8", "strict"
                            )
                            targets = package_functions.get(name, ())
                            if len(targets) == 1:
                                admit(index, caller, *targets[0])
                            elif len(targets) > 1:
                                indeterminate = True
                        elif function.type == "selector_expression" and function.named_children:
                            selector = function.named_children[-1]
                            name = index.source[selector.start_byte:selector.end_byte].decode(
                                "utf-8", "strict"
                            )
                            if any(
                                symbol.kind in {SymbolKind.METHOD, SymbolKind.ASYNC_METHOD}
                                and symbol.name == name
                                for symbol in index.symbols
                            ):
                                indeterminate = True
                stack.extend(reversed(node.named_children))
            continue

        imports: dict[str, list[tuple[SymbolIndex, str]]] = {}
        namespaces: dict[str, list[SymbolIndex]] = {}
        ambiguous_imports: set[str] = set()
        exported = _ecmascript_exported_symbols(index, root)
        stack = [root]
        while stack:
            node = stack.pop()
            tree_nodes += 1
            if tree_nodes > _MAX_PROGRAM_CALL_TREE_NODES:
                raise ValueError("ProgramGraph call parser budget exceeded")
            if node.type == "import_statement":
                bindings, modules, ambiguous = _ecmascript_import_bindings(index, node, index_by_path)
                for alias, targets in bindings.items():
                    imports.setdefault(alias, []).extend(targets)
                for alias, targets in modules.items():
                    namespaces.setdefault(alias, []).extend(targets)
                ambiguous_imports.update(ambiguous)
            stack.extend(reversed(node.named_children))
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                call_sites += 1
                if call_sites > _MAX_PROGRAM_CALL_SITES:
                    raise ValueError("ProgramGraph call-site budget exceeded")
                function = node.child_by_field_name("function")
                caller = _callable_for_bytes(index, node.start_byte, node.end_byte)
                if caller is not None and function is not None:
                    if function.type == "identifier":
                        alias = index.source[function.start_byte:function.end_byte].decode(
                            "utf-8", "strict"
                        )
                        resolved = _resolve_ecmascript_named_import(
                            imports.get(alias, ()), alias, exported
                        )
                        if len(resolved) == 1:
                            admit(index, caller, *resolved[0])
                        elif len(resolved) > 1 or alias in ambiguous_imports:
                            indeterminate = True
                        elif any(
                            target.path != index.path
                            for target, _ in functions_by_language_name[index.language].get(alias, ())
                        ):
                            indeterminate = True
                    elif function.type in {"member_expression", "optional_member_expression"}:
                        children = function.named_children
                        if len(children) >= 2 and children[0].type == "identifier":
                            alias = index.source[children[0].start_byte:children[0].end_byte].decode(
                                "utf-8", "strict"
                            )
                            name = index.source[children[-1].start_byte:children[-1].end_byte].decode(
                                "utf-8", "strict"
                            )
                            targets = namespaces.get(alias, ())
                            if len(targets) == 1:
                                resolved = _resolve_ecmascript_named_import(
                                    tuple((target, name) for target in targets), name, exported
                                )
                                if len(resolved) == 1:
                                    admit(index, caller, *resolved[0])
                                else:
                                    indeterminate = True
                            elif alias in ambiguous_imports or any(
                                target.path != index.path
                                for target, _ in functions_by_language_name[index.language].get(name, ())
                            ):
                                indeterminate = True
                        else:
                            property_name = children[-1] if children else None
                            if property_name is not None:
                                name = index.source[
                                    property_name.start_byte:property_name.end_byte
                                ].decode("utf-8", "strict")
                                if any(
                                    target.path != index.path
                                    for target, _ in functions_by_language_name[index.language].get(name, ())
                                ):
                                    indeterminate = True
            stack.extend(reversed(node.named_children))
    if indeterminate:
        raise ValueError("ProgramGraph contains unresolved internal call sites")
    facts = tuple(
        ProgramCallFact(identity[0], identity[1], caller_id, callee_id)
        for caller_id, callee_id in sorted(pairs)
    )
    return facts


def _symbols_named(index: SymbolIndex, name: str, *, top_level: bool) -> tuple[Symbol, ...]:
    allowed = _TOP_LEVEL_CALLABLE_KINDS if top_level else _CALLABLE_SYMBOL_KINDS
    return tuple(symbol for symbol in index.symbols if symbol.name == name and symbol.kind in allowed)


def _callable_for_bytes(index: SymbolIndex, start: int, end: int) -> Symbol | None:
    matches = tuple(
        symbol
        for symbol in index.symbols
        if symbol.kind in _CALLABLE_SYMBOL_KINDS
        and symbol.declaration.start_byte <= start
        and symbol.declaration.end_byte >= end
    )
    if not matches:
        return None
    narrowest = min(item.declaration.end_byte - item.declaration.start_byte for item in matches)
    closest = tuple(
        item
        for item in matches
        if item.declaration.end_byte - item.declaration.start_byte == narrowest
    )
    return closest[0] if len(closest) == 1 else None


def _python_node_bytes(node: ast.AST, source: bytes) -> tuple[int, int]:
    starts = [0]
    for match in re.finditer(b"\\n", source):
        starts.append(match.end())
    line = getattr(node, "lineno", 1) - 1
    end_line = getattr(node, "end_lineno", line + 1) - 1
    if line < 0 or end_line >= len(starts):
        return (len(source), len(source))
    start = starts[line] + getattr(node, "col_offset", 0)
    end = starts[end_line] + getattr(node, "end_col_offset", 0)
    return (start, end) if 0 <= start <= end <= len(source) else (len(source), len(source))


def _python_scope_bindings(scope: ast.AST | None) -> set[str]:
    if scope is None:
        return set()
    names: set[str] = set()
    pending = [scope]
    first = True
    while pending:
        node = pending.pop()
        if not first and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        first = False
        if isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        pending.extend(ast.iter_child_nodes(node))
    return names


def _resolve_python_import_candidates(
    index: SymbolIndex,
    module: str | None,
    level: int,
    indexes: dict[str, SymbolIndex],
) -> tuple[SymbolIndex, ...]:
    if type(level) is not int or level < 0:
        return ()
    parts = posixpath.dirname(index.path).split("/") if "/" in index.path else []
    if index.path.endswith("/__init__.py") or index.path.endswith("/__init__.pyi"):
        parts = index.path.rsplit("/", 1)[0].split("/")
    if level:
        for _ in range(level - 1):
            if not parts:
                return ()
            parts.pop()
    module_parts = module.split(".") if module else []
    candidate_base = "/".join((*parts, *module_parts))
    paths = (
        candidate_base + ".py",
        candidate_base + ".pyi",
        candidate_base + "/__init__.py",
        candidate_base + "/__init__.pyi",
    )
    return tuple(indexes[path] for path in paths if path in indexes)


def _go_package_name(root: Node, source: bytes) -> str:
    for node in root.named_children:
        if node.type == "package_clause":
            name = node.child_by_field_name("name")
            if name is None and node.named_children:
                name = node.named_children[-1]
            if name is not None:
                return source[name.start_byte:name.end_byte].decode("utf-8", "strict")
    raise ValueError("Go package clause is unavailable")


def _ecmascript_exported_symbols(index: SymbolIndex, root: Node) -> frozenset[str]:
    exported = set()
    pending = [root]
    while pending:
        node = pending.pop()
        if node.type == "export_statement":
            for symbol in index.symbols:
                if (
                    symbol.kind in _TOP_LEVEL_CALLABLE_KINDS
                    and node.start_byte <= symbol.name_location.start_byte
                    and node.end_byte >= symbol.name_location.end_byte
                ):
                    exported.add(symbol.symbol_id)
        pending.extend(reversed(node.named_children))
    return frozenset(exported)


def _ecmascript_import_bindings(
    index: SymbolIndex,
    node: Node,
    indexes: dict[str, SymbolIndex],
) -> tuple[dict[str, list[tuple[SymbolIndex, str]]], dict[str, list[SymbolIndex]], set[str]]:
    bindings: dict[str, list[tuple[SymbolIndex, str]]] = {}
    modules: dict[str, list[SymbolIndex]] = {}
    ambiguous: set[str] = set()
    raw = index.source[node.start_byte:node.end_byte]
    match = re.match(
        rb"\s*import\s+(?:type\s+)?(.*?)\s+from\s*(['\"])([^'\"]+)\2",
        raw,
        re.DOTALL,
    )
    if match is None:
        return bindings, modules, ambiguous
    clause = match.group(1).strip()
    specifier = match.group(3).decode("utf-8", "strict")
    targets = _resolve_ecmascript_import(index, specifier, indexes)
    if not targets:
        return bindings, modules, ambiguous
    if clause.startswith(b"*"):
        namespace_match = re.fullmatch(rb"\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)", clause)
        if namespace_match is not None:
            alias = namespace_match.group(1).decode("ascii")
            if len(targets) == 1:
                modules.setdefault(alias, []).append(targets[0])
            else:
                ambiguous.add(alias)
    elif clause.startswith(b"{") and clause.endswith(b"}"):
        for item in clause[1:-1].split(b","):
            item = re.sub(rb"/\*.*?\*/|//[^\r\n]*", b"", item, flags=re.DOTALL).strip()
            spec = re.fullmatch(
                rb"(?:type\s+)?([A-Za-z_$][A-Za-z0-9_$]*)(?:\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*))?",
                item,
            )
            if spec is None:
                continue
            imported = spec.group(1).decode("ascii")
            alias = (spec.group(2) or spec.group(1)).decode("ascii")
            if len(targets) == 1:
                bindings.setdefault(alias, []).append((targets[0], imported))
            else:
                ambiguous.add(alias)
    return bindings, modules, ambiguous


def _resolve_ecmascript_import(
    index: SymbolIndex, specifier: str, indexes: dict[str, SymbolIndex]
) -> tuple[SymbolIndex, ...]:
    if not specifier.startswith("."):
        return ()
    base = posixpath.normpath(posixpath.join(posixpath.dirname(index.path), specifier))
    if base == ".." or base.startswith("../") or base.startswith("/"):
        return ()
    suffixes = (
        (".js", ".jsx", ".mjs", ".cjs")
        if index.language == "javascript"
        else (".ts", ".tsx", ".mts", ".cts")
    )
    candidates = [base] if posixpath.splitext(base)[1] else [base + suffix for suffix in suffixes]
    if index.language == "typescript" and base.endswith(".js"):
        stem = base[:-3]
        candidates.extend(stem + suffix for suffix in suffixes)
    if not posixpath.splitext(base)[1]:
        candidates.extend(base + "/index" + suffix for suffix in suffixes)
    unique = tuple(dict.fromkeys(path for path in candidates if path in indexes))
    return tuple(target for path in unique if (target := indexes[path]).language == index.language)


def _resolve_ecmascript_named_import(
    bindings: tuple[tuple[SymbolIndex, str], ...],
    name: str,
    exported: frozenset[str],
) -> tuple[tuple[SymbolIndex, Symbol], ...]:
    resolved = []
    for target_index, target_name in bindings:
        for symbol in _symbols_named(target_index, target_name, top_level=True):
            if symbol.symbol_id in exported:
                resolved.append((target_index, symbol))
    return tuple(resolved)


def _catalogue_language_inventory_matches(catalogue: NativeSourceCatalogue) -> bool:
    files = tuple(
        RepositoryFile(file.path, len(file.content), file.content_sha256)
        for file in catalogue.snapshot.files
    )
    inventory = RepositoryInventory(
        files, sum(file.size_bytes for file in files), repository_tree_sha256(files)
    )
    discovery = discover_repository(inventory, IgnorePolicy("product-execution", "1.0.0"))
    discovered = {
        (entry.language.value, item.path, item.content_sha256)
        for entry in discovery.languages
        for item in entry.files
    }
    indexed = {
        (index.language, index.path, index.content_sha256) for index in catalogue.indexes
    }
    return discovered == indexed


def _program_graph_facts_match_receipts(
    results: tuple[
        cwe89.Cwe89ScanResult | cwe89_multilanguage.MultilanguageCwe89ScanResult, ...
    ],
    receipts: tuple[ScannerExecution, ...],
) -> bool:
    results_by_request: dict[
        str,
        cwe89.Cwe89ScanResult | cwe89_multilanguage.MultilanguageCwe89ScanResult,
    ] = {}
    for result in results:
        request_id = "static-" + hashlib.sha256(result.path.encode()).hexdigest()
        if request_id in results_by_request:
            return False
        results_by_request[request_id] = result
    receipts_by_request = {receipt.request_id: receipt for receipt in receipts}
    if (
        len(receipts_by_request) != len(receipts)
        or set(receipts_by_request) != set(results_by_request)
        or any(receipt.status is not ScannerRunStatus.SUCCEEDED for receipt in receipts)
    ):
        return False

    for request_id, result in results_by_request.items():
        receipt = receipts_by_request[request_id]
        if any(
            signal.repository_id != result.repository_id
            or signal.revision != result.revision
            or signal.path != result.path
            or signal.content_sha256 != result.content_sha256
            for signal in result.signals
        ):
            return False
        expected = []
        for ordinal, signal in enumerate(result.signals):
            if not receipt.signals:
                return False
            material = [
                "product-sql-fact-v1",
                receipt.signals[0].tenant_id,
                result.repository_id,
                result.revision,
                result.scan_sha256,
                ordinal,
                receipt.scanner.producer.model_dump(mode="json"),
            ]
            signal_id = "product-sql-" + hashlib.sha256(
                json.dumps(material, sort_keys=True).encode()
            ).hexdigest()
            expected.append(
                (
                    signal_id,
                    result.path,
                    result.content_sha256,
                    result.revision,
                    signal.sink.start_point.row + 1,
                    signal.sink.start_point.column + 1,
                    signal.sink.end_point.row + 1,
                    signal.sink.end_point.column + 1,
                )
            )
        observed = [
            (
                signal.raw_signal_id,
                signal.location.path,
                signal.location.content_sha256,
                signal.head_sha,
                signal.location.start.line,
                signal.location.start.column,
                signal.location.end.line,
                signal.location.end.column,
            )
            for signal in receipt.signals
            if signal.rule_id == "cwe-89-sql-interpolation"
        ]
        if sorted(expected) != sorted(observed):
            return False
        if any(
            signal.tenant_id != receipt.signals[0].tenant_id
            or signal.producer != receipt.scanner.producer
            for signal in receipt.signals
        ):
            return False
    return True
