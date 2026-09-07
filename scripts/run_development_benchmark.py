"""Run the frozen P7.17 matrix using source data and literal-loopback Ollama."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import multiprocessing
import platform
import queue as queue_module
import subprocess
import sys
import time
import tokenize
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, cast

from securecode_ai.core.development_benchmark import Record, aggregate, planned_cells

ENDPOINT = "http://127.0.0.1:11434"
PROMPT_TEMPLATE = (
    "Review this educational Python example. Return only compact JSON using one of: "
    '{{"verdict":"no_finding"}} or '
    '{{"verdict":"confirmed","category":"authz|path|sql|command",'
    '"source_file":"file_N.py"}}. Use only a shown opaque file alias. Do not explain.\n\n{source}'
)
POLICY_TEXT = (
    "source-data-only; label-blind-sha256-alias-order; no corpus execution; "
    "literal-loopback-only; non-success-is-not-clean"
)
SCHEMA_TEXT = "exact-label:vulnerable|safe; record:development-benchmark-record-1.0"
UNSUPPORTED = {
    "scanner_seeded_investigation",
    "model_native_only",
    "full_hybrid",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class ModelRunError(ValueError):
    def __init__(
        self,
        reason: str,
        *,
        prompt_tokens: int | None = None,
        generated_tokens: int | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.prompt_tokens = prompt_tokens
        self.generated_tokens = generated_tokens


def _strict_object(payload: bytes) -> dict[str, Any]:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(payload, object_pairs_hook=pairs_hook)
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return value


def _load(path: Path) -> dict[str, Any]:
    return _strict_object(path.read_bytes())


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _verify_plan(plan: dict[str, Any], plan_path: Path, corpus: dict[str, Any]) -> None:
    if plan.get("schema_version") != "development-benchmark-plan-1.0":
        raise ValueError("unsupported plan schema")
    if plan.get("corpus_content_sha256") != corpus.get("corpus_content_sha256"):
        raise ValueError("stale corpus binding")
    if plan.get("ollama", {}).get("endpoint") != ENDPOINT:
        raise ValueError("unsafe model endpoint")
    bindings = plan.get("bindings")
    if type(bindings) is not dict:
        raise ValueError("missing bindings")
    expected = {
        "component_sha256": _sha256_bytes(Path(__file__).read_bytes()),
        "core_sha256": _sha256_bytes(
            Path("packages/core/src/securecode_ai/core/development_benchmark.py").read_bytes()
        ),
        "recompute_sha256": _sha256_bytes(
            Path(__file__).with_name("recompute_development_benchmark.py").read_bytes()
        ),
        "corpus_validator_sha256": _sha256_bytes(
            Path(__file__).with_name("development_corpus.py").read_bytes()
        ),
        "prompt_sha256": _sha256_text(PROMPT_TEMPLATE),
        "policy_sha256": _sha256_text(POLICY_TEXT),
        "schema_sha256": _sha256_text(SCHEMA_TEXT),
    }
    if bindings != expected:
        raise ValueError("component binding drift")
    environment = plan.get("environment")
    expected_environment = {
        "host_mode": "local-native",
        "evaluation_image": None,
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python_implementation": sys.implementation.name,
        "python_version": platform.python_version(),
        "uv_lock_sha256": _sha256_bytes(Path("uv.lock").read_bytes()),
    }
    if environment != expected_environment:
        raise ValueError("execution environment drift")
    if plan.get("reproduction_commands") != [
        ".venv/Scripts/python.exe scripts/run_development_benchmark.py --plan evaluation/development/run-plan.yaml --records evaluation/development/results/run-records.jsonl --aggregate evaluation/development/results/aggregate.json",
        ".venv/Scripts/python.exe scripts/recompute_development_benchmark.py --plan evaluation/development/run-plan.yaml --records evaluation/development/results/run-records.jsonl --output evaluation/development/results/recomputed.json",
    ]:
        raise ValueError("reproduction command drift")
    profile = plan.get("ollama")
    if (
        type(profile) is not dict
        or profile.get("temperature") != 0.0
        or profile.get("seed") is not None
        or profile.get("seed_support") != "unavailable"
    ):
        raise ValueError("generation profile drift")
    if _sha256_bytes(plan_path.read_bytes()) == "sha256:" + "0" * 64:
        raise ValueError("invalid plan identity")


def _verify_runtime(profile: dict[str, Any], timeout: int) -> None:
    version = _get_json(f"{ENDPOINT}/api/version", timeout)
    if set(version) != {"version"} or version["version"] != profile["version"]:
        raise ValueError("runtime identity drift")
    tags = _get_json(f"{ENDPOINT}/api/tags", timeout)
    if set(tags) != {"models"} or type(tags["models"]) is not list:
        raise ValueError("invalid runtime catalogue")
    matches = [
        item
        for item in tags["models"]
        if type(item) is dict and item.get("name") == profile["model"]
    ]
    if len(matches) != 1 or f"sha256:{matches[0].get('digest')}" != profile["digest"]:
        raise ValueError("model artifact drift")
    details = matches[0].get("details")
    if type(details) is not dict or details.get("quantization_level") != profile["quantization"]:
        raise ValueError("model profile drift")


def _get_json(url: str, timeout: int) -> dict[str, Any]:
    if not url.startswith(f"{ENDPOINT}/"):
        raise ValueError("unsafe endpoint")
    with OPENER.open(url, timeout=timeout) as response:
        payload = response.read(1_048_577)
    if len(payload) > 1_048_576:
        raise ValueError("oversized response")
    return _strict_object(payload)


def _model_projection(source: str) -> str:
    """Remove comments and docstrings that may disclose frozen expectations."""

    tree = ast.parse(source)
    doc_lines: set[int] = set()
    owners = [
        tree,
        *(
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        ),
    ]
    for owner in owners:
        if (
            owner.body
            and isinstance(owner.body[0], ast.Expr)
            and isinstance(owner.body[0].value, ast.Constant)
            and isinstance(owner.body[0].value.value, str)
        ):
            expression = owner.body[0]
            end_lineno = expression.end_lineno or expression.lineno
            doc_lines.update(range(expression.lineno, end_lineno + 1))
    tokens = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT or token.start[0] in doc_lines:
            token = tokenize.TokenInfo(token.type, "", token.start, token.end, token.line)
        tokens.append(token)
    return tokenize.untokenize(tokens)


def _contained_source(root: Path, value: object) -> Path:
    if type(value) is not str or not value.startswith("corpus/"):
        raise ValueError("invalid corpus source path")
    resolved_root = root.resolve()
    resolved = (resolved_root / value).resolve()
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError("corpus source path escapes root")
    return resolved


def _source_aliases(case: dict[str, Any]) -> dict[str, str]:
    ordered = sorted(
        case["sources"],
        key=lambda item: hashlib.sha256(f"{case['case_id']}\0{item['path']}".encode()).digest(),
    )
    return {f"file_{index}.py": item["path"] for index, item in enumerate(ordered, start=1)}


def _ollama(
    case: dict[str, Any],
    root: Path,
    profile: dict[str, Any],
    timeout: int,
    expected_source_path: str,
) -> tuple[str, bool, bool, str | None, str | None, int, int]:
    aliases = _source_aliases(case)
    source = "\n\n".join(
        f"FILE {alias}\n"
        + _model_projection(_contained_source(root, source_path).read_text(encoding="utf-8"))
        for alias, source_path in aliases.items()
    )
    request = urllib.request.Request(
        f"{ENDPOINT}/api/generate",
        data=json.dumps(
            {
                "model": profile["model"],
                "prompt": PROMPT_TEMPLATE.format(source=source),
                "stream": False,
                "options": {
                    "num_predict": 48,
                    "temperature": profile["temperature"],
                },
            },
            separators=(",", ":"),
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with OPENER.open(request, timeout=timeout) as response:
        payload = response.read(1_048_577)
    if len(payload) > 1_048_576:
        raise ValueError("oversized model response")
    value = _strict_object(payload)
    allowed = {
        "model",
        "created_at",
        "response",
        "done",
        "done_reason",
        "context",
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    }
    required = {
        "model",
        "response",
        "done",
        "done_reason",
        "prompt_eval_count",
        "eval_count",
    }
    if not required <= set(value) or not set(value) <= allowed:
        raise ValueError("invalid model response shape")
    if (
        value["model"] != profile["model"]
        or value["done"] is not True
        or value["done_reason"] != "stop"
    ):
        raise ValueError("model response identity or completion drift")
    prompt_tokens = value["prompt_eval_count"]
    generated_tokens = value["eval_count"]
    if (
        type(prompt_tokens) is not int
        or prompt_tokens < 0
        or type(generated_tokens) is not int
        or generated_tokens < 0
    ):
        raise ValueError("invalid model resource facts")
    try:
        finding = (
            _strict_object(value["response"].encode("utf-8"))
            if type(value["response"]) is str
            else {}
        )
    except ValueError as error:
        raise ModelRunError(
            "invalid_structured_finding",
            prompt_tokens=prompt_tokens,
            generated_tokens=generated_tokens,
        ) from error
    if finding == {"verdict": "no_finding"}:
        label, confirmed, matched = "safe", False, False
        category = source_alias = None
    elif (
        set(finding) == {"verdict", "category", "source_file"} and finding["verdict"] == "confirmed"
    ):
        expected_category = case["lineage_group"].removeprefix("lineage-").removesuffix("-v1")
        category = finding["category"]
        source_alias = finding["source_file"]
        if category not in {"authz", "path", "sql", "command"} or source_alias not in aliases:
            raise ModelRunError(
                "invalid_structured_finding",
                prompt_tokens=prompt_tokens,
                generated_tokens=generated_tokens,
            )
        confirmed = True
        matched = (
            category == expected_category
            and source_alias in aliases
            and aliases[source_alias] == expected_source_path
        )
        label = "vulnerable"
    else:
        raise ModelRunError(
            "invalid_structured_finding",
            prompt_tokens=prompt_tokens,
            generated_tokens=generated_tokens,
        )
    return (
        label,
        confirmed,
        matched,
        category,
        source_alias,
        prompt_tokens,
        generated_tokens,
    )


def _record(
    *,
    plan: dict[str, Any],
    plan_sha256: str,
    case_id: str,
    configuration: str,
    repetition: int,
    expected: str,
    state: str,
    predicted: str | None,
    confirmed_finding: bool | None,
    policy_matched: bool | None,
    returned_category: str | None,
    returned_source_alias: str | None,
    reason: str | None,
    wall_seconds: float | None,
    prompt_tokens: int | None,
    generated_tokens: int | None,
    scanner_signals: int | None,
) -> Record:
    model_stage = configuration == "one_shot_llm"
    profile = plan["ollama"]
    budget = plan["budget"]
    bindings = plan["bindings"]
    return Record(
        schema_version="development-benchmark-record-1.0",
        study_id=plan["study_id"],
        case_id=case_id,
        configuration=configuration,  # type: ignore[arg-type]
        repetition=repetition,
        expected_label=expected,  # type: ignore[arg-type]
        state=state,  # type: ignore[arg-type]
        predicted_label=predicted,  # type: ignore[arg-type]
        confirmed_finding=confirmed_finding,
        policy_matched=policy_matched,
        returned_category=returned_category,
        returned_source_alias=returned_source_alias,
        reason=reason,
        run_plan_sha256=plan_sha256,
        candidate_commit=plan["candidate_commit"],
        corpus_content_sha256=plan["corpus_content_sha256"],
        component_sha256=bindings["component_sha256"],
        prompt_sha256=bindings["prompt_sha256"] if model_stage else None,
        policy_sha256=bindings["policy_sha256"],
        schema_sha256=bindings["schema_sha256"],
        model_name=profile["model"] if model_stage else None,
        model_digest=profile["digest"] if model_stage else None,
        runtime_name="ollama" if model_stage else None,
        runtime_version=profile["version"] if model_stage else None,
        quantization=profile["quantization"] if model_stage else None,
        temperature=profile["temperature"] if model_stage else None,
        seed=profile["seed"] if model_stage else None,
        budget_tokens=budget["tokens"] if model_stage else 0,
        budget_calls=budget["calls"] if model_stage else 0,
        budget_wall_seconds=budget["wall_seconds"] if model_stage else 0,
        budget_retries=budget["retries"] if model_stage else 0,
        wall_seconds=wall_seconds,
        prompt_tokens=prompt_tokens,
        generated_tokens=generated_tokens,
        scanner_signal_count=scanner_signals,
        provider_cost=None,
    )


def _ollama_worker(
    queue: Any,
    case: dict[str, Any],
    root: Path,
    profile: dict[str, Any],
    timeout: int,
    expected_source_path: str,
) -> None:
    try:
        queue.put(("ok", _ollama(case, root, profile, timeout, expected_source_path)))
    except Exception as error:
        queue.put(
            (
                "error",
                _failure_reason(error),
                error.prompt_tokens if isinstance(error, ModelRunError) else None,
                error.generated_tokens if isinstance(error, ModelRunError) else None,
            )
        )


def _bounded_ollama(
    case: dict[str, Any],
    root: Path,
    profile: dict[str, Any],
    timeout: int,
    expected_source_path: str,
) -> tuple[str, bool, bool, str | None, str | None, int, int]:
    context = multiprocessing.get_context("spawn")
    queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_ollama_worker,
        args=(queue, case, root, profile, timeout, expected_source_path),
    )
    process.start()
    process.join(timeout)
    if process.is_alive():
        process.terminate()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        queue.close()
        raise ModelRunError("timeout")
    if process.exitcode != 0:
        queue.close()
        raise ModelRunError("provider_process_error")
    try:
        result = queue.get(timeout=1)
    except queue_module.Empty as error:
        raise ModelRunError("provider_process_error") from error
    finally:
        queue.close()
    if result[0] == "error":
        raise ModelRunError(result[1], prompt_tokens=result[2], generated_tokens=result[3])
    return cast(tuple[str, bool, bool, str | None, str | None, int, int], result[1])


def _failure_reason(error: Exception) -> str:
    if isinstance(error, ModelRunError):
        return error.reason
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, urllib.error.HTTPError):
        return "provider_http_error"
    if isinstance(error, ValueError):
        return "invalid_output_or_identity"
    if isinstance(error, OSError):
        return "provider_transport_error"
    return "provider_error"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    plan = _load(args.plan)
    corpus_path = Path(plan["corpus_manifest"])
    corpus = _load(corpus_path)
    _verify_plan(plan, args.plan, corpus)
    corpus_check = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(__file__).with_name("development_corpus.py")),
            "--manifest",
            str(corpus_path),
            "--print-tree-hash",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if (
        corpus_check.returncode != 0
        or plan["corpus_content_sha256"] not in corpus_check.stdout.splitlines()
    ):
        raise ValueError("frozen corpus validation failed")
    planned = planned_cells(
        [(item["case_id"], item["expected_label"]) for item in corpus["cases"]],
        plan["repetitions"],
    )
    if args.dry_run:
        print(json.dumps({"planned_cells": len(planned)}, separators=(",", ":")))
        return 0
    timeout = plan["budget"]["wall_seconds"]
    _verify_runtime(plan["ollama"], timeout)
    plan_sha256 = _sha256_bytes(args.plan.read_bytes())
    root = corpus_path.parent
    cases = {item["case_id"]: item for item in corpus["cases"]}
    oracle_rules = _load(root / "corpus/oracle-rules.json")["rules"]
    output: list[Record] = []
    for case_id, configuration, repetition, expected in planned:
        case = cases[case_id]
        started = time.perf_counter()
        if configuration == "deterministic_only":
            elapsed = float(time.perf_counter() - started)
            output.append(
                _record(
                    plan=plan,
                    plan_sha256=plan_sha256,
                    case_id=case_id,
                    configuration=configuration,
                    repetition=repetition,
                    expected=expected,
                    state="not_run",
                    predicted=None,
                    confirmed_finding=None,
                    policy_matched=None,
                    returned_category=None,
                    returned_source_alias=None,
                    reason="shipped deterministic pipeline does not emit policy-matched CONFIRMED findings for this study",
                    wall_seconds=elapsed,
                    prompt_tokens=None,
                    generated_tokens=None,
                    scanner_signals=None,
                )
            )
        elif configuration == "one_shot_llm":
            try:
                (
                    predicted,
                    confirmed,
                    matched,
                    returned_category,
                    returned_source_alias,
                    prompt_tokens,
                    generated_tokens,
                ) = _bounded_ollama(
                    case,
                    root,
                    plan["ollama"],
                    timeout,
                    oracle_rules[case_id]["source_path"],
                )
                if prompt_tokens + generated_tokens > plan["budget"]["tokens"]:
                    raise ModelRunError(
                        "budget_exhausted",
                        prompt_tokens=prompt_tokens,
                        generated_tokens=generated_tokens,
                    )
                output.append(
                    _record(
                        plan=plan,
                        plan_sha256=plan_sha256,
                        case_id=case_id,
                        configuration=configuration,
                        repetition=repetition,
                        expected=expected,
                        state="executed",
                        predicted=predicted,
                        confirmed_finding=confirmed,
                        policy_matched=matched,
                        returned_category=returned_category,
                        returned_source_alias=returned_source_alias,
                        reason=None,
                        wall_seconds=float(time.perf_counter() - started),
                        prompt_tokens=prompt_tokens,
                        generated_tokens=generated_tokens,
                        scanner_signals=None,
                    )
                )
            except Exception as error:
                output.append(
                    _record(
                        plan=plan,
                        plan_sha256=plan_sha256,
                        case_id=case_id,
                        configuration=configuration,
                        repetition=repetition,
                        expected=expected,
                        state="failed",
                        predicted=None,
                        confirmed_finding=None,
                        policy_matched=None,
                        returned_category=None,
                        returned_source_alias=None,
                        reason=_failure_reason(error),
                        wall_seconds=float(time.perf_counter() - started),
                        prompt_tokens=(
                            error.prompt_tokens if isinstance(error, ModelRunError) else None
                        ),
                        generated_tokens=(
                            error.generated_tokens if isinstance(error, ModelRunError) else None
                        ),
                        scanner_signals=None,
                    )
                )
        elif configuration in UNSUPPORTED:
            output.append(
                _record(
                    plan=plan,
                    plan_sha256=plan_sha256,
                    case_id=case_id,
                    configuration=configuration,
                    repetition=repetition,
                    expected=expected,
                    state="not_run",
                    predicted=None,
                    confirmed_finding=None,
                    policy_matched=None,
                    returned_category=None,
                    returned_source_alias=None,
                    reason="declared product workflow is not implemented",
                    wall_seconds=None,
                    prompt_tokens=None,
                    generated_tokens=None,
                    scanner_signals=None,
                )
            )
        else:
            raise ValueError("unknown configuration")
    args.records.parent.mkdir(parents=True, exist_ok=True)
    args.records.write_bytes(
        (
            "\n".join(
                json.dumps(item.document(), sort_keys=True, separators=(",", ":"))
                for item in output
            )
            + "\n"
        ).encode("utf-8")
    )
    args.aggregate.write_bytes(
        (json.dumps(aggregate(planned, tuple(output)), sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
