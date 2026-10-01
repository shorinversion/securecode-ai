"""Score SecureCode and baseline tools on OWASP Benchmark for Python.

Every test case is one Python file with a known category and ground truth
(``expectedresults-0.1.csv``).  A tool detects a case only when it reports a CWE of
that case's category, as in the official OWASP Benchmark scorecards; the accepted CWE
set per category is listed in ``CATEGORY_CWES``.  The score of a category is
TPR - FPR (Youden's J); the overall score is the average over categories.

Source: https://github.com/OWASP-Benchmark/BenchmarkPython (commit f1291485).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Final

from securecode_ai.adapters.product_scanner import FirstPartyStaticWorker
from securecode_ai.core.repository import RepositoryFile
from securecode_ai.core.scanning import ScannerRequest

CATEGORY_CWES: Final = {
    "pathtraver": frozenset({22, 23, 36, 73}),
    "hash": frozenset({327, 328, 916}),
    "weakrand": frozenset({330, 338}),
    "xss": frozenset({79, 80}),
    "deserialization": frozenset({502}),
    "codeinj": frozenset({94, 95}),
    "securecookie": frozenset({614, 1004}),
    "trustbound": frozenset({501}),
    "redirect": frozenset({601}),
    "ldapi": frozenset({90}),
    "xxe": frozenset({611, 776}),
    "cmdi": frozenset({77, 78}),
    "sqli": frozenset({89}),
    "xpathi": frozenset({643}),
}
_CWE: Final = re.compile(r"cwe[-_:]?\s*(\d{1,4})", re.IGNORECASE)
_INPUT_PRICE: Final = 150_000
_OUTPUT_PRICE: Final = 600_000

Case = tuple[str, str, bool, int]  # test name, category, vulnerable, CWE


def load_cases(root: Path) -> list[Case]:
    cases: list[Case] = []
    for line in (root / "expectedresults-0.1.csv").read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        name, category, truth, cwe = line.split(",")[:4]
        cases.append((name, category, truth.strip() == "true", int(cwe)))
    return cases


def _cwes(text: str) -> set[int]:
    return {int(match) for match in _CWE.findall(text)}


def securecode(root: Path, cases: Sequence[Case]) -> dict[str, set[int]]:
    worker = FirstPartyStaticWorker()
    found: dict[str, set[int]] = {}
    for name, *_ in cases:
        data = (root / "testcode" / f"{name}.py").read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        request = ScannerRequest(
            request_id="owasp-" + digest,
            tenant_id="public-benchmark",
            repository_id="owasp-benchmark-python",
            head_sha=hashlib.sha1(name.encode()).hexdigest(),
            file=RepositoryFile(f"{name}.py", len(data), digest),
            source=data,
        )
        try:
            signals = worker.scan(request).signals
        except Exception:
            signals = ()
        found[name] = (
            set().union(*(_cwes(signal.rule_id) for signal in signals)) if signals else set()
        )
    return found


def semgrep(root: Path, cases: Sequence[Case], config: Path) -> dict[str, set[int]]:
    completed = subprocess.run(
        (
            "semgrep",
            "scan",
            "--config",
            str(config / "python"),
            "--json",
            "--no-git-ignore",
            "--quiet",
            "--metrics=off",
            str(root / "testcode"),
        ),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=3600,
    )
    found: dict[str, set[int]] = {name: set() for name, *_ in cases}
    for result in json.loads(completed.stdout).get("results", []):
        name = Path(result["path"]).stem
        if name in found:
            metadata = result.get("extra", {}).get("metadata", {})
            found[name] |= _cwes(json.dumps(metadata.get("cwe", "")))
    return found


def bandit(root: Path, cases: Sequence[Case]) -> dict[str, set[int]]:
    completed = subprocess.run(
        ("bandit", "-r", str(root / "testcode"), "-f", "json", "-q"),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=3600,
    )
    found: dict[str, set[int]] = {name: set() for name, *_ in cases}
    for result in json.loads(completed.stdout).get("results", []):
        name = Path(result["filename"]).stem
        cwe = (result.get("issue_cwe") or {}).get("id")
        if name in found and isinstance(cwe, int):
            found[name].add(cwe)
    return found


def llm(provider_name: str, root: Path, cases: Sequence[Case]) -> tuple[dict[str, set[int]], int]:
    """Ask one OpenAI-compatible model for the CWEs of every case."""

    from scripts.llm_providers import PROVIDERS, answer_value, complete_json

    provider = PROVIDERS[provider_name]

    def one(case: Case) -> tuple[str, set[int], int]:
        name = case[0]
        source = (root / "testcode" / f"{name}.py").read_text(encoding="utf-8")
        prompt = (
            "Audit this Python web handler for security vulnerabilities. Report only real, "
            'exploitable weaknesses. Return strict json {"cwe": [<CWE numbers>]}, empty if '
            "the code is safe. Do not explain.\nSource:\n" + source
        )
        try:
            answer, cost = complete_json(provider, prompt)
        except ValueError:
            return name, set(), 0
        values = answer_value(answer, "cwe") or []
        values = values if isinstance(values, list) else []
        found = {int(value) for value in values if str(value).isdigit()} | _cwes(json.dumps(values))
        return name, found, cost

    with ThreadPoolExecutor(max_workers=provider.max_parallel) as pool:
        results = list(pool.map(one, cases))
    return {name: found for name, found, _ in results}, sum(cost for *_, cost in results)


def balanced_sample(cases: Sequence[Case], per_category: int) -> list[Case]:
    """The first ``per_category`` cases of every category, half vulnerable where possible."""

    sample: list[Case] = []
    for category in CATEGORY_CWES:
        vulnerable = [case for case in cases if case[1] == category and case[2]]
        safe = [case for case in cases if case[1] == category and not case[2]]
        half = per_category // 2
        chosen = vulnerable[:half] + safe[: per_category - min(half, len(vulnerable))]
        sample.extend(chosen[:per_category])
    return sample


def _cached(path: Path, compute: Any) -> tuple[dict[str, set[int]], int]:
    if path.is_file():
        document = json.loads(path.read_text(encoding="utf-8"))
        return {name: set(values) for name, values in document["found"].items()}, document["cost"]
    found, cost = compute()
    path.write_text(
        json.dumps({"found": {k: sorted(v) for k, v in found.items()}, "cost": cost}),
        encoding="utf-8",
    )
    return found, cost


def score(cases: Sequence[Case], found: dict[str, set[int]]) -> dict[str, Any]:
    per_category: dict[str, dict[str, Any]] = {}
    tp_all = fp_all = positives = 0
    for category, accepted in CATEGORY_CWES.items():
        selected = [case for case in cases if case[1] == category]
        vulnerable = [case for case in selected if case[2]]
        safe = [case for case in selected if not case[2]]
        tp = sum(bool(found.get(case[0], set()) & accepted) for case in vulnerable)
        fp = sum(bool(found.get(case[0], set()) & accepted) for case in safe)
        tpr = tp / len(vulnerable) if vulnerable else 0.0
        fpr = fp / len(safe) if safe else 0.0
        per_category[category] = {
            "cases": len(selected),
            "tp": tp,
            "fp": fp,
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "score": round(tpr - fpr, 4),
        }
        tp_all += tp
        fp_all += fp
        positives += len(vulnerable)
    scores = [item["score"] for item in per_category.values()]
    return {
        "score": round(sum(scores) / len(scores), 4),
        "tpr": round(tp_all / positives, 4) if positives else 0.0,
        "precision": round(tp_all / (tp_all + fp_all), 4) if tp_all + fp_all else 0.0,
        "categories": per_category,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", required=True, type=Path)
    parser.add_argument("--semgrep-config", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--models", nargs="*", default=[], help="models scored on every case (deepseek, luna, glm)"
    )
    parser.add_argument(
        "--sampled-models", nargs="*", default=[], help="models scored on a balanced sample only"
    )
    parser.add_argument("--sample-per-category", type=int, default=20)
    arguments = parser.parse_args(argv)
    from scripts.llm_providers import load_dotenv

    load_dotenv()
    root = arguments.benchmark
    cases = load_cases(root)
    cache = arguments.output.parent / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    found: dict[str, dict[str, set[int]]] = {
        "securecode": securecode(root, cases),
        "semgrep": semgrep(root, cases, arguments.semgrep_config),
        "bandit": bandit(root, cases),
    }
    costs: dict[str, int] = {}
    for model in arguments.models:
        found[model], costs[model] = _cached(
            cache / f"{model}.json", lambda model=model: llm(model, root, cases)
        )
        found[f"securecode+{model}"] = {
            name: found["securecode"][name] | found[model].get(name, set()) for name, *_ in cases
        }
    sample = balanced_sample(cases, arguments.sample_per_category)
    sampled: dict[str, dict[str, set[int]]] = {}
    for model in arguments.sampled_models:
        sampled[model], costs[model] = _cached(
            cache / f"{model}-sample.json", lambda model=model: llm(model, root, sample)
        )
    result: dict[str, Any] = {
        "cases": len(cases),
        "source": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "cost_usd": {model: round(cost / 1e6, 4) for model, cost in costs.items()},
        "tools": {tool: score(cases, values) for tool, values in found.items()},
    }
    if sampled:
        result["sample"] = {
            "cases": len(sample),
            "per_category": arguments.sample_per_category,
            "tools": {tool: score(sample, values) for tool, values in {**found, **sampled}.items()},
        }
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({tool: v["score"] for tool, v in result["tools"].items()}, indent=2))
    if sampled:
        print(
            json.dumps(
                {tool: v["score"] for tool, v in result["sample"]["tools"].items()}, indent=2
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
