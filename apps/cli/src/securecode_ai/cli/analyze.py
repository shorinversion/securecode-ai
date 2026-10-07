"""``securecode analyze``: trial run of the full audit pipeline, no host approval needed."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TextIO

from securecode_ai.adapters.local_product_trial import (
    DEEPSEEK_PRICES_PER_MILLION,
    DEFAULT_LOCAL_MODEL,
    TrialAnalysis,
    TrialAnalysisError,
    operator_endpoint,
    run_trial_analysis,
)
from securecode_ai.adapters.product_audit_types import ProductAuditComposition
from securecode_ai.adapters.product_execution import (
    masked_product_sources,
    restricted_product_source_paths,
)
from securecode_ai.adapters.trial_architect import (
    Complete,
    ProposedFix,
    findings_from_report,
    git_apply_check,
    git_revision_reader,
    openai_compatible_complete,
    propose_fixes,
)
from securecode_ai.adapters.trial_fix_export import (
    attach_decisions_to_json,
    attach_decisions_to_sarif,
    attach_fixes_to_json,
    attach_fixes_to_sarif,
    attach_groups_to_json,
    attach_groups_to_sarif,
)
from securecode_ai.adapters.trial_report import (
    TrialReportContext,
    render_trial_report,
    report_paths,
)
from securecode_ai.adapters.trial_unresolved import (
    attach_undecided_to_json,
    finding_decisions,
    unresolved_report,
)
from securecode_ai.core.reports import ReportFormat, render_report

_FORMATS = {
    "markdown": ReportFormat.MARKDOWN,
    "html": ReportFormat.HTML,
    "json": ReportFormat.JSON,
    "sarif": ReportFormat.SARIF,
}
_EXIT_INDETERMINATE = 3
_EXIT_CONFIG = 4


def analyze_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securecode analyze",
        description=(
            "Audit one Git checkout with the full pipeline: scanners, model Discovery, "
            "Auditor, Skeptic, finding gate and Architect fixes, with an OWASP Top 10 "
            "report. No host approval is required; results are not a CI-blocking verdict."
        ),
        epilog=(
            "exit codes: 0 PASS - no confirmed finding and every required stage completed; "
            "2 FAIL - at least one confirmed finding (takes precedence over incomplete "
            "stages); 3 INDETERMINATE - no confirmed finding, but a required stage or a "
            "candidate is unresolved, or the run failed; 4 - invalid arguments, missing "
            "key, unsupported Git or an existing output path"
        ),
    )
    parser.add_argument("target", help="Git checkout to audit")
    parser.add_argument(
        "--provider",
        choices=("deepseek", "openai-compatible", "local"),
        default="deepseek",
        help=(
            "deepseek (DEEPSEEK_API_KEY); openai-compatible: any HTTPS endpoint with the "
            "OpenAI Chat Completions API (SECURECODE_MODEL_BASE_URL, SECURECODE_MODEL, "
            "SECURECODE_MODEL_API_KEY); local: Ollama on 127.0.0.1:11434"
        ),
    )
    parser.add_argument("--format", choices=tuple(_FORMATS), default="markdown")
    parser.add_argument("--output", help="write the report to a new file instead of stdout")
    parser.add_argument(
        "--output-dir",
        help=(
            "write report.md, report.html, report.json and report.sarif of one run "
            "into this new directory (--format and --output are then ignored)"
        ),
    )
    parser.add_argument(
        "--max-cost-usd",
        type=float,
        default=1.0,
        help=(
            "spend cap for one run (default 1.0); for openai-compatible it applies only "
            "with SECURECODE_MODEL_PRICE_INPUT and SECURECODE_MODEL_PRICE_OUTPUT"
        ),
    )
    parser.add_argument("--no-fix", action="store_true", help="do not ask the Architect for fixes")
    parser.add_argument(
        "--patch-dir", help="write validated fixes as .diff files into this new directory"
    )
    return parser


def run_analyze_command(
    tokens: Sequence[str],
    *,
    stdout: TextIO,
    stderr: TextIO,
    environment: Mapping[str, str],
) -> int:
    try:
        arguments = analyze_parser().parse_args(list(tokens[1:]))
    except SystemExit as exit_request:
        return int(exit_request.code or 0)
    output = Path(arguments.output) if arguments.output else None
    if output is not None and output.exists():
        stderr.write(f"output file already exists: {output}\n")
        return _EXIT_CONFIG
    output_dir = Path(arguments.output_dir) if arguments.output_dir else None
    if output_dir is not None and output_dir.exists():
        stderr.write(f"output directory already exists: {output_dir}\n")
        return _EXIT_CONFIG
    patch_dir = Path(arguments.patch_dir) if arguments.patch_dir else None
    if patch_dir is not None and patch_dir.exists():
        stderr.write(f"patch directory already exists: {patch_dir}\n")
        return _EXIT_CONFIG
    values = _with_dotenv(environment)
    try:
        analysis = run_trial_analysis(
            arguments.target,
            provider=arguments.provider,
            report_format=_FORMATS[arguments.format],
            environment=values,
            max_cost_microusd=max(1, int(arguments.max_cost_usd * 1_000_000)),
        )
    except TrialAnalysisError as error:
        stderr.write(f"securecode analyze: {error}\n")
        return _EXIT_CONFIG
    except Exception as error:
        stderr.write(f"securecode analyze: failed ({type(error).__name__})\n")
        return _EXIT_INDETERMINATE
    rendered = analysis.result.rendered
    cost = analysis.cost_microusd
    readable = arguments.format in {"markdown", "html"}
    reports: dict[str, bytes] = {}
    if readable or output_dir is not None or patch_dir is not None or not arguments.no_fix:
        document = json.loads(analysis.result.composition.json_report)
        revision = document.get("repository_revision", {})
        head_sha = str(revision.get("head_sha", "")) if isinstance(revision, dict) else ""
        repository = Path(arguments.target).resolve()
        raw_source = git_revision_reader(repository, head_sha)
        # The Architect prompt and the report fragments use masked source: a detected
        # secret value never reaches the model or a report (D-116).
        read_source = _secret_safe_reader(raw_source, analysis)
        fixes: tuple[ProposedFix, ...] = ()
        findings = findings_from_report(document)
        if findings and not arguments.no_fix:
            usage: list[tuple[int, int]] = []
            fixes = _unique_fixes(
                propose_fixes(
                    findings,
                    _architect(arguments.provider, values, usage),
                    read_source=read_source,
                )
            )
            if arguments.provider == "deepseek" and cost is not None:
                cost += _usage_cost(usage, DEEPSEEK_PRICES_PER_MILLION)
            elif arguments.provider == "openai-compatible" and cost is not None:
                prices = operator_endpoint(values).prices
                cost = None if prices is None else cost + _usage_cost(usage, prices)
        unresolved, covered = unresolved_report(analysis.result.composition)
        context = TrialReportContext(
            repository,
            head_sha,
            analysis.provider,
            analysis.model_id,
            cost,
            _sources(read_source, report_paths(document)) if readable or output_dir else {},
            tuple(
                (item.cwe_id, item.path, item.line, item.origin, item.reason) for item in unresolved
            ),
            covered,
        )
        if output_dir is not None:
            composition = analysis.result.composition
            decisions = finding_decisions(composition)
            reports = {
                "report.md": render_trial_report(document, context, fixes, html_format=False),
                "report.html": render_trial_report(document, context, fixes, html_format=True),
                "report.json": _machine_json(
                    attach_fixes_to_json(composition.json_report, fixes, findings), composition
                ),
                "report.sarif": _machine_sarif(
                    attach_fixes_to_sarif(
                        render_report(composition.report, ReportFormat.SARIF), fixes, findings
                    ),
                    composition.json_report,
                    decisions,
                ),
            }
        elif readable:
            rendered = render_trial_report(
                document, context, fixes, html_format=arguments.format == "html"
            )
        elif arguments.format == "json":
            rendered = attach_fixes_to_json(rendered, fixes, findings)
        elif arguments.format == "sarif":
            rendered = attach_fixes_to_sarif(rendered, fixes, findings)
        if patch_dir is not None:
            skipped = _write_patches(patch_dir, fixes, raw_source)
            for path in skipped:
                stderr.write(
                    f"securecode analyze: the fix for {path} changes a line with a masked "
                    "secret; apply it by hand from the report and rotate the secret\n"
                )
    if arguments.format == "json" and output_dir is None:
        rendered = _machine_json(rendered, analysis.result.composition)
    elif arguments.format == "sarif" and output_dir is None:
        rendered = _machine_sarif(
            rendered,
            analysis.result.composition.json_report,
            finding_decisions(analysis.result.composition),
        )
    if output_dir is not None:
        output_dir.mkdir(parents=True)
        for name, content in reports.items():
            (output_dir / name).write_bytes(content)
        stdout.write(f"reports written to {output_dir}\n")
    elif output is None:
        stdout.write(rendered.decode("utf-8"))
        if not rendered.endswith(b"\n"):
            stdout.write("\n")
    else:
        with output.open("xb") as handle:
            handle.write(rendered)
    stderr.write(_summary(analysis, cost))
    return int(analysis.result.exit_code)


def _architect(provider: str, values: Mapping[str, str], usage: list[tuple[int, int]]) -> Complete:
    # The Architect calls the same endpoint as the rest of the run: a source file never goes
    # to a host the egress policy did not admit.
    if provider == "deepseek":
        return openai_compatible_complete(
            "https://api.deepseek.com",
            values.get("DEEPSEEK_API_KEY"),
            values.get("DEEPSEEK_MODEL") or "deepseek-flash",
            usage=usage,
        )
    if provider == "openai-compatible":
        endpoint = operator_endpoint(values)
        return openai_compatible_complete(
            endpoint.base_url, endpoint.api_key, endpoint.model_id, usage=usage
        )
    return openai_compatible_complete(
        "http://127.0.0.1:11434/v1",
        None,
        values.get("SECURECODE_LOCAL_MODEL") or DEFAULT_LOCAL_MODEL,
        usage=usage,
    )


def _sources(read_source: Callable[[str], str], paths: Sequence[str]) -> dict[str, str]:
    sources: dict[str, str] = {}
    for path in paths:
        try:
            sources[path] = read_source(path)
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            continue
    return sources


def _usage_cost(usage: Sequence[tuple[int, int]], prices: tuple[int, int]) -> int:
    input_price, output_price = prices
    return sum(
        (prompt * input_price + completion * output_price) // 1_000_000
        for prompt, completion in usage
    )


def _unique_fixes(fixes: Sequence[ProposedFix]) -> tuple[ProposedFix, ...]:
    """Drop a validated fix whose diff repeats an earlier one."""
    seen: set[tuple[str, str]] = set()
    unique: list[ProposedFix] = []
    for fix in fixes:
        key = (fix.path, fix.diff)
        if fix.status == "VALIDATED" and key in seen:
            continue
        seen.add(key)
        unique.append(fix)
    return tuple(unique)


def _machine_json(rendered: bytes, composition: ProductAuditComposition) -> bytes:
    return attach_undecided_to_json(
        attach_decisions_to_json(attach_groups_to_json(rendered), finding_decisions(composition)),
        composition,
    )


def _machine_sarif(
    rendered: bytes, json_report: bytes, decisions: Mapping[str, Mapping[str, object]]
) -> bytes:
    return attach_decisions_to_sarif(attach_groups_to_sarif(rendered), json_report, decisions)


def _write_patches(
    directory: Path, fixes: Sequence[ProposedFix], read_original: Callable[[str], str]
) -> tuple[str, ...]:
    """Write validated fixes that apply to the original files; return the skipped paths.

    A fix is built on masked source, so one that touches a masked secret line does not
    apply to the original file and is left for a manual change.
    """
    directory.mkdir(parents=True)
    skipped: list[str] = []
    for index, fix in enumerate(fixes, start=1):
        if fix.status != "VALIDATED":
            continue
        try:
            applies = git_apply_check(fix.path, read_original(fix.path), fix.diff)
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            applies = False
        if not applies:
            skipped.append(fix.path)
            continue
        name = f"{index:02d}-" + fix.path.replace("/", "_") + ".diff"
        (directory / name).write_text(fix.diff, encoding="utf-8", newline="\n")
    return tuple(skipped)


def _secret_safe_reader(
    read: Callable[[str], str], analysis: TrialAnalysis
) -> Callable[[str], str]:
    """Serve files with detected secrets masked; withhold them when spans are unknown."""

    host = analysis.result.composition.host_inputs
    execution = None if host is None else host.deterministic_execution
    if execution is None:

        def withheld(_path: str) -> str:
            raise ValueError("source withheld: secret scan result is unavailable")

        return withheld
    masked = masked_product_sources(execution)
    restricted = frozenset(restricted_product_source_paths(execution))

    def masked_read(path: str) -> str:
        if path in masked:
            return masked[path]
        if path in restricted:
            raise ValueError("source withheld: secret positions are not verified")
        return read(path)

    return masked_read


def _summary(analysis: TrialAnalysis, cost_microusd: int | None) -> str:
    findings = "?"
    try:
        document = json.loads(analysis.result.sarif_rendered)
        findings = str(len(document["runs"][0].get("results", [])))
    except Exception:
        pass
    outcome = {0: "PASS", 2: "FAIL"}.get(analysis.result.exit_code, "INDETERMINATE")
    return (
        f"trial analysis: outcome={outcome} findings={findings} "
        f"provider={analysis.provider} model={analysis.model_id} "
        + (
            "cost=unknown\n"
            if cost_microusd is None
            else f"cost=${cost_microusd / 1_000_000:.4f}\n"
        )
    )


def _with_dotenv(environment: Mapping[str, str]) -> dict[str, str]:
    """Add DEEPSEEK_* / SECURECODE_* from ./.env without overriding the environment."""

    values = dict(environment)
    dotenv = Path.cwd() / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and key.startswith(("DEEPSEEK_", "SECURECODE_")):
                values.setdefault(key, value.strip().strip("'\""))
    return values


__all__ = ["analyze_parser", "run_analyze_command"]
