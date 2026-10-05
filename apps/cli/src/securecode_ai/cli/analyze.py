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
    run_trial_analysis,
)
from securecode_ai.adapters.trial_architect import (
    Complete,
    ProposedFix,
    findings_from_report,
    git_revision_reader,
    openai_compatible_complete,
    propose_fixes,
)
from securecode_ai.adapters.trial_fix_export import attach_fixes_to_json, attach_fixes_to_sarif
from securecode_ai.adapters.trial_report import (
    TrialReportContext,
    render_trial_report,
    report_paths,
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
        choices=("deepseek", "local"),
        default="deepseek",
        help="deepseek (DEEPSEEK_API_KEY) or local Ollama on 127.0.0.1:11434",
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
        help="spend cap for one DeepSeek run (default 1.0)",
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
        read_source = git_revision_reader(repository, head_sha)
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
            if arguments.provider == "deepseek":
                cost += _deepseek_cost(usage)
        context = TrialReportContext(
            repository,
            head_sha,
            analysis.provider,
            analysis.model_id,
            cost,
            _sources(read_source, report_paths(document)) if readable or output_dir else {},
        )
        if output_dir is not None:
            composition = analysis.result.composition
            reports = {
                "report.md": render_trial_report(document, context, fixes, html_format=False),
                "report.html": render_trial_report(document, context, fixes, html_format=True),
                "report.json": attach_fixes_to_json(composition.json_report, fixes, findings),
                "report.sarif": attach_fixes_to_sarif(
                    render_report(composition.report, ReportFormat.SARIF), fixes, findings
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
            _write_patches(patch_dir, fixes)
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
    if provider == "deepseek":
        return openai_compatible_complete(
            values.get("DEEPSEEK_BASE_URL") or "https://api.deepseek.com",
            values.get("DEEPSEEK_API_KEY"),
            values.get("DEEPSEEK_MODEL") or "deepseek-flash",
            usage=usage,
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


def _deepseek_cost(usage: Sequence[tuple[int, int]]) -> int:
    input_price, output_price = DEEPSEEK_PRICES_PER_MILLION
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


def _write_patches(directory: Path, fixes: Sequence[ProposedFix]) -> None:
    directory.mkdir(parents=True)
    for index, fix in enumerate(fixes, start=1):
        if fix.status == "VALIDATED":
            name = f"{index:02d}-" + fix.path.replace("/", "_") + ".diff"
            (directory / name).write_text(fix.diff, encoding="utf-8", newline="\n")


def _summary(analysis: TrialAnalysis, cost_microusd: int) -> str:
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
        f"cost=${cost_microusd / 1_000_000:.4f}\n"
    )


def _with_dotenv(environment: Mapping[str, str]) -> dict[str, str]:
    """Add DEEPSEEK_* / SECURECODE_LOCAL_MODEL from ./.env without overriding the environment."""

    values = dict(environment)
    dotenv = Path.cwd() / ".env"
    if dotenv.is_file():
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.strip().partition("=")
            if separator and (key.startswith("DEEPSEEK_") or key == "SECURECODE_LOCAL_MODEL"):
                values.setdefault(key, value.strip().strip("'\""))
    return values


__all__ = ["analyze_parser", "run_analyze_command"]
