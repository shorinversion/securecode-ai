"""``securecode analyze``: trial run of the full audit pipeline, no host approval needed."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from securecode_ai.adapters.local_product_trial import (
    TrialAnalysis,
    TrialAnalysisError,
    run_trial_analysis,
)
from securecode_ai.core.reports import ReportFormat

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
            "Trial audit of one Git checkout with the full pipeline (scanners, Auditor, "
            "Skeptic, finding gate, OWASP Top 10 report). No host approval is required; "
            "trial results are not a publishable or CI-blocking verdict."
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
        "--max-cost-usd",
        type=float,
        default=1.0,
        help="spend cap for one DeepSeek run (default 1.0)",
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
    try:
        analysis = run_trial_analysis(
            arguments.target,
            provider=arguments.provider,
            report_format=_FORMATS[arguments.format],
            environment=_with_dotenv(environment),
            max_cost_microusd=max(1, int(arguments.max_cost_usd * 1_000_000)),
        )
    except TrialAnalysisError as error:
        stderr.write(f"securecode analyze: {error}\n")
        return _EXIT_CONFIG
    except Exception as error:
        stderr.write(f"securecode analyze: failed ({type(error).__name__})\n")
        return _EXIT_INDETERMINATE
    rendered = analysis.result.rendered
    if output is None:
        stdout.write(rendered.decode("utf-8"))
        if not rendered.endswith(b"\n"):
            stdout.write("\n")
    else:
        with output.open("xb") as handle:
            handle.write(rendered)
    stderr.write(_summary(analysis))
    return int(analysis.result.exit_code)


def _summary(analysis: TrialAnalysis) -> str:
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
        f"cost=${analysis.cost_microusd / 1_000_000:.4f}\n"
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
