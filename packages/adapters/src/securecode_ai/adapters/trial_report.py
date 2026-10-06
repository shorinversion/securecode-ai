# ruff: noqa: RUF001 - the report is written in Russian
"""Human-readable Markdown and HTML report for ``securecode analyze``.

The canonical JSON report stays the source of truth.  This view adds what a reader
needs and the canonical report deliberately omits: the vulnerable code fragment read
from the analysed revision, plain-language names for CWE and OWASP categories, and the
Architect's validated fix.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .trial_architect import ProposedFix

OWASP_2021: Final = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

CWE_NAMES: Final = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-117": "Log Injection",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-209": "Error Message Information Exposure",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-252": "Unchecked Return Value",
    "CWE-259": "Hard-coded Password",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-307": "Excessive Authentication Attempts",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken or Risky Cryptographic Algorithm",
    "CWE-328": "Weak Hash",
    "CWE-330": "Insufficiently Random Values",
    "CWE-338": "Weak PRNG for Security",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-362": "Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-532": "Sensitive Information in Log File",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-770": "Allocation without Limits",
    "CWE-776": "XML Entity Expansion",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-915": "Mass Assignment",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-943": "NoSQL Injection",
    "CWE-1021": "Clickjacking",
    "CWE-1321": "Prototype Pollution",
    "CWE-1333": "Regular Expression Denial of Service",
}

_ORIGINS: Final = {
    "deterministic": "сканер",
    "model_native": "модель",
}
_SINKS: Final = {
    "CWE-78": re.compile(
        r"subprocess|os\.(system|popen|exec|spawn)|\bexec\(|child_process|exec\.Command"
    ),
    "CWE-88": re.compile(r"subprocess|os\.(exec|spawn)|child_process|exec\.Command"),
    "CWE-89": re.compile(
        r"\.(execute|executemany|raw|query|exec)\s*\(|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b",
        re.I,
    ),
    "CWE-22": re.compile(r"\bopen\(|send_file|os\.path\.join|readFile|filepath\.Join"),
    "CWE-79": re.compile(
        r"render_template_string|Markup|innerHTML|dangerouslySetInnerHTML|\|\s*safe"
    ),
    "CWE-94": re.compile(r"\beval\(|\bexec\(|new Function"),
    "CWE-502": re.compile(r"pickle\.loads?|yaml\.load|marshal\.loads?"),
    "CWE-918": re.compile(r"requests\.(get|post)|urlopen|fetch\(|http\.Get"),
    "CWE-798": re.compile(r"(key|secret|token|password|passwd)\s*[=:]", re.I),
}
_SEVERITY_ORDER: Final = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_OUTCOMES: Final = {
    "FAIL": "Найдены подтверждённые уязвимости",
    "PASS": "Подтверждённых уязвимостей не найдено",
    "INDETERMINATE": "Результат не определён",
}
_FIX_STATUS: Final = {
    "VALIDATED": "исправление проверено",
    "NOT_VALIDATED": "исправление не прошло проверку",
    "NO_FIX": "исправление не предложено",
}
_STAGES: Final = {
    "model_native_discovery": "поиск уязвимостей моделью",
    "auditor_investigation": "проверка Аудитором",
    "skeptic_review": "проверка Скептиком",
    "finding_gate": "итоговое решение",
    "deterministic_analysis": "детерминированные сканеры",
    "normalization": "объединение результатов",
    "evidence_graph": "граф доказательств",
}
_CONTEXT_LINES: Final = 3
_CHECKS: Final = {
    "apply:ok": "патч применяется (git apply --check)",
    "apply:failed": "патч не применяется",
    "syntax:ok": "синтаксис корректен",
    "syntax:failed": "синтаксическая ошибка",
    "rescan:clean": "повторное сканирование не нашло новых проблем",
    "original:gone": "исходная находка устранена",
    "original:remains": "исходная находка осталась",
    "options:guarded": "пользовательский ввод не может стать опцией команды",
    "options:unguarded": "пользовательский ввод может стать опцией команды (CWE-88)",
}


def _check(code: str) -> str:
    if code.startswith("rescan:new="):
        return "повторное сканирование нашло: " + code.removeprefix("rescan:new=")
    return _CHECKS.get(code, code)


def _checks(fix: ProposedFix) -> str:
    return "; ".join(_check(code) for code in fix.checks)


def _lines(entry: _Entry) -> str:
    if entry.start_line == entry.end_line:
        return f"строка {entry.start_line}"
    return f"строки {entry.start_line}-{entry.end_line}"


@dataclass(frozen=True, slots=True)
class TrialReportContext:
    repository: Path
    head_sha: str
    provider: str
    model_id: str
    cost_microusd: int
    sources: Mapping[str, str]
    # Candidates without a final decision: (CWE, path, line, origin, reason).
    unresolved: tuple[tuple[str, str, int, str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class _Entry:
    cwe_id: str
    owasp: str
    severity: str
    origins: tuple[str, ...]
    path: str
    start_line: int
    end_line: int
    finding_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Section:
    number: int
    entry: _Entry
    fragment: tuple[tuple[int, str, bool], ...]
    fix: ProposedFix | None


@dataclass(frozen=True, slots=True)
class _Report:
    summary: tuple[tuple[str, str], ...]
    sections: tuple[_Section, ...]
    gaps: tuple[str, ...]
    unresolved: tuple[tuple[str, str, int, str, str], ...] = ()


def render_trial_report(
    document: Mapping[str, object],
    context: TrialReportContext,
    fixes: Sequence[ProposedFix],
    *,
    html_format: bool,
) -> bytes:
    fix_by_id = {fix.finding_id: fix for fix in fixes}
    entries = _entries(document, context.sources)
    sections = tuple(
        _Section(
            number,
            entry,
            _fragment(context, entry),
            next((fix_by_id[item] for item in entry.finding_ids if item in fix_by_id), None),
        )
        for number, entry in enumerate(entries, start=1)
    )
    outcome = str(document.get("outcome"))
    gaps = _coverage_gaps(document)
    verdict = _OUTCOMES.get(outcome, outcome)
    if outcome == "INDETERMINATE":
        verdict += (
            ": не все этапы проверки завершены, см. раздел ниже"
            if gaps
            else ": у части кандидатов нет окончательного решения, см. раздел ниже"
        )
    report = _Report(
        summary=(
            ("Итог", verdict),
            ("Репозиторий", str(context.repository)),
            ("Ревизия", context.head_sha[:12]),
            ("Модель", f"{context.model_id} ({context.provider})"),
            ("Стоимость запросов к модели", f"${context.cost_microusd / 1_000_000:.4f}"),
            ("Находок", str(len(entries))),
            ("Без окончательного решения", str(len(context.unresolved))),
            (
                "Этапы проверки",
                "все обязательные этапы выполнены" if not gaps else "есть незавершённые, см. ниже",
            ),
        ),
        sections=sections,
        gaps=gaps,
        unresolved=context.unresolved,
    )
    text = _html(report) if html_format else _markdown(report)
    return text.encode("utf-8")


def _dicts(value: object) -> list[dict[str, object]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _line(location: Mapping[str, object], key: str) -> int:
    point = location.get(key)
    line = point.get("line") if isinstance(point, dict) else None
    return line if isinstance(line, int) else 1


def _entries(
    document: Mapping[str, object], sources: Mapping[str, str] | None = None
) -> list[_Entry]:
    groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for item in _dicts(document.get("findings")):
        locations = _dicts(item.get("locations"))
        path = str(locations[0].get("path")) if locations else ""
        groups.setdefault((str(item.get("cwe_id")), path), []).append(item)
    entries: list[_Entry] = []
    for (cwe_id, path), items in groups.items():
        # The scanner lane carries exact sink lines; model locations are a fallback.
        scanner = [item for item in items if item.get("candidate_origin") == "deterministic"]
        locations = [
            location
            for item in scanner or items
            for location in _dicts(item.get("locations"))
            if location.get("path") == path
        ]
        lines = (sources or {}).get(path, "").splitlines()
        sink = _SINKS.get(cwe_id)
        ranked = sorted(
            (
                (not _at_sink(value, lines, sink), _line(value, "end") - _line(value, "start"), i)
                for i, value in enumerate(locations)
            )
        )
        narrow = locations[ranked[0][2]] if ranked else None
        start = _line(narrow, "start") if narrow is not None else 1
        end = max(start, _line(narrow, "end")) if narrow is not None else 1
        entries.append(
            _Entry(
                cwe_id=cwe_id,
                owasp=str(items[0].get("owasp_category", "")),
                severity=min((str(item.get("severity")) for item in items), key=_rank),
                origins=tuple(sorted({str(item.get("candidate_origin")) for item in items})),
                path=path,
                start_line=start,
                end_line=end,
                finding_ids=tuple(str(item.get("finding_id")) for item in items),
            )
        )
    entries.sort(key=lambda entry: (_rank(entry.severity), entry.path, entry.start_line))
    return entries


def _at_sink(
    location: Mapping[str, object], lines: list[str], sink: re.Pattern[str] | None
) -> bool:
    """Whether a cited location is the dangerous operation for the weakness.

    A model may cite several one-line calls; the report shows the one that is the sink.
    """
    first, last = _line(location, "start"), _line(location, "end")
    return sink is not None and any(sink.search(line) for line in lines[first - 1 : last])


def _rank(severity: str) -> int:
    return _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _cwe(cwe_id: str) -> str:
    name = CWE_NAMES.get(cwe_id)
    return f"{cwe_id} {name}" if name else cwe_id


def _owasp(category: str) -> str:
    name = OWASP_2021.get(category)
    return f"{category} {name}" if name else category


def _origins(entry: _Entry) -> str:
    return " + ".join(_ORIGINS.get(origin, origin) for origin in entry.origins)


def _fix_status(fix: ProposedFix | None) -> str:
    return _FIX_STATUS.get(fix.status, fix.status) if fix is not None else "—"


def _fragment(context: TrialReportContext, entry: _Entry) -> tuple[tuple[int, str, bool], ...]:
    source = context.sources.get(entry.path)
    if source is None:
        return ()
    lines = source.splitlines()
    start = max(1, entry.start_line - _CONTEXT_LINES)
    end = min(len(lines), entry.end_line + _CONTEXT_LINES, start + 40)
    return tuple(
        (number, lines[number - 1], entry.start_line <= number <= entry.end_line)
        for number in range(start, end + 1)
    )


def report_paths(document: Mapping[str, object]) -> tuple[str, ...]:
    """Files whose fragments the report shows."""

    return tuple(sorted({entry.path for entry in _entries(document)}))


def _coverage_gaps(document: Mapping[str, object]) -> tuple[str, ...]:
    manifest = document.get("coverage_manifest")
    units = _dicts(manifest.get("units")) if isinstance(manifest, dict) else []
    counts: dict[str, int] = {}
    for unit in units:
        if unit.get("required") and unit.get("coverage_status") == "FAILED":
            stage = str(unit.get("stage_id"))
            label = _STAGES.get(stage, stage)
            counts[label] = counts.get(label, 0) + 1
    return tuple(f"{label}: не завершена ({count})" for label, count in counts.items())


_HEADER: Final = (
    "№",
    "Уязвимость",
    "OWASP Top 10",
    "Критичность",
    "Место",
    "Источник",
    "Исправление",
)
_UNRESOLVED_NOTE: Final = (
    "Это не подтверждённые уязвимости и не безопасный код: модели не вынесли решение. "
    "Проверьте эти места вручную; код возврата 3 не означает, что уязвимостей нет."
)
_GAPS_NOTE: Final = (
    "Кандидаты с незавершённой проверкой не считаются ни уязвимостями, ни безопасным "
    "кодом и требуют ручного анализа."
)
_MACHINE_NOTE: Final = (
    "Машиночитаемый отчёт с полной трассировкой формируется с флагом --format json "
    "или --format sarif; флаг --output-dir за один прогон сохраняет все четыре формата."
)


def _row(section: _Section) -> tuple[str, ...]:
    entry = section.entry
    return (
        str(section.number),
        _cwe(entry.cwe_id),
        _owasp(entry.owasp),
        entry.severity,
        f"{entry.path}:{entry.start_line}",
        _origins(entry),
        _fix_status(section.fix),
    )


def _markdown(report: _Report) -> str:
    out = ["# SecureCode AI: отчёт аудита безопасности", ""]
    out += [f"- **{key}:** {value}" for key, value in report.summary]
    out.append("")
    if report.sections:
        out += ["## Находки", "", "| " + " | ".join(_HEADER) + " |"]
        out.append("|" + "---|" * len(_HEADER))
        for section in report.sections:
            out.append("| " + " | ".join(cell.replace("|", "\\|") for cell in _row(section)) + " |")
        out.append("")
    for section in report.sections:
        entry, fix = section.entry, section.fix
        out += [
            f"## {section.number}. {_cwe(entry.cwe_id)}",
            "",
            f"- **OWASP Top 10:** {_owasp(entry.owasp)}",
            f"- **Критичность:** {entry.severity}",
            f"- **Место:** `{entry.path}`, {_lines(entry)}",
            f"- **Источник:** {_origins(entry)}; подтверждено Аудитором и Скептиком",
            "",
        ]
        if section.fragment:
            width = len(str(section.fragment[-1][0]))
            out.append("```")
            out += [
                f"{'>' if marked else ' '} {number:>{width}} | {line}"
                for number, line, marked in section.fragment
            ]
            out += ["```", ""]
        if fix is not None and fix.diff:
            out += [f"**Исправление Архитектора** ({_fix_status(fix)}).", ""]
            if fix.explanation:
                out += [fix.explanation, ""]
            out += ["```diff", fix.diff.rstrip("\n"), "```", ""]
            out += ["Проверки: " + _checks(fix) + ".", ""]
        elif fix is not None:
            out += ["Исправление не предложено: " + _checks(fix) + ".", ""]
    if report.unresolved:
        out += ["## Кандидаты без окончательного решения", ""]
        out.append("| № | Уязвимость | Место | Источник | Причина |")
        out.append("|---|---|---|---|---|")
        for number, (cwe_id, path, line, origin, reason) in enumerate(report.unresolved, 1):
            cells = (str(number), _cwe(cwe_id), f"{path}:{line}", origin, reason)
            out.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
        out += ["", _UNRESOLVED_NOTE, ""]
    if report.gaps:
        out += ["## Неполная проверка", ""]
        out += [f"- {item}" for item in report.gaps]
        out += ["", _GAPS_NOTE, ""]
    out += ["---", "", _MACHINE_NOTE, ""]
    return "\n".join(out)


_CSS: Final = (
    "body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1000px;"
    "margin:32px auto;padding:0 16px;color:#1d1d1f;line-height:1.5}"
    "h1{font-size:28px}h2{margin-top:32px;border-bottom:1px solid #e5e5e5;padding-bottom:4px}"
    "table{border-collapse:collapse;width:100%;font-size:14px}"
    "th,td{border:1px solid #e0e0e0;padding:6px 8px;text-align:left;vertical-align:top}"
    "th{background:#f5f5f7}pre{background:#f6f8fa;padding:12px;overflow-x:auto;"
    "font-size:13px;border-radius:6px}.hit{background:#ffe3e3;display:block}"
    ".add{color:#116329;background:#dafbe1;display:block}"
    ".del{color:#82071e;background:#ffebe9;display:block}.line{display:block}"
    ".sev-CRITICAL,.sev-HIGH{color:#c00;font-weight:600}.muted{color:#6e6e73}"
)


def _diff_line(line: str) -> str:
    if line.startswith("+") and not line.startswith("+++"):
        css = "add"
    elif line.startswith("-") and not line.startswith("---"):
        css = "del"
    else:
        css = "line"
    return f'<span class="{css}">{html.escape(line)}</span>'


def _html(report: _Report) -> str:
    e = html.escape
    title = "SecureCode AI: отчёт аудита безопасности"
    out = [f"<h1>{e(title)}</h1><ul>"]
    out += [f"<li><b>{e(key)}:</b> {e(value)}</li>" for key, value in report.summary]
    out.append("</ul>")
    if report.sections:
        out.append("<h2>Находки</h2><table><tr>")
        out += [f"<th>{e(cell)}</th>" for cell in _HEADER]
        out.append("</tr>")
        for section in report.sections:
            cells = _row(section)
            out.append(
                "<tr>"
                + "".join(
                    f'<td class="sev-{e(cell)}">{e(cell)}</td>'
                    if index == 3
                    else f"<td>{e(cell)}</td>"
                    for index, cell in enumerate(cells)
                )
                + "</tr>"
            )
        out.append("</table>")
    for section in report.sections:
        entry, fix = section.entry, section.fix
        out.append(f"<h2>{section.number}. {e(_cwe(entry.cwe_id))}</h2><ul>")
        out.append(f"<li><b>OWASP Top 10:</b> {e(_owasp(entry.owasp))}</li>")
        out.append(
            f'<li><b>Критичность:</b> <span class="sev-{e(entry.severity)}">'
            f"{e(entry.severity)}</span></li>"
        )
        out.append(f"<li><b>Место:</b> <code>{e(entry.path)}</code>, {e(_lines(entry))}</li>")
        out.append(
            f"<li><b>Источник:</b> {e(_origins(entry))}; подтверждено Аудитором и Скептиком</li>"
            "</ul>"
        )
        if section.fragment:
            width = len(str(section.fragment[-1][0]))
            out.append(
                "<pre>"
                + "".join(
                    f'<span class="{"hit" if marked else "line"}">'
                    f"{e(f'{number:>{width}} | {line}')}</span>"
                    for number, line, marked in section.fragment
                )
                + "</pre>"
            )
        if fix is not None and fix.diff:
            out.append(f"<p><b>Исправление Архитектора</b> ({e(_fix_status(fix))}).</p>")
            if fix.explanation:
                out.append(f"<p>{e(fix.explanation)}</p>")
            out.append(
                "<pre>" + "".join(_diff_line(line) for line in fix.diff.splitlines()) + "</pre>"
            )
            out.append(f'<p class="muted">Проверки: {e(_checks(fix))}.</p>')
        elif fix is not None:
            out.append(f'<p class="muted">Исправление не предложено: {e(_checks(fix))}.</p>')
    if report.unresolved:
        out.append("<h2>Кандидаты без окончательного решения</h2><table><tr>")
        out += [
            f"<th>{e(cell)}</th>" for cell in ("№", "Уязвимость", "Место", "Источник", "Причина")
        ]
        out.append("</tr>")
        for number, (cwe_id, path, line, origin, reason) in enumerate(report.unresolved, 1):
            cells = (str(number), _cwe(cwe_id), f"{path}:{line}", origin, reason)
            out.append("<tr>" + "".join(f"<td>{e(cell)}</td>" for cell in cells) + "</tr>")
        out.append(f"</table><p>{e(_UNRESOLVED_NOTE)}</p>")
    if report.gaps:
        out.append("<h2>Неполная проверка</h2><ul>")
        out += [f"<li>{e(item)}</li>" for item in report.gaps]
        out.append(f"</ul><p>{e(_GAPS_NOTE)}</p>")
    out.append(f'<hr><p class="muted">{e(_MACHINE_NOTE)}</p>')
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{e(title)}</title><style>{_CSS}</style></head><body>"
        + "".join(out)
        + "</body></html>\n"
    )
