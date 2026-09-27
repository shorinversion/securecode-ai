"""Render the verified submission benchmark aggregate as a printable PDF."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

ROOT = Path(__file__).resolve().parent
AGGREGATE = ROOT / "aggregate.json"
STRATIFIED = ROOT / "stratified-metrics.csv"
OUTPUT = ROOT.parents[1] / "output" / "pdf" / "securecode-ai-submission-benchmark.pdf"
REGULAR_FONT = Path("C:/Windows/Fonts/arial.ttf")
BOLD_FONT = Path("C:/Windows/Fonts/arialbd.ttf")

COLORS = {
    "ink": colors.HexColor("#172033"),
    "muted": colors.HexColor("#526079"),
    "blue": colors.HexColor("#2355A6"),
    "pale": colors.HexColor("#EEF3FA"),
    "rule": colors.HexColor("#D7DFEA"),
    "warning": colors.HexColor("#8A3F12"),
    "warning_bg": colors.HexColor("#FFF2E6"),
}


def _pct(value: Any) -> str:
    return "n/a" if value is None else f"{float(value) * 100:.1f}%"


def _money(value: Any) -> str:
    return f"${float(value):,.6f}"


def _text(value: Any) -> str:
    return escape(str(value))


def _styles() -> dict[str, ParagraphStyle]:
    if not REGULAR_FONT.is_file() or not BOLD_FONT.is_file():
        raise FileNotFoundError("Arial Unicode fonts are required to render Russian text")
    pdfmetrics.registerFont(TTFont("Arial", str(REGULAR_FONT)))
    pdfmetrics.registerFont(TTFont("Arial-Bold", str(BOLD_FONT)))
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title",
            parent=base["Title"],
            fontName="Arial-Bold",
            fontSize=25,
            leading=31,
            textColor=COLORS["ink"],
            alignment=TA_LEFT,
            spaceAfter=8 * mm,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle",
            parent=base["Normal"],
            fontName="Arial",
            fontSize=11,
            leading=16,
            textColor=COLORS["muted"],
            spaceAfter=4 * mm,
        ),
        "h1": ParagraphStyle(
            "H1",
            parent=base["Heading1"],
            fontName="Arial-Bold",
            fontSize=17,
            leading=21,
            textColor=COLORS["blue"],
            spaceBefore=5 * mm,
            spaceAfter=3 * mm,
        ),
        "h2": ParagraphStyle(
            "H2",
            parent=base["Heading2"],
            fontName="Arial-Bold",
            fontSize=11,
            leading=14,
            textColor=COLORS["ink"],
            spaceBefore=3 * mm,
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "Body",
            parent=base["BodyText"],
            fontName="Arial",
            fontSize=9.2,
            leading=13.4,
            textColor=COLORS["ink"],
            spaceAfter=2.2 * mm,
        ),
        "small": ParagraphStyle(
            "Small",
            parent=base["BodyText"],
            fontName="Arial",
            fontSize=7.2,
            leading=9.4,
            textColor=COLORS["muted"],
            spaceAfter=1.3 * mm,
        ),
        "table_head": ParagraphStyle(
            "TableHead",
            parent=base["BodyText"],
            fontName="Arial-Bold",
            fontSize=7.4,
            leading=9.2,
            textColor=colors.white,
            alignment=TA_CENTER,
        ),
        "table": ParagraphStyle(
            "Table",
            parent=base["BodyText"],
            fontName="Arial",
            fontSize=7.1,
            leading=8.6,
            textColor=COLORS["ink"],
            alignment=TA_CENTER,
        ),
        "table_left": ParagraphStyle(
            "TableLeft",
            parent=base["BodyText"],
            fontName="Arial",
            fontSize=7.1,
            leading=8.6,
            textColor=COLORS["ink"],
            alignment=TA_LEFT,
        ),
        "callout": ParagraphStyle(
            "Callout",
            parent=base["BodyText"],
            fontName="Arial-Bold",
            fontSize=10,
            leading=15,
            textColor=COLORS["warning"],
            spaceAfter=1 * mm,
        ),
    }


def _para(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text, style)


def _table(rows: list[list[Any]], widths: list[float], repeat_rows: int = 1) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=repeat_rows, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLORS["blue"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, COLORS["rule"]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, COLORS["pale"]]),
            ]
        )
    )
    return table


def _footer(canvas: Any, document: Any) -> None:
    canvas.saveState()
    width, _ = landscape(A4)
    canvas.setStrokeColor(COLORS["rule"])
    canvas.line(18 * mm, 14 * mm, width - 18 * mm, 14 * mm)
    canvas.setFont("Arial", 7)
    canvas.setFillColor(COLORS["muted"])
    canvas.drawString(18 * mm, 9 * mm, "SecureCode AI submission benchmark | 27 September 2026")
    canvas.drawRightString(width - 18 * mm, 9 * mm, f"Page {document.page}")
    canvas.restoreState()


def _load_language_split_rows() -> list[dict[str, str]]:
    with STRATIFIED.open(encoding="utf-8", newline="") as stream:
        return [
            row
            for row in csv.DictReader(stream)
            if row["dimension"] == "language_split" and row["group"].endswith(":held-out")
        ]


def _lane_table(aggregate: dict[str, Any], styles: dict[str, ParagraphStyle]) -> Table:
    labels = {
        "deterministic_only": "Deterministic",
        "scanner_seeded": "Scanner-seeded derived",
        "model_native": "DeepSeek model-native",
        "one_shot": "DeepSeek one-shot",
        "full_hybrid": "Full hybrid derived",
        "semgrep": "Semgrep 1.177.0",
    }
    rows: list[list[Any]] = [
        [
            _para(label, styles["table_head"])
            for label in (
                "Lane",
                "Cells",
                "TP/FP/TN/FN",
                "Precision",
                "Recall",
                "F1",
                "Completed",
                "New calls",
            )
        ]
    ]
    calls = {
        "deterministic_only": 0,
        "scanner_seeded": 0,
        "model_native": 1800,
        "one_shot": 1800,
        "full_hybrid": 0,
        "semgrep": 0,
    }
    for lane, label in labels.items():
        item = aggregate["lanes"][lane]
        rows.append(
            [
                _para(_text(label), styles["table_left"]),
                _para(str(item["cells"]), styles["table"]),
                _para(f"{item['tp']}/{item['fp']}/{item['tn']}/{item['fn']}", styles["table"]),
                _para(_pct(item["precision"]), styles["table"]),
                _para(_pct(item["recall"]), styles["table"]),
                _para(_pct(item["f1"]), styles["table"]),
                _para(_pct(item["completion_rate"]), styles["table"]),
                _para(str(calls[lane]), styles["table"]),
            ]
        )
    return _table(rows, [83 * mm, 17 * mm, 35 * mm, 22 * mm, 22 * mm, 18 * mm, 23 * mm, 20 * mm])


def _heldout_table(rows: list[dict[str, str]], styles: dict[str, ParagraphStyle]) -> Table:
    lane_order = ("model_native", "one_shot", "full_hybrid", "semgrep")
    language_order = ("python", "js-ts", "go")
    selected = {
        (row["lane"], row["group"].split(":", 1)[0]): row
        for row in rows
        if row["lane"] in lane_order
    }
    names = {"python": "Python", "js-ts": "JavaScript/TypeScript", "go": "Go"}
    lane_names = {
        "model_native": "Model-native",
        "one_shot": "One-shot",
        "full_hybrid": "Hybrid derived",
        "semgrep": "Semgrep",
    }
    result: list[list[Any]] = [
        [
            _para(label, styles["table_head"])
            for label in ("Language", "Lane", "Valid", "TP/FP/TN/FN", "Precision", "Recall", "F1")
        ]
    ]
    for language in language_order:
        for lane in lane_order:
            row = selected[(lane, language)]
            result.append(
                [
                    _para(names[language], styles["table_left"]),
                    _para(lane_names[lane], styles["table_left"]),
                    _para(_pct(float(row["completion_rate"])), styles["table"]),
                    _para(f"{row['tp']}/{row['fp']}/{row['tn']}/{row['fn']}", styles["table"]),
                    _para(_pct(float(row["precision"])), styles["table"]),
                    _para(_pct(float(row["recall"])), styles["table"]),
                    _para(_pct(float(row["f1"])), styles["table"]),
                ]
            )
    return _table(result, [48 * mm, 38 * mm, 19 * mm, 38 * mm, 24 * mm, 24 * mm, 20 * mm])


def _callout(text: str, styles: dict[str, ParagraphStyle]) -> Table:
    box = Table([[_para(text, styles["callout"])]], colWidths=[250 * mm])
    box.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), COLORS["warning_bg"]),
                ("BOX", (0, 0), (-1, -1), 0.7, colors.HexColor("#F0C9A8")),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return box


def main() -> None:
    aggregate = json.loads(AGGREGATE.read_text(encoding="utf-8"))
    if aggregate.get("schema_version") != "securecode.submission-benchmark-aggregate.v1":
        raise ValueError("benchmark aggregate schema is not recognized")
    heldout = _load_language_split_rows()
    styles = _styles()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=landscape(A4),
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=20 * mm,
        title="SecureCode AI submission benchmark",
        author="SecureCode AI project",
    )
    flow: list[Any] = []
    flow.append(_para("SecureCode AI", styles["subtitle"]))
    flow.append(_para("Submission benchmark", styles["title"]))
    flow.append(
        _para(
            "600 public vulnerable/fixed cases | Python, JavaScript/TypeScript, Go | 27 September 2026",
            styles["subtitle"],
        )
    )
    flow.append(
        _callout(
            "Result: this diagnostic benchmark does not show an advantage over SAST. "
            "The full-hybrid lane is a paired post-hoc composition, not an end-to-end SecureCode pipeline run.",
            styles,
        )
    )
    flow.append(Spacer(1, 5 * mm))
    flow.append(_para("Краткий вывод", styles["h1"]))
    flow.append(
        _para(
            "В отложенной выборке полнота гибридной композиции составляет 27.8%, а "  # noqa: RUF001
            "полнота базового статического анализатора составляет 32.5%. Разница равна "
            "-4.7 процентного пункта; 95% интервал по группам изменений от -13.9 до "
            "+4.7 п.п. включает ноль. Сканер завершил "
            "только 347 из 600 кейсов. Остальные 253 ошибки сохранены в знаменателях.",
            styles["body"],
        )
    )
    flow.append(
        _para(
            "The held-out hybrid-minus-Semgrep recall difference is -4.7 percentage points "
            "with a lineage-cluster 95% interval from -13.9 to +4.7 pp. The interval includes "
            "zero. The deterministic scanner completed 347 of 600 cases; all 253 failures "
            "remain visible in completion denominators.",
            styles["body"],
        )
    )
    flow.append(_para("Results across all cases", styles["h1"]))
    flow.append(_lane_table(aggregate, styles))
    flow.append(Spacer(1, 2 * mm))
    flow.append(
        _para(
            "Three-repeat lanes show pooled cell counts. Repetitions are grouped by lineage "
            "for confidence intervals and are not independent source cases. Scanner failures "
            "remain explicit even when a reused model prediction exists.",
            styles["small"],
        )
    )

    flow.append(PageBreak())
    flow.append(_para("Held-out results by language", styles["h1"]))
    flow.append(_heldout_table(heldout, styles))
    flow.append(Spacer(1, 4 * mm))
    paired = aggregate["paired_comparison"]["held-out"]
    lower, upper = paired["cluster_bootstrap_95_percentile_interval"]
    flow.append(
        _para(
            f"Paired comparison: hybrid minus Semgrep recall = {_pct(paired['observed_difference'])}; "
            f"95% lineage-cluster interval {_pct(lower)} to {_pct(upper)}, "
            f"from {paired['paired_lineage_groups']} held-out lineage groups and "
            f"{paired['bootstrap_iterations']:,} deterministic resamples.",
            styles["body"],
        )
    )
    flow.append(_para("Corpus and identity", styles["h1"]))
    dataset = aggregate["dataset"]
    flow.append(
        _para(
            f"{dataset['cases']} public revisions in {dataset['lineage_groups']} vulnerable/fixed "
            f"lineages. Splits: development {dataset['splits']['development']}, calibration "
            f"{dataset['splits']['calibration']}, held-out {dataset['splits']['held-out']}. "
            f"Manifest SHA-256: {dataset['manifest_sha256']}. Content digest: "
            f"{dataset['content_sha256']}. Candidate source manifest: "
            f"{aggregate['candidate_source_manifest_sha256']} ({aggregate['candidate_source_files']} files).",
            styles["body"],
        )
    )
    flow.append(
        _para(
            'Dataset source: <link href="https://zenodo.org/records/13118970" '
            'color="#2456a6">CVEfixes v1.0.8 on Zenodo</link>. '
            "The source-cache verification recorded 600 matching content hashes and zero mismatches. "
            "Raw code is not included. The dataset manifest uses the license value NOASSERTION.",
            styles["body"],
        )
    )

    flow.append(PageBreak())
    flow.append(_para("Cost, provenance and limits", styles["h1"]))
    spend = aggregate["spend"]["final_scope"]
    flow.append(
        _para(
            f"Final-scope API ledger: {spend['settled_attempts']:,} settled attempts, "
            f"{_money(spend['settled_charged_usd'])} charged; {spend['pending_attempts']} "
            f"reservations totaling {_money(spend['pending_reserved_usd'])} remain pending. "
            f"Settled plus pending exposure: {_money(spend['settled_plus_pending_exposure_usd'])}. "
            "The ledger includes corrected/retried runs and a duplicate interrupted rerun "
            "with no output, so it exceeds the cost attached to scored raw cells.",
            styles["body"],
        )
    )
    for text in (
        "The model-native and one-shot lanes are direct DeepSeek classifications of public source. They do not run the full scanner, EvidenceGraph, Auditor, Skeptic, validation and verdict pipeline.",
        "Scanner-seeded and full-hybrid outputs are post-hoc paired compositions. They reuse raw model results and made zero new API requests.",
        "Semgrep is scored with a broad any-finding-in-file rule, not a CWE-aligned mapping.",
        "The full-hybrid completion rate is 57.8%. Recall is below Semgrep on both the full corpus and held-out split. The paired confidence interval includes zero.",
        "No full repair study was run. Zero unsafe-patch observations are not evidence that generated patches are safe.",
        "The corpus has 79 CWE labels, one file per case, and no private-code generalization evidence. RAM/VRAM and end-to-end scan time were not measured.",
        "The current Ollama 0.34.4 demo found one Python CWE-89 candidate but proposed no patch; outcome is INDETERMINATE, so patch applicability, syntax and security regression were not evaluated. A separate historical Ollama 0.16.2 run proposed a patch and passed ephemeral parse/rescan only; the runs are not combined.",
    ):
        flow.append(_para("• " + _text(text), styles["body"]))
    flow.append(_para("Evidence files", styles["h1"]))
    for file_name, label in (
        ("aggregate.json", "Aggregate metrics and confidence intervals"),
        ("stratified-metrics.csv", "All languages, splits and 79 CWE groups"),
        ("aggregate-output-manifest.json", "Input and output SHA-256 records"),
        ("lane-composition.json", "Provenance for derived lanes"),
    ):
        flow.append(_para(f"{_text(label)}: {_text(file_name)}", styles["body"]))
    document.build(flow, onFirstPage=_footer, onLaterPages=_footer)
    print(OUTPUT)


if __name__ == "__main__":
    main()
