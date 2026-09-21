from __future__ import annotations

import json

from securecode_ai.cli import RepairCli, RepairFormat, main, render_receipt
from securecode_ai.contracts import CliCommand, CliExitCode


def test_repair_receipt_is_not_product_pass() -> None:
    cli = RepairCli(scan=lambda target: {"run_id": "run-1", "finding_count": 1})
    receipt = cli.run(CliCommand.SCAN, "repository")
    document = json.loads(render_receipt(receipt, RepairFormat.JSON))
    assert receipt.exit_code is CliExitCode.COMPLETED
    assert document["product_outcome"] == "NOT_EVALUATED"
    assert document["metadata"]["product_pass"] is False


def test_unavailable_worker_is_indeterminate() -> None:
    receipt = RepairCli().run(CliCommand.VALIDATE, "patch")
    assert receipt.exit_code is CliExitCode.INDETERMINATE


def test_main_routes_product_scan_without_claiming_pass() -> None:
    import io

    stdout, stderr = io.StringIO(), io.StringIO()
    code = main(["scan", "repo", "--json"], repair=RepairCli(), stdout=stdout, stderr=stderr)
    assert code == int(CliExitCode.INDETERMINATE)
    assert json.loads(stdout.getvalue())["product_outcome"] == "NOT_EVALUATED"
