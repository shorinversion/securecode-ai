"""Installed scan grammar and exact closed error exits."""

import io
import json
from pathlib import Path

import pytest
from securecode_ai.adapters.local_product_runner import (
    LocalProductCancelledError,
    LocalProductSupersededError,
    LocalProductUnavailableError,
)
from securecode_ai.cli import application, scan


def test_product_scan_accepted_config_and_format_grammar() -> None:
    parsed = scan.parse_product_scan(
        ("scan", ".", "--config", "selectors.json", "--format", "sarif", "--output", "report.sarif")
    )
    assert parsed.config == Path("selectors.json")
    assert parsed.report_format.value == "sarif"


@pytest.mark.parametrize(
    "tokens",
    [
        ("scan",),
        ("scan", ".", "--format", "diff"),
        ("scan", ".", "--format", "json", "--format", "html"),
        ("scan", ".", "--config", "a", "--config", "b"),
    ],
)
def test_product_scan_invalid_grammar(tokens: tuple[str, ...]) -> None:
    with pytest.raises(scan.ProductScanConfigurationError):
        scan.parse_product_scan(tokens)


@pytest.mark.parametrize(
    "error, expected",
    [
        (LocalProductCancelledError, 6),
        (LocalProductSupersededError, 6),
        (LocalProductUnavailableError, 3),
        (scan.ProductScanConfigurationError, 5),
        (OSError, 4),
    ],
)
def test_product_scan_closed_exact_exits(
    monkeypatch: pytest.MonkeyPatch,
    error: type[Exception],
    expected: int,
) -> None:
    def deny(*args: object, **kwargs: object) -> None:
        raise error()

    monkeypatch.setattr(application, "execute_installed_product_scan", deny)
    stdout, stderr = io.StringIO(), io.StringIO()
    code = application.main(("scan", ".", "--json"), stdout=stdout, stderr=stderr, environment={})
    assert code == expected == json.loads(stdout.getvalue())["exit_code"]
    assert not stderr.getvalue()


def test_selection_duplicate_keys_rejected(tmp_path: Path) -> None:
    selection = tmp_path / "config.json"
    selection.write_bytes(b'{"provider_profile":"one@1.0.0","provider_profile":"two@1.0.0"}')
    with pytest.raises(scan.ProductScanConfigurationError):
        scan._selection_file(selection)
