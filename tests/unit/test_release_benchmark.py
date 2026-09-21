from __future__ import annotations

from collections.abc import Callable

import pytest
from securecode_ai.core.release_benchmark import (
    BenchmarkCell,
    Configuration,
    aggregate,
    release_ready,
)
from securecode_ai.core.release_metrics import f1, percentile, ratio, wilson_lower


def test_missing_cells_prevent_release() -> None:
    hybrid = aggregate(
        (BenchmarkCell(Configuration.HYBRID, "python", "CWE-89", "l", 1, "not_run"),),
        Configuration.HYBRID,
    )
    sast = aggregate((), Configuration.SEMGREP)
    assert not release_ready(hybrid, sast)


def test_release_metrics_cover_empty_and_observed_samples() -> None:
    assert ratio(3, 4) == 0.75
    assert ratio(0, 0) == 0.0
    assert f1(0.75, 0.5) == pytest.approx(0.6)
    assert f1(0.0, 0.0) == 0.0
    assert wilson_lower(0, 0) == 0.0
    assert 0.0 < wilson_lower(9, 10) < 0.9
    assert percentile((), 0.95) == 0
    assert percentile((40, 10, 20, 30), 0.5) == 20
    assert percentile((40, 10, 20, 30), 1.0) == 40


@pytest.mark.parametrize(
    ("function", "arguments"),
    (
        (ratio, (-1, 1)),
        (ratio, (2, 1)),
        (f1, (True, 0.5)),
        (percentile, ((1, -1), 0.5)),
        (percentile, ((1,), float("nan"))),
    ),
)
def test_release_metrics_reject_invalid_measurements(
    function: Callable[..., object], arguments: tuple[object, ...]
) -> None:
    with pytest.raises(ValueError):
        function(*arguments)
