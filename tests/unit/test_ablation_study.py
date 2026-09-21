from __future__ import annotations

from securecode_ai.core.ablation_study import AblationCell, compare


def test_missing_cells_never_claim_contribution() -> None:
    assert not compare((), ())["contribution"]


def test_crossing_zero_is_not_contribution() -> None:
    cells = tuple(
        AblationCell(
            str(i),
            "lineage",
            1,
            "deterministic_lane",
            ("budget", "model", "prompt", "policy", "tool"),
            "completed",
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            1,
            1,
        )
        for i in range(2)
    )
    changed = tuple(
        AblationCell(
            str(i),
            "lineage",
            1,
            "model_native_lane",
            ("budget", "model", "prompt", "policy", "tool"),
            "completed",
            0.5,
            0.5,
            0.5,
            0.5,
            0.5,
            1,
            1,
        )
        for i in range(2)
    )
    assert not compare(cells, changed)["contribution"]
