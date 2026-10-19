"""The CI template for pull requests pins every third-party action and keeps secrets out of shell."""

from __future__ import annotations

import re
from pathlib import Path

ACTION = Path(__file__).resolve().parents[2] / "integrations" / "github" / "action.yml"


def test_every_action_is_pinned_to_a_commit_sha() -> None:
    uses = re.findall(r"^\s+uses:\s*(\S+)", ACTION.read_text(encoding="utf-8"), re.MULTILINE)

    assert len(uses) >= 5
    for reference in uses:
        assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", reference), reference


def test_inputs_reach_the_shell_only_through_the_environment() -> None:
    text = ACTION.read_text(encoding="utf-8")
    run_blocks = re.findall(r"run: \|?\n?((?:\s{8,}.*\n)+|.*\n)", text)

    assert run_blocks
    assert not any("${{" in block for block in run_blocks)


def test_the_template_audits_the_changes_and_posts_them() -> None:
    text = ACTION.read_text(encoding="utf-8")

    for fragment in ("--base", "--output-dir", "securecode publish github", "upload-sarif"):
        assert fragment in text
    assert "fetch-depth: 0" in text
