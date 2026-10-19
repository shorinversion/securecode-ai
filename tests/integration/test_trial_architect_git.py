"""The Architect reads the analysed revision from Git and checks fixes with git apply."""

from __future__ import annotations

import subprocess
from pathlib import Path

from securecode_ai.adapters.trial_architect import git_apply_check, git_revision_reader

_SOURCE = "def f(conn, name):\n    return conn.execute('SELECT ' + name)\n"
_DIFF = (
    "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n def f(conn, name):\n"
    "-    return conn.execute('SELECT ' + name)\n"
    "+    return conn.execute('SELECT ?', (name,))\n"
)


def test_reader_uses_the_revision_and_apply_check_leaves_the_checkout(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(_SOURCE, encoding="utf-8", newline="\n")
    identity = ("-c", "user.name=Test", "-c", "user.email=test@example.invalid")
    for command in (("init", "-q"), ("add", "--all"), (*identity, "commit", "-qm", "init")):
        subprocess.run(["git", "-C", str(tmp_path), *command], check=True, capture_output=True)
    head = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (tmp_path / "app.py").write_text("changed in the worktree\n", encoding="utf-8")

    source = git_revision_reader(tmp_path, head)("app.py")

    assert source == _SOURCE
    assert git_apply_check("app.py", source, _DIFF)
    assert not git_apply_check("app.py", "other content\n", _DIFF)
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == "changed in the worktree\n"


def test_sequential_fixes_of_one_file_each_apply_to_the_original(tmp_path: Path) -> None:
    import json

    from securecode_ai.adapters.trial_architect import FixFinding, propose_fixes

    source = 'import os\n\nKEY_A = "demo-value-a"\nKEY_B = "demo-value-b"\n'
    (tmp_path / "app.py").write_text(source, encoding="utf-8", newline="\n")
    identity = ("-c", "user.name=Test", "-c", "user.email=test@example.invalid")
    for command in (("init", "-q"), ("add", "--all"), (*identity, "commit", "-qm", "init")):
        subprocess.run(["git", "-C", str(tmp_path), *command], check=True, capture_output=True)
    head = subprocess.run(
        ["git", "-C", str(tmp_path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    answers = iter(
        [
            ("KEY_A = os.environ.get('KEY_A')\nif not KEY_A:\n    raise RuntimeError('unset')", 3),
            ("KEY_B = os.environ.get('KEY_B')", 6),
        ]
    )

    def complete(_system: str, _user: str) -> str:
        replacement, line = next(answers)
        edit = {"start_line": line, "end_line": line, "replacement": replacement}
        return json.dumps({"explanation": "Read the key from the environment.", "edits": [edit]})

    findings = [
        FixFinding("key-a", "CWE-798", "app.py", 3, 3, "deterministic", "group-a"),
        FixFinding("key-b", "CWE-798", "app.py", 4, 4, "deterministic", "group-b"),
    ]

    first, second = propose_fixes(
        findings, complete, read_source=git_revision_reader(tmp_path, head)
    )

    assert (first.status, second.status) == ("VALIDATED", "VALIDATED")
    # Both diffs are taken against the original file, so each applies to it as it is.
    assert git_apply_check("app.py", source, first.diff)
    assert git_apply_check("app.py", source, second.diff)
    assert second.includes == ("key-a",)
    assert "os.environ.get('KEY_A')" in second.diff and "os.environ.get('KEY_B')" in second.diff
    assert "os.environ.get('KEY_B')" not in first.diff


def test_patch_directory_holds_each_fix_and_a_summary_per_file(tmp_path: Path) -> None:
    from securecode_ai.adapters.trial_architect import ProposedFix
    from securecode_ai.cli.analyze import _write_patches

    source = "a = 1\nb = 2\n"
    first_diff = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n-a = 1\n+a = 10\n b = 2\n"
    both_diff = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n-a = 1\n-b = 2\n+a = 10\n+b = 20\n"
    other_diff = "--- a/other.py\n+++ b/other.py\n@@ -1,2 +1,2 @@\n-a = 1\n+a = 3\n b = 2\n"
    fixes = [
        ProposedFix("one", "app.py", "VALIDATED", (), "", first_diff, "g1"),
        ProposedFix("two", "app.py", "VALIDATED", (), "", both_diff, "g2", ("one",)),
        ProposedFix("three", "other.py", "VALIDATED", (), "", other_diff, "g3"),
    ]
    directory = tmp_path / "patches"

    skipped = _write_patches(directory, fixes, lambda _path: source)

    assert skipped == ()
    assert sorted(item.name for item in directory.iterdir()) == [
        "01-app.py.diff",
        "02-app.py.diff",
        "03-other.py.diff",
        "patch-app.py.diff",
    ]
    assert (directory / "patch-app.py.diff").read_text(encoding="utf-8") == both_diff
