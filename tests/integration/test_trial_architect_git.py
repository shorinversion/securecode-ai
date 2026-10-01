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
