"""The files of an incremental run: validated base, merge base, bounded diff."""

from __future__ import annotations

import pytest
from securecode_ai.adapters.local_product_runner_config import (
    LocalProductConfigurationError,
    LocalProductScanOptions,
    LocalProductUnavailableError,
)
from securecode_ai.adapters.local_product_scope import changed_paths_since, valid_base

HEAD = "a" * 40
BASE = "b" * 40
MERGE = "c" * 40


class Git:
    """A scripted sealed Git: answers by the first argument, records every call."""

    def __init__(self, **answers: str | Exception) -> None:
        self.answers = answers
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *arguments: str) -> str:
        self.calls.append(arguments)
        answer = self.answers[arguments[0]]
        if isinstance(answer, Exception):
            raise answer
        return answer


FAILED = LocalProductUnavailableError("GIT_COMMAND_FAILED")


def test_changed_files_are_the_diff_from_the_merge_base() -> None:
    git = Git(
        **{
            "rev-parse": BASE,
            "merge-base": MERGE,
            "diff": "src/b.py\x00README.md\x00src/a.py\x00",
        }
    )

    scope = changed_paths_since(git, "origin/main", HEAD)

    assert (scope.base_rev, scope.base_sha, scope.merge_base_sha) == ("origin/main", BASE, MERGE)
    assert scope.changed_paths == ("README.md", "src/a.py", "src/b.py")
    assert scope.scanned_paths == ()
    assert git.calls == [
        ("rev-parse", "--verify", "--end-of-options", "origin/main^{commit}"),
        ("merge-base", BASE, HEAD),
        ("diff", "--name-only", "--no-renames", "-z", MERGE, HEAD),
    ]


def test_head_already_in_the_base_means_nothing_changed() -> None:
    git = Git(**{"rev-parse": BASE, "merge-base": HEAD})

    with pytest.raises(LocalProductUnavailableError) as error:
        changed_paths_since(git, "main", HEAD)

    assert error.value.reason == "BASE_CONTAINS_HEAD"
    assert [call[0] for call in git.calls] == ["rev-parse", "merge-base"]


@pytest.mark.parametrize(
    ("answers", "reason"),
    [
        ({"rev-parse": FAILED}, "BASE_REVISION_INVALID"),
        ({"rev-parse": "not-a-commit"}, "BASE_REVISION_INVALID"),
        ({"rev-parse": BASE, "merge-base": FAILED}, "BASE_NOT_RELATED"),
        ({"rev-parse": BASE, "merge-base": MERGE, "diff": FAILED}, "BASE_DIFF_TOO_LARGE"),
        ({"rev-parse": BASE, "merge-base": MERGE, "diff": ""}, "NO_CHANGED_FILES"),
        ({"rev-parse": BASE, "merge-base": MERGE, "diff": "a\nb\x00"}, "NO_CHANGED_FILES"),
    ],
)
def test_each_failure_has_its_own_reason(answers: dict[str, str | Exception], reason: str) -> None:
    with pytest.raises(LocalProductUnavailableError) as error:
        changed_paths_since(Git(**answers), "main", HEAD)

    assert error.value.reason == reason


@pytest.mark.parametrize(
    "base", ["", "-oops", "--upload-pack=x", "a b", "a;b", "a\nb", "x" * 300, "$(id)", "a`b`"]
)
def test_a_hostile_base_never_reaches_git(base: str) -> None:
    git = Git()

    with pytest.raises(LocalProductUnavailableError) as error:
        changed_paths_since(git, base, HEAD)

    assert error.value.reason == "BASE_REVISION_INVALID" and git.calls == []
    assert not valid_base(base)


@pytest.mark.parametrize(
    "base", ["main", "origin/main", "HEAD~1", "v1.2.3", "feature/x-1", "a" * 40]
)
def test_ordinary_revision_names_are_accepted(base: str) -> None:
    assert valid_base(base)


def test_options_validate_the_base_too() -> None:
    assert LocalProductScanOptions(base="origin/main").base == "origin/main"
    with pytest.raises(LocalProductConfigurationError):
        LocalProductScanOptions(base="--exec=x")
