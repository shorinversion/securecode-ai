"""P5.7 GitLab inline discussions: only confirmed, precise, changed new-code lines."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, cast

import pytest
from securecode_ai.adapters.gitlab_ci import (
    GitlabCIAdapter,
    GitlabCIAdmissionRequest,
    GitlabContributionTrust,
)
from securecode_ai.adapters.gitlab_discussions import (
    GitlabChangedLine,
    GitlabDiscussionCandidate,
    GitlabDiscussionError,
    GitlabDiscussionPublisher,
    GitlabDiscussionRequest,
    GitlabDiscussionSuppression,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    FindingCase,
    FindingVerdict,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core.scm_run_state import SCMRunState

ROOT = Path(__file__).resolve().parents[2]
HEAD = "a" * 40
BASE = "b" * 40
OTHER_HEAD = "c" * 40
TENANT = "tenant-1"
REPO = "repo-1"
CONTENT = "e" * 64


def _root_cause() -> Any:
    spec = importlib.util.spec_from_file_location(
        "p57_root_cause_fixture", ROOT / "tests" / "unit" / "test_root_cause.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("root cause fixture unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pin(name: str, digest: str) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity(
    *,
    provider: str = "gitlab",
    repository_id: str = REPO,
    head_sha: str = HEAD,
    base_sha: str | None = BASE,
) -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            scm_provider=provider,
            repository_id=repository_id,
            head_sha=head_sha,
            base_sha=base_sha,
        ),
        stage_catalogue=_pin("catalogue", "0" * 64),
        workflow=_pin("workflow", "b" * 64),
        policy=_pin("policy", "c" * 64),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


def _finding(
    *,
    finding_id: str = "finding-1",
    verdict: FindingVerdict = FindingVerdict.CONFIRMED,
    locations: tuple[Any, ...] | None = None,
    provider: str = "gitlab",
    repository_id: str = REPO,
    head_sha: str = HEAD,
) -> FindingCase:
    module = _root_cause()
    finding = module._finding(module._graph())
    revision = RepositoryRevision(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id=TENANT,
        scm_provider=provider,
        repository_id=repository_id,
        head_sha=head_sha,
        base_sha=BASE,
    )
    updates: dict[str, Any] = {
        "finding_id": finding_id,
        "finding_verdict": verdict,
        "repository_revision": revision,
        "locations": (
            locations if locations is not None else (_root_cause()._location("src/in.py", 2),)
        ),
    }
    return cast("FindingCase", finding.model_copy(update=updates))


def _changed_line(
    *,
    path: str = "src/in.py",
    line: int = 2,
    content: str = CONTENT,
    base_sha: str = BASE,
    start_sha: str = BASE,
    head_sha: str = HEAD,
) -> GitlabChangedLine:
    return GitlabChangedLine(
        path=path,
        line=line,
        content_sha256=content,
        base_sha=base_sha,
        start_sha=start_sha,
        head_sha=head_sha,
    )


class _Head:
    def __init__(self, sha: str = HEAD) -> None:
        self.sha = sha

    def __call__(self, _project_id: str, _merge_request_iid: str) -> str:
        return self.sha


def _publisher(
    *, identity: RunExecutionIdentity | None = None, head: str = HEAD
) -> tuple[GitlabDiscussionPublisher, str, _Head]:
    identity = identity or _identity()
    resolver = _Head(head)
    adapter = GitlabCIAdapter(run_state=SCMRunState(), head_resolver=resolver)
    admission = adapter.admit(
        GitlabCIAdmissionRequest(
            pipeline_id="9001",
            job_id="1",
            project_id=REPO,
            merge_request_iid="7",
            source_project_id=REPO,
            target_project_id=REPO,
            contribution_trust=GitlabContributionTrust.TRUSTED,
            execution_identity=identity,
        )
    )
    return GitlabDiscussionPublisher(adapter), admission.admission.run_id, resolver


def _request(
    run_id: str,
    *,
    identity: RunExecutionIdentity | None = None,
    candidates: tuple[GitlabDiscussionCandidate, ...] | None = None,
    changed_lines: tuple[GitlabChangedLine, ...] | None = None,
) -> GitlabDiscussionRequest:
    return GitlabDiscussionRequest(
        scm_run_id=run_id,
        execution_identity=identity or _identity(),
        candidates=candidates
        if candidates is not None
        else (GitlabDiscussionCandidate(_finding(), True),),
        changed_lines=changed_lines if changed_lines is not None else (_changed_line(),),
    )


def test_publisher_requires_gitlab_adapter() -> None:
    with pytest.raises(GitlabDiscussionError):
        GitlabDiscussionPublisher(object())  # type: ignore[arg-type]


def test_project_rejects_non_request() -> None:
    publisher, _run_id, _resolver = _publisher()
    with pytest.raises(GitlabDiscussionError):
        publisher.project(object())  # type: ignore[arg-type]


def test_unknown_run_is_rejected_without_posting() -> None:
    publisher, _run_id, _resolver = _publisher()
    with pytest.raises(GitlabDiscussionError):
        publisher.project(_request("run-unknown"))


def test_confirmed_precise_new_code_line_posts_one_discussion() -> None:
    publisher, run_id, _resolver = _publisher()
    receipt = publisher.project(_request(run_id))
    assert receipt.suppressions == ()
    assert len(receipt.discussions) == 1
    discussion = receipt.discussions[0]
    assert discussion.finding_id == "finding-1"
    assert discussion.new_path == "src/in.py"
    assert discussion.new_line == 2
    assert discussion.head_sha == HEAD
    assert discussion.cwe_id == "CWE-89"
    assert "confirmed" in discussion.body.lower()
    assert discussion.merge_authority is False


def test_stale_run_suppresses_every_candidate() -> None:
    publisher, run_id, resolver = _publisher()
    resolver.sha = OTHER_HEAD
    request = _request(
        run_id,
        candidates=(
            GitlabDiscussionCandidate(_finding(), True),
            GitlabDiscussionCandidate(_finding(finding_id="finding-2"), True),
        ),
    )
    receipt = publisher.project(request)
    assert receipt.discussions == ()
    assert [item.reason for item in receipt.suppressions] == [
        GitlabDiscussionSuppression.STALE_RUN,
        GitlabDiscussionSuppression.STALE_RUN,
    ]


@pytest.mark.parametrize(
    ("candidate", "changed_lines", "expected"),
    [
        (
            GitlabDiscussionCandidate(_finding(repository_id="other-repo"), True),
            None,
            GitlabDiscussionSuppression.IDENTITY_MISMATCH,
        ),
        (
            GitlabDiscussionCandidate(_finding(provider="github"), True),
            None,
            GitlabDiscussionSuppression.IDENTITY_MISMATCH,
        ),
        (
            GitlabDiscussionCandidate(_finding(head_sha=OTHER_HEAD), True),
            None,
            GitlabDiscussionSuppression.IDENTITY_MISMATCH,
        ),
        (
            GitlabDiscussionCandidate(_finding(), False),
            None,
            GitlabDiscussionSuppression.LEGACY,
        ),
        (
            GitlabDiscussionCandidate(_finding(verdict=FindingVerdict.NEEDS_MORE_EVIDENCE), True),
            None,
            GitlabDiscussionSuppression.UNCONFIRMED,
        ),
        (
            GitlabDiscussionCandidate(
                _finding(
                    locations=(
                        _root_cause()._location("src/in.py", 2),
                        _root_cause()._location("src/db.py", 8),
                    )
                ),
                True,
            ),
            None,
            GitlabDiscussionSuppression.AMBIGUOUS_LOCATION,
        ),
        (
            GitlabDiscussionCandidate(
                _finding(
                    locations=(
                        __import__(
                            "securecode_ai.contracts", fromlist=["SourceLocation"]
                        ).SourceLocation(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            path="src/in.py",
                            start=__import__(
                                "securecode_ai.contracts", fromlist=["SourcePosition"]
                            ).SourcePosition(
                                schema_version=CONTRACT_SCHEMA_VERSION, line=2, column=1
                            ),
                            end=__import__(
                                "securecode_ai.contracts", fromlist=["SourcePosition"]
                            ).SourcePosition(
                                schema_version=CONTRACT_SCHEMA_VERSION, line=3, column=1
                            ),
                            content_sha256=CONTENT,
                        ),
                    )
                ),
                True,
            ),
            None,
            GitlabDiscussionSuppression.IMPRECISE_LOCATION,
        ),
        (
            GitlabDiscussionCandidate(_finding(), True),
            (),
            GitlabDiscussionSuppression.UNCHANGED_LINE,
        ),
        (
            GitlabDiscussionCandidate(_finding(), True),
            (_changed_line(content="f" * 64),),
            GitlabDiscussionSuppression.UNCHANGED_LINE,
        ),
        (
            GitlabDiscussionCandidate(_finding(), True),
            (_changed_line(head_sha=OTHER_HEAD),),
            GitlabDiscussionSuppression.INVALID_DIFF_POSITION,
        ),
        (
            GitlabDiscussionCandidate(_finding(), True),
            (_changed_line(base_sha=OTHER_HEAD),),
            GitlabDiscussionSuppression.INVALID_DIFF_POSITION,
        ),
    ],
)
def test_unsafe_candidates_are_suppressed_without_posting(
    candidate: GitlabDiscussionCandidate,
    changed_lines: tuple[GitlabChangedLine, ...] | None,
    expected: GitlabDiscussionSuppression,
) -> None:
    publisher, run_id, _resolver = _publisher()
    receipt = publisher.project(
        _request(run_id, candidates=(candidate,), changed_lines=changed_lines)
    )
    assert receipt.discussions == ()
    assert [item.reason for item in receipt.suppressions] == [expected]


def test_parent_segment_path_is_rejected_by_the_contract_first() -> None:
    """Defense in depth: the source-location contract rejects traversal before the adapter."""

    module = _root_cause()
    with pytest.raises(Exception) as error:
        module._location("../escape.py", 2)
    assert "parent segments" in str(error.value)


def test_unsafe_path_is_rejected_by_the_changed_line_contract() -> None:
    """Defense in depth: an unsafe path cannot even form a changed-line record.

    Because the discussion lookup keys on the same path the changed-line record
    validated, the adapter's UNSAFE_PATH suppression is unreachable in practice.
    """

    for unsafe in (".hidden.py", "/etc/passwd", "src//in.py", "src/../in.py", "src/.."):
        with pytest.raises(GitlabDiscussionError):
            _changed_line(path=unsafe)


def test_volume_limit_suppresses_beyond_fifty_but_posts_sorted_prefix() -> None:
    publisher, run_id, _resolver = _publisher()
    candidates = tuple(
        GitlabDiscussionCandidate(_finding(finding_id=f"finding-{index:03d}"), True)
        for index in range(51)
    )
    receipt = publisher.project(_request(run_id, candidates=candidates))
    assert len(receipt.discussions) == 50
    assert [item.finding_id for item in receipt.discussions] == sorted(
        item.finding_id for item in receipt.discussions
    )
    assert [item.reason for item in receipt.suppressions] == [
        GitlabDiscussionSuppression.VOLUME_LIMIT
    ]


def test_identity_argument_must_match_the_authorized_run() -> None:
    publisher, run_id, _resolver = _publisher()
    request = _request(
        run_id,
        identity=_identity(head_sha=OTHER_HEAD),
        candidates=(GitlabDiscussionCandidate(_finding(), True),),
        changed_lines=(_changed_line(head_sha=OTHER_HEAD),),
    )
    with pytest.raises(GitlabDiscussionError):
        publisher.project(request)


def test_request_validation_rejects_malformed_shapes() -> None:
    with pytest.raises(GitlabDiscussionError):
        GitlabDiscussionRequest(
            scm_run_id="",
            execution_identity=_identity(),
            candidates=(),
            changed_lines=(),
        )
    with pytest.raises(GitlabDiscussionError):
        GitlabDiscussionCandidate(object(), True)  # type: ignore[arg-type]
    with pytest.raises(GitlabDiscussionError):
        GitlabChangedLine(
            path="src/in.py",
            line=0,
            content_sha256=CONTENT,
            base_sha=BASE,
            start_sha=BASE,
            head_sha=HEAD,
        )
