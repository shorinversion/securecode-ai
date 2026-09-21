"""P5.12 local artifact controls for canonical CI worker metadata."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import stat
import sys
import threading
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "apps" / "worker" / "src"
if str(WORKER_SOURCE) not in sys.path:
    sys.path.insert(0, str(WORKER_SOURCE))

from securecode_ai.contracts import DataClass  # noqa: E402
from securecode_ai.worker import (  # noqa: E402
    CiWorkerArtifactError,
    CiWorkerRequest,
    artifacts,
    canonical_ci_worker_result_json,
    run_ci_worker,
    write_ci_worker_artifact,
)

_LINUX_ONLY = pytest.mark.skipif(os.name != "posix", reason="P5.12 is Linux-only")


def _unit_contract_module() -> Any:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    specification = importlib.util.spec_from_file_location("p5_11_worker_unit_contract", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _request_and_result() -> tuple[CiWorkerRequest, Any]:
    fixture = _unit_contract_module()
    request = CiWorkerRequest(audit_run=fixture._admitted_run())
    return request, run_ci_worker(request)


def _expected_names(request: CiWorkerRequest, result: Any) -> tuple[str, str, bytes]:
    tenant_id = request.audit_run.execution_identity.repository_revision.tenant_id
    payload = canonical_ci_worker_result_json(result).encode("ascii")
    tenant_directory = hashlib.sha256(
        b"securecode.ci-worker-artifact-tenant.v1\0" + tenant_id.encode("utf-8")
    ).hexdigest()
    content_id = (
        "ciwr-"
        + hashlib.sha256(
            b"securecode.ci-worker-artifact.v1\0" + tenant_id.encode("utf-8") + b"\0" + payload
        ).hexdigest()
    )
    return tenant_directory, content_id, payload


@_LINUX_ONLY
def test_first_write_returns_tenant_bound_metadata_reference(tmp_path: Path) -> None:
    request, result = _request_and_result()
    tenant_directory, content_id, payload = _expected_names(request, result)

    reference = write_ci_worker_artifact(tmp_path, request, result)

    assert reference.tenant_id == request.audit_run.execution_identity.repository_revision.tenant_id
    assert reference.content_id == content_id
    assert reference.content_sha256 == hashlib.sha256(payload).hexdigest()
    assert reference.size_bytes == len(payload)
    assert reference.data_class is DataClass.INTERNAL_METADATA
    assert (tmp_path / "tenants" / tenant_directory / f"{content_id}.json").read_bytes() == payload
    assert request.audit_run.execution_identity.repository_revision.tenant_id not in {
        part.name for part in (tmp_path / "tenants").iterdir()
    }


@_LINUX_ONLY
def test_exact_replay_is_idempotent_and_does_not_overwrite(tmp_path: Path) -> None:
    request, result = _request_and_result()
    tenant_directory, content_id, payload = _expected_names(request, result)
    destination = tmp_path / "tenants" / tenant_directory / f"{content_id}.json"

    first = write_ci_worker_artifact(tmp_path, request, result)
    first_identity = (destination.stat().st_dev, destination.stat().st_ino)
    second = write_ci_worker_artifact(tmp_path, request, result)

    assert second == first
    assert (destination.stat().st_dev, destination.stat().st_ino) == first_identity
    assert destination.read_bytes() == payload


@_LINUX_ONLY
def test_result_that_does_not_match_revalidated_request_has_zero_effect(tmp_path: Path) -> None:
    fixture = _unit_contract_module()
    request = CiWorkerRequest(audit_run=fixture._admitted_run())
    stale = run_ci_worker(
        CiWorkerRequest(audit_run=fixture._admitted_run(outcome=fixture.AuditRunOutcome.FAIL))
    )

    with pytest.raises(CiWorkerArtifactError, match=r"^CI worker artifact operation failed$"):
        write_ci_worker_artifact(tmp_path, request, stale)

    assert list(tmp_path.iterdir()) == []


@_LINUX_ONLY
def test_non_directory_root_and_symlink_root_fail_without_following(tmp_path: Path) -> None:
    request, result = _request_and_result()
    not_directory = tmp_path / "result.json"
    not_directory.write_bytes(b"unchanged")

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(not_directory, request, result)
    assert not_directory.read_bytes() == b"unchanged"

    target = tmp_path / "target"
    target.mkdir()
    root_link = tmp_path / "root-link"
    try:
        root_link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("directory links are unavailable")
    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(root_link, request, result)
    assert list(target.iterdir()) == []

    ancestor = tmp_path / "ancestor"
    nested = ancestor / "nested"
    nested.mkdir(parents=True)
    ancestor_link = tmp_path / "ancestor-link"
    try:
        ancestor_link.symlink_to(ancestor, target_is_directory=True)
    except OSError:
        pytest.skip("directory links are unavailable")
    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(ancestor_link / "nested", request, result)
    assert list(nested.iterdir()) == []


@_LINUX_ONLY
def test_conflicting_regular_file_and_leaf_link_fail_closed(tmp_path: Path) -> None:
    request, result = _request_and_result()
    tenant_directory, content_id, _ = _expected_names(request, result)
    tenant_root = tmp_path / "tenants" / tenant_directory
    tenant_root.mkdir(parents=True)
    destination = tenant_root / f"{content_id}.json"
    destination.write_bytes(b"conflicting")

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)
    assert destination.read_bytes() == b"conflicting"

    destination.unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    try:
        destination.symlink_to(outside)
    except OSError:
        pytest.skip("file links are unavailable")
    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)
    assert outside.read_bytes() == b"outside"


@_LINUX_ONLY
def test_ancestor_substitution_after_publish_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, result = _request_and_result()
    tenant_directory, _, _ = _expected_names(request, result)
    tenant_root = tmp_path / "tenants" / tenant_directory
    original_link = os.link
    swapped = False

    def swapping_link(*args: Any, **kwargs: Any) -> None:
        nonlocal swapped
        original_link(*args, **kwargs)
        if not swapped:
            swapped = True
            tenant_root.rename(tmp_path / "detached-tenant")
            tenant_root.mkdir()

    monkeypatch.setattr(os, "link", swapping_link)

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)

    assert list(tenant_root.iterdir()) == []


@_LINUX_ONLY
def test_leaf_substitution_after_publish_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, result = _request_and_result()
    tenant_directory, content_id, _ = _expected_names(request, result)
    tenant_root = tmp_path / "tenants" / tenant_directory
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    original_link = os.link

    def swapping_link(*args: Any, **kwargs: Any) -> None:
        original_link(*args, **kwargs)
        os.unlink(f"{content_id}.json", dir_fd=kwargs["dst_dir_fd"])
        os.symlink(outside, f"{content_id}.json", dir_fd=kwargs["dst_dir_fd"])

    monkeypatch.setattr(os, "link", swapping_link)

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)

    assert tenant_root.joinpath(f"{content_id}.json").is_symlink()
    assert outside.read_bytes() == b"outside"


@_LINUX_ONLY
def test_leaf_swap_during_final_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, result = _request_and_result()
    tenant_directory, content_id, _ = _expected_names(request, result)
    destination = tmp_path / "tenants" / tenant_directory / f"{content_id}.json"
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    original_read = cast(Callable[[int, int], bytes], artifacts._read_bounded)
    calls = 0

    def swapping_read(descriptor: int, expected_size: int) -> bytes:
        nonlocal calls
        data = original_read(descriptor, expected_size)
        calls += 1
        if calls == 2:
            destination.unlink()
            destination.symlink_to(outside)
        return data

    monkeypatch.setattr(artifacts, "_read_bounded", swapping_read)

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)

    assert calls == 2
    assert destination.is_symlink()
    assert outside.read_bytes() == b"outside"


@_LINUX_ONLY
def test_tenant_directory_swap_during_final_read_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, result = _request_and_result()
    tenant_directory, _, _ = _expected_names(request, result)
    tenant_root = tmp_path / "tenants" / tenant_directory
    original_read = cast(Callable[[int, int], bytes], artifacts._read_bounded)
    calls = 0

    def swapping_read(descriptor: int, expected_size: int) -> bytes:
        nonlocal calls
        data = original_read(descriptor, expected_size)
        calls += 1
        if calls == 2:
            tenant_root.rename(tmp_path / "detached-tenant-final-read")
            tenant_root.mkdir()
        return data

    monkeypatch.setattr(artifacts, "_read_bounded", swapping_read)

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)

    assert calls == 2
    assert list(tenant_root.iterdir()) == []


@_LINUX_ONLY
def test_fifo_substitution_is_nonblocking_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, result = _request_and_result()
    tenant_directory, content_id, payload = _expected_names(request, result)
    tenant_root = tmp_path / "tenants" / tenant_directory
    tenant_root.mkdir(parents=True)
    leaf_name = f"{content_id}.json"
    destination = tenant_root / leaf_name
    destination.write_bytes(payload)
    original_open = cast(Callable[..., int], os.open)
    fifo_name = "mkfifo"
    nonblocking_name = "O_NONBLOCK"
    make_fifo = cast(Callable[..., None], getattr(os, fifo_name))
    nonblocking_flag = int(getattr(os, nonblocking_name, 0))
    substituted = False

    def fifo_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        nonlocal substituted
        if path == leaf_name and not substituted:
            substituted = True
            assert flags & nonblocking_flag
            os.unlink(leaf_name, dir_fd=kwargs["dir_fd"])
            make_fifo(leaf_name, dir_fd=kwargs["dir_fd"])
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fifo_open)

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)

    assert substituted
    assert stat.S_ISFIFO(destination.stat(follow_symlinks=False).st_mode)


@_LINUX_ONLY
def test_concurrent_publication_allows_only_identical_replay(tmp_path: Path) -> None:
    request, result = _request_and_result()
    barrier = threading.Barrier(2)
    references: list[object] = []
    failures: list[BaseException] = []

    def publish() -> None:
        try:
            barrier.wait()
            references.append(write_ci_worker_artifact(tmp_path, request, result))
        except BaseException as error:  # pragma: no cover - failure is asserted below
            failures.append(error)

    first = threading.Thread(target=publish)
    second = threading.Thread(target=publish)
    first.start()
    second.start()
    first.join()
    second.join()

    assert failures == []
    assert len(references) == 2
    assert references[0] == references[1]


def test_non_linux_platform_is_rejected_before_any_filesystem_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request, result = _request_and_result()
    monkeypatch.setattr(sys, "platform", "darwin")

    with pytest.raises(CiWorkerArtifactError):
        write_ci_worker_artifact(tmp_path, request, result)

    assert list(tmp_path.iterdir()) == []


@_LINUX_ONLY
def test_formatted_error_does_not_expose_path_canary(tmp_path: Path) -> None:
    request, result = _request_and_result()
    canary = "p512-path-canary"

    with pytest.raises(CiWorkerArtifactError) as raised:
        write_ci_worker_artifact(tmp_path / canary, request, result)

    formatted = "".join(traceback.format_exception(raised.value))
    assert canary not in str(raised.value)
    assert canary not in formatted
