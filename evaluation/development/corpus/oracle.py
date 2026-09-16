"""Generic Docker worker; it has no corpus manifest, rules, labels, or verdicts."""

from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
import selectors
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

_FRAME_PREFIX = "SECURECODE_ORACLE_OBSERVATION_V1:"
_ACK_PREFIX = "SECURECODE_ORACLE_ACK_V1:"
_CHILD_TIMEOUT_SECONDS = 3
_MAX_FRAME_BYTES = 65_536


class _Request:
    def __init__(self, args: dict[str, str], form: dict[str, str]) -> None:
        self.args = args
        self.form = form


class _Db:
    def execute(self, query: str, parameters: object = None) -> dict[str, object]:
        return {"parameters": parameters, "query": query}


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def _argument(value: object) -> object:
    if type(value) is dict and set(value) == {"$fixture", "values"}:
        fixture, values = value["$fixture"], value["values"]
        if type(values) is not dict or any(
            type(key) is not str or type(item) is not str for key, item in values.items()
        ):
            raise ValueError("fixture values are invalid")
        if fixture == "request_args":
            return _Request(dict(values), {})
        if fixture == "request_form":
            return _Request({}, dict(values))
    if type(value) is dict and value == {"$fixture": "db"}:
        return _Db()
    return value


def _normal(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if type(value) is dict:
        return {str(key): _normal(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normal(item) for item in value]
    return value


def _load_source(source: Path) -> ModuleType:
    if source != Path("/case/case.py") or not source.is_file():
        raise ValueError("source path is invalid")
    specification = importlib.util.spec_from_file_location("p7_case", source)
    if specification is None or specification.loader is None:
        raise ValueError("case module is not loadable")
    module = importlib.util.module_from_spec(specification)
    sys.path.insert(0, "/case")
    try:
        specification.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        sys.modules.pop("support", None)
    return module


def _evaluate(source: Path, entrypoint: str, arguments: list[object]) -> int:
    """Untrusted execution process: no trusted framing or challenge descriptors."""
    try:
        observed = _normal(
            getattr(_load_source(source), entrypoint)(*[_argument(item) for item in arguments])
        )
        print(
            json.dumps(
                {"observation": observed}, sort_keys=True, separators=(",", ":"), allow_nan=False
            ),
            flush=True,
        )
        return 0
    except (AttributeError, ImportError, OSError, TypeError, ValueError, KeyError):
        return 2


def _protect_channels() -> None:
    # Same-UID corpus processes must not reopen our pipes through /proc or ptrace.
    # The container is Linux and drops every capability, including CAP_SYS_PTRACE.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise OSError("trusted process isolation unavailable")


def _child(source: Path, entrypoint: str, arguments_json: str) -> int:
    process: subprocess.Popen[bytes] | None = None
    try:
        _protect_channels()
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--evaluate",
                "--source",
                str(source),
                "--entrypoint",
                entrypoint,
                "--arguments-json",
                arguments_json,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env={"PYTHONIOENCODING": "utf-8"},
        )
        if process.stdout is None or process.stderr is None:
            raise ValueError("evaluation pipes unavailable")
        deadline = time.monotonic() + _CHILD_TIMEOUT_SECONDS
        buffered = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            value = _read_frame(process, selector, buffered, deadline)
        observation = json.loads(value, object_pairs_hook=_no_duplicate_object)
        if type(observation) is not dict or set(observation) != {"observation"}:
            raise ValueError("evaluation observation shape invalid")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise ValueError("evaluation failed")
        if buffered or process.stdout.read() or process.stderr.read():
            raise ValueError("evaluation emitted extra output")
        print(
            _FRAME_PREFIX
            + json.dumps(observation, sort_keys=True, separators=(",", ":"), allow_nan=False),
            flush=True,
        )
        challenge = sys.stdin.readline().strip()
        if not challenge:
            return 2
        print(_ACK_PREFIX + challenge, flush=True)
        return 0
    except (json.JSONDecodeError, OSError, subprocess.SubprocessError, TypeError, ValueError):
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        return 2


def _read_frame(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    buffered: bytearray,
    deadline: float,
) -> bytes:
    while b"\n" not in buffered:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, _CHILD_TIMEOUT_SECONDS)
        events = selector.select(remaining)
        if not events:
            raise subprocess.TimeoutExpired(process.args, _CHILD_TIMEOUT_SECONDS)
        for key, _ in events:
            chunk = os.read(key.fd, 4096)
            if key.data == "stderr":
                if chunk:
                    raise ValueError("child wrote stderr")
                selector.unregister(key.fileobj)
                continue
            if not chunk:
                raise ValueError("child observation ended early")
            buffered.extend(chunk)
            if len(buffered) > _MAX_FRAME_BYTES:
                raise ValueError("child observation is oversized")
    line, remainder = buffered.split(b"\n", 1)
    buffered[:] = remainder
    return bytes(line)


def _supervise(source: Path, entrypoint: str, arguments_json: str) -> int:
    process: subprocess.Popen[bytes] | None = None
    try:
        _protect_channels()
        arguments = json.loads(arguments_json, object_pairs_hook=_no_duplicate_object)
        if type(arguments) is not list or type(entrypoint) is not str:
            raise ValueError("probe arguments are invalid")
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--child",
                "--source",
                str(source),
                "--entrypoint",
                entrypoint,
                "--arguments-json",
                arguments_json,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env={"PYTHONIOENCODING": "utf-8"},
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise ValueError("child pipes are unavailable")
        deadline = time.monotonic() + _CHILD_TIMEOUT_SECONDS
        buffered = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            first = _read_frame(process, selector, buffered, deadline)
            if not first.startswith(_FRAME_PREFIX.encode("ascii")):
                raise ValueError("child observation frame is invalid")
            observation = json.loads(
                first.removeprefix(_FRAME_PREFIX.encode("ascii")),
                object_pairs_hook=_no_duplicate_object,
            )
            if type(observation) is not dict or set(observation) != {"observation"}:
                raise ValueError("child observation shape is invalid")
            challenge = os.urandom(32).hex()
            process.stdin.write(challenge.encode("ascii") + b"\n")
            process.stdin.flush()
            process.stdin.close()
            acknowledgement = _read_frame(process, selector, buffered, deadline)
        if acknowledgement != (_ACK_PREFIX + challenge).encode("ascii"):
            raise ValueError("child acknowledgement is invalid")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or process.wait(timeout=remaining) != 0:
            raise ValueError("child did not exit successfully")
        if buffered or process.stdout.read() or process.stderr.read():
            raise ValueError("child observation frame is invalid")
        print(
            _FRAME_PREFIX
            + json.dumps(observation, sort_keys=True, separators=(",", ":"), allow_nan=False)
        )
        return 0
    except (json.JSONDecodeError, OSError, subprocess.SubprocessError, TypeError, ValueError):
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--entrypoint", required=True)
    parser.add_argument("--arguments-json", required=True)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--evaluate", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.child and arguments.evaluate:
        return 2
    if arguments.child:
        return _child(arguments.source, arguments.entrypoint, arguments.arguments_json)
    if arguments.evaluate:
        try:
            values = json.loads(arguments.arguments_json, object_pairs_hook=_no_duplicate_object)
        except (json.JSONDecodeError, ValueError):
            return 2
        return (
            _evaluate(arguments.source, arguments.entrypoint, values) if type(values) is list else 2
        )
    return _supervise(arguments.source, arguments.entrypoint, arguments.arguments_json)


if __name__ == "__main__":
    raise SystemExit(main())
