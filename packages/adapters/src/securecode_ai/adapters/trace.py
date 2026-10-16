"""Opt-in JSONL trace of the stages of one trial run (``SECURECODE_TRACE=path``).

The trace answers "which stage failed and why" without a debugger. Every event carries only
a kind, a time stamp and short scalar facts (stage names, status codes, exception types,
counts, durations). File paths, source text, prompts and model output never enter it: a
value that is not a short scalar is dropped, and a long string is cut.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

_MAX_TEXT: Final = 120
_lock = threading.Lock()
_path: Path | None = None
_clock = time.monotonic
_started = 0.0


def configure_trace(path: str | None) -> None:
    """Start (or, with ``None``, stop) tracing into ``path``; the file is appended to."""

    global _path, _started
    with _lock:
        _path = Path(path) if path else None
        _started = _clock()


def trace_enabled() -> bool:
    return _path is not None


def trace_event(kind: str, **fields: object) -> None:
    """Append one event; a no-op without ``configure_trace``. It never raises."""

    target = _path
    if target is None:
        return
    try:
        event: dict[str, object] = {
            "time": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "t": round(_clock() - _started, 3),
            "kind": kind[:_MAX_TEXT],
        }
        for key, value in fields.items():
            safe = _scalar(value)
            if safe is not _DROPPED:
                event[key] = safe
        line = json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        with _lock, target.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    except Exception:
        return


class _Dropped:
    pass


_DROPPED: Final = _Dropped()


def _scalar(value: object) -> object:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        return value if len(value) <= _MAX_TEXT else value[:_MAX_TEXT] + "..."
    if isinstance(value, tuple | list) and all(isinstance(item, str) for item in value):
        return [_scalar(item) for item in value[:16]]
    if isinstance(value, Mapping):
        return _DROPPED
    return _DROPPED


def exception_label(error: BaseException) -> str:
    """The exception type, plus the fixed ``code`` of a closed domain error when it has one."""

    code = getattr(getattr(error, "code", None), "value", None)
    name = type(error).__name__
    return f"{name}/{code}" if isinstance(code, str) and code else name


__all__ = ["configure_trace", "exception_label", "trace_enabled", "trace_event"]
