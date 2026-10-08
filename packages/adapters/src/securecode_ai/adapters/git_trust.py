"""The operator's own trust decision for a checkout, carried into sealed Git calls."""

from __future__ import annotations

import functools
import os
import subprocess
import sys
from pathlib import Path


@functools.lru_cache(maxsize=16)
def operator_safe_directory(checkout: Path, executable: Path) -> dict[str, str]:
    """``GIT_CONFIG_*`` entries for a sealed Git call on ``checkout``.

    Sealed calls ignore global and system configuration, so a checkout owned by another
    user (a CI container, a mounted volume) is refused as "dubious ownership" even when
    the operator trusts it. The operator's Git, with their configuration, decides once;
    only when it accepts the checkout do sealed calls get ``safe.directory`` for it.
    Every other configuration value stays excluded.
    """

    sealed = {"GIT_CONFIG_COUNT": "0"}
    if sys.platform == "win32":
        # Git for Windows checks the owner SID; the trial precheck runs the same Git
        # with the operator's configuration, so the decision is taken there.
        owned = not _refused_without_config(checkout, executable)
    else:
        try:
            owned = checkout.stat().st_uid == os.geteuid()
        except OSError:
            return sealed
    if owned:
        return sealed
    try:
        accepted = (
            subprocess.run(
                [str(executable), "-C", str(checkout), "rev-parse", "--git-dir"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return sealed
    if not accepted:
        return sealed
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(checkout.resolve()),
    }


def _refused_without_config(checkout: Path, executable: Path) -> bool:
    env = {
        name: os.environ[name]
        for name in ("SystemRoot", "WINDIR", "PATH", "TEMP", "TMP")
        if name in os.environ
    }
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_COUNT="0",
    )
    try:
        return (
            subprocess.run(
                [str(executable), "-C", str(checkout), "rev-parse", "--git-dir"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
                timeout=10,
                check=False,
            ).returncode
            != 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


__all__ = ["operator_safe_directory"]
