"""Run the bounded in-process capacity profile and print the measured receipt.

Usage:
    python -I scripts/capacity_profile.py --concurrency 8 --iterations 256
    SECURECODE_CAPACITY_BEARER="$TOKEN" python -I scripts/capacity_profile.py --path /api/v1/policies

The profile drives the real control-plane application in process: no network,
no external services, and no source or credentials in the output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
for candidate in (
    REPOSITORY_ROOT / "apps" / "server" / "src",
    REPOSITORY_ROOT / "packages" / "contracts" / "src",
    REPOSITORY_ROOT / "packages" / "core" / "src",
):
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from securecode_ai.server.bootstrap import build_local_app  # noqa: E402
from securecode_ai.server.capacity import CapacityReceipt  # noqa: E402
from securecode_ai.server.capacity_profile import (  # noqa: E402
    EXECUTABLE_SCENARIOS,
    InProcessCapacityExecutor,
    render,
)
from securecode_ai.server.resilience import ResiliencePlan, run  # noqa: E402  # noqa: E402
from securecode_ai.server.runtime import load_settings  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--iterations", type=int, default=256)
    parser.add_argument("--path", default="/api/v1/health/live")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)

    if not arguments.path.startswith("/api/"):
        print("CAPACITY=FAIL: path must be an API route")
        return 1
    try:
        requests = (("GET", arguments.path, b""),)
        app = build_local_app(load_settings())
        token = os.environ.get("SECURECODE_CAPACITY_BEARER")
        headers = None if token is None else {"authorization": f"Bearer {token}"}
        receipt = profile_with(
            app,
            requests,
            arguments.concurrency,
            arguments.iterations,
            headers=headers,
        )
    except (TypeError, ValueError) as error:
        print(f"CAPACITY=FAIL: {error}")
        return 1
    document = render(receipt)
    if arguments.output is not None:
        arguments.output.write_text(document + chr(10), encoding="utf-8")
    summary = json.loads(document)
    for cell in summary["cells"]:
        print(
            f"scenario={cell['scenario']} throughput={cell['throughput']} "
            f"run_p50={cell['run_p50']} run_p95={cell['run_p95']} "
            f"errors={cell['errors']} completed={cell['completed']}"
        )
    print(f"CAPACITY={'PASS' if summary['passed'] else 'FAIL'} cells={len(summary['cells'])}")
    return 0 if summary["passed"] else 1


def profile_with(
    app: object,
    requests: tuple[tuple[str, str, bytes], ...],
    concurrency: int,
    iterations: int,
    *,
    headers: dict[str, str] | None = None,
) -> CapacityReceipt:
    """Run the plan over the honestly measurable scenarios only."""

    plan = ResiliencePlan(
        concurrency=concurrency,
        iterations=iterations,
        scenarios=EXECUTABLE_SCENARIOS,
    )
    return run(plan, InProcessCapacityExecutor(app, requests=requests, headers=headers))


if __name__ == "__main__":
    raise SystemExit(main())
