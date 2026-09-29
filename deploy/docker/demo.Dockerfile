# syntax=docker/dockerfile:1
# One-command reviewer demo: audits a vulnerable fixture offline (no model, no network at run time),
# prints the finding, the parameterized-query patch and the report locations.
#   docker build -f deploy/docker/demo.Dockerfile -t securecode-demo .
#   docker run --rm securecode-demo
ARG RUNTIME_IMAGE=python:3.12-slim-bookworm@sha256:d5ae74acb8026b32a2f6deea45003c5bd4e2880700c19c44bda54670ad3eff90
FROM ${RUNTIME_IMAGE}

WORKDIR /app
COPY deploy/docker/runtime-requirements.txt /tmp/runtime-requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-deps \
        --requirement /tmp/runtime-requirements.txt \
    && rm /tmp/runtime-requirements.txt

COPY apps/cli/src /app/apps/cli/src
COPY packages /app/packages
COPY demo /app/demo
COPY tests/fixtures/p4_10 /app/tests/fixtures/p4_10
ENV PYTHONPATH=/app/apps/cli/src:/app/packages/adapters/src:/app/packages/contracts/src:/app/packages/core/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 65532 demo && mkdir /out && chown demo /out
USER demo
VOLUME ["/out"]
CMD ["sh", "-c", "python demo/mvp_cwe89_demo.py --output /out/report && echo && echo '=== Markdown report ===' && cat /out/report/final-report.md"]
