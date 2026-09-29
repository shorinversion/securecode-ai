# syntax=docker/dockerfile:1
# One-command reviewer demo.  Without a key it audits a vulnerable fixture offline (no model, no
# network); with DEEPSEEK_API_KEY the Auditor and Architect run on DeepSeek.  Prints the report.
#   docker build -f deploy/docker/demo.Dockerfile -t securecode-demo .
#   docker run --rm securecode-demo
#   docker run --rm -e DEEPSEEK_API_KEY securecode-demo
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
COPY specs/contracts/provider-fixtures/valid.local-openai-compatible.json \
     /app/specs/contracts/provider-fixtures/valid.local-openai-compatible.json
COPY specs/contracts/policy/fixtures/egress.valid.private-model-source.json \
     /app/specs/contracts/policy/fixtures/egress.valid.private-model-source.json
COPY --chmod=0555 deploy/docker/demo-entrypoint.sh /app/demo-entrypoint.sh
ENV PYTHONPATH=/app/apps/cli/src:/app/packages/adapters/src:/app/packages/contracts/src:/app/packages/core/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 65532 demo && mkdir /out && chown demo /out
USER demo
VOLUME ["/out"]
CMD ["/app/demo-entrypoint.sh"]
