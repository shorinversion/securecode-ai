ARG RUNTIME_IMAGE=securecode-default-runtime
FROM python:3.12-slim-bookworm@sha256:d5ae74acb8026b32a2f6deea45003c5bd4e2880700c19c44bda54670ad3eff90 AS securecode-default-runtime
COPY deploy/docker/runtime-requirements.txt /tmp/runtime-requirements.txt
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git libatomic1 \
    && python -m pip install --no-cache-dir --disable-pip-version-check --no-deps \
        --requirement /tmp/runtime-requirements.txt \
    && rm -rf /var/lib/apt/lists/* /tmp/runtime-requirements.txt

FROM ${RUNTIME_IMAGE}
WORKDIR /app
COPY apps/worker/src /app/apps/worker/src
COPY packages/adapters /app/packages/adapters
COPY packages/contracts /app/packages/contracts
COPY packages/core /app/packages/core
COPY deploy/docker/entrypoint.py /app/entrypoint.py
COPY deploy/docker/worker_healthcheck.py /app/worker_healthcheck.py
ENV PYTHONPATH=/app/apps/worker/src:/app/packages/adapters/src:/app/packages/contracts/src:/app/packages/core/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONUNBUFFERED=1 \
    SECURECODE_DATA_DIR=/var/lib/securecode \
    SECURECODE_TMP_DIR=/tmp/securecode
RUN mkdir -p /var/lib/securecode /tmp/securecode \
    && chown -R 65532:65532 /var/lib/securecode /tmp/securecode \
    && chmod 0700 /var/lib/securecode /tmp/securecode \
    && chmod -R a-w /app
USER 65532:65532
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 CMD ["python", "/app/worker_healthcheck.py"]
ENTRYPOINT ["python","/app/entrypoint.py"]
CMD ["python","-m","securecode_ai.worker.service"]
