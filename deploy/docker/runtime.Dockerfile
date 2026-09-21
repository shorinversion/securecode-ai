# syntax=docker/dockerfile:1
FROM python:3.12-slim-bookworm@sha256:d5ae74acb8026b32a2f6deea45003c5bd4e2880700c19c44bda54670ad3eff90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONUNBUFFERED=1

COPY deploy/docker/runtime-requirements.txt /tmp/runtime-requirements.txt
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates git libatomic1 \
    && python -m pip install --no-cache-dir --disable-pip-version-check --no-deps \
        --requirement /tmp/runtime-requirements.txt \
    && rm -rf /var/lib/apt/lists/* /tmp/runtime-requirements.txt
