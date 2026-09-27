FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS node-runtime

RUN npm install --global --ignore-scripts --no-audit --no-fund typescript@5.9.3

FROM golang:1.26-bookworm@sha256:1523f0e445c6bc9306a1437088ea12b1191a5d0fa203907f99aab350bd5303df AS go-runtime

FROM python:3.12-slim-bookworm@sha256:d5ae74acb8026b32a2f6deea45003c5bd4e2880700c19c44bda54670ad3eff90 AS python-build

WORKDIR /build

COPY packages/contracts /build/packages/contracts
COPY packages/core /build/packages/core
COPY packages/adapters /build/packages/adapters

RUN python -m pip install --no-cache-dir --disable-pip-version-check --no-deps \
        annotated-types==0.8.0 \
        iniconfig==2.3.0 \
        packaging==26.3 \
        pluggy==1.6.0 \
        pydantic==2.13.4 \
        pydantic-core==2.46.4 \
        pygments==2.20.0 \
        pytest==9.1.1 \
        tree-sitter==0.25.2 \
        tree-sitter-go==0.25.0 \
        tree-sitter-javascript==0.25.0 \
        tree-sitter-python==0.25.0 \
        tree-sitter-typescript==0.23.2 \
        typing-extensions==4.16.0 \
        typing-inspection==0.4.4 \
        uv-build==0.12.3 \
    && python -m pip install --no-cache-dir --disable-pip-version-check \
        --no-deps --no-build-isolation /build/packages/contracts \
    && python -m pip install --no-cache-dir --disable-pip-version-check \
        --no-deps --no-build-isolation /build/packages/core \
    && python -m pip install --no-cache-dir --disable-pip-version-check \
        --no-deps --no-build-isolation /build/packages/adapters

FROM python:3.12-slim-bookworm@sha256:d5ae74acb8026b32a2f6deea45003c5bd4e2880700c19c44bda54670ad3eff90

ENV HOME=/tmp \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    TMPDIR=/tmp

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libatomic1 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /workspace /scratch /run/securecode/validator /srv/securecode/validator-bundles \
    && chown 65532:65532 /workspace /scratch /run/securecode/validator /srv/securecode/validator-bundles \
    && chmod 0770 /run/securecode/validator

COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=go-runtime /usr/local/go /usr/local/go
COPY --from=python-build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && ln -s /usr/local/lib/node_modules/typescript/bin/tsc /usr/local/bin/tsc

WORKDIR /workspace
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/python", "-I", "-m", "securecode_ai.adapters.local_repair_oci_child"]
