# syntax=docker/dockerfile:1
# One image for both roles. Entrypoint selects the role:
#   receiver: python -m azure_sre receiver   (HTTPS, port 8080)
#   worker:   python -m azure_sre worker     (no ingress)
# Build for amd64 only (the pinned github-mcp-server asset is Linux_x86_64):
#   docker build --platform linux/amd64 -t azure-sre-copilot:<tag> .
#
# Everything the incident path needs is baked in at build time:
# Python 3.13 venv (uv --frozen), Azure CLI + log-analytics extension,
# Copilot runtime bundle, and the pinned github-mcp-server. No runtime downloads.

ARG PYTHON_IMAGE=python:3.13-slim-bookworm
# TODO(live): pin by digest (python:3.13-slim-bookworm@sha256:...) before publishing.
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.28

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates tar \
 && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

WORKDIR /app

# App deps first for layer caching. Lock is frozen; no pyproject/lock edits here.
COPY pyproject.toml uv.lock .python-version README.md ./
RUN uv sync --frozen --no-dev --no-install-project --python /usr/local/bin/python3.13

COPY src ./src
RUN uv sync --frozen --no-dev --python /usr/local/bin/python3.13

# Copilot runtime bundle, predownloaded into a fixed location.
ENV COPILOT_CLI_EXTRACT_DIR=/opt/copilot-runtime
RUN /app/.venv/bin/python -m copilot download-runtime \
 && bin="$(find /opt/copilot-runtime -type f -perm -u+x -name 'copilot*' | head -n 1)" \
 && test -n "$bin" \
 && mkdir -p /opt/copilot \
 && ln -s "$bin" /opt/copilot/copilot \
 && test -x /opt/copilot/copilot \
 && chmod -R a+rX /opt/copilot-runtime

# Pinned github-mcp-server, sha256-verified by the repo script.
COPY scripts/fetch_github_mcp_server.sh /app/scripts/fetch_github_mcp_server.sh
RUN bash /app/scripts/fetch_github_mcp_server.sh /opt/gms

# Azure CLI in its own venv (kept separate from the app venv). Extension is installed
# from a wheel whose sha256 is pinned here; no index lookup happens at build or runtime.
ARG AZURE_CLI_VERSION=2.91.0
ARG LOG_ANALYTICS_EXT_URL=https://azcliprod.blob.core.windows.net/cli-extensions/log_analytics-1.0.0b3-py2.py3-none-any.whl
ARG LOG_ANALYTICS_EXT_SHA256=d35a34b5d1a1e9823fd99e770f9f8653b8cb4783a5a961e25b3fd1e62436f7a9
ENV AZURE_EXTENSION_DIR=/opt/az-ext
RUN python3.13 -m venv /opt/az \
 && /opt/az/bin/pip install --no-cache-dir "azure-cli==${AZURE_CLI_VERSION}" \
 && mkdir -p /opt/build/ext \
 && curl -fsSL -o /opt/build/ext/log_analytics-1.0.0b3-py2.py3-none-any.whl "${LOG_ANALYTICS_EXT_URL}" \
 && echo "${LOG_ANALYTICS_EXT_SHA256}  /opt/build/ext/log_analytics-1.0.0b3-py2.py3-none-any.whl" | sha256sum -c - \
 && mkdir -p "${AZURE_EXTENSION_DIR}" \
 && AZURE_CONFIG_DIR=/opt/build/az-config /opt/az/bin/az extension add --source /opt/build/ext/log_analytics-1.0.0b3-py2.py3-none-any.whl --yes \
 && rm -rf /opt/build/ext /opt/build/az-config \
 && /opt/az/bin/az --version >/dev/null

FROM ${PYTHON_IMAGE} AS runtime
# Runtime is preinstalled; the SDK must never download on an incident.
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/app/.venv/bin:/opt/az/bin:$PATH \
    VIRTUAL_ENV=/app/.venv \
    COPILOT_SKIP_CLI_DOWNLOAD=1 \
    COPILOT_CLI_PATH=/opt/copilot/copilot \
    AZURE_EXTENSION_DIR=/opt/az-ext \
    AZURE_CONFIG_DIR=/var/lib/sre/azure \
    SRE_SMOKE_WORKDIR=/var/lib/sre/smoke \
    HOME=/var/lib/sre/home

# Runtime needs the Azure CLI's Python venv at the same path, so the base must match the build stage.
# The app runs as a numeric non-root UID (65532). No shell tools beyond the base image are added.
RUN groupadd --gid 65532 sre \
 && useradd --uid 65532 --gid sre --no-create-home --home-dir /var/lib/sre/home --shell /usr/sbin/nologin sre \
 && mkdir -p /var/lib/sre/azure /var/lib/sre/home \
 && chown -R 65532:65532 /var/lib/sre

COPY --from=build /app /app
COPY --from=build /opt/copilot-runtime /opt/copilot-runtime
COPY --from=build /opt/copilot /opt/copilot
COPY --from=build /opt/gms /opt/gms
COPY --from=build /opt/az /opt/az
COPY --from=build /opt/az-ext /opt/az-ext

WORKDIR /app
USER 65532:65532

EXPOSE 8080

# Role is selected by args: receiver (HTTP) or worker (queue consumer).
ENTRYPOINT ["python", "-m", "azure_sre"]
CMD ["receiver"]
