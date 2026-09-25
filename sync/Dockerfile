FROM docker.io/ubuntu:24.04 as helm

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && \
    apt-get install -y --no-install-suggests --no-install-recommends \
    wget \
    ca-certificates

# Install yq from the official Docker image
COPY --from=docker.io/mikefarah/yq /usr/bin/yq /usr/bin/

ARG HELM_VERSION=v4.3.0
# TARGETATCH is automatically populated by docker
ARG TARGETARCH
ADD https://get.helm.sh/helm-${HELM_VERSION}-linux-${TARGETARCH}.tar.gz /tmp/helm.tar.gz
RUN tar -xz --strip-components 1 -C /usr/bin -f /tmp/helm.tar.gz linux-${TARGETARCH}/helm \
    && helm version

# Install the zenith-service chart
COPY ./sync/chart /charts/zenith-service
# Pull in the dependencies
RUN helm dependency update /charts/zenith-service
# Generate a checksum to add to the version that depends on the contents
# This is because we only turn over the Helm releases when either the chart version
# or values change, so we need a version that changes when the content changes
RUN set -e; \
    CHECKSUM="$( \
      find /charts/zenith-service -type f -print0 | \
        sort -z | \
        xargs -0 cat | \
        sha256sum | \
        awk '{print $1}' | \
        head -c 8 \
    )"; \
    yq -i ".version += \"+$CHECKSUM\"" /charts/zenith-service/Chart.yaml


############################
## INSTALL AND BUILD APP ###
############################
FROM ghcr.io/astral-sh/uv:trixie AS build
# Note: distro should match final image stage to ensure build compat. trixie=debian13
# Non-slim version required for git.

# These env vars setup UV for a docker installation as opposed to
# the defaults which are optimised for local development.
# https://docs.astral.sh/uv/guides/integration/docker/#optimizations
# https://docs.astral.sh/uv/reference/environment/
ENV UV_NO_DEV=1 \
    UV_NO_EDITABLE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_FROZEN=1 \
    UV_CACHE_DIR=/uv-cache/ \
    UV_PYTHON_INSTALL_DIR=/python \
    UV_PYTHON_INSTALL_BIN=0 \
    UV_PYTHON_PREFERENCE=only-managed

WORKDIR /app-source

### INSTALL PINNED PYTHON ###
# https://docs.astral.sh/uv/guides/install-python/
COPY .python-version /app-source
RUN uv python install \
    && chmod -R ugo=rX /python

### INSTALL PROJECT INTO VENV ###
# uv sync --active makes uv (re)create the currently
# active venv and install into it.
ENV VIRTUAL_ENV=/app

### INSTALL PINNED DEPENDENCIES ###
# --frozen makes uv install the versions which are pinned in uv.lock
# Installing the dependencies first optimizes caching so if the app
# changes but not the deps there is no need to rebuild this.
COPY uv.lock pyproject.toml /app-source
COPY sync/pyproject.toml /app-source/sync/
RUN --mount=type=cache,target=/uv-cache/ \
    uv sync --package zenith-sync \
            --active \
            --frozen \
            --no-install-project \
            --no-install-workspace \
    && chmod -R ugo=rX /app

### INSTALL THE PROJECT ###
# Then install the app.
COPY . /app-source
RUN --mount=type=cache,target=/uv-cache/ \
    uv sync --package zenith-sync \
            --active \
            --frozen \
    && chmod -R ugo=rX /app

FROM docker.io/ubuntu:24.04

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED=1

# Make httpx use the system trust roots
# By default, this means we use the CAs from the ca-certificates package
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Tell Helm to use /tmp for mutable data
ENV HELM_CACHE_HOME=/tmp/helm/cache \
    HELM_CONFIG_HOME=/tmp/helm/config \
    HELM_DATA_HOME=/tmp/helm/data

# Create the user that will be used to run the app
ENV ZENITH_UID 1001
ENV ZENITH_GID 1001
ENV ZENITH_USER zenith
ENV ZENITH_GROUP zenith
RUN groupadd --gid $ZENITH_GID $ZENITH_GROUP && \
    useradd \
      --no-create-home \
      --no-user-group \
      --gid $ZENITH_GID \
      --shell /sbin/nologin \
      --uid $ZENITH_UID \
      $ZENITH_USER

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && \
    apt-get install -y --no-install-suggests --no-install-recommends \
    ca-certificates

COPY --from=helm /usr/bin/helm /usr/bin/helm
COPY --from=helm /charts /charts
COPY --from=build /python /python
COPY --from=build /app /app

USER $ZENITH_UID
CMD ["/app/bin/zenith-sync"]
