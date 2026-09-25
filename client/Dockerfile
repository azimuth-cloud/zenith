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
COPY client/pyproject.toml /app-source/client/
RUN --mount=type=cache,target=/uv-cache/ \
    uv sync --package zenith-client \
            --active \
            --frozen \
            --no-install-project \
            --no-install-workspace \
    && chmod -R ugo=rX /app

### INSTALL THE PROJECT ###
# Then install the app.
COPY . /app-source
RUN --mount=type=cache,target=/uv-cache/ \
    uv sync --package zenith-client \
            --active \
            --frozen \
    && chmod -R ugo=rX /app

###########################
### COMPILE FINAL IMAGE ###
###########################
# This cannot be distroless because zenith-client
# requires the openssh client
# However the final image should match the build image
FROM docker.io/debian:trixie-slim

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED=1

# Make requests use the system trust roots
# By default, this means we use the roots baked into the image
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Create the user that will be used to run the client process
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

# By default, we run as root but switch to the zenith user after reading configuration
ENV ZENITH_CLIENT__RUN_AS_USER 1001

# Install tini, which we will use to marshal the processes, Python and the OpenSSH client
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && \
    apt-get install --no-install-recommends --no-install-suggests -y \
        ca-certificates \
        openssh-client

COPY --from=build /python /python
COPY --from=build /app /app

# Symlink the zenith-client somewhere in the default PATH
RUN ln -s /app/bin/zenith-client /usr/local/bin/

CMD ["zenith-client", "connect"]
