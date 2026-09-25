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
COPY sshd/pyproject.toml /app-source/sshd/
RUN --mount=type=cache,target=/uv-cache/ \
    uv sync --package zenith-sshd \
            --active \
            --frozen \
            --no-install-project \
            --no-install-workspace \
    && chmod -R ugo=rX /app

### INSTALL THE PROJECT ###
# Then install the app.
COPY . /app-source
RUN --mount=type=cache,target=/uv-cache/ \
    uv sync --package zenith-sshd \
            --active \
            --frozen \
            --no-install-workspace \
    && chmod -R ugo=rX /app

###########################
### COMPILE FINAL IMAGE ###
###########################
FROM docker.io/ubuntu:24.04

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED=1

# Make requests and httpx use the system trust roots
# By default, this means we use the CAs from the ca-certificates package
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Create an unprivileged user to accept tunnel requests
# The user has a home directory, a restricted shell to allow the tunnel script
# to run and an empty password to allow anonymous SSH
ENV ZENITH_UID=1001
ENV ZENITH_GID=1001
ENV ZENITH_USER=zenith
ENV ZENITH_GROUP=zenith
RUN groupadd --gid $ZENITH_GID $ZENITH_GROUP && \
    useradd \
      --create-home \
      --home-dir /home/zenith \
      --no-user-group \
      --gid $ZENITH_GID \
      --shell /bin/rbash \
      --uid $ZENITH_UID \
      $ZENITH_USER && \
    passwd -d $ZENITH_USER

# Install tini, which we will use to marshal the processes, and the OpenSSH server
# Make sure to remove the built-in keys
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt update && \
    apt-get install --no-install-recommends --no-install-suggests -y ca-certificates openssh-server && \
    rm -rf /etc/ssh/ssh_host_*_key && \
    mkdir -p /var/run/sshd && \
    chown zenith:zenith /var/run/sshd

COPY ./sshd/etc/ /etc/
COPY --from=build /python /python
COPY --from=build /app /app

# Symlink zenith-sshd somewhere in the default PATH
RUN ln -s /app/bin/zenith-sshd /usr/local/bin/

USER $ZENITH_UID
CMD ["zenith-sshd", "start"]
