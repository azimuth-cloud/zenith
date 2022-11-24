FROM debian:bullseye-slim

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# Create an unprivileged user to run the application process
ENV ZENITH_UID 1001
ENV ZENITH_USER zenith
RUN useradd \
      --no-create-home \
      --user-group \
      --shell /sbin/nologin \
      --uid $ZENITH_UID \
      $ZENITH_USER

# Install tini, which we will use to marshal the processes and Python
RUN apt-get update && \
    apt-get install -y curl git python3 python3-pip tini && \
    rm -rf /var/lib/apt/lists/*

# Install the Helm CLI
ENV HELM_CACHE_HOME /tmp/helm/cache
ENV HELM_CONFIG_HOME /tmp/helm/config
ENV HELM_DATA_HOME /tmp/helm/data
ENV HELM_PLUGINS /opt/helm-plugins
ARG HELM_VERSION=v3.10.2
RUN set -ex; \
    OS_ARCH="$(uname -m)"; \
    case "$OS_ARCH" in \
        x86_64) helm_arch=amd64 ;; \
        aarch64) helm_arch=arm64 ;; \
        *) false ;; \
    esac; \
    curl -fsSL https://get.helm.sh/helm-${HELM_VERSION}-linux-${helm_arch}.tar.gz | \
      tar -xz --strip-components 1 -C /usr/bin linux-${helm_arch}/helm; \
    helm version

# Installing dependencies separately ensures better use of the build cache
COPY requirements.txt /opt/zenith/sync/
RUN pip3 install --no-deps --requirement /opt/zenith/sync/requirements.txt

COPY . /opt/zenith/sync
RUN pip3 install --no-deps -e /opt/zenith/sync

USER $ZENITH_UID
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["zenith-sync"]
