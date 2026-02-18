FROM ubuntu:24.04 as helm

RUN apt-get update && \
    apt-get install -y wget && \
    rm -rf /var/lib/apt/lists/*

# Install yq from the official Docker image
COPY --from=mikefarah/yq /usr/bin/yq /usr/bin/

ARG HELM_VERSION=v4.1.1
RUN set -ex; \
    OS_ARCH="$(uname -m)"; \
    case "$OS_ARCH" in \
        x86_64) helm_arch=amd64 ;; \
        aarch64) helm_arch=arm64 ;; \
        *) false ;; \
    esac; \
    wget -q -O - https://get.helm.sh/helm-${HELM_VERSION}-linux-${helm_arch}.tar.gz | \
      tar -xz --strip-components 1 -C /usr/bin linux-${helm_arch}/helm; \
    helm version

# Install the zenith-service chart
COPY ./chart /charts/zenith-service
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


FROM ubuntu:24.04 AS python-builder

RUN apt-get update && \
    apt-get install -y python3 python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv && \
    /venv/bin/pip install -U pip setuptools

COPY requirements.txt /app/requirements.txt
RUN  /venv/bin/pip install --requirement /app/requirements.txt

COPY . /app
RUN /venv/bin/pip install /app


FROM ubuntu:24.04

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# Make httpx use the system trust roots
# By default, this means we use the CAs from the ca-certificates package
ENV SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt

# Tell Helm to use /tmp for mutable data
ENV HELM_CACHE_HOME /tmp/helm/cache
ENV HELM_CONFIG_HOME /tmp/helm/config
ENV HELM_DATA_HOME /tmp/helm/data

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

RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y ca-certificates python3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=helm /usr/bin/helm /usr/bin/helm
COPY --from=helm /charts /charts
COPY --from=python-builder /venv /venv

USER $ZENITH_UID
CMD ["/venv/bin/zenith-sync"]
