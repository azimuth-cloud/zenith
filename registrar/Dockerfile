FROM ubuntu:jammy AS python-builder

RUN apt-get update && \
    apt-get install -y python3 python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv && \
    /venv/bin/pip install -U pip setuptools

COPY requirements.txt /app/requirements.txt
RUN  /venv/bin/pip install --no-deps --requirement /app/requirements.txt

COPY . /app
RUN /venv/bin/pip install --no-deps /app


FROM ubuntu:jammy

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# Make httpx use the system trust roots
# By default, this means we use the CAs from the ca-certificates package
ENV SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt

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
    apt-get install --no-install-recommends --no-install-suggests -y ca-certificates python3 tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /venv /venv

USER $ZENITH_UID
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/venv/bin/uvicorn", "--host", "0.0.0.0", "--port", "8000", "--access-log", "zenith.registrar:app"]
