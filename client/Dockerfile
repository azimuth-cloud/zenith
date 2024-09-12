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

# Make requests use the system trust roots
# By default, this means we use the roots baked into the image
ENV REQUESTS_CA_BUNDLE /etc/ssl/certs/ca-certificates.crt

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
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y ca-certificates openssh-client python3 tini && \
    rm -rf /var/lib/apt/lists/*

COPY --from=python-builder /venv /venv

# Symlink the zenith-client somewhere in the default PATH
RUN ln -s /venv/bin/zenith-client /usr/local/bin/

ENTRYPOINT ["tini", "-g", "--"]
CMD ["zenith-client", "connect"]
