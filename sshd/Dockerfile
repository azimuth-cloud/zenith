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

# Make requests and httpx use the system trust roots
# By default, this means we use the CAs from the ca-certificates package
ENV SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE /etc/ssl/certs/ca-certificates.crt

# Create an unprivileged user to accept tunnel requests
# The user has a home directory, a restricted shell to allow the tunnel script
# to run and an empty password to allow anonymous SSH
ENV ZENITH_UID 1001
ENV ZENITH_GID 1001
ENV ZENITH_USER zenith
ENV ZENITH_GROUP zenith
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

# Install tini, which we will use to marshal the processes, Python and the OpenSSH client
# Make sure to remove the built-in keys
RUN apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y ca-certificates openssh-server python3 && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /etc/ssh/ssh_host_*_key && \
    mkdir -p /var/run/sshd && \
    chown zenith:zenith /var/run/sshd

COPY etc/ /etc/
COPY --from=python-builder /venv /venv

# Symlink zenith-sshd somewhere in the default PATH
RUN ln -s /venv/bin/zenith-sshd /usr/local/bin/

USER $ZENITH_UID
CMD ["zenith-sshd", "start"]
