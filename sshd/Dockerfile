FROM debian:bullseye-slim

# Don't buffer stdout and stderr as it breaks realtime logging
ENV PYTHONUNBUFFERED 1

# Create an unprivileged user to accept tunnel requests
# The user has a home directory, a restricted shell to allow the tunnel script
# to run and an empty password to allow anonymous SSH
ENV ZENITH_UID 1001
ENV ZENITH_USER zenith
RUN useradd \
      --create-home \
      --home-dir /home/zenith \
      --user-group \
      --shell /bin/rbash \
      --uid $ZENITH_UID \
      $ZENITH_USER && \
    passwd -d $ZENITH_USER

# Install tini, which we will use to marshal the processes, Python and OpenSSH
RUN apt-get update && \
    apt-get install -y git openssh-server python3 python3-pip tini && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/run/sshd && \
    chown zenith:zenith /var/run/sshd

# Installing dependencies separately ensures better use of the build cache
COPY requirements.txt /opt/zenith/sshd/
RUN pip3 install --no-deps --requirement /opt/zenith/sshd/requirements.txt

COPY etc/ /etc/
COPY setup.cfg setup.py /opt/zenith/sshd/
COPY zenith/ /opt/zenith/sshd/zenith/
RUN pip3 install --no-deps -e /opt/zenith/sshd

USER $ZENITH_UID
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["zenith-sshd", "start"]
