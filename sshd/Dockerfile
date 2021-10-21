ARG ZENITH_TAG=
FROM ghcr.io/stackhpc/zenith-common:${ZENITH_TAG}

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

# Install openssh server package
RUN apt-get update && \
    apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/run/sshd && \
    chown zenith:zenith /var/run/sshd

# Installing dependencies separately ensures better use of the build cache
COPY requirements.txt /opt/zenith/sshd/
RUN pip3 install --no-deps --requirement /opt/zenith/sshd/requirements.txt

COPY setup.py setup.cfg zenith /opt/zenith/sshd/
RUN pip3 install --no-deps -e /opt/zenith/sshd

COPY ./etc /etc/

USER $ZENITH_UID
CMD ["zenith", "sshd", "start"]
