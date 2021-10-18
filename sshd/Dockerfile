#####
## Container image spec for zenith SSHD server
#####

FROM debian:bullseye-slim

# Add an unprivileged user to accept tunnel requests
# The user has a home directory, a restricted shell to allow the tunnel-init
# script to run and an empty password to allow anonymous SSH
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

RUN apt-get update && \
    apt-get install -y openssh-server python3 python3-pip tini && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/run/sshd && \
    chown zenith:zenith /var/run/sshd

# The tunnel-init script requires requests
RUN pip3 install --no-cache-dir requests

COPY ./etc /etc/
COPY ./bin /usr/bin/

USER $ZENITH_UID
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/usr/bin/sshd-start"]
