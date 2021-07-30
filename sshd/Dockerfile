#####
## Container image spec for tunnel-server SSHD server
#####

FROM debian:buster-slim

# Add an unprivileged user to accept tunnel requests
# The user has a home directory, a restricted shell to allow the tunnel-init
# script to run and an empty password to allow anonymous SSH
ENV TUNNEL_UID 1001
ENV TUNNEL_USER tunnel
RUN useradd \
      --create-home \
      --home-dir /home/tunnel \
      --user-group \
      --shell /bin/rbash \
      --uid $TUNNEL_UID \
      $TUNNEL_USER && \
    passwd -d $TUNNEL_USER

RUN apt-get update && \
    apt-get install -y openssh-server python3 python3-pip tini && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/run/sshd && \
    chown tunnel:tunnel /var/run/sshd

# The tunnel-init script requires requests
RUN pip3 install --no-cache-dir requests

COPY ./etc /etc/
COPY ./bin /usr/bin/

USER $TUNNEL_UID
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/usr/bin/sshd-start"]
