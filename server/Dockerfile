#####
## Container image spec for tunnel-proxy server
#####

FROM debian:buster-slim

# Add an unprivileged user to accept tunnel requests
# This user has an empty password to allow anonymous SSH
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
    apt-get install -y openssh-server python3 tini && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /run/sshd

COPY ./etc /etc/
COPY ./bin /usr/bin/

ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
