#####
## Container image spec for tunnel-proxy client
#####

FROM debian:buster-slim

# Add an unprivileged user to initiate tunnels
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
    apt-get install -y openssh-client python3 tini && \
    rm -rf /var/lib/apt/lists/*

# Copy in required files
COPY ./bin /usr/bin/

USER $TUNNEL_UID
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/usr/bin/tunnel-init"]
