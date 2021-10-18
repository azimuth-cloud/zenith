#####
## Container image spec for zenith client
#####

FROM debian:buster-slim

# Add an unprivileged user to initiate tunnels
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
    apt-get install -y openssh-client python3 tini && \
    rm -rf /var/lib/apt/lists/*

# Copy in required files
COPY ./bin /usr/bin/

USER $ZENITH_UID
ENTRYPOINT ["/usr/bin/tini", "-g", "--"]
CMD ["/usr/bin/tunnel-init"]
